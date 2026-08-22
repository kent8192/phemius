use std::{
    collections::HashSet,
    error::Error,
    ffi::{CString, OsStr, OsString},
    fmt,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};

use crate::{
    changeset::{
        Changeset, FileOperation, OperationKind, approval_record_bytes, canon_root_hash,
        canon_root_hash_at, path_alias_key, sha256_bytes, validate_changeset,
        validate_target_lexical,
    },
    domain::{EntityKind, is_prefixed_uuid},
    project::Project,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use cap_std::{
    ambient_authority,
    fs::{Dir, MetadataExt, OpenOptions, OpenOptionsExt},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum JournalState {
    Prepared,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyJournal {
    changeset_id: String,
    state: JournalState,
    base_root_hash: String,
    result_root_hash: String,
    approval_record_sha256: String,
    entries: Vec<JournalEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    kind: OperationKind,
    target_path: PathBuf,
    before_sha256: Option<String>,
    after_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestInterruption {
    AfterFirstRename,
    AfterReplacePreserve,
    AfterReplaceInstall,
    AfterDeletePreserve,
    AfterApprovalInstall,
    CommitDurabilityUnknown,
    AfterCommit,
    CleanupPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestRecoveryInterruption {
    AfterFirstQuarantine,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryOutcome {
    pub rolled_back: usize,
    pub kept_committed: usize,
}

pub fn apply_changeset(project: &Project, change: &Changeset) -> Result<()> {
    apply(project, change, None, None)
}

#[doc(hidden)]
pub fn apply_changeset_for_test(
    project: &Project,
    change: &Changeset,
    interruption: TestInterruption,
) -> Result<()> {
    apply(project, change, Some(interruption), None)
}

#[doc(hidden)]
pub fn apply_changeset_with_test_hook(
    project: &Project,
    change: &Changeset,
    hook: fn(&Project),
) -> Result<()> {
    apply(project, change, None, Some(hook))
}

pub fn recover_pending(project_root: &Path) -> Result<RecoveryOutcome> {
    recover(project_root, None)
}

#[doc(hidden)]
pub fn recover_pending_for_test(
    project_root: &Path,
    interruption: TestRecoveryInterruption,
) -> Result<RecoveryOutcome> {
    recover(project_root, Some(interruption))
}

fn recover(
    project_root: &Path,
    interruption: Option<TestRecoveryInterruption>,
) -> Result<RecoveryOutcome> {
    let root = project_dir(project_root)?;
    let lock = WriterLock::acquire(&root)?;
    recover_pending_locked(&root, &lock.runtime, project_root, interruption)
}

fn apply(
    project: &Project,
    change: &Changeset,
    interruption: Option<TestInterruption>,
    hook: Option<fn(&Project)>,
) -> Result<()> {
    let root = project_dir(&project.root)?;
    let lock = WriterLock::acquire(&root)?;
    recover_pending_locked(&root, &lock.runtime, &project.root, None)?;
    validate_changeset(project, change).context("changeset is not approvable")?;

    let transaction = prepare_transaction(&root, &lock.runtime, &project.root, change)?;
    if let Err(error) = persist_journal(&transaction.dir, &transaction.journal, false, false) {
        return match error {
            PersistError::Before(error) => {
                let _ = remove_unprepared(&transaction);
                Err(error)
            }
            PersistError::After(error) => Err(error
                .context("prepared journal durability is unknown; run recovery before retrying")),
        };
    }

    if let Some(hook) = hook {
        hook(project);
    }
    for index in 0..transaction.journal.entries.len() {
        match apply_entry(&transaction, index, interruption) {
            Ok(()) => {}
            Err(error) if error.downcast_ref::<SimulatedCrash>().is_some() => return Err(error),
            Err(error) => return rollback_after_error(&transaction, error),
        }
        let entry = &transaction.journal.entries[index];
        if (index == 0 && interruption == Some(TestInterruption::AfterFirstRename))
            || (entry.kind == OperationKind::Replace
                && interruption == Some(TestInterruption::AfterReplaceInstall))
        {
            return Err(SimulatedCrash.into());
        }
    }

    if let Err(error) = install_approval_record(&transaction) {
        return rollback_after_error(&transaction, error);
    }
    if interruption == Some(TestInterruption::AfterApprovalInstall) {
        return Err(SimulatedCrash.into());
    }
    match canon_root_hash(project) {
        Ok(actual) if actual == transaction.journal.result_root_hash => {}
        Ok(actual) => {
            return rollback_after_error(
                &transaction,
                anyhow!(
                    "applied canon root {actual} does not match {}",
                    transaction.journal.result_root_hash
                ),
            );
        }
        Err(error) => return rollback_after_error(&transaction, anyhow!(error)),
    }

    let mut committed = transaction.journal.clone();
    committed.state = JournalState::Committed;
    let force_sync_failure = interruption == Some(TestInterruption::CommitDurabilityUnknown);
    match persist_journal(&transaction.dir, &committed, true, force_sync_failure) {
        Ok(()) => {}
        Err(PersistError::Before(error)) => return rollback_after_error(&transaction, error),
        Err(PersistError::After(error)) => {
            return Err(error.context("commit durability unknown; run recovery, do not retry"));
        }
    }
    if interruption == Some(TestInterruption::AfterCommit) {
        return Err(SimulatedCrash.into());
    }
    if interruption == Some(TestInterruption::CleanupPending) {
        return Ok(());
    }
    let _ = cleanup_transaction(&transaction);
    Ok(())
}

struct Transaction {
    project_root: PathBuf,
    journal_root: Dir,
    dir: Dir,
    journal: ApplyJournal,
    targets: Vec<ManagedPath>,
    approval: ManagedPath,
}

struct ManagedPath {
    parent: Dir,
    leaf: OsString,
    display: PathBuf,
}

fn prepare_transaction(
    root: &Dir,
    runtime: &Dir,
    project_root: &Path,
    change: &Changeset,
) -> Result<Transaction> {
    let journal_root = open_or_create_dir(runtime, OsStr::new("journal"))
        .context("failed to open runtime journal directory")?;
    let name = OsString::from(change.id.as_str());
    journal_root
        .create_dir(&name)
        .with_context(|| format!("failed to create transaction {}", change.id.as_str()))?;
    sync_dir(&journal_root)?;
    let dir = open_dir_no_follow(&journal_root, &name)?;
    let approval_dir = approval_directory(root, true)?
        .ok_or_else(|| anyhow!("approval directory was not created"))?;
    let approval = ManagedPath {
        parent: approval_dir,
        leaf: OsString::from(format!("{}.json", change.id.as_str())),
        display: PathBuf::from(".phemius/records/approvals")
            .join(format!("{}.json", change.id.as_str())),
    };

    let result = (|| {
        let mut entries = Vec::with_capacity(change.operations.len());
        let mut targets = Vec::with_capacity(change.operations.len());
        for (index, operation) in change.operations.iter().enumerate() {
            let target = open_managed(root, &operation.path)?;
            snapshot_operation(root, &dir, index, operation, &target)?;
            entries.push(JournalEntry {
                kind: operation.kind,
                target_path: operation.path.clone(),
                before_sha256: operation.before_sha256.clone(),
                after_sha256: operation.after_sha256.clone(),
            });
            targets.push(target);
        }
        let approval_bytes = approval_record_bytes(change)?;
        write_new_synced(&dir, OsStr::new("approval-record.json"), &approval_bytes)?;
        sync_dir(&dir)?;
        Ok(Transaction {
            project_root: project_root.to_path_buf(),
            journal_root: journal_root.try_clone()?,
            dir: dir.try_clone()?,
            journal: ApplyJournal {
                changeset_id: change.id.as_str().to_owned(),
                state: JournalState::Prepared,
                base_root_hash: change.base_root_hash.clone(),
                result_root_hash: change.result_root_hash.clone(),
                approval_record_sha256: sha256_bytes(&approval_bytes),
                entries,
            },
            targets,
            approval,
        })
    })();
    if result.is_err() {
        let _ = dir.try_clone().and_then(Dir::remove_open_dir_all);
        let _ = sync_dir(&journal_root);
    }
    result
}

fn snapshot_operation(
    root: &Dir,
    transaction: &Dir,
    index: usize,
    operation: &FileOperation,
    target: &ManagedPath,
) -> Result<()> {
    if let Some(expected) = &operation.before_sha256 {
        let bytes = read_regular(target)?;
        ensure!(
            sha256_bytes(&bytes) == *expected,
            "canon changed while snapshotting {}",
            operation.path.display()
        );
        write_new_synced(
            transaction,
            OsStr::new(&format!("before-{index:04}")),
            &bytes,
        )?;
    }
    if let Some(candidate_path) = &operation.candidate_path {
        let candidate = open_managed(root, candidate_path)?;
        let bytes = read_regular(&candidate)?;
        ensure!(
            operation.after_sha256.as_deref() == Some(sha256_bytes(&bytes).as_str()),
            "candidate changed while snapshotting {}",
            candidate_path.display()
        );
        write_new_synced(
            transaction,
            OsStr::new(&format!("after-{index:04}")),
            &bytes,
        )?;
    }
    Ok(())
}

fn apply_entry(
    transaction: &Transaction,
    index: usize,
    interruption: Option<TestInterruption>,
) -> Result<()> {
    let entry = &transaction.journal.entries[index];
    let target = &transaction.targets[index];
    match entry.kind {
        OperationKind::Create => ensure!(
            maybe_hash(target)?.is_none(),
            "create target appeared: {}",
            target.display.display()
        ),
        OperationKind::Replace | OperationKind::Delete => {
            ensure_hash(target, entry.before_sha256.as_deref(), "canon changed")?;
            let old = OsString::from(format!("old-live-{index:04}"));
            rename_no_replace(&target.parent, &target.leaf, &transaction.dir, &old)
                .with_context(|| format!("failed to preserve {}", target.display.display()))?;
            sync_dir(&target.parent)?;
            sync_dir(&transaction.dir)?;
            if let Err(error) = ensure_hash_at(
                &transaction.dir,
                &old,
                entry.before_sha256.as_deref(),
                "preserved canon raced",
            ) {
                if maybe_hash(target)?.is_none() {
                    let _ = rename_no_replace(&transaction.dir, &old, &target.parent, &target.leaf);
                    let _ = sync_dir(&target.parent);
                }
                return Err(error);
            }
            if (entry.kind == OperationKind::Replace
                && interruption == Some(TestInterruption::AfterReplacePreserve))
                || (entry.kind == OperationKind::Delete
                    && interruption == Some(TestInterruption::AfterDeletePreserve))
            {
                return Err(SimulatedCrash.into());
            }
        }
    }
    if entry.after_sha256.is_some() {
        let after = OsString::from(format!("after-{index:04}"));
        rename_no_replace(&transaction.dir, &after, &target.parent, &target.leaf)
            .with_context(|| format!("failed to install {}", target.display.display()))?;
        sync_dir(&transaction.dir)?;
        sync_dir(&target.parent)?;
        ensure_hash(
            target,
            entry.after_sha256.as_deref(),
            "installed file changed",
        )?;
    }
    Ok(())
}

fn install_approval_record(transaction: &Transaction) -> Result<()> {
    ensure!(
        maybe_hash(&transaction.approval)?.is_none(),
        "approval record appeared during apply: {}",
        transaction.approval.display.display()
    );
    ensure_hash_at(
        &transaction.dir,
        OsStr::new("approval-record.json"),
        Some(&transaction.journal.approval_record_sha256),
        "approval stage changed",
    )?;
    rename_no_replace(
        &transaction.dir,
        OsStr::new("approval-record.json"),
        &transaction.approval.parent,
        &transaction.approval.leaf,
    )?;
    sync_dir(&transaction.dir)?;
    sync_dir(&transaction.approval.parent)?;
    Ok(())
}

fn rollback_after_error(transaction: &Transaction, error: anyhow::Error) -> Result<()> {
    match rollback_prepared(transaction, None).and_then(|()| cleanup_transaction(transaction)) {
        Ok(()) => Err(error),
        Err(rollback) => Err(anyhow!(
            "apply failed: {error}; rollback remains pending: {rollback}"
        )),
    }
}

fn recover_pending_locked(
    root: &Dir,
    runtime: &Dir,
    project_root: &Path,
    interruption: Option<TestRecoveryInterruption>,
) -> Result<RecoveryOutcome> {
    let Some(transaction) = load_pending(root, runtime, project_root)? else {
        return Ok(RecoveryOutcome::default());
    };
    match transaction.journal.state {
        JournalState::Prepared => {
            rollback_prepared(&transaction, interruption)?;
            cleanup_transaction(&transaction)?;
            Ok(RecoveryOutcome {
                rolled_back: 1,
                kept_committed: 0,
            })
        }
        JournalState::Committed => {
            verify_committed(&transaction)?;
            cleanup_transaction(&transaction)?;
            Ok(RecoveryOutcome {
                rolled_back: 0,
                kept_committed: 1,
            })
        }
    }
}

fn load_pending(root: &Dir, runtime: &Dir, project_root: &Path) -> Result<Option<Transaction>> {
    let Some(journal_root) = try_open_dir(runtime, OsStr::new("journal"))? else {
        return Ok(None);
    };
    let mut entries = journal_root
        .entries()
        .context("failed to enumerate journal root")?
        .collect::<std::io::Result<Vec<_>>>()
        .context("failed to read journal root entry")?;
    entries.sort_by_key(|entry| entry.file_name());
    if entries.is_empty() {
        return Ok(None);
    }
    ensure!(entries.len() == 1, "multiple pending journal transactions");
    let name = entries[0].file_name();
    let name_text = name.to_string_lossy();
    ensure!(
        is_prefixed_uuid(&name_text, EntityKind::Changeset),
        "invalid journal transaction name: {name_text}"
    );
    let dir = open_dir_no_follow(&journal_root, &name)
        .with_context(|| format!("journal entry is not a real directory: {name_text}"))?;
    let journal_bytes = read_regular_at(&dir, OsStr::new("journal.json"))
        .context("pending journal.json is missing or invalid")?;
    let journal: ApplyJournal =
        serde_json::from_slice(&journal_bytes).context("failed to parse pending journal")?;
    ensure!(
        journal.changeset_id == name_text,
        "journal identity does not match its transaction directory"
    );
    validate_journal(&journal)?;
    validate_transaction_entries(&dir, &journal)?;

    let approval_dir = approval_directory(root, false)?
        .ok_or_else(|| anyhow!("approval directory is missing for pending journal"))?;
    let approval = ManagedPath {
        parent: approval_dir,
        leaf: OsString::from(format!("{}.json", journal.changeset_id)),
        display: PathBuf::from(".phemius/records/approvals")
            .join(format!("{}.json", journal.changeset_id)),
    };
    let mut targets = Vec::with_capacity(journal.entries.len());
    for entry in &journal.entries {
        targets.push(open_managed(root, &entry.target_path)?);
    }
    let transaction = Transaction {
        project_root: project_root.to_path_buf(),
        journal_root,
        dir,
        journal,
        targets,
        approval,
    };
    if transaction.journal.state == JournalState::Prepared {
        validate_recovery_evidence(&transaction)?;
    }
    Ok(Some(transaction))
}

fn validate_journal(journal: &ApplyJournal) -> Result<()> {
    ensure!(!journal.entries.is_empty(), "journal has no operations");
    ensure!(
        is_hash(&journal.base_root_hash)
            && is_hash(&journal.result_root_hash)
            && is_hash(&journal.approval_record_sha256),
        "journal contains an invalid root or approval hash"
    );
    let mut targets = HashSet::new();
    for entry in &journal.entries {
        validate_target_lexical(&entry.target_path).context("journal contains an unsafe target")?;
        ensure!(
            targets.insert(path_alias_key(&entry.target_path)?),
            "journal has duplicate target aliases"
        );
        let shape = match entry.kind {
            OperationKind::Create => entry.before_sha256.is_none() && entry.after_sha256.is_some(),
            OperationKind::Replace => {
                entry.before_sha256.is_some()
                    && entry.after_sha256.is_some()
                    && entry.before_sha256 != entry.after_sha256
            }
            OperationKind::Delete => entry.before_sha256.is_some() && entry.after_sha256.is_none(),
        };
        ensure!(shape, "journal contains an invalid operation shape");
        ensure!(
            entry
                .before_sha256
                .iter()
                .chain(&entry.after_sha256)
                .all(|hash| is_hash(hash)),
            "journal contains an invalid file hash"
        );
    }
    Ok(())
}

fn validate_transaction_entries(dir: &Dir, journal: &ApplyJournal) -> Result<()> {
    let mut allowed = HashSet::from([
        OsString::from("journal.json"),
        OsString::from("approval-record.json"),
        OsString::from("approval-quarantine"),
    ]);
    for (index, entry) in journal.entries.iter().enumerate() {
        if entry.before_sha256.is_some() {
            allowed.insert(OsString::from(format!("before-{index:04}")));
            allowed.insert(OsString::from(format!("old-live-{index:04}")));
            allowed.insert(OsString::from(format!("restore-{index:04}")));
        }
        if entry.after_sha256.is_some() {
            allowed.insert(OsString::from(format!("after-{index:04}")));
            allowed.insert(OsString::from(format!("quarantine-{index:04}")));
        }
    }
    for entry in dir.entries().context("failed to enumerate transaction")? {
        let entry = entry.context("failed to read transaction entry")?;
        ensure!(
            allowed.contains(&entry.file_name()),
            "unknown transaction entry: {}",
            entry.file_name().to_string_lossy()
        );
        ensure!(
            entry
                .file_type()
                .context("failed to inspect transaction entry")?
                .is_file(),
            "transaction entry is not a regular file: {}",
            entry.file_name().to_string_lossy()
        );
    }
    Ok(())
}

fn validate_recovery_evidence(transaction: &Transaction) -> Result<()> {
    for (index, entry) in transaction.journal.entries.iter().enumerate() {
        if let Some(before) = &entry.before_sha256 {
            ensure_hash_at(
                &transaction.dir,
                OsStr::new(&format!("before-{index:04}")),
                Some(before),
                "before image changed",
            )?;
            let old = OsString::from(format!("old-live-{index:04}"));
            if exists_at(&transaction.dir, &old)? {
                ensure_hash_at(
                    &transaction.dir,
                    &old,
                    Some(before),
                    "preserved canon changed",
                )?;
            }
        }
        let quarantine = OsString::from(format!("quarantine-{index:04}"));
        if exists_at(&transaction.dir, &quarantine)? {
            ensure_hash_at(
                &transaction.dir,
                &quarantine,
                entry.after_sha256.as_deref(),
                "quarantined target changed",
            )?;
        }
    }
    if exists_at(&transaction.dir, OsStr::new("approval-quarantine"))? {
        ensure_hash_at(
            &transaction.dir,
            OsStr::new("approval-quarantine"),
            Some(&transaction.journal.approval_record_sha256),
            "quarantined approval changed",
        )?;
    }
    Ok(())
}

fn rollback_prepared(
    transaction: &Transaction,
    interruption: Option<TestRecoveryInterruption>,
) -> Result<()> {
    let mut quarantined = 0;
    quarantine_created(
        &transaction.approval,
        &transaction.dir,
        OsStr::new("approval-quarantine"),
        &transaction.journal.approval_record_sha256,
        interruption,
        &mut quarantined,
    )?;

    // ponytail: Recovery covers bytes and existence; mode, xattr, and ACL images are outside v0.1.
    for index in (0..transaction.journal.entries.len()).rev() {
        let entry = &transaction.journal.entries[index];
        let target = &transaction.targets[index];
        match &entry.before_sha256 {
            None => quarantine_created(
                target,
                &transaction.dir,
                OsStr::new(&format!("quarantine-{index:04}")),
                entry
                    .after_sha256
                    .as_deref()
                    .ok_or_else(|| anyhow!("create operation has no after hash"))?,
                interruption,
                &mut quarantined,
            )?,
            Some(before) => restore_before(
                transaction,
                index,
                target,
                before,
                entry.after_sha256.as_deref(),
                interruption,
                &mut quarantined,
            )?,
        }
    }
    ensure!(
        canon_root_hash_at(&transaction.project_root)? == transaction.journal.base_root_hash,
        "rolled-back canon does not match the journal base root"
    );
    Ok(())
}

fn quarantine_created(
    live: &ManagedPath,
    transaction: &Dir,
    quarantine: &OsStr,
    expected: &str,
    interruption: Option<TestRecoveryInterruption>,
    quarantined: &mut usize,
) -> Result<()> {
    if exists_at(transaction, quarantine)? {
        ensure_hash_at(
            transaction,
            quarantine,
            Some(expected),
            "quarantined file changed",
        )?;
        ensure!(
            maybe_hash(live)?.is_none(),
            "live file reappeared beside quarantine: {}",
            live.display.display()
        );
        return Ok(());
    }
    let Some(actual) = maybe_hash(live)? else {
        return Ok(());
    };
    ensure!(
        actual == expected,
        "refusing to overwrite externally changed file {}",
        live.display.display()
    );
    rename_no_replace(&live.parent, &live.leaf, transaction, quarantine)?;
    sync_dir(&live.parent)?;
    sync_dir(transaction)?;
    *quarantined += 1;
    if *quarantined == 1 && interruption == Some(TestRecoveryInterruption::AfterFirstQuarantine) {
        return Err(SimulatedCrash.into());
    }
    match ensure_hash_at(
        transaction,
        quarantine,
        Some(expected),
        "quarantined file raced",
    ) {
        Ok(()) => {}
        Err(error) => {
            if maybe_hash(live)?.is_none() {
                let _ = rename_no_replace(transaction, quarantine, &live.parent, &live.leaf);
                let _ = sync_dir(&live.parent);
            }
            return Err(error);
        }
    }
    ensure!(
        maybe_hash(live)?.is_none(),
        "live file reappeared after quarantine: {}",
        live.display.display()
    );
    Ok(())
}

fn restore_before(
    transaction: &Transaction,
    index: usize,
    target: &ManagedPath,
    before: &str,
    after: Option<&str>,
    interruption: Option<TestRecoveryInterruption>,
    quarantined: &mut usize,
) -> Result<()> {
    match maybe_hash(target)? {
        Some(actual) if actual == before => return Ok(()),
        Some(actual) if after == Some(actual.as_str()) => quarantine_created(
            target,
            &transaction.dir,
            OsStr::new(&format!("quarantine-{index:04}")),
            &actual,
            interruption,
            quarantined,
        )?,
        Some(_) => {
            bail!(
                "refusing to overwrite externally changed target {}",
                target.display.display()
            )
        }
        None => {}
    }

    let old = OsString::from(format!("old-live-{index:04}"));
    let restore = OsString::from(format!("restore-{index:04}"));
    let source = if exists_at(&transaction.dir, &old)? {
        ensure_hash_at(
            &transaction.dir,
            &old,
            Some(before),
            "preserved canon changed",
        )?;
        &old
    } else {
        if !exists_at(&transaction.dir, &restore)? {
            let before_bytes =
                read_regular_at(&transaction.dir, OsStr::new(&format!("before-{index:04}")))?;
            ensure!(
                sha256_bytes(&before_bytes) == before,
                "before image changed"
            );
            write_new_synced(&transaction.dir, &restore, &before_bytes)?;
            sync_dir(&transaction.dir)?;
        }
        ensure_hash_at(
            &transaction.dir,
            &restore,
            Some(before),
            "restore image changed",
        )?;
        &restore
    };
    rename_no_replace(&transaction.dir, source, &target.parent, &target.leaf)
        .with_context(|| format!("failed to restore {}", target.display.display()))?;
    sync_dir(&transaction.dir)?;
    sync_dir(&target.parent)?;
    ensure_hash(target, Some(before), "restored target changed")
}

fn verify_committed(transaction: &Transaction) -> Result<()> {
    ensure!(
        canon_root_hash_at(&transaction.project_root)? == transaction.journal.result_root_hash,
        "committed canon root changed"
    );
    ensure_hash(
        &transaction.approval,
        Some(&transaction.journal.approval_record_sha256),
        "committed approval record changed",
    )
}

enum PersistError {
    Before(anyhow::Error),
    After(anyhow::Error),
}

fn persist_journal(
    transaction: &Dir,
    journal: &ApplyJournal,
    replace: bool,
    force_sync_failure: bool,
) -> std::result::Result<(), PersistError> {
    let temporary = OsString::from(format!("journal-{}.tmp", uuid::Uuid::now_v7()));
    let mut bytes =
        serde_json::to_vec_pretty(journal).map_err(|error| PersistError::Before(anyhow!(error)))?;
    bytes.push(b'\n');
    if let Err(error) = write_new_synced(transaction, &temporary, &bytes) {
        let _ = transaction.remove_file(&temporary);
        return Err(PersistError::Before(error));
    }
    let rename = if replace {
        transaction.rename(&temporary, transaction, "journal.json")
    } else {
        rename_no_replace(
            transaction,
            &temporary,
            transaction,
            OsStr::new("journal.json"),
        )
    };
    if let Err(error) = rename {
        let _ = transaction.remove_file(&temporary);
        return Err(PersistError::Before(
            anyhow!(error).context("failed to rename journal"),
        ));
    }
    if force_sync_failure {
        return Err(PersistError::After(anyhow!(
            "simulated directory sync failure"
        )));
    }
    sync_dir(transaction).map_err(PersistError::After)
}

fn cleanup_transaction(transaction: &Transaction) -> Result<()> {
    validate_transaction_entries(&transaction.dir, &transaction.journal)?;
    transaction
        .dir
        .try_clone()?
        .remove_open_dir_all()
        .context("failed to clean transaction directory")?;
    sync_dir(&transaction.journal_root)
}

fn remove_unprepared(transaction: &Transaction) -> Result<()> {
    transaction.dir.try_clone()?.remove_open_dir_all()?;
    sync_dir(&transaction.journal_root)
}

fn approval_directory(root: &Dir, create: bool) -> Result<Option<Dir>> {
    let Some(phemius) = open_or_missing(root, OsStr::new(".phemius"), create)? else {
        return Ok(None);
    };
    let Some(records) = open_or_missing(&phemius, OsStr::new("records"), create)? else {
        return Ok(None);
    };
    open_or_missing(&records, OsStr::new("approvals"), create)
}

fn open_or_missing(parent: &Dir, name: &OsStr, create: bool) -> Result<Option<Dir>> {
    if create {
        return open_or_create_dir(parent, name).map(Some);
    }
    try_open_dir(parent, name)
}

fn project_dir(root: &Path) -> Result<Dir> {
    Dir::open_ambient_dir(root, ambient_authority())
        .with_context(|| format!("project root is not a real directory: {}", root.display()))
}

fn open_managed(root: &Dir, relative: &Path) -> Result<ManagedPath> {
    ensure!(!relative.is_absolute(), "managed path must be relative");
    let components = relative.components().collect::<Vec<_>>();
    ensure!(!components.is_empty(), "managed path is empty");
    let mut parent = root.try_clone()?;
    for component in &components[..components.len() - 1] {
        let Component::Normal(name) = component else {
            bail!("unsafe managed path: {}", relative.display());
        };
        parent = open_dir_no_follow(&parent, name)?;
    }
    let Component::Normal(leaf) = components[components.len() - 1] else {
        bail!("unsafe managed path: {}", relative.display());
    };
    Ok(ManagedPath {
        parent,
        leaf: leaf.to_os_string(),
        display: relative.to_path_buf(),
    })
}

fn open_or_create_dir(parent: &Dir, name: &OsStr) -> Result<Dir> {
    match open_dir_no_follow(parent, name) {
        Ok(dir) => Ok(dir),
        Err(error) if io_kind(&error) == Some(std::io::ErrorKind::NotFound) => {
            match parent.create_dir(name) {
                Ok(()) => sync_dir(parent)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error).context("failed to create managed directory"),
            }
            open_dir_no_follow(parent, name)
        }
        Err(error) => Err(error),
    }
}

fn try_open_dir(parent: &Dir, name: &OsStr) -> Result<Option<Dir>> {
    match open_dir_no_follow(parent, name) {
        Ok(dir) => Ok(Some(dir)),
        Err(error) if io_kind(&error) == Some(std::io::ErrorKind::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

fn io_kind(error: &anyhow::Error) -> Option<std::io::ErrorKind> {
    error
        .downcast_ref::<std::io::Error>()
        .map(std::io::Error::kind)
}

fn open_dir_no_follow(parent: &Dir, name: &OsStr) -> Result<Dir> {
    let anchor = parent.try_clone()?.into_std_file();
    let name = c_string(name)?;
    // SAFETY: The directory descriptor and NUL-terminated leaf name stay valid for this call.
    let descriptor = unsafe {
        libc::openat(
            anchor.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor == -1 {
        return Err(std::io::Error::last_os_error()).context("failed to open managed directory");
    }
    // SAFETY: openat returned a new owned descriptor which is transferred exactly once.
    let file = unsafe { File::from_raw_fd(descriptor) };
    Ok(Dir::from_std_file(file))
}

fn rename_no_replace(
    from_dir: &Dir,
    from: &OsStr,
    to_dir: &Dir,
    to: &OsStr,
) -> std::io::Result<()> {
    let from_anchor = from_dir.try_clone()?.into_std_file();
    let to_anchor = to_dir.try_clone()?.into_std_file();
    let from = c_string_io(from)?;
    let to = c_string_io(to)?;
    // SAFETY: Both descriptors and NUL-terminated leaf names stay valid for this call.
    let result = unsafe {
        libc::renameatx_np(
            from_anchor.as_raw_fd(),
            from.as_ptr(),
            to_anchor.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn c_string(value: &OsStr) -> Result<CString> {
    c_string_io(value).map_err(anyhow::Error::from)
}

fn c_string_io(value: &OsStr) -> std::io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "name contains NUL"))
}

fn write_new_synced(dir: &Dir, name: &OsStr, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = dir
        .open_with(name, &options)
        .with_context(|| format!("failed to create {}", name.to_string_lossy()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", name.to_string_lossy()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", name.to_string_lossy()))
}

fn read_regular(path: &ManagedPath) -> Result<Vec<u8>> {
    read_regular_at(&path.parent, &path.leaf)
        .with_context(|| format!("failed to read {}", path.display.display()))
}

fn read_regular_at(dir: &Dir, name: &OsStr) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = dir.open_with(name, &options)?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "managed entry is not a regular file");
    let identity = (before.dev(), before.ino());
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        identity == (after.dev(), after.ino()),
        "managed file identity changed while reading"
    );
    Ok(bytes)
}

fn maybe_hash(path: &ManagedPath) -> Result<Option<String>> {
    match read_regular(path) {
        Ok(bytes) => Ok(Some(sha256_bytes(&bytes))),
        Err(error) if io_kind(&error) == Some(std::io::ErrorKind::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

fn exists_at(dir: &Dir, name: &OsStr) -> Result<bool> {
    match dir.symlink_metadata(name) {
        Ok(metadata) => {
            ensure!(metadata.is_file(), "managed entry is not a regular file");
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn ensure_hash(path: &ManagedPath, expected: Option<&str>, label: &str) -> Result<()> {
    let expected = expected.ok_or_else(|| anyhow!("{label}: expected hash is missing"))?;
    let actual = maybe_hash(path)?.ok_or_else(|| anyhow!("{label}: file is missing"))?;
    ensure!(actual == expected, "{label}: {}", path.display.display());
    Ok(())
}

fn ensure_hash_at(dir: &Dir, name: &OsStr, expected: Option<&str>, label: &str) -> Result<()> {
    let expected = expected.ok_or_else(|| anyhow!("{label}: expected hash is missing"))?;
    let actual = sha256_bytes(&read_regular_at(dir, name)?);
    ensure!(actual == expected, "{label}: {}", name.to_string_lossy());
    Ok(())
}

fn sync_dir(dir: &Dir) -> Result<()> {
    dir.try_clone()?
        .into_std_file()
        .sync_all()
        .context("failed to sync managed directory")
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug)]
struct SimulatedCrash;

impl fmt::Display for SimulatedCrash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("simulated crash")
    }
}

impl Error for SimulatedCrash {}

struct WriterLock {
    _file: File,
    runtime: Dir,
}

impl WriterLock {
    fn acquire(root: &Dir) -> Result<Self> {
        let phemius = open_or_create_dir(root, OsStr::new(".phemius"))?;
        let runtime = open_or_create_dir(&phemius, OsStr::new("runtime"))?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW);
        let file = runtime
            .open_with("approve.lock", &options)
            .context("failed to open writer lock")?
            .into_std();
        ensure!(
            file.metadata()?.is_file(),
            "writer lock is not a regular file"
        );
        file.lock().context("failed to acquire writer lock")?;
        Ok(Self {
            _file: file,
            runtime,
        })
    }
}
