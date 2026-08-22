use std::{
    collections::HashSet,
    error::Error,
    ffi::{CString, OsStr, OsString},
    fmt,
    fs::File,
    io::Write,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
};

use crate::{
    changeset::{
        ApprovalRecord, Changeset, FileOperation, OperationKind, PinnedPath,
        approval_chain_head_in, approval_record_bytes, canon_root_hash_in, open_dir_no_follow_io,
        open_pinned_path_io, open_project_root_io, path_alias_key, read_regular_at_io,
        sha256_bytes, validate_changeset_in, validate_target_lexical,
    },
    domain::{EntityKind, is_prefixed_uuid},
    project::Project,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum JournalState {
    Prepared,
    Committed,
    RolledBack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyJournal {
    changeset_id: String,
    state: JournalState,
    base_root_hash: String,
    result_root_hash: String,
    approval_record_sha256: String,
    chapter_order: u32,
    entries: Vec<JournalEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    recover(project_root, None, None)
}

#[doc(hidden)]
pub fn recover_pending_for_test(
    project_root: &Path,
    interruption: TestRecoveryInterruption,
) -> Result<RecoveryOutcome> {
    recover(project_root, Some(interruption), None)
}

#[doc(hidden)]
pub fn recover_pending_with_root_test_hook(
    project_root: &Path,
    hook: fn(&Path),
) -> Result<RecoveryOutcome> {
    recover(project_root, None, Some(hook))
}

fn recover(
    project_root: &Path,
    interruption: Option<TestRecoveryInterruption>,
    root_hook: Option<fn(&Path)>,
) -> Result<RecoveryOutcome> {
    let root = project_dir(project_root)?;
    if let Some(hook) = root_hook {
        hook(project_root);
    }
    let lock = WriterLock::acquire(&root)?;
    recover_pending_locked(&root, &lock.runtime, interruption)
}

fn apply(
    project: &Project,
    change: &Changeset,
    interruption: Option<TestInterruption>,
    hook: Option<fn(&Project)>,
) -> Result<()> {
    let root = project_dir(&project.root)?;
    let lock = WriterLock::acquire(&root)?;
    recover_pending_locked(&root, &lock.runtime, None)?;
    validate_changeset_in(project, &root, change).context("changeset is not approvable")?;

    let transaction = prepare_transaction(&root, &lock.runtime, change)?;
    if let Err(error) = persist_journal(&transaction.dir, &transaction.journal, false) {
        return match error {
            PersistError::Before(error) => Err(error),
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
    match canon_root_hash_in(&transaction.root) {
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
    match persist_journal(&transaction.dir, &committed, force_sync_failure) {
        Ok(()) => {}
        Err(PersistError::Before(error)) => return rollback_after_error(&transaction, error),
        Err(PersistError::After(error)) => {
            return Err(error.context("commit durability unknown; run recovery, do not retry"));
        }
    }
    if interruption == Some(TestInterruption::AfterCommit) {
        return Err(SimulatedCrash.into());
    }
    Ok(())
}

struct Transaction {
    root: Dir,
    dir: Dir,
    journal: ApplyJournal,
    targets: Vec<ManagedPath>,
    approval: ManagedPath,
}

type ManagedPath = PinnedPath;

fn prepare_transaction(root: &Dir, runtime: &Dir, change: &Changeset) -> Result<Transaction> {
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
            root: root.try_clone()?,
            dir: dir.try_clone()?,
            journal: ApplyJournal {
                changeset_id: change.id.as_str().to_owned(),
                state: JournalState::Prepared,
                base_root_hash: change.base_root_hash.clone(),
                result_root_hash: change.result_root_hash.clone(),
                approval_record_sha256: sha256_bytes(&approval_bytes),
                chapter_order: change.chapter_order,
                entries,
            },
            targets,
            approval,
        })
    })();
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
    match rollback_prepared(transaction, None).and_then(|()| persist_rolled_back(transaction)) {
        Ok(()) => Err(error),
        Err(rollback) => Err(anyhow!(
            "apply failed: {error}; rollback remains pending: {rollback}"
        )),
    }
}

fn recover_pending_locked(
    root: &Dir,
    runtime: &Dir,
    interruption: Option<TestRecoveryInterruption>,
) -> Result<RecoveryOutcome> {
    let transactions = load_transactions(root, runtime)?;
    if transactions.is_empty() {
        return Ok(RecoveryOutcome::default());
    }
    for transaction in &transactions {
        if transaction.journal.state == JournalState::Committed {
            verify_committed_approval(transaction)?;
        }
    }
    let prepared = transactions
        .iter()
        .find(|transaction| transaction.journal.state == JournalState::Prepared);
    let rolled_back = if let Some(transaction) = prepared {
        rollback_prepared(transaction, interruption)?;
        persist_rolled_back(transaction)?;
        1
    } else {
        0
    };
    verify_current_committed_head(root, &transactions)?;
    Ok(RecoveryOutcome {
        rolled_back,
        kept_committed: transactions
            .iter()
            .filter(|transaction| transaction.journal.state == JournalState::Committed)
            .count(),
    })
}

fn load_transactions(root: &Dir, runtime: &Dir) -> Result<Vec<Transaction>> {
    let Some(journal_root) = try_open_dir(runtime, OsStr::new("journal"))? else {
        return Ok(Vec::new());
    };
    let mut entries = journal_root
        .entries()
        .context("failed to enumerate journal root")?
        .collect::<std::io::Result<Vec<_>>>()
        .context("failed to read journal root entry")?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut transactions = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry.file_name();
        transactions.push(load_transaction(root, &journal_root, &name)?);
    }
    ensure!(
        transactions
            .iter()
            .filter(|transaction| transaction.journal.state == JournalState::Prepared)
            .count()
            <= 1,
        "multiple prepared journal transactions"
    );
    Ok(transactions)
}

fn load_transaction(root: &Dir, journal_root: &Dir, name: &OsStr) -> Result<Transaction> {
    let name_text = name.to_string_lossy();
    ensure!(
        is_prefixed_uuid(&name_text, EntityKind::Changeset),
        "invalid journal transaction name: {name_text}"
    );
    let dir = open_dir_no_follow(journal_root, name)
        .with_context(|| format!("journal entry is not a real directory: {name_text}"))?;
    let prepared = read_journal(&dir, "journal.prepared.json")?
        .ok_or_else(|| anyhow!("journal.prepared.json is missing"))?;
    ensure!(
        prepared.state == JournalState::Prepared,
        "prepared journal has the wrong state"
    );
    let committed = read_journal(&dir, "journal.committed.json")?;
    let rolled_back = read_journal(&dir, "journal.rolled-back.json")?;
    ensure!(
        committed
            .as_ref()
            .is_none_or(|journal| journal.state == JournalState::Committed),
        "committed journal has the wrong state"
    );
    ensure!(
        rolled_back
            .as_ref()
            .is_none_or(|journal| journal.state == JournalState::RolledBack),
        "rolled-back journal has the wrong state"
    );
    ensure!(
        !(committed.is_some() && rolled_back.is_some()),
        "transaction has conflicting terminal journals"
    );
    let journal = committed
        .or(rolled_back)
        .unwrap_or_else(|| prepared.clone());
    if journal.state != JournalState::Prepared {
        let mut expected = prepared.clone();
        expected.state = journal.state;
        ensure!(
            expected == journal,
            "terminal journal does not match prepared evidence"
        );
    }
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
        root: root.try_clone()?,
        dir,
        journal,
        targets,
        approval,
    };
    if transaction.journal.state == JournalState::Prepared {
        validate_recovery_evidence(&transaction)?;
    }
    Ok(transaction)
}

fn read_journal(dir: &Dir, name: &str) -> Result<Option<ApplyJournal>> {
    let bytes = match read_regular_at(dir, OsStr::new(name)) {
        Ok(bytes) => bytes,
        Err(error) if io_kind(&error) == Some(std::io::ErrorKind::NotFound) => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("{name} is invalid")),
    };
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {name}"))
        .map(Some)
}

fn validate_journal(journal: &ApplyJournal) -> Result<()> {
    ensure!(!journal.entries.is_empty(), "journal has no operations");
    ensure!(journal.chapter_order > 0, "journal has no chapter order");
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
        OsString::from("journal.prepared.json"),
        OsString::from("journal.committed.json"),
        OsString::from("journal.rolled-back.json"),
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
        canon_root_hash_in(&transaction.root)? == transaction.journal.base_root_hash,
        "rolled-back canon does not match the journal base root"
    );
    Ok(())
}

fn persist_rolled_back(transaction: &Transaction) -> Result<()> {
    let mut rolled_back = transaction.journal.clone();
    rolled_back.state = JournalState::RolledBack;
    match persist_journal(&transaction.dir, &rolled_back, false) {
        Ok(()) => Ok(()),
        Err(PersistError::Before(error)) => Err(error),
        Err(PersistError::After(error)) => {
            Err(error.context("rollback durability is unknown; run recovery before retrying"))
        }
    }
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

fn verify_committed_approval(transaction: &Transaction) -> Result<()> {
    let bytes = read_regular(&transaction.approval)?;
    ensure!(
        sha256_bytes(&bytes) == transaction.journal.approval_record_sha256,
        "committed approval record changed"
    );
    let record: ApprovalRecord =
        serde_json::from_slice(&bytes).context("committed approval record is invalid")?;
    ensure!(
        record.changeset_id.as_str() == transaction.journal.changeset_id
            && record.base_root_hash == transaction.journal.base_root_hash
            && record.chapter_order == transaction.journal.chapter_order,
        "committed journal does not match its approval record"
    );
    Ok(())
}

fn verify_current_committed_head(root: &Dir, transactions: &[Transaction]) -> Result<()> {
    let Some((head_id, head_order)) = approval_chain_head_in(root)? else {
        return Ok(());
    };
    let Some(head) = transactions.iter().find(|transaction| {
        transaction.journal.state == JournalState::Committed
            && transaction.journal.changeset_id == head_id.as_str()
    }) else {
        return Ok(());
    };
    ensure!(
        head.journal.chapter_order == head_order,
        "committed journal chapter order does not match the approval chain head"
    );
    ensure!(
        canon_root_hash_in(root)? == head.journal.result_root_hash,
        "current committed canon root changed"
    );
    Ok(())
}

enum PersistError {
    Before(anyhow::Error),
    After(anyhow::Error),
}

fn persist_journal(
    transaction: &Dir,
    journal: &ApplyJournal,
    force_sync_failure: bool,
) -> std::result::Result<(), PersistError> {
    let temporary = OsString::from(format!("journal-{}.tmp", uuid::Uuid::now_v7()));
    let mut bytes =
        serde_json::to_vec_pretty(journal).map_err(|error| PersistError::Before(anyhow!(error)))?;
    bytes.push(b'\n');
    if let Err(error) = write_new_synced(transaction, &temporary, &bytes) {
        return Err(PersistError::Before(error));
    }
    let name = match journal.state {
        JournalState::Prepared => OsStr::new("journal.prepared.json"),
        JournalState::Committed => OsStr::new("journal.committed.json"),
        JournalState::RolledBack => OsStr::new("journal.rolled-back.json"),
    };
    if let Err(error) = rename_no_replace(transaction, &temporary, transaction, name) {
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
    open_project_root_io(root)
        .with_context(|| format!("project root is not a real directory: {}", root.display()))
}

fn open_managed(root: &Dir, relative: &Path) -> Result<ManagedPath> {
    open_pinned_path_io(root, relative)
        .with_context(|| format!("failed to open managed path {}", relative.display()))
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
    open_dir_no_follow_io(parent, name).context("failed to open managed directory")
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
    Ok(read_regular_at_io(dir, name)?)
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
