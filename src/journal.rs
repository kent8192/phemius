use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    changeset::{
        Changeset, FileOperation, OperationKind, approval_record_bytes, canon_root_hash,
        canon_root_hash_at, sha256_bytes, validate_changeset, validate_target_path,
    },
    domain::{EntityKind, is_prefixed_uuid},
    project::{Project, rename_without_replacing},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum JournalState {
    Prepared,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplyJournal {
    changeset_id: String,
    state: JournalState,
    result_root_hash: String,
    approval_record_sha256: String,
    entries: Vec<JournalEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct JournalEntry {
    kind: OperationKind,
    target_path: PathBuf,
    before_sha256: Option<String>,
    after_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestInterruption {
    AfterFirstRename,
    AfterCommit,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryOutcome {
    pub rolled_back: usize,
    pub kept_committed: usize,
}

pub fn apply_changeset(project: &Project, change: &Changeset) -> Result<()> {
    apply(project, change, None)
}

#[doc(hidden)]
pub fn apply_changeset_for_test(
    project: &Project,
    change: &Changeset,
    interruption: TestInterruption,
) -> Result<()> {
    apply(project, change, Some(interruption))
}

pub fn recover_pending(project_root: &Path) -> Result<RecoveryOutcome> {
    let _lock = WriterLock::acquire(project_root)?;
    recover_pending_locked(project_root)
}

fn apply(
    project: &Project,
    change: &Changeset,
    interruption: Option<TestInterruption>,
) -> Result<()> {
    let _lock = WriterLock::acquire(&project.root)?;
    recover_pending_locked(&project.root)?;
    validate_changeset(project, change).context("changeset is not approvable")?;

    let (journal_path, mut journal) = prepare_journal(project, change)?;
    if let Err(error) = persist_journal(&project.root, &journal_path, &journal, false) {
        let _ = cleanup_transaction(&project.root, &journal_path);
        return Err(error);
    }

    for (index, entry) in journal.entries.iter().enumerate() {
        if let Err(error) = apply_entry(&project.root, &journal.changeset_id, index, entry) {
            return rollback_after_error(&project.root, &journal_path, &journal, error);
        }
        if index == 0 && interruption == Some(TestInterruption::AfterFirstRename) {
            bail!("simulated interruption after first rename");
        }
    }

    if let Err(error) = install_approval_record(&project.root, &journal) {
        return rollback_after_error(&project.root, &journal_path, &journal, error);
    }
    match canon_root_hash(project) {
        Ok(actual) if actual == journal.result_root_hash => {}
        Ok(actual) => {
            return rollback_after_error(
                &project.root,
                &journal_path,
                &journal,
                anyhow!(
                    "applied canon root {actual} does not match {}",
                    journal.result_root_hash
                ),
            );
        }
        Err(error) => {
            return rollback_after_error(&project.root, &journal_path, &journal, anyhow!(error));
        }
    }

    journal.state = JournalState::Committed;
    if let Err(error) = persist_journal(&project.root, &journal_path, &journal, true) {
        return rollback_after_error(&project.root, &journal_path, &journal, error);
    }
    if interruption == Some(TestInterruption::AfterCommit) {
        bail!("simulated interruption after journal commit");
    }
    cleanup_transaction(&project.root, &journal_path)
}

fn prepare_journal(project: &Project, change: &Changeset) -> Result<(PathBuf, ApplyJournal)> {
    let journal_parent = project.root.join(".phemius/runtime/journal");
    fs::create_dir_all(&journal_parent)
        .with_context(|| format!("failed to create {}", journal_parent.display()))?;
    ensure!(
        fs::symlink_metadata(&journal_parent)
            .with_context(|| format!("failed to inspect {}", journal_parent.display()))?
            .file_type()
            .is_dir(),
        "journal root is not a real directory: {}",
        journal_parent.display()
    );
    sync_directory(
        journal_parent
            .parent()
            .expect("journal parent has a parent"),
    )?;
    sync_directory(&journal_parent)?;
    let transaction_relative = PathBuf::from(".phemius/runtime/journal").join(change.id.as_str());
    let transaction = project.root.join(&transaction_relative);
    fs::create_dir(&transaction)
        .with_context(|| format!("failed to create transaction {}", transaction.display()))?;
    sync_directory(&journal_parent)?;

    let result = (|| {
        let mut entries = Vec::with_capacity(change.operations.len());
        for (index, operation) in change.operations.iter().enumerate() {
            entries.push(snapshot_operation(
                &project.root,
                &transaction_relative,
                index,
                operation,
            )?);
        }
        let approval_bytes = approval_record_bytes(change);
        write_new_synced(
            &project
                .root
                .join(transaction_relative.join("approval-record.json")),
            &approval_bytes,
        )?;
        sync_directory(&transaction)?;
        let journal = ApplyJournal {
            changeset_id: change.id.as_str().to_owned(),
            state: JournalState::Prepared,
            result_root_hash: change.result_root_hash.clone(),
            approval_record_sha256: sha256_bytes(&approval_bytes),
            entries,
        };
        Ok((transaction_relative.join("journal.json"), journal))
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&transaction);
        let _ = sync_directory(&journal_parent);
    }
    result
}

fn snapshot_operation(
    root: &Path,
    transaction_relative: &Path,
    index: usize,
    operation: &FileOperation,
) -> Result<JournalEntry> {
    if operation.before_sha256.is_some() {
        let relative = transaction_relative.join(format!("before-{index:04}"));
        let bytes = fs::read(root.join(&operation.path))
            .with_context(|| format!("failed to snapshot {}", operation.path.display()))?;
        ensure!(
            operation.before_sha256.as_deref() == Some(sha256_bytes(&bytes).as_str()),
            "canon changed while snapshotting {}",
            operation.path.display()
        );
        write_new_synced(&root.join(&relative), &bytes)?;
    }
    if let Some(candidate_path) = &operation.candidate_path {
        let relative = transaction_relative.join(format!("after-{index:04}"));
        let bytes = fs::read(root.join(candidate_path))
            .with_context(|| format!("failed to snapshot {}", candidate_path.display()))?;
        ensure!(
            operation.after_sha256.as_deref() == Some(sha256_bytes(&bytes).as_str()),
            "candidate changed while snapshotting {}",
            candidate_path.display()
        );
        write_new_synced(&root.join(&relative), &bytes)?;
    }
    Ok(JournalEntry {
        kind: operation.kind,
        target_path: operation.path.clone(),
        before_sha256: operation.before_sha256.clone(),
        after_sha256: operation.after_sha256.clone(),
    })
}

fn apply_entry(root: &Path, changeset_id: &str, index: usize, entry: &JournalEntry) -> Result<()> {
    let target = root.join(&entry.target_path);
    let target_parent = target
        .parent()
        .ok_or_else(|| anyhow!("target has no parent: {}", target.display()))?;
    match entry.kind {
        OperationKind::Create => {
            ensure!(
                !target.exists(),
                "create target appeared: {}",
                target.display()
            );
        }
        OperationKind::Replace | OperationKind::Delete => {
            ensure_file_hash(&target, entry.before_sha256.as_deref(), "canon changed")?;
            let old_live =
                root.join(transaction_path(changeset_id).join(format!("old-live-{index:04}")));
            rename_without_replacing(&target, &old_live).with_context(|| {
                format!(
                    "failed to preserve live file {} as {}",
                    target.display(),
                    old_live.display()
                )
            })?;
            sync_directory(target_parent)?;
            sync_directory(old_live.parent().expect("old-live path has a parent"))?;
            if let Err(error) =
                ensure_file_hash(&old_live, entry.before_sha256.as_deref(), "canon raced")
            {
                let _ = rename_without_replacing(&old_live, &target);
                let _ = sync_directory(target_parent);
                return Err(error);
            }
        }
    }
    if entry.after_sha256.is_some() {
        let stage = root.join(transaction_path(changeset_id).join(format!("after-{index:04}")));
        rename_without_replacing(&stage, &target).with_context(|| {
            format!(
                "failed to install staged file {} at {}",
                stage.display(),
                target.display()
            )
        })?;
        sync_directory(target_parent)?;
        sync_directory(stage.parent().expect("stage path has a parent"))?;
        ensure_file_hash(
            &target,
            entry.after_sha256.as_deref(),
            "installed file changed",
        )?;
    }
    Ok(())
}

fn install_approval_record(root: &Path, journal: &ApplyJournal) -> Result<()> {
    let destination = approval_path(root, &journal.changeset_id);
    ensure!(
        !destination.exists(),
        "approval record appeared during apply: {}",
        destination.display()
    );
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("approval record has no parent"))?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    sync_directory(parent.parent().expect("approval parent has a parent"))?;
    sync_directory(
        parent
            .parent()
            .and_then(Path::parent)
            .expect("approval records have a .phemius parent"),
    )?;
    sync_directory(parent)?;
    let stage = root.join(transaction_path(&journal.changeset_id).join("approval-record.json"));
    ensure_file_hash(
        &stage,
        Some(&journal.approval_record_sha256),
        "approval stage changed",
    )?;
    rename_without_replacing(&stage, &destination).with_context(|| {
        format!(
            "failed to install approval record {}",
            destination.display()
        )
    })?;
    sync_directory(parent)?;
    sync_directory(stage.parent().expect("approval stage has a parent"))?;
    Ok(())
}

fn rollback_after_error(
    root: &Path,
    journal_path: &Path,
    journal: &ApplyJournal,
    error: anyhow::Error,
) -> Result<()> {
    match rollback_journal(root, journal).and_then(|()| cleanup_transaction(root, journal_path)) {
        Ok(()) => Err(error),
        Err(rollback) => Err(anyhow!(
            "apply failed: {error}; rollback remains pending: {rollback}"
        )),
    }
}

fn recover_pending_locked(project_root: &Path) -> Result<RecoveryOutcome> {
    let journal_parent = project_root.join(".phemius/runtime/journal");
    if !journal_parent.exists() {
        return Ok(RecoveryOutcome::default());
    }
    ensure!(
        fs::symlink_metadata(&journal_parent)
            .with_context(|| format!("failed to inspect {}", journal_parent.display()))?
            .file_type()
            .is_dir(),
        "journal root is not a real directory: {}",
        journal_parent.display()
    );
    let mut directories = fs::read_dir(&journal_parent)
        .with_context(|| format!("failed to read {}", journal_parent.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("failed to enumerate {}", journal_parent.display()))?;
    directories.sort_by_key(|entry| entry.file_name());
    let mut outcome = RecoveryOutcome::default();
    for directory in directories {
        if !directory
            .file_type()
            .with_context(|| format!("failed to inspect {}", directory.path().display()))?
            .is_dir()
        {
            bail!("unexpected journal entry: {}", directory.path().display());
        }
        let journal_path = directory.path().join("journal.json");
        if !journal_path.exists() {
            fs::remove_dir_all(directory.path()).with_context(|| {
                format!(
                    "failed to clean orphan journal {}",
                    directory.path().display()
                )
            })?;
            sync_directory(&journal_parent)?;
            continue;
        }
        let journal: ApplyJournal = serde_json::from_slice(
            &fs::read(&journal_path)
                .with_context(|| format!("failed to read {}", journal_path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", journal_path.display()))?;
        ensure!(
            is_prefixed_uuid(&journal.changeset_id, EntityKind::Changeset)
                && directory.file_name().to_string_lossy() == journal.changeset_id,
            "journal identity does not match {}",
            directory.path().display()
        );
        for entry in &journal.entries {
            validate_target_path(project_root, &entry.target_path)
                .context("journal contains an unsafe target path")?;
        }
        match journal.state {
            JournalState::Prepared => {
                rollback_journal(project_root, &journal)?;
                outcome.rolled_back += 1;
            }
            JournalState::Committed => {
                verify_committed(project_root, &journal)?;
                outcome.kept_committed += 1;
            }
        }
        cleanup_transaction(project_root, &journal_path)?;
    }
    Ok(outcome)
}

fn rollback_journal(root: &Path, journal: &ApplyJournal) -> Result<()> {
    for (index, entry) in journal.entries.iter().enumerate() {
        if let Some(before_hash) = &entry.before_sha256 {
            let before = before_image(root, &journal.changeset_id, index);
            if before.exists() {
                ensure_file_hash(&before, Some(before_hash), "before image changed")?;
            } else {
                ensure_file_hash(
                    &root.join(&entry.target_path),
                    Some(before_hash),
                    "before image is missing and target is not restored",
                )?;
            }
        }
    }
    let approval = approval_path(root, &journal.changeset_id);
    remove_if_expected(
        &approval,
        Some(&journal.approval_record_sha256),
        "approval record",
    )?;

    // ponytail: Recovery restores bytes and existence; add metadata images if mode/xattr/ACL fidelity is required.
    let mut external_conflict = None;
    for (index, entry) in journal.entries.iter().enumerate().rev() {
        let target = root.join(&entry.target_path);
        match &entry.before_sha256 {
            None => remove_if_expected(&target, entry.after_sha256.as_deref(), "created target")?,
            Some(before_hash) => {
                if target.exists() {
                    let actual = hash_file(&target)?;
                    if actual == *before_hash {
                        continue;
                    }
                    if entry.after_sha256.as_deref() != Some(actual.as_str()) {
                        external_conflict.get_or_insert_with(|| target.clone());
                        continue;
                    }
                    fs::remove_file(&target)
                        .with_context(|| format!("failed to remove {}", target.display()))?;
                    sync_directory(target.parent().expect("target has a parent"))?;
                }
                let before = before_image(root, &journal.changeset_id, index);
                ensure_file_hash(&before, Some(before_hash), "before image changed")?;
                let restore = before.with_extension(format!("restore-{}", uuid::Uuid::now_v7()));
                fs::copy(&before, &restore).with_context(|| {
                    format!(
                        "failed to copy before image {} to {}",
                        before.display(),
                        restore.display()
                    )
                })?;
                File::open(&restore)
                    .with_context(|| format!("failed to open {}", restore.display()))?
                    .sync_all()
                    .with_context(|| format!("failed to sync {}", restore.display()))?;
                rename_without_replacing(&restore, &target).with_context(|| {
                    format!("failed to restore old target {}", target.display())
                })?;
                sync_directory(target.parent().expect("target has a parent"))?;
            }
        }
    }
    if let Some(path) = external_conflict {
        bail!(
            "refusing to overwrite externally changed target {}",
            path.display()
        );
    }
    Ok(())
}

fn verify_committed(root: &Path, journal: &ApplyJournal) -> Result<()> {
    ensure!(
        canon_root_hash_at(root).context("failed to hash committed canon")?
            == journal.result_root_hash,
        "committed canon root changed"
    );
    ensure_file_hash(
        &approval_path(root, &journal.changeset_id),
        Some(&journal.approval_record_sha256),
        "committed approval record changed",
    )
}

fn persist_journal(
    root: &Path,
    relative: &Path,
    journal: &ApplyJournal,
    replace: bool,
) -> Result<()> {
    let path = root.join(relative);
    let parent = path.parent().expect("journal path has a parent");
    let temporary = parent.join(format!("journal-{}.tmp", uuid::Uuid::now_v7()));
    let mut bytes = serde_json::to_vec_pretty(journal).context("failed to serialize journal")?;
    bytes.push(b'\n');
    write_new_synced(&temporary, &bytes)?;
    let rename_result = if replace {
        fs::rename(&temporary, &path)
    } else {
        rename_without_replacing(&temporary, &path)
    };
    rename_result.with_context(|| format!("failed to persist journal {}", path.display()))?;
    sync_directory(parent)
}

fn cleanup_transaction(root: &Path, journal_path: &Path) -> Result<()> {
    let transaction = root
        .join(journal_path)
        .parent()
        .expect("journal has a parent")
        .to_path_buf();
    let parent = transaction
        .parent()
        .expect("transaction has a journal parent")
        .to_path_buf();
    fs::remove_dir_all(&transaction)
        .with_context(|| format!("failed to clean transaction {}", transaction.display()))?;
    sync_directory(&parent)
}

fn remove_if_expected(path: &Path, expected: Option<&str>, label: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    ensure_file_hash(path, expected, &format!("{label} changed"))?;
    fs::remove_file(path)
        .with_context(|| format!("failed to remove {label} {}", path.display()))?;
    sync_directory(path.parent().expect("managed file has a parent"))
}

fn ensure_file_hash(path: &Path, expected: Option<&str>, context: &str) -> Result<()> {
    let expected = expected.ok_or_else(|| anyhow!("{context}: expected hash is missing"))?;
    let actual = hash_file(path)?;
    ensure!(actual == expected, "{context}: {}", path.display());
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "managed path is not a regular file: {}",
        path.display()
    );
    Ok(sha256_bytes(&fs::read(path).with_context(|| {
        format!("failed to read {}", path.display())
    })?))
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))
}

fn transaction_path(changeset_id: &str) -> PathBuf {
    PathBuf::from(".phemius/runtime/journal").join(changeset_id)
}

fn approval_path(root: &Path, changeset_id: &str) -> PathBuf {
    root.join(".phemius/records/approvals")
        .join(format!("{changeset_id}.json"))
}

fn before_image(root: &Path, changeset_id: &str, index: usize) -> PathBuf {
    root.join(transaction_path(changeset_id).join(format!("before-{index:04}")))
}

struct WriterLock {
    _file: File,
}

impl WriterLock {
    fn acquire(project_root: &Path) -> Result<Self> {
        ensure!(
            project_root.is_dir(),
            "project root is not a directory: {}",
            project_root.display()
        );
        let runtime = project_root.join(".phemius/runtime");
        fs::create_dir_all(&runtime)
            .with_context(|| format!("failed to create {}", runtime.display()))?;
        for directory in [project_root.join(".phemius"), runtime.clone()] {
            ensure!(
                fs::symlink_metadata(&directory)
                    .with_context(|| format!("failed to inspect {}", directory.display()))?
                    .file_type()
                    .is_dir(),
                "managed path is not a real directory: {}",
                directory.display()
            );
        }
        let path = runtime.join("approve.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("failed to open writer lock {}", path.display()))?;
        file.lock()
            .with_context(|| format!("failed to lock {}", path.display()))?;
        Ok(Self { _file: file })
    }
}
