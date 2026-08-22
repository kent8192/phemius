use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    ffi::{CString, OsStr, OsString},
    fmt,
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};

use cap_std::fs::{Dir, MetadataExt, OpenOptions, OpenOptionsExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::TextDiff;
use unicode_normalization::UnicodeNormalization;

use crate::{
    domain::{EntityId, EntityKind, is_known_entity_id, is_prefixed_uuid},
    project::{Project, ProjectConfig, parse_markdown},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationKind {
    Create,
    Replace,
    Delete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileOperation {
    pub kind: OperationKind,
    pub path: PathBuf,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
    pub candidate_path: Option<PathBuf>,
    pub affected_entities: Vec<EntityId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangesetState {
    Candidate,
    Reviewing,
    Revising,
    Approvable,
    Approved,
    Rejected,
    Stale,
    Incomplete,
    NeedsRevalidation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChangesetDependency {
    pub id: EntityId,
    pub approval_record_sha256: String,
    pub chapter_order: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Changeset {
    pub id: EntityId,
    pub parent_changeset_id: Option<EntityId>,
    pub base_root_hash: String,
    pub content_result_hash: String,
    pub result_root_hash: String,
    pub state: ChangesetState,
    pub operations: Vec<FileOperation>,
    pub candidate_hash: String,
    pub validation_hash: Option<String>,
    pub unresolved_blocker_ids: Vec<EntityId>,
    pub dependencies: Vec<ChangesetDependency>,
    pub chapter_order: u32,
}

impl Changeset {
    pub fn mark_regenerated(&mut self, candidate_hash: impl Into<String>) {
        self.candidate_hash = candidate_hash.into();
        self.validation_hash = None;
        self.state = ChangesetState::Candidate;
    }

    pub fn mark_fully_revalidated(&mut self, validation_hash: impl Into<String>) {
        self.validation_hash = Some(validation_hash.into());
        self.state = if self.state == ChangesetState::NeedsRevalidation {
            ChangesetState::Approved
        } else {
            ChangesetState::Approvable
        };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationErrorKind {
    Stale,
    Incomplete,
    NeedsRevalidation,
    NotApprovable,
    Blockers,
    BaseRoot,
    ResultRoot,
    ValidationHash,
    CandidateHash,
    DependencyHash,
    DependencyOrder,
    InvalidPath,
    CandidatePath,
    HashMismatch,
    InvalidOperation,
    ApprovalNamespace,
    Schema,
    Io,
    MissingChangeset,
}

impl ValidationErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::Incomplete => "incomplete",
            Self::NeedsRevalidation => "needs-revalidation",
            Self::NotApprovable => "not-approvable",
            Self::Blockers => "blockers",
            Self::BaseRoot => "base-root",
            Self::ResultRoot => "result-root",
            Self::ValidationHash => "validation-hash",
            Self::CandidateHash => "candidate-hash",
            Self::DependencyHash => "dependency-hash",
            Self::DependencyOrder => "dependency-order",
            Self::InvalidPath => "invalid-path",
            Self::CandidatePath => "candidate-path",
            Self::HashMismatch => "hash-mismatch",
            Self::InvalidOperation => "invalid-operation",
            Self::ApprovalNamespace => "approval-namespace",
            Self::Schema => "schema",
            Self::Io => "io",
            Self::MissingChangeset => "missing-changeset",
        }
    }
}

#[derive(Debug)]
pub struct ValidationError {
    kind: ValidationErrorKind,
    message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApprovalRecord {
    pub changeset_id: EntityId,
    pub base_root_hash: String,
    pub candidate_hash: String,
    pub operations_hash: String,
    pub content_result_hash: String,
    pub validation_hash: String,
    pub dependencies: Vec<ChangesetDependency>,
    pub chapter_order: u32,
}

impl ValidationError {
    pub fn kind(&self) -> ValidationErrorKind {
        self.kind
    }

    fn new(kind: ValidationErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn io(context: &str, error: std::io::Error) -> Self {
        Self::new(ValidationErrorKind::Io, format!("{context}: {error}"))
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind.as_str(), self.message)
    }
}

impl Error for ValidationError {}

pub fn validate_changeset(project: &Project, change: &Changeset) -> Result<(), ValidationError> {
    let root = open_project_root(&project.root)?;
    validate_changeset_in(project, &root, change)
}

pub(crate) fn validate_changeset_in(
    project: &Project,
    root: &Dir,
    change: &Changeset,
) -> Result<(), ValidationError> {
    if !is_prefixed_uuid(change.id.as_str(), EntityKind::Changeset)
        || change
            .parent_changeset_id
            .as_ref()
            .is_some_and(|id| !is_prefixed_uuid(id.as_str(), EntityKind::Changeset))
        || change
            .dependencies
            .iter()
            .any(|dependency| !is_prefixed_uuid(dependency.id.as_str(), EntityKind::Changeset))
    {
        return validation_error(
            ValidationErrorKind::InvalidOperation,
            "changeset identifiers are invalid",
        );
    }
    match change.state {
        ChangesetState::Approvable => {}
        ChangesetState::Stale => {
            return validation_error(ValidationErrorKind::Stale, "changeset is stale");
        }
        ChangesetState::Incomplete => {
            return validation_error(ValidationErrorKind::Incomplete, "changeset is incomplete");
        }
        ChangesetState::NeedsRevalidation => {
            return validation_error(
                ValidationErrorKind::NeedsRevalidation,
                "changeset needs revalidation",
            );
        }
        _ => {
            return validation_error(
                ValidationErrorKind::NotApprovable,
                "only an approvable changeset can be approved",
            );
        }
    }
    if !change.unresolved_blocker_ids.is_empty() {
        return validation_error(
            ValidationErrorKind::Blockers,
            "changeset has unresolved blockers",
        );
    }

    validate_reserved_targets(&change.operations)?;

    let base_entries = collect_canon_files_in(root)?;
    let actual_root = hash_entries(
        base_entries
            .iter()
            .map(|(path, bytes)| (path, bytes.as_slice())),
    );
    if actual_root != change.base_root_hash {
        return validation_error(
            ValidationErrorKind::BaseRoot,
            "canon no longer matches the changeset base root",
        );
    }
    validate_approval_order_in(root, change)?;
    validate_operations_in(project, root, &change.id, &change.operations, &base_entries)?;
    let actual_candidate_hash = calculate_candidate_hash_in(root, change)?;
    if actual_candidate_hash != change.candidate_hash {
        return validation_error(
            ValidationErrorKind::CandidateHash,
            "candidate files changed after validation",
        );
    }
    let entries = projected_content_in(root, change, base_entries.clone())?;
    let actual_content = hash_entries(entries.iter().map(|(path, bytes)| (path, bytes.as_slice())));
    if actual_content != change.content_result_hash {
        return validation_error(
            ValidationErrorKind::ResultRoot,
            "projected content root does not match the changeset",
        );
    }
    validate_projected_schema(project, change, &base_entries, &entries)?;
    if change.validation_hash.as_deref() != Some(calculate_validation_hash(change).as_str()) {
        return validation_error(
            ValidationErrorKind::ValidationHash,
            "changeset validation hash is missing or invalid",
        );
    }
    let actual_result = projected_root_hash_from_entries(change, entries)?;
    if actual_result != change.result_root_hash {
        return validation_error(
            ValidationErrorKind::ResultRoot,
            "projected canon root does not match the changeset result",
        );
    }
    Ok(())
}

pub fn calculate_validation_hash(change: &Changeset) -> String {
    #[derive(Serialize)]
    struct ValidationMaterial<'a> {
        id: &'a EntityId,
        base_root_hash: &'a str,
        content_result_hash: &'a str,
        operations_hash: String,
        candidate_hash: &'a str,
        dependencies: &'a [ChangesetDependency],
        chapter_order: u32,
    }

    let material = ValidationMaterial {
        id: &change.id,
        base_root_hash: &change.base_root_hash,
        content_result_hash: &change.content_result_hash,
        operations_hash: sha256_bytes(
            &serde_json::to_vec(&change.operations)
                .expect("file operations contain only serializable values"),
        ),
        candidate_hash: &change.candidate_hash,
        dependencies: &change.dependencies,
        chapter_order: change.chapter_order,
    };
    sha256_bytes(
        &serde_json::to_vec(&material).expect("validation material contains serializable values"),
    )
}

pub fn calculate_candidate_hash(
    project: &Project,
    change: &Changeset,
) -> Result<String, ValidationError> {
    let root = open_project_root(&project.root)?;
    calculate_candidate_hash_in(&root, change)
}

pub(crate) fn calculate_candidate_hash_in(
    root: &Dir,
    change: &Changeset,
) -> Result<String, ValidationError> {
    let mut entries = Vec::new();
    for operation in &change.operations {
        if let Some(path) = &operation.candidate_path {
            validate_candidate_path_in(root, &change.id, path)?;
            let bytes = read_regular_path(root, path, ValidationErrorKind::CandidatePath)?;
            entries.push((path.clone(), bytes));
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(hash_entries(
        entries.iter().map(|(path, bytes)| (path, bytes.as_slice())),
    ))
}

pub fn canon_root_hash(project: &Project) -> Result<String, ValidationError> {
    let root = open_project_root(&project.root)?;
    canon_root_hash_in(&root)
}

pub(crate) fn canon_root_hash_in(root: &Dir) -> Result<String, ValidationError> {
    let entries = collect_canon_files_in(root)?;
    Ok(hash_entries(
        entries.iter().map(|(path, bytes)| (path, bytes.as_slice())),
    ))
}

pub fn projected_root_hash(
    project: &Project,
    change: &Changeset,
) -> Result<String, ValidationError> {
    let root = open_project_root(&project.root)?;
    projected_root_hash_in(&root, change)
}

pub(crate) fn projected_root_hash_in(
    root: &Dir,
    change: &Changeset,
) -> Result<String, ValidationError> {
    let entries = projected_content_in(root, change, collect_canon_files_in(root)?)?;
    projected_root_hash_from_entries(change, entries)
}

fn projected_root_hash_from_entries(
    change: &Changeset,
    mut entries: BTreeMap<PathBuf, Vec<u8>>,
) -> Result<String, ValidationError> {
    entries.insert(
        approval_record_relative_path(&change.id),
        approval_record_bytes(change)?,
    );
    Ok(hash_entries(
        entries.iter().map(|(path, bytes)| (path, bytes.as_slice())),
    ))
}

pub fn content_result_hash(
    project: &Project,
    change: &Changeset,
) -> Result<String, ValidationError> {
    let root = open_project_root(&project.root)?;
    let entries = projected_content_in(&root, change, collect_canon_files_in(&root)?)?;
    Ok(hash_entries(
        entries.iter().map(|(path, bytes)| (path, bytes.as_slice())),
    ))
}

fn projected_content_in(
    root: &Dir,
    change: &Changeset,
    mut entries: BTreeMap<PathBuf, Vec<u8>>,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, ValidationError> {
    for operation in &change.operations {
        validate_target_path_in(root, &operation.path)?;
        match operation.kind {
            OperationKind::Create | OperationKind::Replace => {
                let candidate_path = operation.candidate_path.as_ref().ok_or_else(|| {
                    ValidationError::new(
                        ValidationErrorKind::InvalidOperation,
                        "create and replace operations require a candidate file",
                    )
                })?;
                validate_candidate_path_in(root, &change.id, candidate_path)?;
                let bytes =
                    read_regular_path(root, candidate_path, ValidationErrorKind::CandidatePath)?;
                entries.insert(operation.path.clone(), bytes);
            }
            OperationKind::Delete => {
                entries.remove(&operation.path);
            }
        }
    }
    Ok(entries)
}

pub fn render_diff(project: &Project, change: &Changeset) -> Result<String, ValidationError> {
    let root = open_project_root(&project.root)?;
    let base_entries = collect_canon_files_in(&root)?;
    validate_operations_in(
        project,
        &root,
        &change.id,
        &change.operations,
        &base_entries,
    )?;
    let mut operations = change.operations.iter().collect::<Vec<_>>();
    operations.sort_by(|left, right| left.path.cmp(&right.path));
    let mut rendered = String::new();
    for operation in operations {
        let before = match operation.kind {
            OperationKind::Create => String::new(),
            OperationKind::Replace | OperationKind::Delete => read_utf8_bytes(
                base_entries
                    .get(&operation.path)
                    .expect("validated canon operation has a base file"),
                &operation.path,
                "canon file",
            )?,
        };
        let after = match operation.kind {
            OperationKind::Delete => String::new(),
            OperationKind::Create | OperationKind::Replace => {
                let candidate = operation
                    .candidate_path
                    .as_ref()
                    .expect("validated operation has a candidate path");
                read_utf8_bytes(
                    &read_regular_path(&root, candidate, ValidationErrorKind::CandidatePath)?,
                    candidate,
                    "candidate file",
                )?
            }
        };
        let name = operation.path.to_string_lossy();
        rendered.push_str(
            &TextDiff::from_lines(&before, &after)
                .unified_diff()
                .header(&format!("a/{name}"), &format!("b/{name}"))
                .to_string(),
        );
    }
    Ok(rendered)
}

pub fn mark_candidate_hash_changed(
    changesets: &mut [Changeset],
    id: &EntityId,
    new_hash: impl Into<String>,
) -> Result<(), ValidationError> {
    let Some(root) = changesets.iter_mut().find(|change| change.id == *id) else {
        return validation_error(
            ValidationErrorKind::MissingChangeset,
            format!("changeset {} was not found", id.as_str()),
        );
    };
    root.candidate_hash = new_hash.into();
    root.validation_hash = None;
    root.state = ChangesetState::Reviewing;

    mark_descendants(changesets, id)
}

pub fn mark_descendants(
    changesets: &mut [Changeset],
    id: &EntityId,
) -> Result<(), ValidationError> {
    if !changesets.iter().any(|change| change.id == *id) {
        return validation_error(
            ValidationErrorKind::MissingChangeset,
            format!("changeset {} was not found", id.as_str()),
        );
    }
    let mut ancestors = HashSet::from([id.clone()]);
    loop {
        let mut changed = false;
        for change in &mut *changesets {
            if ancestors.contains(&change.id) {
                continue;
            }
            if change
                .parent_changeset_id
                .as_ref()
                .is_some_and(|parent| ancestors.contains(parent))
            {
                change.validation_hash = None;
                change.state = if matches!(
                    change.state,
                    ChangesetState::Approved | ChangesetState::NeedsRevalidation
                ) {
                    ChangesetState::NeedsRevalidation
                } else {
                    ChangesetState::Stale
                };
                ancestors.insert(change.id.clone());
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
    }
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

pub fn approval_record_relative_path(changeset_id: &EntityId) -> PathBuf {
    PathBuf::from(".phemius/records/approvals").join(format!("{}.json", changeset_id.as_str()))
}

pub fn approval_record_path(project_root: &Path, changeset_id: &EntityId) -> PathBuf {
    project_root.join(approval_record_relative_path(changeset_id))
}

pub fn approval_record_bytes(change: &Changeset) -> Result<Vec<u8>, ValidationError> {
    let operations_hash = sha256_bytes(
        &serde_json::to_vec(&change.operations)
            .expect("file operations contain only serializable values"),
    );
    let record = ApprovalRecord {
        changeset_id: change.id.clone(),
        base_root_hash: change.base_root_hash.clone(),
        candidate_hash: change.candidate_hash.clone(),
        operations_hash,
        content_result_hash: change.content_result_hash.clone(),
        validation_hash: change.validation_hash.clone().ok_or_else(|| {
            ValidationError::new(
                ValidationErrorKind::ValidationHash,
                "approval record requires a validation hash",
            )
        })?,
        dependencies: change.dependencies.clone(),
        chapter_order: change.chapter_order,
    };
    let mut bytes = serde_json::to_vec_pretty(&record)
        .expect("approval record contains only serializable values");
    bytes.push(b'\n');
    Ok(bytes)
}

struct ScannedApproval {
    record: ApprovalRecord,
    sha256: String,
}

fn validate_approval_order_in(root: &Dir, change: &Changeset) -> Result<(), ValidationError> {
    let approvals = scan_approval_records_in(root)?;
    if approvals
        .iter()
        .any(|approval| approval.record.changeset_id == change.id)
    {
        return validation_error(
            ValidationErrorKind::InvalidOperation,
            "changeset already has an approval record",
        );
    }
    let mut dependency_ids = HashSet::new();
    for dependency in &change.dependencies {
        if !dependency_ids.insert(dependency.id.as_str()) {
            return validation_error(
                ValidationErrorKind::DependencyOrder,
                "changeset has duplicate dependencies",
            );
        }
        if dependency.chapter_order >= change.chapter_order {
            return validation_error(
                ValidationErrorKind::DependencyOrder,
                "dependency is not earlier than the changeset",
            );
        }
        let Some(approved) = approvals
            .iter()
            .find(|approval| approval.record.changeset_id == dependency.id)
        else {
            return validation_error(
                ValidationErrorKind::DependencyHash,
                format!(
                    "dependency {} is not durably approved",
                    dependency.id.as_str()
                ),
            );
        };
        if approved.sha256 != dependency.approval_record_sha256
            || approved.record.chapter_order != dependency.chapter_order
        {
            return validation_error(
                ValidationErrorKind::DependencyHash,
                format!(
                    "dependency {} approval proof changed",
                    dependency.id.as_str()
                ),
            );
        }
    }

    match approvals.last() {
        None if change.chapter_order == 1
            && change.parent_changeset_id.is_none()
            && change.dependencies.is_empty() =>
        {
            Ok(())
        }
        Some(head)
            if change.chapter_order == head.record.chapter_order.checked_add(1).unwrap_or(0)
                && change.parent_changeset_id.as_ref() == Some(&head.record.changeset_id)
                && change.dependencies.iter().any(|dependency| {
                    dependency.id == head.record.changeset_id
                        && dependency.approval_record_sha256 == head.sha256
                        && dependency.chapter_order == head.record.chapter_order
                }) =>
        {
            Ok(())
        }
        _ => validation_error(
            ValidationErrorKind::DependencyOrder,
            "changeset does not extend the durable approval chain head",
        ),
    }
}

fn scan_approval_records_in(root: &Dir) -> Result<Vec<ScannedApproval>, ValidationError> {
    let Some(directory) = try_open_directory_chain(
        root,
        &[
            OsStr::new(".phemius"),
            OsStr::new("records"),
            OsStr::new("approvals"),
        ],
    )?
    else {
        return Ok(Vec::new());
    };
    let mut entries = directory
        .entries()
        .map_err(|error| ValidationError::io("failed to enumerate approval records", error))?
        .collect::<io::Result<Vec<_>>>()
        .map_err(|error| ValidationError::io("failed to read approval record entry", error))?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut approvals = Vec::with_capacity(entries.len());
    let mut orders = HashSet::new();
    for entry in entries {
        let file_type = entry
            .file_type()
            .map_err(|error| ValidationError::io("failed to inspect approval record", error))?;
        if !file_type.is_file() {
            return validation_error(
                ValidationErrorKind::DependencyHash,
                format!(
                    "unknown approval entry: {}",
                    PathBuf::from(".phemius/records/approvals")
                        .join(entry.file_name())
                        .display()
                ),
            );
        }
        let name = entry.file_name();
        let bytes = read_regular_at_io(&directory, &name)
            .map_err(|error| ValidationError::io("failed to read approval record", error))?;
        let record: ApprovalRecord = serde_json::from_slice(&bytes).map_err(|error| {
            ValidationError::new(
                ValidationErrorKind::DependencyHash,
                format!(
                    "invalid approval record {}: {error}",
                    PathBuf::from(".phemius/records/approvals")
                        .join(&name)
                        .display()
                ),
            )
        })?;
        let expected_name = format!("{}.json", record.changeset_id.as_str());
        if name != expected_name.as_str()
            || !is_prefixed_uuid(record.changeset_id.as_str(), EntityKind::Changeset)
            || record.chapter_order == 0
            || !orders.insert(record.chapter_order)
            || ![
                &record.base_root_hash,
                &record.candidate_hash,
                &record.operations_hash,
                &record.content_result_hash,
                &record.validation_hash,
            ]
            .into_iter()
            .all(|hash| is_sha256(hash))
            || approval_validation_hash(&record) != record.validation_hash
        {
            return validation_error(
                ValidationErrorKind::DependencyHash,
                format!(
                    "invalid approval proof: {}",
                    PathBuf::from(".phemius/records/approvals")
                        .join(&name)
                        .display()
                ),
            );
        }
        approvals.push(ScannedApproval {
            record,
            sha256: sha256_bytes(&bytes),
        });
    }
    approvals.sort_by_key(|approval| approval.record.chapter_order);
    for (index, approval) in approvals.iter().enumerate() {
        let expected_order = index as u32 + 1;
        if approval.record.chapter_order != expected_order {
            return validation_error(
                ValidationErrorKind::DependencyOrder,
                "approval chain contains a chapter-order gap",
            );
        }
        if index == 0 {
            if !approval.record.dependencies.is_empty() {
                return validation_error(
                    ValidationErrorKind::DependencyOrder,
                    "first approval record has dependencies",
                );
            }
            continue;
        }
        let previous = &approvals[index - 1];
        if !approval.record.dependencies.iter().any(|dependency| {
            dependency.id == previous.record.changeset_id
                && dependency.chapter_order == previous.record.chapter_order
                && dependency.approval_record_sha256 == previous.sha256
        }) {
            return validation_error(
                ValidationErrorKind::DependencyOrder,
                "approval chain does not reference its previous head",
            );
        }
        for dependency in &approval.record.dependencies {
            if !approvals[..index].iter().any(|earlier| {
                dependency.id == earlier.record.changeset_id
                    && dependency.chapter_order == earlier.record.chapter_order
                    && dependency.approval_record_sha256 == earlier.sha256
            }) {
                return validation_error(
                    ValidationErrorKind::DependencyHash,
                    "approval record has an invalid dependency proof",
                );
            }
        }
    }
    Ok(approvals)
}

pub(crate) fn approval_chain_head_in(
    root: &Dir,
) -> Result<Option<(EntityId, u32)>, ValidationError> {
    Ok(scan_approval_records_in(root)?.last().map(|approval| {
        (
            approval.record.changeset_id.clone(),
            approval.record.chapter_order,
        )
    }))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn approval_validation_hash(record: &ApprovalRecord) -> String {
    #[derive(Serialize)]
    struct Material<'a> {
        id: &'a EntityId,
        base_root_hash: &'a str,
        content_result_hash: &'a str,
        operations_hash: &'a str,
        candidate_hash: &'a str,
        dependencies: &'a [ChangesetDependency],
        chapter_order: u32,
    }
    sha256_bytes(
        &serde_json::to_vec(&Material {
            id: &record.changeset_id,
            base_root_hash: &record.base_root_hash,
            content_result_hash: &record.content_result_hash,
            operations_hash: &record.operations_hash,
            candidate_hash: &record.candidate_hash,
            dependencies: &record.dependencies,
            chapter_order: record.chapter_order,
        })
        .expect("approval validation material is serializable"),
    )
}

pub(crate) fn validate_target_path_in(root: &Dir, path: &Path) -> Result<(), ValidationError> {
    validate_target_lexical(path)?;
    let target = open_pinned_path_io(root, path).map_err(|error| {
        ValidationError::io(
            &format!("failed to open target parent {}", path.display()),
            error,
        )
    })?;
    match target.parent.symlink_metadata(&target.leaf) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => validation_error(
            ValidationErrorKind::InvalidPath,
            format!("target is a symlink or special entry: {}", path.display()),
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ValidationError::io(
            &format!("failed to inspect target {}", path.display()),
            error,
        )),
    }
}

pub(crate) fn validate_target_lexical(path: &Path) -> Result<(), ValidationError> {
    validate_lexical_path(path, ValidationErrorKind::InvalidPath)?;
    let segments = path_segments(path, ValidationErrorKind::InvalidPath)?;
    if is_git_path(&segments) || is_runtime_path(&segments) || is_local_settings_path(&segments) {
        return validation_error(
            ValidationErrorKind::InvalidPath,
            format!("target path is outside canon: {}", path.display()),
        );
    }
    if is_approval_namespace(path)? {
        return validation_error(
            ValidationErrorKind::ApprovalNamespace,
            format!("approval records are controller-owned: {}", path.display()),
        );
    }
    Ok(())
}

pub(crate) fn validate_candidate_path_in(
    root: &Dir,
    changeset_id: &EntityId,
    path: &Path,
) -> Result<(), ValidationError> {
    validate_lexical_path(path, ValidationErrorKind::CandidatePath)?;
    let expected = PathBuf::from(".phemius/runtime/candidates").join(changeset_id.as_str());
    if !path.starts_with(&expected) || path == expected {
        return validation_error(
            ValidationErrorKind::CandidatePath,
            format!(
                "candidate {} is not owned by changeset {}",
                path.display(),
                changeset_id.as_str()
            ),
        );
    }
    read_regular_path(root, path, ValidationErrorKind::CandidatePath).map(|_| ())
}

fn validate_operations_in(
    project: &Project,
    root: &Dir,
    changeset_id: &EntityId,
    operations: &[FileOperation],
    base_entries: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<(), ValidationError> {
    if operations.is_empty() {
        return validation_error(
            ValidationErrorKind::Incomplete,
            "changeset has no file operations",
        );
    }
    validate_reserved_targets(operations)?;
    let mut targets = HashSet::new();
    let mut existing_aliases = BTreeMap::new();
    for path in base_entries.keys() {
        let alias = path_alias_key(path)?;
        if existing_aliases.insert(alias, path).is_some() {
            return validation_error(
                ValidationErrorKind::InvalidOperation,
                "canon contains colliding path aliases",
            );
        }
    }
    for operation in operations {
        validate_target_path_in(root, &operation.path)?;
        let alias = path_alias_key(&operation.path)?;
        if !targets.insert(alias.clone()) {
            return validation_error(
                ValidationErrorKind::InvalidOperation,
                format!("duplicate target path: {}", operation.path.display()),
            );
        }
        if operation.affected_entities.is_empty() {
            return validation_error(
                ValidationErrorKind::InvalidOperation,
                "every operation requires an affected entity ID",
            );
        }
        let mut affected_entities = HashSet::new();
        for entity in &operation.affected_entities {
            if !is_known_entity_id(entity.as_str())
                || !affected_entities.insert(entity.as_str().to_owned())
            {
                return validation_error(
                    ValidationErrorKind::InvalidOperation,
                    "affected entity IDs must be valid and unique within each operation",
                );
            }
        }
        if alias == "project.toml"
            && (operation.affected_entities.len() != 1
                || operation.affected_entities[0] != project.config.work_id)
        {
            return validation_error(
                ValidationErrorKind::InvalidOperation,
                "project.toml must affect only the immutable work ID",
            );
        }
        let existing = existing_aliases.get(&alias).copied();
        match operation.kind {
            OperationKind::Create => {
                if existing.is_some()
                    || operation.before_sha256.is_some()
                    || operation.after_sha256.is_none()
                    || operation.candidate_path.is_none()
                {
                    return validation_error(
                        ValidationErrorKind::InvalidOperation,
                        format!("invalid create operation for {}", operation.path.display()),
                    );
                }
            }
            OperationKind::Replace => {
                if existing != Some(&operation.path)
                    || operation.before_sha256.is_none()
                    || operation.after_sha256.is_none()
                    || operation.candidate_path.is_none()
                    || operation.before_sha256 == operation.after_sha256
                {
                    return validation_error(
                        ValidationErrorKind::InvalidOperation,
                        format!("invalid replace operation for {}", operation.path.display()),
                    );
                }
            }
            OperationKind::Delete => {
                if existing != Some(&operation.path)
                    || operation.before_sha256.is_none()
                    || operation.after_sha256.is_some()
                    || operation.candidate_path.is_some()
                    || is_required_project_path(&operation.path)?
                {
                    return validation_error(
                        ValidationErrorKind::InvalidOperation,
                        format!("invalid delete operation for {}", operation.path.display()),
                    );
                }
            }
        }
        if let Some(expected) = &operation.before_sha256 {
            let bytes = base_entries.get(&operation.path).ok_or_else(|| {
                ValidationError::new(
                    ValidationErrorKind::HashMismatch,
                    format!("canon file is missing: {}", operation.path.display()),
                )
            })?;
            if sha256_bytes(&bytes) != *expected {
                return validation_error(
                    ValidationErrorKind::HashMismatch,
                    format!("canon hash mismatch for {}", operation.path.display()),
                );
            }
        }
        if let Some(candidate_path) = &operation.candidate_path {
            validate_candidate_path_in(root, changeset_id, candidate_path)?;
            let bytes =
                read_regular_path(root, candidate_path, ValidationErrorKind::CandidatePath)?;
            if operation.after_sha256.as_deref() != Some(sha256_bytes(&bytes).as_str()) {
                return validation_error(
                    ValidationErrorKind::HashMismatch,
                    format!("candidate hash mismatch for {}", operation.path.display()),
                );
            }
        }
    }
    Ok(())
}

fn validate_reserved_targets(operations: &[FileOperation]) -> Result<(), ValidationError> {
    for operation in operations {
        validate_target_lexical(&operation.path)?;
    }
    Ok(())
}

fn validate_projected_schema(
    project: &Project,
    change: &Changeset,
    base_entries: &BTreeMap<PathBuf, Vec<u8>>,
    entries: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<(), ValidationError> {
    let config_bytes = entries.get(Path::new("project.toml")).ok_or_else(|| {
        ValidationError::new(ValidationErrorKind::Schema, "project.toml is missing")
    })?;
    let config_text = std::str::from_utf8(config_bytes).map_err(|error| {
        ValidationError::new(
            ValidationErrorKind::Schema,
            format!("project.toml is not UTF-8: {error}"),
        )
    })?;
    let config: ProjectConfig = toml::from_str(config_text).map_err(|error| {
        ValidationError::new(
            ValidationErrorKind::Schema,
            format!("project.toml is invalid: {error}"),
        )
    })?;
    if config.format_version != 1
        || !is_prefixed_uuid(config.work_id.as_str(), EntityKind::Work)
        || config.work_id != project.config.work_id
    {
        return validation_error(
            ValidationErrorKind::Schema,
            "project.toml has an unsupported format or changed work ID",
        );
    }

    let mut semantic_ids = HashSet::new();
    for (path, bytes) in entries {
        if !is_artifact_markdown(path)? {
            continue;
        }
        let semantic_id = markdown_semantic_id(bytes, path)?;
        if !semantic_ids.insert(semantic_id.to_owned()) {
            return validation_error(
                ValidationErrorKind::Schema,
                format!("duplicate Markdown semantic ID at {}", path.display()),
            );
        }
    }
    for operation in &change.operations {
        if operation.kind != OperationKind::Replace || !is_artifact_markdown(&operation.path)? {
            continue;
        }
        let before = base_entries.get(&operation.path).ok_or_else(|| {
            ValidationError::new(
                ValidationErrorKind::Schema,
                format!("base Markdown is missing: {}", operation.path.display()),
            )
        })?;
        let after = entries.get(&operation.path).ok_or_else(|| {
            ValidationError::new(
                ValidationErrorKind::Schema,
                format!(
                    "projected Markdown is missing: {}",
                    operation.path.display()
                ),
            )
        })?;
        if markdown_semantic_id(before, &operation.path)?
            != markdown_semantic_id(after, &operation.path)?
        {
            return validation_error(
                ValidationErrorKind::Schema,
                format!(
                    "replace operation changes Markdown semantic ID: {}",
                    operation.path.display()
                ),
            );
        }
    }
    Ok(())
}

fn markdown_semantic_id(bytes: &[u8], path: &Path) -> Result<String, ValidationError> {
    let artifact = parse_markdown(bytes).map_err(|error| {
        ValidationError::new(
            ValidationErrorKind::Schema,
            format!("invalid Markdown {}: {error}", path.display()),
        )
    })?;
    let id = artifact
        .frontmatter()
        .get("id")
        .and_then(yaml_serde::Value::as_str)
        .ok_or_else(|| {
            ValidationError::new(
                ValidationErrorKind::Schema,
                format!("Markdown {} has no semantic ID", path.display()),
            )
        })?;
    if !is_known_entity_id(id) {
        return validation_error(
            ValidationErrorKind::Schema,
            format!("Markdown {} has an invalid semantic ID", path.display()),
        );
    }
    Ok(id.to_owned())
}

fn is_artifact_markdown(path: &Path) -> Result<bool, ValidationError> {
    let key = path_alias_key(path)?;
    Ok(key == "資料/manifest.md"
        || ["前提/", "箱書き/", "本文/", "メモ/"]
            .iter()
            .any(|prefix| key.starts_with(prefix) && key.ends_with(".md")))
}

fn collect_canon_files_in(root: &Dir) -> Result<BTreeMap<PathBuf, Vec<u8>>, ValidationError> {
    let mut files = BTreeMap::new();
    collect_directory_in(root, Path::new(""), &mut files)?;
    Ok(files)
}

fn collect_directory_in(
    directory: &Dir,
    relative: &Path,
    files: &mut BTreeMap<PathBuf, Vec<u8>>,
) -> Result<(), ValidationError> {
    let mut entries = directory
        .entries()
        .map_err(|error| {
            ValidationError::io(&format!("failed to read {}", relative.display()), error)
        })?
        .collect::<io::Result<Vec<_>>>()
        .map_err(|error| {
            ValidationError::io(
                &format!("failed to enumerate {}", relative.display()),
                error,
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let child_relative = relative.join(&name);
        let segments = path_segments(&child_relative, ValidationErrorKind::InvalidPath)?;
        if is_git_path(&segments) || is_runtime_path(&segments) || is_local_settings_path(&segments)
        {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            ValidationError::io(
                &format!("failed to inspect {}", child_relative.display()),
                error,
            )
        })?;
        if file_type.is_symlink() {
            return validation_error(
                ValidationErrorKind::InvalidPath,
                format!("canon contains a symlink: {}", child_relative.display()),
            );
        }
        if file_type.is_dir() {
            let child = open_dir_no_follow_io(directory, &name).map_err(|error| {
                ValidationError::io(
                    &format!("failed to open {}", child_relative.display()),
                    error,
                )
            })?;
            collect_directory_in(&child, &child_relative, files)?;
        } else if file_type.is_file() {
            files.insert(
                child_relative,
                read_regular_at_io(directory, &name).map_err(|error| {
                    ValidationError::io(
                        &format!("failed to read {}", relative.join(&name).display()),
                        error,
                    )
                })?,
            );
        } else {
            return validation_error(
                ValidationErrorKind::InvalidPath,
                format!(
                    "canon contains a special file: {}",
                    child_relative.display()
                ),
            );
        }
    }
    Ok(())
}

fn hash_entries<'a>(entries: impl Iterator<Item = (&'a PathBuf, &'a [u8])>) -> String {
    let mut hasher = Sha256::new();
    for (path, bytes) in entries {
        let path = path.as_os_str().as_bytes();
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hex_digest(&hasher.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn validate_lexical_path(path: &Path, kind: ValidationErrorKind) -> Result<(), ValidationError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return validation_error(
            kind,
            format!("path must be project-relative: {}", path.display()),
        );
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return validation_error(kind, format!("unsafe path: {}", path.display()));
    }
    let _ = path_segments(path, kind)?;
    Ok(())
}

fn path_segments(path: &Path, kind: ValidationErrorKind) -> Result<Vec<&str>, ValidationError> {
    let text = path.to_str().ok_or_else(|| {
        ValidationError::new(kind, format!("path is not valid UTF-8: {}", path.display()))
    })?;
    let segments = text.split('/').collect::<Vec<_>>();
    if segments
        .iter()
        .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return validation_error(kind, format!("unsafe path: {}", path.display()));
    }
    Ok(segments)
}

pub(crate) struct PinnedPath {
    pub(crate) parent: Dir,
    pub(crate) leaf: OsString,
    pub(crate) display: PathBuf,
}

pub(crate) fn open_project_root_io(root: &Path) -> io::Result<Dir> {
    let root = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "root path contains NUL"))?;
    // SAFETY: The NUL-terminated path remains valid for the call, and a successful descriptor is
    // transferred exactly once to File.
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: libc::open returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    Ok(Dir::from_std_file(file))
}

pub(crate) fn open_project_root(root: &Path) -> Result<Dir, ValidationError> {
    open_project_root_io(root).map_err(|error| {
        ValidationError::io(
            &format!("project root is not a real directory: {}", root.display()),
            error,
        )
    })
}

pub(crate) fn open_dir_no_follow_io(parent: &Dir, name: &OsStr) -> io::Result<Dir> {
    let anchor = parent.try_clone()?.into_std_file();
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    // SAFETY: The directory descriptor and NUL-terminated leaf name remain valid for the call.
    let descriptor = unsafe {
        libc::openat(
            anchor.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: libc::openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    Ok(Dir::from_std_file(file))
}

pub(crate) fn open_pinned_path_io(root: &Dir, relative: &Path) -> io::Result<PinnedPath> {
    if relative.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed path must be relative",
        ));
    }
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed path is empty",
        ));
    }
    let mut parent = root.try_clone()?;
    for component in &components[..components.len() - 1] {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed path has an unsafe component",
            ));
        };
        parent = open_dir_no_follow_io(&parent, name)?;
    }
    let Component::Normal(leaf) = components[components.len() - 1] else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed path has an unsafe leaf",
        ));
    };
    Ok(PinnedPath {
        parent,
        leaf: leaf.to_os_string(),
        display: relative.to_path_buf(),
    })
}

pub(crate) fn read_regular_at_io(dir: &Dir, name: &OsStr) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = dir.open_with(name, &options)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed entry is not a regular file",
        ));
    }
    let identity = (before.dev(), before.ino());
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if identity != (after.dev(), after.ino()) {
        return Err(io::Error::other(
            "managed file identity changed while reading",
        ));
    }
    Ok(bytes)
}

fn read_regular_path(
    root: &Dir,
    path: &Path,
    kind: ValidationErrorKind,
) -> Result<Vec<u8>, ValidationError> {
    let pinned = open_pinned_path_io(root, path).map_err(|error| {
        ValidationError::new(
            kind,
            format!(
                "failed to open {} without symlinks: {error}",
                path.display()
            ),
        )
    })?;
    read_regular_at_io(&pinned.parent, &pinned.leaf).map_err(|error| {
        ValidationError::new(
            kind,
            format!("failed to read regular file {}: {error}", path.display()),
        )
    })
}

fn try_open_directory_chain(root: &Dir, names: &[&OsStr]) -> Result<Option<Dir>, ValidationError> {
    let mut directory = root
        .try_clone()
        .map_err(|error| ValidationError::io("failed to clone project root", error))?;
    for name in names {
        match open_dir_no_follow_io(&directory, name) {
            Ok(child) => directory = child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(ValidationError::io(
                    &format!("failed to open directory {}", name.to_string_lossy()),
                    error,
                ));
            }
        }
    }
    Ok(Some(directory))
}

fn read_utf8_bytes(bytes: &[u8], path: &Path, label: &str) -> Result<String, ValidationError> {
    String::from_utf8(bytes.to_vec()).map_err(|error| {
        ValidationError::new(
            ValidationErrorKind::InvalidOperation,
            format!("{label} {} is not UTF-8: {error}", path.display()),
        )
    })
}

fn validation_error<T>(
    kind: ValidationErrorKind,
    message: impl Into<String>,
) -> Result<T, ValidationError> {
    Err(ValidationError::new(kind, message))
}

fn is_git_path(segments: &[&str]) -> bool {
    segments
        .iter()
        .any(|segment| segment.eq_ignore_ascii_case(".git"))
}

fn is_runtime_path(segments: &[&str]) -> bool {
    segments.len() >= 2
        && segments[0].eq_ignore_ascii_case(".phemius")
        && segments[1].eq_ignore_ascii_case("runtime")
}

fn is_local_settings_path(segments: &[&str]) -> bool {
    segments.len() == 2
        && segments[0].eq_ignore_ascii_case(".phemius")
        && segments[1].eq_ignore_ascii_case("local.toml")
}

pub(crate) fn path_alias_key(path: &Path) -> Result<String, ValidationError> {
    let text = path.to_str().ok_or_else(|| {
        ValidationError::new(
            ValidationErrorKind::InvalidPath,
            format!("path is not valid UTF-8: {}", path.display()),
        )
    })?;
    Ok(text.nfkc().flat_map(char::to_lowercase).collect::<String>())
}

fn is_approval_namespace(path: &Path) -> Result<bool, ValidationError> {
    let key = path_alias_key(path)?;
    Ok(key == ".phemius/records/approvals" || key.starts_with(".phemius/records/approvals/"))
}

fn is_required_project_path(path: &Path) -> Result<bool, ValidationError> {
    let key = path_alias_key(path)?;
    Ok([
        "project.toml",
        "agents.md",
        "前提/作品.md",
        "前提/世界観設定.md",
        "前提/時系列.md",
        "前提/伏線.md",
        "前提/文章スタイル.md",
        "前提/執筆ルール.md",
        "箱書き/構成.md",
        "資料/manifest.md",
    ]
    .contains(&key.as_str()))
}
