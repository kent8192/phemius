use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt, fs,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

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

    let actual_root = canon_root_hash(project)?;
    if actual_root != change.base_root_hash {
        return validation_error(
            ValidationErrorKind::BaseRoot,
            "canon no longer matches the changeset base root",
        );
    }
    validate_approval_order(project, change)?;
    validate_operations(project, &change.id, &change.operations)?;
    let actual_candidate_hash = calculate_candidate_hash(project, change)?;
    if actual_candidate_hash != change.candidate_hash {
        return validation_error(
            ValidationErrorKind::CandidateHash,
            "candidate files changed after validation",
        );
    }
    let entries = projected_content(project, change)?;
    let actual_content = hash_entries(entries.iter().map(|(path, bytes)| (path, bytes.as_slice())));
    if actual_content != change.content_result_hash {
        return validation_error(
            ValidationErrorKind::ResultRoot,
            "projected content root does not match the changeset",
        );
    }
    validate_projected_schema(project, change, &entries)?;
    if change.validation_hash.as_deref() != Some(calculate_validation_hash(change).as_str()) {
        return validation_error(
            ValidationErrorKind::ValidationHash,
            "changeset validation hash is missing or invalid",
        );
    }
    let actual_result = projected_root_hash(project, change)?;
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
    let mut entries = Vec::new();
    for operation in &change.operations {
        if let Some(path) = &operation.candidate_path {
            validate_candidate_path(project, &change.id, path)?;
            let bytes = fs::read(project.root.join(path)).map_err(|error| {
                ValidationError::io(
                    &format!("failed to read candidate {}", path.display()),
                    error,
                )
            })?;
            entries.push((path.clone(), bytes));
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(hash_entries(
        entries.iter().map(|(path, bytes)| (path, bytes.as_slice())),
    ))
}

pub fn canon_root_hash(project: &Project) -> Result<String, ValidationError> {
    canon_root_hash_at(&project.root)
}

pub(crate) fn canon_root_hash_at(root: &Path) -> Result<String, ValidationError> {
    let entries = collect_canon_files(root)?;
    Ok(hash_entries(
        entries.iter().map(|(path, bytes)| (path, bytes.as_slice())),
    ))
}

pub fn projected_root_hash(
    project: &Project,
    change: &Changeset,
) -> Result<String, ValidationError> {
    let mut entries = projected_content(project, change)?;
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
    let entries = projected_content(project, change)?;
    Ok(hash_entries(
        entries.iter().map(|(path, bytes)| (path, bytes.as_slice())),
    ))
}

fn projected_content(
    project: &Project,
    change: &Changeset,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, ValidationError> {
    let mut entries = collect_canon_files(&project.root)?;
    for operation in &change.operations {
        validate_target_path(&project.root, &operation.path)?;
        match operation.kind {
            OperationKind::Create | OperationKind::Replace => {
                let candidate_path = operation.candidate_path.as_ref().ok_or_else(|| {
                    ValidationError::new(
                        ValidationErrorKind::InvalidOperation,
                        "create and replace operations require a candidate file",
                    )
                })?;
                validate_candidate_path(project, &change.id, candidate_path)?;
                let bytes = fs::read(project.root.join(candidate_path)).map_err(|error| {
                    ValidationError::io(
                        &format!("failed to read candidate {}", candidate_path.display()),
                        error,
                    )
                })?;
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
    validate_operations(project, &change.id, &change.operations)?;
    let mut operations = change.operations.iter().collect::<Vec<_>>();
    operations.sort_by(|left, right| left.path.cmp(&right.path));
    let mut rendered = String::new();
    for operation in operations {
        let before = match operation.kind {
            OperationKind::Create => String::new(),
            OperationKind::Replace | OperationKind::Delete => {
                read_utf8(project.root.join(&operation.path), "canon file")?
            }
        };
        let after = match operation.kind {
            OperationKind::Delete => String::new(),
            OperationKind::Create | OperationKind::Replace => read_utf8(
                project.root.join(
                    operation
                        .candidate_path
                        .as_ref()
                        .expect("validated operation has a candidate path"),
                ),
                "candidate file",
            )?,
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

fn validate_approval_order(project: &Project, change: &Changeset) -> Result<(), ValidationError> {
    let approvals = scan_approval_records(&project.root)?;
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

fn scan_approval_records(root: &Path) -> Result<Vec<ScannedApproval>, ValidationError> {
    let directory = root.join(".phemius/records/approvals");
    let mut entries = match fs::read_dir(&directory) {
        Ok(entries) => entries
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|error| ValidationError::io("failed to enumerate approval records", error))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(ValidationError::io(
                "failed to read approval records",
                error,
            ));
        }
    };
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
                format!("unknown approval entry: {}", entry.path().display()),
            );
        }
        let bytes = fs::read(entry.path())
            .map_err(|error| ValidationError::io("failed to read approval record", error))?;
        let record: ApprovalRecord = serde_json::from_slice(&bytes).map_err(|error| {
            ValidationError::new(
                ValidationErrorKind::DependencyHash,
                format!(
                    "invalid approval record {}: {error}",
                    entry.path().display()
                ),
            )
        })?;
        let expected_name = format!("{}.json", record.changeset_id.as_str());
        if entry.file_name() != expected_name.as_str()
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
                format!("invalid approval proof: {}", entry.path().display()),
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

pub(crate) fn validate_target_path(root: &Path, path: &Path) -> Result<(), ValidationError> {
    validate_target_lexical(path)?;
    reject_symlink_components(root, path, ValidationErrorKind::InvalidPath)?;
    ensure_within_root(root, path, ValidationErrorKind::InvalidPath)
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

pub(crate) fn validate_candidate_path(
    project: &Project,
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
    reject_symlink_components(&project.root, path, ValidationErrorKind::CandidatePath)?;
    let expected_absolute = project.root.join(&expected);
    let expected_canonical = fs::canonicalize(&expected_absolute).map_err(|error| {
        ValidationError::io(
            &format!(
                "failed to canonicalize candidate root {}",
                expected_absolute.display()
            ),
            error,
        )
    })?;
    let candidate = project.root.join(path);
    let candidate_canonical = fs::canonicalize(&candidate).map_err(|error| {
        ValidationError::io(
            &format!("failed to canonicalize candidate {}", candidate.display()),
            error,
        )
    })?;
    if !candidate_canonical.starts_with(expected_canonical) {
        return validation_error(
            ValidationErrorKind::CandidatePath,
            format!("candidate escapes its changeset root: {}", path.display()),
        );
    }
    let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
        ValidationError::io(
            &format!("failed to inspect candidate {}", candidate.display()),
            error,
        )
    })?;
    if !metadata.file_type().is_file() {
        return validation_error(
            ValidationErrorKind::CandidatePath,
            format!("candidate is not a regular file: {}", path.display()),
        );
    }
    Ok(())
}

fn validate_operations(
    project: &Project,
    changeset_id: &EntityId,
    operations: &[FileOperation],
) -> Result<(), ValidationError> {
    if operations.is_empty() {
        return validation_error(
            ValidationErrorKind::Incomplete,
            "changeset has no file operations",
        );
    }
    validate_reserved_targets(operations)?;
    let mut targets = HashSet::new();
    let mut affected_entities = HashSet::new();
    for operation in operations {
        validate_target_path(&project.root, &operation.path)?;
        let alias = path_alias_key(&operation.path)?;
        if !targets.insert(alias) {
            return validation_error(
                ValidationErrorKind::InvalidOperation,
                format!("duplicate target path: {}", operation.path.display()),
            );
        }
        let target = project.root.join(&operation.path);
        for entity in &operation.affected_entities {
            if !is_known_entity_id(entity.as_str())
                || !affected_entities.insert(entity.as_str().to_owned())
            {
                return validation_error(
                    ValidationErrorKind::InvalidOperation,
                    "affected entity IDs must be valid and unique",
                );
            }
        }
        match operation.kind {
            OperationKind::Create => {
                if target.exists()
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
                if operation.before_sha256.is_none()
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
                if operation.before_sha256.is_none()
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
            let bytes = read_regular_file(&target, ValidationErrorKind::HashMismatch)?;
            if sha256_bytes(&bytes) != *expected {
                return validation_error(
                    ValidationErrorKind::HashMismatch,
                    format!("canon hash mismatch for {}", operation.path.display()),
                );
            }
        }
        if let Some(candidate_path) = &operation.candidate_path {
            validate_candidate_path(project, changeset_id, candidate_path)?;
            let bytes = read_regular_file(
                &project.root.join(candidate_path),
                ValidationErrorKind::CandidatePath,
            )?;
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
    if config.format_version != 1 || !is_prefixed_uuid(config.work_id.as_str(), EntityKind::Work) {
        return validation_error(
            ValidationErrorKind::Schema,
            "project.toml has an unsupported format or work ID",
        );
    }

    for operation in &change.operations {
        if !path_alias_key(&operation.path)?.ends_with(".md") {
            continue;
        }
        if matches!(
            operation.kind,
            OperationKind::Replace | OperationKind::Delete
        ) {
            validate_markdown_schema(
                &fs::read(project.root.join(&operation.path)).map_err(|error| {
                    ValidationError::io("failed to read changed canon Markdown", error)
                })?,
                &operation.path,
            )?;
        }
        if matches!(
            operation.kind,
            OperationKind::Create | OperationKind::Replace
        ) {
            validate_markdown_schema(
                entries.get(&operation.path).ok_or_else(|| {
                    ValidationError::new(
                        ValidationErrorKind::Schema,
                        format!(
                            "projected Markdown is missing: {}",
                            operation.path.display()
                        ),
                    )
                })?,
                &operation.path,
            )?;
        }
    }
    Ok(())
}

fn validate_markdown_schema(bytes: &[u8], path: &Path) -> Result<(), ValidationError> {
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
    Ok(())
}

fn collect_canon_files(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, ValidationError> {
    let mut files = BTreeMap::new();
    collect_directory(root, Path::new(""), &mut files)?;
    Ok(files)
}

fn collect_directory(
    root: &Path,
    relative: &Path,
    files: &mut BTreeMap<PathBuf, Vec<u8>>,
) -> Result<(), ValidationError> {
    let directory = root.join(relative);
    let mut entries = fs::read_dir(&directory)
        .map_err(|error| {
            ValidationError::io(&format!("failed to read {}", directory.display()), error)
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ValidationError::io(
                &format!("failed to enumerate {}", directory.display()),
                error,
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let child_relative = relative.join(entry.file_name());
        let segments = path_segments(&child_relative, ValidationErrorKind::InvalidPath)?;
        if is_git_path(&segments) || is_runtime_path(&segments) || is_local_settings_path(&segments)
        {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            ValidationError::io(
                &format!("failed to inspect {}", entry.path().display()),
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
            collect_directory(root, &child_relative, files)?;
        } else if file_type.is_file() {
            files.insert(
                child_relative,
                fs::read(entry.path()).map_err(|error| {
                    ValidationError::io(
                        &format!("failed to read {}", entry.path().display()),
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

fn reject_symlink_components(
    root: &Path,
    relative: &Path,
    kind: ValidationErrorKind,
) -> Result<(), ValidationError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return validation_error(
                    kind,
                    format!("path contains a symlink: {}", relative.display()),
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(ValidationError::io(
                    &format!("failed to inspect {}", current.display()),
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn ensure_within_root(
    project_root: &Path,
    relative: &Path,
    kind: ValidationErrorKind,
) -> Result<(), ValidationError> {
    let root = fs::canonicalize(project_root).map_err(|error| {
        ValidationError::io(
            &format!("failed to canonicalize {}", project_root.display()),
            error,
        )
    })?;
    let absolute = project_root.join(relative);
    let existing = if absolute.exists() {
        absolute.clone()
    } else {
        absolute.parent().unwrap_or(project_root).to_path_buf()
    };
    let canonical = fs::canonicalize(&existing).map_err(|error| {
        ValidationError::io(
            &format!("failed to canonicalize {}", existing.display()),
            error,
        )
    })?;
    if !canonical.starts_with(root) {
        return validation_error(
            kind,
            format!("path escapes project root: {}", relative.display()),
        );
    }
    if !existing.is_dir() && !absolute.exists() {
        return validation_error(
            kind,
            format!("target parent is not a directory: {}", existing.display()),
        );
    }
    Ok(())
}

fn read_regular_file(path: &Path, kind: ValidationErrorKind) -> Result<Vec<u8>, ValidationError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ValidationError::io(&format!("failed to inspect {}", path.display()), error)
    })?;
    if !metadata.file_type().is_file() {
        return validation_error(kind, format!("not a regular file: {}", path.display()));
    }
    fs::read(path)
        .map_err(|error| ValidationError::io(&format!("failed to read {}", path.display()), error))
}

fn read_utf8(path: PathBuf, label: &str) -> Result<String, ValidationError> {
    let bytes = fs::read(&path).map_err(|error| {
        ValidationError::io(&format!("failed to read {label} {}", path.display()), error)
    })?;
    String::from_utf8(bytes).map_err(|error| {
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
