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

use crate::{
    domain::{EntityId, EntityKind, is_prefixed_uuid},
    project::Project,
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
        self.state = ChangesetState::Approvable;
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

    let actual_root = canon_root_hash(project)?;
    if actual_root != change.base_root_hash {
        return validation_error(
            ValidationErrorKind::BaseRoot,
            "canon no longer matches the changeset base root",
        );
    }
    if change.parent_changeset_id.as_ref().is_some_and(|parent| {
        !change
            .dependencies
            .iter()
            .any(|dependency| dependency.id == *parent)
    }) {
        return validation_error(
            ValidationErrorKind::DependencyOrder,
            "parent changeset has no durable approval dependency",
        );
    }
    let expected_order = change
        .dependencies
        .iter()
        .map(|dependency| dependency.chapter_order)
        .max()
        .map_or(Some(1), |order| order.checked_add(1));
    if Some(change.chapter_order) != expected_order
        || change.parent_changeset_id.as_ref().is_some_and(|parent| {
            !change.dependencies.iter().any(|dependency| {
                dependency.id == *parent
                    && dependency.chapter_order.checked_add(1) == Some(change.chapter_order)
            })
        })
    {
        return validation_error(
            ValidationErrorKind::DependencyOrder,
            "changeset is outside chapter approval order",
        );
    }
    for dependency in &change.dependencies {
        if dependency.chapter_order >= change.chapter_order {
            return validation_error(
                ValidationErrorKind::DependencyOrder,
                format!(
                    "dependency {} is not approved earlier",
                    dependency.id.as_str()
                ),
            );
        }
        let record_path = approval_record_path(&project.root, &dependency.id);
        let record_bytes = fs::read(&record_path).map_err(|error| {
            ValidationError::new(
                ValidationErrorKind::DependencyHash,
                format!(
                    "failed to read approval record {}: {error}",
                    record_path.display()
                ),
            )
        })?;
        if sha256_bytes(&record_bytes) != dependency.approval_record_sha256 {
            return validation_error(
                ValidationErrorKind::DependencyHash,
                format!(
                    "dependency {} approval record changed",
                    dependency.id.as_str()
                ),
            );
        }
        let record: ApprovalRecord = serde_json::from_slice(&record_bytes).map_err(|error| {
            ValidationError::new(
                ValidationErrorKind::DependencyHash,
                format!(
                    "dependency {} approval record is invalid: {error}",
                    dependency.id.as_str()
                ),
            )
        })?;
        if record.changeset_id != dependency.id || record.chapter_order != dependency.chapter_order
        {
            return validation_error(
                ValidationErrorKind::DependencyHash,
                format!(
                    "dependency {} approval record does not match",
                    dependency.id.as_str()
                ),
            );
        }
    }

    let approval_path = approval_record_path(&project.root, &change.id);
    if approval_path.exists() {
        return validation_error(
            ValidationErrorKind::InvalidOperation,
            format!(
                "approval record already exists: {}",
                approval_path.display()
            ),
        );
    }

    validate_operations(project, &change.id, &change.operations)?;
    let actual_candidate_hash = calculate_candidate_hash(project, change)?;
    if actual_candidate_hash != change.candidate_hash {
        return validation_error(
            ValidationErrorKind::CandidateHash,
            "candidate files changed after validation",
        );
    }
    let actual_result = projected_root_hash(project, change)?;
    if actual_result != change.result_root_hash {
        return validation_error(
            ValidationErrorKind::ResultRoot,
            "projected canon root does not match the changeset result",
        );
    }
    if change.validation_hash.as_deref() != Some(calculate_validation_hash(change).as_str()) {
        return validation_error(
            ValidationErrorKind::ValidationHash,
            "changeset validation hash is missing or invalid",
        );
    }
    Ok(())
}

pub fn calculate_validation_hash(change: &Changeset) -> String {
    #[derive(Serialize)]
    struct ValidationMaterial<'a> {
        id: &'a EntityId,
        parent_changeset_id: &'a Option<EntityId>,
        base_root_hash: &'a str,
        result_root_hash: &'a str,
        operations: &'a [FileOperation],
        candidate_hash: &'a str,
        unresolved_blocker_ids: &'a [EntityId],
        dependencies: &'a [ChangesetDependency],
        chapter_order: u32,
    }

    let material = ValidationMaterial {
        id: &change.id,
        parent_changeset_id: &change.parent_changeset_id,
        base_root_hash: &change.base_root_hash,
        result_root_hash: &change.result_root_hash,
        operations: &change.operations,
        candidate_hash: &change.candidate_hash,
        unresolved_blocker_ids: &change.unresolved_blocker_ids,
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
    entries.insert(
        approval_record_relative_path(&change.id),
        approval_record_bytes(change),
    );
    Ok(hash_entries(
        entries.iter().map(|(path, bytes)| (path, bytes.as_slice())),
    ))
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

pub fn approval_record_bytes(change: &Changeset) -> Vec<u8> {
    let operations_hash = sha256_bytes(
        &serde_json::to_vec(&change.operations)
            .expect("file operations contain only serializable values"),
    );
    let record = ApprovalRecord {
        changeset_id: change.id.clone(),
        base_root_hash: change.base_root_hash.clone(),
        candidate_hash: change.candidate_hash.clone(),
        operations_hash,
        chapter_order: change.chapter_order,
    };
    let mut bytes = serde_json::to_vec_pretty(&record)
        .expect("approval record contains only serializable values");
    bytes.push(b'\n');
    bytes
}

pub(crate) fn validate_target_path(root: &Path, path: &Path) -> Result<(), ValidationError> {
    validate_lexical_path(path, ValidationErrorKind::InvalidPath)?;
    let segments = path_segments(path, ValidationErrorKind::InvalidPath)?;
    if is_git_path(&segments) || is_runtime_path(&segments) || is_local_settings_path(&segments) {
        return validation_error(
            ValidationErrorKind::InvalidPath,
            format!("target path is outside canon: {}", path.display()),
        );
    }
    reject_symlink_components(root, path, ValidationErrorKind::InvalidPath)?;
    ensure_within_root(root, path, ValidationErrorKind::InvalidPath)
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
    let mut targets = HashSet::new();
    for operation in operations {
        validate_target_path(&project.root, &operation.path)?;
        let alias = operation.path.to_string_lossy().to_lowercase();
        if !targets.insert(alias) {
            return validation_error(
                ValidationErrorKind::InvalidOperation,
                format!("duplicate target path: {}", operation.path.display()),
            );
        }
        let target = project.root.join(&operation.path);
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
