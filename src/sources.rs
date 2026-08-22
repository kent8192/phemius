//! Source-manifest validation and bounded material ingestion.
//!
//! Ingestion produces hash-bound candidates only. Canonical source artifacts are persisted by
//! the approved changeset flow rather than by this module.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use futures_util::StreamExt;
use reqwest::{
    Client, Url,
    dns::{Addrs, Name, Resolve, Resolving},
    header::{CONTENT_LENGTH, CONTENT_TYPE, ETAG, LAST_MODIFIED, LOCATION},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::domain::{EntityId, EntityKind, is_prefixed_uuid};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceErrorKind {
    InvalidGrant,
    GrantChanged,
    InvalidManifest,
    UnsupportedFormat,
    InvalidUtf8,
    OcrRequired,
    UnsafeUrl,
    Redirect,
    TooLarge,
    Network,
    Io,
}

#[derive(Debug)]
pub struct SourceError {
    kind: SourceErrorKind,
    message: String,
}

impl SourceError {
    pub(crate) fn new(kind: SourceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn io(context: &str, error: std::io::Error) -> Self {
        Self::new(SourceErrorKind::Io, format!("{context}: {error}"))
    }

    pub fn kind(&self) -> SourceErrorKind {
        self.kind
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for SourceError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    PlainText,
    Markdown,
    Pdf,
    Web,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceScope {
    Work,
    Part(String),
    Chapter(String),
    Scene(String),
    Role(String),
}

impl SourceScope {
    pub fn applies_to(&self, target_and_ancestors: &BTreeSet<String>, role: &str) -> bool {
        match self {
            Self::Work => true,
            Self::Part(id) | Self::Chapter(id) | Self::Scene(id) => {
                target_and_ancestors.contains(id)
            }
            Self::Role(expected) => expected == role,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
/// Determines when a source enters a compiled context.
///
/// Manifest entries that omit `tier` default to [`Self::Compactable`].
pub enum SourceTier {
    /// The complete source must fit before any lower-priority material is selected.
    RequiredRaw,
    #[default]
    /// Prefer a current source-anchored summary and otherwise require complete raw fallback.
    Compactable,
    /// Include only when complete material fits after required and compactable sources.
    Optional,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotReference {
    pub raw_sha256: String,
    pub content_sha256: String,
    pub raw_artifact: Option<PathBuf>,
    pub content_artifact: Option<PathBuf>,
    pub ephemeral: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceEntry {
    pub source_id: EntityId,
    pub kind: SourceKind,
    pub scope: SourceScope,
    #[serde(default)]
    pub tier: SourceTier,
    pub expected_sha256: String,
    pub snapshot: SnapshotReference,
    pub web: Option<WebSnapshotMetadata>,
}

impl SourceEntry {
    pub fn from_snapshot(
        source_id: EntityId,
        scope: SourceScope,
        tier: SourceTier,
        snapshot: &Snapshot,
    ) -> Self {
        Self {
            source_id,
            kind: snapshot.kind,
            scope,
            tier,
            expected_sha256: snapshot.sha256.clone(),
            snapshot: snapshot.reference(),
            web: snapshot.web_metadata().cloned(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceManifest {
    pub entries: Vec<SourceEntry>,
}

impl SourceManifest {
    pub fn new(mut entries: Vec<SourceEntry>) -> Result<Self, SourceError> {
        entries.sort_by(|left, right| left.source_id.as_str().cmp(right.source_id.as_str()));
        let manifest = Self { entries };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn entries(&self) -> &[SourceEntry] {
        &self.entries
    }

    pub fn validate(&self) -> Result<(), SourceError> {
        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            if !is_prefixed_uuid(entry.source_id.as_str(), EntityKind::Source) {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!(
                        "source entry has an invalid source ID: {}",
                        entry.source_id.as_str()
                    ),
                ));
            }
            if !ids.insert(entry.source_id.as_str()) {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!("source manifest repeats {}", entry.source_id.as_str()),
                ));
            }
            validate_scope(&entry.scope)?;
            if !is_sha256(&entry.expected_sha256)
                || !is_sha256(&entry.snapshot.raw_sha256)
                || !is_sha256(&entry.snapshot.content_sha256)
            {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!("source {} has an invalid SHA-256", entry.source_id.as_str()),
                ));
            }
            if entry.expected_sha256 != entry.snapshot.raw_sha256 {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!(
                        "source {} expected hash does not match its snapshot",
                        entry.source_id.as_str()
                    ),
                ));
            }
            if entry.snapshot.ephemeral
                && (entry.snapshot.raw_artifact.is_some()
                    || entry.snapshot.content_artifact.is_some()
                    || entry.web.is_some())
            {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!(
                        "secret source {} names durable source metadata",
                        entry.source_id.as_str()
                    ),
                ));
            }
            if !entry.snapshot.ephemeral && !has_expected_artifact_paths(&entry.snapshot) {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!(
                        "source {} has unsafe or incomplete snapshot artifact paths",
                        entry.source_id.as_str()
                    ),
                ));
            }
            if entry.kind == SourceKind::Web && !entry.snapshot.ephemeral && entry.web.is_none() {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!(
                        "web source {} lacks snapshot metadata",
                        entry.source_id.as_str()
                    ),
                ));
            }
            if entry.kind != SourceKind::Web && entry.web.is_some() {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!(
                        "non-web source {} has web snapshot metadata",
                        entry.source_id.as_str()
                    ),
                ));
            }
            if let Some(web) = &entry.web
                && (web.raw_sha256 != entry.snapshot.raw_sha256
                    || web.content_sha256 != entry.snapshot.content_sha256)
            {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!(
                        "web source {} metadata hashes do not match its snapshot",
                        entry.source_id.as_str()
                    ),
                ));
            }
            if let Some(web) = &entry.web {
                for url in std::iter::once(web.initial_url.as_str())
                    .chain(std::iter::once(web.final_url.as_str()))
                    .chain(web.redirect_chain.iter().map(String::as_str))
                {
                    validate_web_url(url).map_err(|error| {
                        SourceError::new(
                            SourceErrorKind::InvalidManifest,
                            format!(
                                "web source {} has unsafe metadata: {error}",
                                entry.source_id.as_str()
                            ),
                        )
                    })?;
                }
            }
        }
        Ok(())
    }
}

fn validate_scope(scope: &SourceScope) -> Result<(), SourceError> {
    let valid = match scope {
        SourceScope::Work => true,
        SourceScope::Part(id) => is_prefixed_uuid(id, EntityKind::Part),
        SourceScope::Chapter(id) => is_prefixed_uuid(id, EntityKind::Chapter),
        SourceScope::Scene(id) => is_prefixed_uuid(id, EntityKind::Scene),
        SourceScope::Role(role) => !role.trim().is_empty(),
    };
    if valid {
        Ok(())
    } else {
        Err(SourceError::new(
            SourceErrorKind::InvalidManifest,
            "source scope has an invalid ID or empty role",
        ))
    }
}

fn has_expected_artifact_paths(reference: &SnapshotReference) -> bool {
    let root = Path::new("資料/snapshots");
    let raw = root.join(format!("{}.raw", reference.raw_sha256));
    let content = if reference.raw_sha256 == reference.content_sha256 {
        raw.clone()
    } else {
        root.join(format!("{}.context.txt", reference.raw_sha256))
    };
    reference.raw_artifact.as_deref() == Some(raw.as_path())
        && reference.content_artifact.as_deref() == Some(content.as_path())
}

pub struct ManifestDocument {
    artifact: crate::project::MarkdownArtifact,
    manifest: SourceManifest,
}

impl ManifestDocument {
    pub fn parse(bytes: &[u8]) -> Result<Self, SourceError> {
        let artifact = crate::project::parse_markdown(bytes).map_err(|error| {
            SourceError::new(
                SourceErrorKind::InvalidManifest,
                format!("invalid source manifest Markdown: {error}"),
            )
        })?;
        let key = yaml_serde::Value::String("sources".into());
        let entries = match artifact.frontmatter().get(&key) {
            Some(value) => yaml_serde::from_value(value.clone()).map_err(|error| {
                SourceError::new(
                    SourceErrorKind::InvalidManifest,
                    format!("invalid source manifest entries: {error}"),
                )
            })?,
            None => Vec::new(),
        };
        Ok(Self {
            artifact,
            manifest: SourceManifest::new(entries)?,
        })
    }

    pub fn manifest(&self) -> &SourceManifest {
        &self.manifest
    }

    pub fn manifest_mut(&mut self) -> &mut SourceManifest {
        &mut self.manifest
    }

    pub fn render(mut self) -> Result<Vec<u8>, SourceError> {
        self.manifest
            .entries
            .sort_by(|left, right| left.source_id.as_str().cmp(right.source_id.as_str()));
        self.manifest.validate()?;
        let entries = yaml_serde::to_value(&self.manifest.entries).map_err(|error| {
            SourceError::new(
                SourceErrorKind::InvalidManifest,
                format!("failed to serialize source manifest entries: {error}"),
            )
        })?;
        self.artifact
            .frontmatter_mut()
            .insert(yaml_serde::Value::String("sources".into()), entries);
        crate::project::render_markdown(&self.artifact).map_err(|error| {
            SourceError::new(
                SourceErrorKind::InvalidManifest,
                format!("failed to render source manifest Markdown: {error}"),
            )
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WebSnapshotMetadata {
    pub initial_url: String,
    pub final_url: String,
    pub redirect_chain: Vec<String>,
    pub selected_headers: BTreeMap<String, String>,
    pub retrieved_unix_seconds: u64,
    pub converter_version: String,
    pub raw_sha256: String,
    pub content_sha256: String,
}

#[derive(Clone)]
pub struct Snapshot {
    sha256: String,
    content_sha256: String,
    kind: SourceKind,
    byte_len: u64,
    secret: bool,
    web: Option<WebSnapshotMetadata>,
    raw_bytes: Vec<u8>,
    content: String,
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Snapshot")
            .field("sha256", &self.sha256)
            .field("content_sha256", &self.content_sha256)
            .field("kind", &self.kind)
            .field("byte_len", &self.byte_len)
            .field("secret", &self.secret)
            .field("web", &(!self.secret).then_some(&self.web))
            .finish_non_exhaustive()
    }
}

impl Snapshot {
    /// Reconstructs a snapshot from its durable raw and extracted-content artifacts.
    ///
    /// The raw bytes anchor the manifest's source hash while the UTF-8 content bytes are the
    /// bounded representation handed to the context compiler.  Keeping both hashes here makes
    /// artifact loading equivalent to the original ingestion path.
    pub fn from_artifacts(
        kind: SourceKind,
        raw_bytes: impl AsRef<[u8]>,
        content_bytes: impl AsRef<[u8]>,
        secret: bool,
        web: Option<WebSnapshotMetadata>,
    ) -> Result<Self, SourceError> {
        let raw_bytes = raw_bytes.as_ref().to_vec();
        let content = std::str::from_utf8(content_bytes.as_ref())
            .map_err(|error| {
                SourceError::new(
                    SourceErrorKind::InvalidUtf8,
                    format!("snapshot content must be UTF-8: {error}"),
                )
            })?
            .to_owned();
        if secret {
            return Err(SourceError::new(
                SourceErrorKind::InvalidManifest,
                "secret snapshots cannot be reconstructed from durable artifacts",
            ));
        }
        if kind != SourceKind::Web && web.is_some() {
            return Err(SourceError::new(
                SourceErrorKind::InvalidManifest,
                "non-web snapshots cannot carry web metadata",
            ));
        }
        Ok(Self::from_content(kind, raw_bytes, content, secret, web))
    }

    pub fn from_text(
        kind: SourceKind,
        bytes: impl AsRef<[u8]>,
        secret: bool,
    ) -> Result<Self, SourceError> {
        if !matches!(kind, SourceKind::PlainText | SourceKind::Markdown) {
            return Err(SourceError::new(
                SourceErrorKind::UnsupportedFormat,
                "from_text only accepts plain text or Markdown",
            ));
        }
        let bytes = bytes.as_ref().to_vec();
        let text = std::str::from_utf8(&bytes)
            .map_err(|error| {
                SourceError::new(
                    SourceErrorKind::InvalidUtf8,
                    format!("text source must be UTF-8: {error}"),
                )
            })?
            .to_owned();
        Ok(Self::from_content(kind, bytes, text, secret, None))
    }

    pub fn text(&self) -> &str {
        &self.content
    }

    pub fn raw_sha256(&self) -> &str {
        &self.sha256
    }

    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    pub fn kind(&self) -> SourceKind {
        self.kind
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub fn is_secret(&self) -> bool {
        self.secret
    }

    pub fn web_metadata(&self) -> Option<&WebSnapshotMetadata> {
        (!self.secret).then_some(self.web.as_ref()).flatten()
    }

    pub fn reference(&self) -> SnapshotReference {
        let root = Path::new("資料/snapshots");
        let raw_artifact = (!self.secret).then(|| root.join(format!("{}.raw", self.sha256)));
        let content_artifact = (!self.secret).then(|| {
            if self.raw_bytes == self.content.as_bytes() {
                root.join(format!("{}.raw", self.sha256))
            } else {
                root.join(format!("{}.context.txt", self.sha256))
            }
        });
        SnapshotReference {
            raw_sha256: self.sha256.clone(),
            content_sha256: self.content_sha256.clone(),
            raw_artifact,
            content_artifact,
            ephemeral: self.secret,
        }
    }

    pub fn candidate_artifacts(&self) -> Vec<SnapshotArtifact> {
        if self.secret {
            return Vec::new();
        }
        let root = Path::new("資料/snapshots");
        let raw = SnapshotArtifact {
            path: root.join(format!("{}.raw", self.sha256)),
            sha256: self.sha256.clone(),
            bytes: self.raw_bytes.clone(),
        };
        if self.raw_bytes == self.content.as_bytes() {
            vec![raw]
        } else {
            vec![
                raw,
                SnapshotArtifact {
                    path: root.join(format!("{}.context.txt", self.sha256)),
                    sha256: self.content_sha256.clone(),
                    bytes: self.content.as_bytes().to_vec(),
                },
            ]
        }
    }

    pub(crate) fn matches_entry(&self, entry: &SourceEntry) -> bool {
        self.has_current_hashes()
            && self.sha256 == entry.expected_sha256
            && self.content_sha256 == entry.snapshot.content_sha256
            && self.kind == entry.kind
            && self.secret == entry.snapshot.ephemeral
            && match self.kind {
                SourceKind::Web if self.secret => entry.web.is_none(),
                SourceKind::Web => self.web.as_ref() == entry.web.as_ref(),
                _ => self.web.is_none() && entry.web.is_none(),
            }
    }

    fn has_current_hashes(&self) -> bool {
        self.sha256 == sha256_bytes(&self.raw_bytes)
            && self.content_sha256 == sha256_bytes(self.content.as_bytes())
    }

    fn from_content(
        kind: SourceKind,
        raw_bytes: Vec<u8>,
        content: String,
        secret: bool,
        web: Option<WebSnapshotMetadata>,
    ) -> Self {
        let sha256 = sha256_bytes(&raw_bytes);
        Self::from_content_with_raw_hash(kind, raw_bytes, content, secret, web, sha256)
    }

    fn from_content_with_raw_hash(
        kind: SourceKind,
        raw_bytes: Vec<u8>,
        content: String,
        secret: bool,
        web: Option<WebSnapshotMetadata>,
        sha256: String,
    ) -> Self {
        let content_sha256 = sha256_bytes(content.as_bytes());
        Self {
            sha256,
            content_sha256,
            kind,
            byte_len: raw_bytes.len() as u64,
            secret,
            web,
            raw_bytes,
            content,
        }
    }
}

#[derive(Clone)]
pub struct SnapshotArtifact {
    path: PathBuf,
    sha256: String,
    bytes: Vec<u8>,
}

impl SnapshotArtifact {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SnapshotArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotArtifact")
            .field("path", &self.path)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Fingerprint {
    sha256: String,
    byte_len: u64,
    device: u64,
    inode: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrantKind {
    File,
    Directory,
}

pub struct PathGrant {
    root: PathBuf,
    kind: GrantKind,
    files: BTreeMap<PathBuf, Fingerprint>,
    root_handle: File,
}

impl fmt::Debug for PathGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PathGrant")
            .field("root", &self.root)
            .field("kind", &self.kind)
            .field("files", &self.files)
            .finish_non_exhaustive()
    }
}

impl PathGrant {
    pub fn freeze(path: &Path) -> Result<Self, SourceError> {
        let (root, kind, root_handle) = open_grant_root(path)?;
        if kind == GrantKind::File {
            let (_, fingerprint) = read_open_regular_file(
                root_handle
                    .try_clone()
                    .map_err(|error| SourceError::io("failed to clone granted file", error))?,
            )?;
            return Ok(Self {
                root,
                kind: GrantKind::File,
                files: BTreeMap::from([(PathBuf::new(), fingerprint)]),
                root_handle,
            });
        }
        if root.parent().is_none() {
            return Err(SourceError::new(
                SourceErrorKind::InvalidGrant,
                "refusing a filesystem-root recursive source grant",
            ));
        }
        Ok(Self {
            files: collect_directory(&root_handle)?,
            root,
            kind: GrantKind::Directory,
            root_handle,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn read_file(&self, path: &Path) -> Result<Vec<u8>, SourceError> {
        let relative = self.validate_path(path)?;
        let (bytes, fingerprint) = read_open_regular_file(self.open_granted_file(&relative)?)?;
        if self.files.get(&relative) != Some(&fingerprint) {
            return Err(SourceError::new(
                SourceErrorKind::GrantChanged,
                "source changed while its granted snapshot was read",
            ));
        }
        self.validate_current_set()?;
        Ok(bytes)
    }

    fn open_granted_file(&self, relative: &Path) -> Result<File, SourceError> {
        match self.kind {
            GrantKind::File => self
                .root_handle
                .try_clone()
                .map_err(|error| SourceError::io("failed to clone granted file", error)),
            GrantKind::Directory => {
                let mut directory = self
                    .root_handle
                    .try_clone()
                    .map_err(|error| SourceError::io("failed to clone granted directory", error))?;
                let components = relative
                    .components()
                    .map(|component| match component {
                        Component::Normal(name) => Ok(name),
                        _ => Err(SourceError::new(
                            SourceErrorKind::InvalidGrant,
                            "granted source path is not a normal relative path",
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let (last, parents) = components.split_last().ok_or_else(|| {
                    SourceError::new(
                        SourceErrorKind::InvalidGrant,
                        "a directory grant cannot ingest its root as a file",
                    )
                })?;
                for parent in parents {
                    directory = open_directory_at(&directory, parent)?;
                }
                open_file_at(&directory, last)
            }
        }
    }

    fn validate_path(&self, path: &Path) -> Result<PathBuf, SourceError> {
        self.validate_current_set()?;
        let normalized = absolute_lexical_path(path)?;
        let relative = match self.kind {
            GrantKind::File => {
                if normalized != self.root {
                    return Err(SourceError::new(
                        SourceErrorKind::InvalidGrant,
                        "source path is outside its granted file",
                    ));
                }
                PathBuf::new()
            }
            GrantKind::Directory => normalized
                .strip_prefix(&self.root)
                .map_err(|_| {
                    SourceError::new(
                        SourceErrorKind::InvalidGrant,
                        "source path escapes its granted directory",
                    )
                })?
                .to_path_buf(),
        };
        if !self.files.contains_key(&relative) {
            return Err(SourceError::new(
                SourceErrorKind::GrantChanged,
                "source was not present in the granted directory snapshot",
            ));
        }
        Ok(relative)
    }

    fn validate_current_set(&self) -> Result<(), SourceError> {
        let current = match self.kind {
            GrantKind::File => {
                let (_, fingerprint) =
                    read_open_regular_file(self.root_handle.try_clone().map_err(|error| {
                        SourceError::io("failed to clone granted file", error)
                    })?)?;
                BTreeMap::from([(PathBuf::new(), fingerprint)])
            }
            GrantKind::Directory => collect_directory(&self.root_handle)?,
        };
        if current == self.files {
            Ok(())
        } else {
            Err(SourceError::new(
                SourceErrorKind::GrantChanged,
                "the granted source set changed; request a new grant",
            ))
        }
    }
}

pub fn ingest_path(path: &Path, grant: &PathGrant, secret: bool) -> Result<Snapshot, SourceError> {
    let kind = text_kind(path)?;
    let bytes = grant.read_file(path)?;
    Snapshot::from_text(kind, bytes, secret)
}

pub async fn ingest_pdf(
    path: &Path,
    grant: &PathGrant,
    secret: bool,
) -> Result<Snapshot, SourceError> {
    let bytes = grant.read_file(path)?;
    let extraction_bytes = bytes.clone();
    let extraction =
        tokio::task::spawn_blocking(move || extract_pdf_pages(&extraction_bytes)).await;
    let pages = match extraction {
        Ok(Ok(pages)) => pages,
        Ok(Err(message)) => {
            return Err(SourceError::new(SourceErrorKind::OcrRequired, message));
        }
        Err(error) => {
            return Err(SourceError::new(
                SourceErrorKind::OcrRequired,
                format!("ocr_required: PDF extraction worker stopped: {error}"),
            ));
        }
    };
    let content = pages.join("\n\n");
    Ok(Snapshot::from_content(
        SourceKind::Pdf,
        bytes,
        content,
        secret,
        None,
    ))
}

fn extract_pdf_pages(bytes: &[u8]) -> Result<Vec<String>, String> {
    let document = pdf_extract::Document::load_mem(bytes)
        .map_err(|error| format!("ocr_required: cannot load PDF: {error}"))?;
    if document.is_encrypted() {
        return Err(
            "ocr_required: encrypted PDFs require OCR or decryption outside Phemius".into(),
        );
    }
    let pages = document.get_pages();
    if pages.is_empty() {
        return Err("ocr_required: PDF contains no extractable pages".into());
    }
    let mut extracted = Vec::with_capacity(pages.len());
    for page_number in pages.keys() {
        let mut text = String::new();
        let mut output = pdf_extract::PlainTextOutput::new(&mut text);
        pdf_extract::output_doc_page(&document, &mut output, *page_number).map_err(|error| {
            format!("ocr_required: page {page_number} cannot be extracted: {error}")
        })?;
        if text.trim().is_empty() {
            return Err(format!(
                "ocr_required: page {page_number} has no extractable text"
            ));
        }
        extracted.push(text);
    }
    Ok(extracted)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSnapshotLimits {
    pub max_redirects: usize,
    pub max_bytes: usize,
}

impl Default for WebSnapshotLimits {
    fn default() -> Self {
        Self {
            max_redirects: 5,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone)]
pub struct WebResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl WebResponse {
    pub fn redirect(location: impl Into<String>) -> Self {
        Self {
            status: 302,
            headers: BTreeMap::from([("location".into(), location.into())]),
            body: Vec::new(),
        }
    }

    pub fn success(status: u16, headers: BTreeMap<String, String>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: normalize_headers(headers),
            body,
        }
    }
}

impl fmt::Debug for WebResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct SourceHttpClient {
    client: Client,
}

impl SourceHttpClient {
    pub fn new() -> Result<Self, SourceError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .dns_resolver(SafeDnsResolver)
            .build()
            .map_err(|error| {
                SourceError::new(
                    SourceErrorKind::Network,
                    format!("failed to build source HTTP client: {error}"),
                )
            })?;
        Ok(Self { client })
    }
}

pub async fn snapshot_web(
    client: &SourceHttpClient,
    initial_url: &str,
    limits: &WebSnapshotLimits,
    secret: bool,
) -> Result<Snapshot, SourceError> {
    let initial = validate_web_url(initial_url)?;
    let mut current = initial.clone();
    let mut chain = Vec::new();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.as_str().to_owned()) {
            return Err(SourceError::new(
                SourceErrorKind::Redirect,
                "web redirect loop detected",
            ));
        }
        let response = client
            .client
            .get(current.clone())
            .send()
            .await
            .map_err(|error| {
                SourceError::new(
                    SourceErrorKind::Network,
                    format!("web snapshot request failed: {error}"),
                )
            })?;
        let status = response.status().as_u16();
        if is_redirect(status) {
            let next = redirect_target(
                &current,
                response
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok()),
            )?;
            chain.push(current.as_str().to_owned());
            if chain.len() > limits.max_redirects {
                return Err(SourceError::new(
                    SourceErrorKind::Redirect,
                    "web redirect limit exceeded",
                ));
            }
            current = next;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(SourceError::new(
                SourceErrorKind::Network,
                format!("web snapshot returned HTTP {status}"),
            ));
        }
        check_content_length(
            response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            limits,
        )?;
        let headers = selected_headers_from_reqwest(response.headers());
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                SourceError::new(
                    SourceErrorKind::Network,
                    format!("web snapshot body failed: {error}"),
                )
            })?;
            if body.len().saturating_add(chunk.len()) > limits.max_bytes {
                return Err(SourceError::new(
                    SourceErrorKind::TooLarge,
                    "web snapshot body exceeds the configured limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        return finish_web_snapshot(initial, current, chain, headers, body, limits, secret);
    }
}

pub fn snapshot_web_from_responses(
    initial_url: &str,
    responses: Vec<WebResponse>,
    limits: &WebSnapshotLimits,
    secret: bool,
) -> Result<Snapshot, SourceError> {
    let initial = validate_web_url(initial_url)?;
    let mut current = initial.clone();
    let mut chain = Vec::new();
    let mut visited = BTreeSet::new();
    for response in responses {
        if !visited.insert(current.as_str().to_owned()) {
            return Err(SourceError::new(
                SourceErrorKind::Redirect,
                "web redirect loop detected",
            ));
        }
        if is_redirect(response.status) {
            let next = redirect_target(
                &current,
                response.headers.get("location").map(String::as_str),
            )?;
            chain.push(current.as_str().to_owned());
            if chain.len() > limits.max_redirects {
                return Err(SourceError::new(
                    SourceErrorKind::Redirect,
                    "web redirect limit exceeded",
                ));
            }
            current = next;
            continue;
        }
        if !(200..300).contains(&response.status) {
            return Err(SourceError::new(
                SourceErrorKind::Network,
                format!("web snapshot returned HTTP {}", response.status),
            ));
        }
        check_content_length(
            response.headers.get("content-length").map(String::as_str),
            limits,
        )?;
        return finish_web_snapshot(
            initial,
            current,
            chain,
            selected_headers(&response.headers),
            response.body,
            limits,
            secret,
        );
    }
    Err(SourceError::new(
        SourceErrorKind::Network,
        "web snapshot response sequence ended before a final response",
    ))
}

fn finish_web_snapshot(
    initial: Url,
    final_url: Url,
    mut redirect_chain: Vec<String>,
    selected_headers: BTreeMap<String, String>,
    raw_bytes: Vec<u8>,
    limits: &WebSnapshotLimits,
    secret: bool,
) -> Result<Snapshot, SourceError> {
    if raw_bytes.len() > limits.max_bytes {
        return Err(SourceError::new(
            SourceErrorKind::TooLarge,
            "web snapshot body exceeds the configured limit",
        ));
    }
    let raw_sha256 = sha256_bytes(&raw_bytes);
    let content = std::str::from_utf8(&raw_bytes).map_err(|error| {
        SourceError::new(
            SourceErrorKind::InvalidUtf8,
            format!("web snapshot is not UTF-8: {error}"),
        )
    })?;
    let markdown = htmd::convert(content).map_err(|error| {
        SourceError::new(
            SourceErrorKind::Network,
            format!("failed to convert web snapshot to Markdown: {error}"),
        )
    })?;
    let web = if secret {
        None
    } else {
        redirect_chain.push(final_url.as_str().to_owned());
        let retrieved_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                SourceError::new(
                    SourceErrorKind::Network,
                    format!("system clock predates the Unix epoch: {error}"),
                )
            })?
            .as_secs();
        Some(WebSnapshotMetadata {
            initial_url: initial.as_str().to_owned(),
            final_url: final_url.as_str().to_owned(),
            redirect_chain,
            selected_headers,
            retrieved_unix_seconds,
            converter_version: "htmd-0.5".into(),
            raw_sha256: raw_sha256.clone(),
            content_sha256: sha256_bytes(markdown.as_bytes()),
        })
    };
    Ok(Snapshot::from_content_with_raw_hash(
        SourceKind::Web,
        raw_bytes,
        markdown,
        secret,
        web,
        raw_sha256,
    ))
}

#[derive(Clone, Debug)]
struct SafeDnsResolver;

impl Resolve for SafeDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let hostname = name.as_str().to_owned();
        Box::pin(async move {
            let result = tokio::task::spawn_blocking(move || {
                (hostname.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addresses| addresses.collect::<Vec<_>>())
            })
            .await;
            let addresses = match result {
                Ok(Ok(addresses)) => addresses,
                Ok(Err(error)) => {
                    return Err(Box::new(error) as Box<dyn std::error::Error + Send + Sync>);
                }
                Err(error) => {
                    return Err(Box::new(std::io::Error::other(format!(
                        "DNS worker failed: {error}"
                    )))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
            };
            validate_dns_addresses(&addresses)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

fn collect_directory(root: &File) -> Result<BTreeMap<PathBuf, Fingerprint>, SourceError> {
    let mut files = BTreeMap::new();
    collect_directory_into(root, Path::new(""), &mut files)?;
    Ok(files)
}

fn collect_directory_into(
    directory: &File,
    relative: &Path,
    files: &mut BTreeMap<PathBuf, Fingerprint>,
) -> Result<(), SourceError> {
    let enumerator = cap_std::fs::Dir::from_std_file(
        directory
            .try_clone()
            .map_err(|error| SourceError::io("failed to clone granted directory", error))?,
    );
    let mut entries = enumerator
        .entries()
        .map_err(|error| SourceError::io("failed to enumerate granted directory", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| SourceError::io("failed to read granted directory", error))?;
    entries.sort_by(|left, right| {
        left.file_name()
            .as_bytes()
            .cmp(right.file_name().as_bytes())
    });
    let mut aliases = BTreeSet::new();
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            SourceError::new(
                SourceErrorKind::InvalidGrant,
                "source grants require UTF-8 path names",
            )
        })?;
        let alias = name.nfkc().flat_map(char::to_lowercase).collect::<String>();
        if !aliases.insert(alias) {
            return Err(SourceError::new(
                SourceErrorKind::InvalidGrant,
                "source grant contains Unicode/case-colliding path names",
            ));
        }
        let file_type = entry
            .file_type()
            .map_err(|error| SourceError::io("failed to inspect granted entry", error))?;
        if file_type.is_symlink() {
            return Err(SourceError::new(
                SourceErrorKind::InvalidGrant,
                "source grants reject symbolic links",
            ));
        }
        if file_type.is_dir() {
            let child = open_directory_at(directory, &entry.file_name())?;
            collect_directory_into(&child, &relative.join(&entry.file_name()), files)?;
        } else if file_type.is_file() {
            let (_, fingerprint) =
                read_open_regular_file(open_file_at(directory, &entry.file_name())?)?;
            let child_relative = relative.join(&entry.file_name());
            if files.insert(child_relative, fingerprint).is_some() {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidGrant,
                    "source grant contains duplicate relative paths",
                ));
            }
        } else {
            return Err(SourceError::new(
                SourceErrorKind::InvalidGrant,
                "source grants reject device files, FIFOs, sockets, and other special files",
            ));
        }
    }
    Ok(())
}

fn read_open_regular_file(mut file: File) -> Result<(Vec<u8>, Fingerprint), SourceError> {
    let metadata = file
        .metadata()
        .map_err(|error| SourceError::io("failed to inspect opened source file", error))?;
    if !metadata.is_file() {
        return Err(SourceError::new(
            SourceErrorKind::InvalidGrant,
            "source path must be a regular non-symlink file",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| SourceError::io("failed to seek to the start of a source file", error))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| SourceError::io("failed to read source file", error))?;
    let after = file
        .metadata()
        .map_err(|error| SourceError::io("failed to inspect read source file", error))?;
    let fingerprint = Fingerprint {
        sha256: sha256_bytes(&bytes),
        byte_len: bytes.len() as u64,
        device: after.dev(),
        inode: after.ino(),
        modified_seconds: after.mtime(),
        modified_nanoseconds: after.mtime_nsec(),
        changed_seconds: after.ctime(),
        changed_nanoseconds: after.ctime_nsec(),
    };
    if after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != bytes.len() as u64
        || after.mtime() != metadata.mtime()
        || after.mtime_nsec() != metadata.mtime_nsec()
        || after.ctime() != metadata.ctime()
        || after.ctime_nsec() != metadata.ctime_nsec()
    {
        return Err(SourceError::new(
            SourceErrorKind::GrantChanged,
            "source changed while it was read",
        ));
    }
    Ok((bytes, fingerprint))
}

fn open_directory_no_follow(path: &Path) -> Result<File, SourceError> {
    let bytes = path.as_os_str().as_bytes();
    let name = std::ffi::CString::new(bytes).map_err(|_| {
        SourceError::new(
            SourceErrorKind::InvalidGrant,
            "source grant path contains an interior NUL",
        )
    })?;
    let descriptor = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return source_open_error(
            "failed to open granted directory without following links",
            std::io::Error::last_os_error(),
        );
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_directory_at(directory: &File, name: &std::ffi::OsStr) -> Result<File, SourceError> {
    open_at(directory, name, libc::O_RDONLY | libc::O_DIRECTORY)
}

fn open_file_at(directory: &File, name: &std::ffi::OsStr) -> Result<File, SourceError> {
    open_at(directory, name, libc::O_RDONLY | libc::O_NONBLOCK)
}

fn open_at(
    directory: &File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
) -> Result<File, SourceError> {
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        SourceError::new(
            SourceErrorKind::InvalidGrant,
            "source grant path contains an interior NUL",
        )
    })?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return source_open_error(
            "failed to open granted source without following links",
            std::io::Error::last_os_error(),
        );
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn open_grant_root(path: &Path) -> Result<(PathBuf, GrantKind, File), SourceError> {
    let root = absolute_lexical_path(path)?;
    let mut directory = open_directory_no_follow(Path::new("/"))?;
    let components = root
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(Ok(name)),
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir | Component::Prefix(_) => Some(Err(SourceError::new(
                SourceErrorKind::InvalidGrant,
                "source grant path is not a normalized absolute path",
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (last, parents) = components.split_last().ok_or_else(|| {
        SourceError::new(
            SourceErrorKind::InvalidGrant,
            "refusing a filesystem-root recursive source grant",
        )
    })?;
    for parent in parents {
        directory = open_directory_at(&directory, parent)?;
    }
    match open_directory_at(&directory, last) {
        Ok(handle) => Ok((root, GrantKind::Directory, handle)),
        Err(directory_error) => match open_file_at(&directory, last) {
            Ok(handle) => {
                let metadata = handle
                    .metadata()
                    .map_err(|error| SourceError::io("failed to inspect granted file", error))?;
                if metadata.is_file() {
                    Ok((root, GrantKind::File, handle))
                } else {
                    Err(SourceError::new(
                        SourceErrorKind::InvalidGrant,
                        "source grants require a regular file or directory",
                    ))
                }
            }
            Err(file_error) => {
                if directory_error.kind() == SourceErrorKind::InvalidGrant
                    || file_error.kind() == SourceErrorKind::InvalidGrant
                {
                    Err(SourceError::new(
                        SourceErrorKind::InvalidGrant,
                        "source grants cannot traverse a symbolic link",
                    ))
                } else {
                    Err(file_error)
                }
            }
        },
    }
}

fn absolute_lexical_path(path: &Path) -> Result<PathBuf, SourceError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| SourceError::io("failed to resolve the current directory", error))?
            .join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::Prefix(_) => {
                return Err(SourceError::new(
                    SourceErrorKind::InvalidGrant,
                    "source grants require POSIX paths",
                ));
            }
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(name) => normalized.push(name),
        }
    }
    Ok(normalized)
}

fn source_open_error(context: &str, error: std::io::Error) -> Result<File, SourceError> {
    if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        Err(SourceError::new(
            SourceErrorKind::InvalidGrant,
            "source grants cannot traverse a symbolic link",
        ))
    } else {
        Err(SourceError::io(context, error))
    }
}

fn text_kind(path: &Path) -> Result<SourceKind, SourceError> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase());
    match extension.as_deref() {
        Some("txt") | Some("text") => Ok(SourceKind::PlainText),
        Some("md") | Some("markdown") => Ok(SourceKind::Markdown),
        _ => Err(SourceError::new(
            SourceErrorKind::UnsupportedFormat,
            "only UTF-8 .txt, .text, .md, and .markdown files are supported",
        )),
    }
}

fn validate_web_url(value: &str) -> Result<Url, SourceError> {
    let url = Url::parse(value).map_err(|error| {
        SourceError::new(
            SourceErrorKind::UnsafeUrl,
            format!("invalid web source URL: {error}"),
        )
    })?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(SourceError::new(
            SourceErrorKind::UnsafeUrl,
            "web sources require HTTPS without userinfo",
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        SourceError::new(SourceErrorKind::UnsafeUrl, "web source URL has no host")
    })?;
    let literal_host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = literal_host.parse::<IpAddr>() {
        if !is_public_ip(address) {
            return Err(SourceError::new(
                SourceErrorKind::UnsafeUrl,
                "web source IP address is not publicly routable",
            ));
        }
    } else {
        if host.starts_with('[') || host.ends_with(']') {
            return Err(SourceError::new(
                SourceErrorKind::UnsafeUrl,
                "web source IP address is invalid",
            ));
        }
        let domain = host.to_ascii_lowercase();
        if domain == "localhost" || domain.ends_with(".localhost") {
            return Err(SourceError::new(
                SourceErrorKind::UnsafeUrl,
                "web source host is not publicly routable",
            ));
        }
    }
    Ok(url)
}

fn redirect_target(current: &Url, location: Option<&str>) -> Result<Url, SourceError> {
    let location = location.ok_or_else(|| {
        SourceError::new(
            SourceErrorKind::Redirect,
            "web redirect has no Location header",
        )
    })?;
    let next = current.join(location).map_err(|error| {
        SourceError::new(
            SourceErrorKind::Redirect,
            format!("invalid web redirect target: {error}"),
        )
    })?;
    validate_web_url(next.as_str())
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn check_content_length(
    value: Option<&str>,
    limits: &WebSnapshotLimits,
) -> Result<(), SourceError> {
    let Some(value) = value else {
        return Ok(());
    };
    let length = value.parse::<usize>().map_err(|_| {
        SourceError::new(
            SourceErrorKind::Network,
            "web snapshot has an invalid Content-Length",
        )
    })?;
    if length > limits.max_bytes {
        return Err(SourceError::new(
            SourceErrorKind::TooLarge,
            "web snapshot Content-Length exceeds the configured limit",
        ));
    }
    Ok(())
}

fn selected_headers_from_reqwest(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    [CONTENT_TYPE, ETAG, LAST_MODIFIED]
        .into_iter()
        .filter_map(|name| {
            headers
                .get(&name)
                .and_then(|value| value.to_str().ok())
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

fn selected_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    ["content-type", "etag", "last-modified"]
        .into_iter()
        .filter_map(|name| {
            headers
                .get(name)
                .map(|value| (name.to_owned(), value.clone()))
        })
        .collect()
}

fn normalize_headers(headers: BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .into_iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .collect()
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_broadcast()
                && !address.is_unspecified()
                && !address.is_multicast()
                && octets[0] != 0
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && !(octets[0] == 198 && matches!(octets[1], 18 | 19))
        }
        IpAddr::V6(address) => {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
                && !address.is_unique_local()
                && !address.is_unicast_link_local()
                && address
                    .to_ipv4()
                    .is_none_or(|address| is_public_ip(IpAddr::V4(address)))
        }
    }
}

fn validate_dns_addresses(addresses: &[SocketAddr]) -> Result<(), std::io::Error> {
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "DNS result contains no exclusively public addresses",
        ));
    }
    Ok(())
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    crate::changeset::sha256_bytes(bytes)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    fn dns_results_reject_a_mixed_public_and_loopback_answer() {
        let addresses = [
            "1.1.1.1:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            "[::127.0.0.1]:443".parse().unwrap(),
        ];

        let error = validate_dns_addresses(&addresses).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
