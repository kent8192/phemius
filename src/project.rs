use std::{
    ffi::CString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use yaml_serde::{Mapping, Value};

use crate::domain::{EntityId, EntityKind, is_prefixed_uuid, prefixed_uuid};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectConfig {
    pub format_version: u8,
    pub work_id: EntityId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitAnswers {
    pub title: String,
    pub premise: String,
    pub language: String,
    pub genre: String,
    pub framework: String,
    pub style: String,
}

impl InitAnswers {
    pub fn minimal(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            premise: String::new(),
            language: String::new(),
            genre: String::new(),
            framework: String::new(),
            style: String::new(),
        }
    }

    pub fn interview(
        title: impl Into<String>,
        premise: impl Into<String>,
        language: impl Into<String>,
        genre: impl Into<String>,
        framework: impl Into<String>,
        style: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            premise: premise.into(),
            language: language.into(),
            genre: genre.into(),
            framework: framework.into(),
            style: style.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Project {
    pub root: PathBuf,
    pub config: ProjectConfig,
}

impl Project {
    /// Opens an existing project without changing any canonical bytes.
    ///
    /// The root is canonicalized before it is retained, and the on-disk
    /// `project.toml` is checked for the supported format and immutable work ID.
    pub fn open(root: &Path) -> Result<Self> {
        let root = fs::canonicalize(root)
            .with_context(|| format!("failed to canonicalize project root {}", root.display()))?;
        ensure!(
            root.is_dir(),
            "project root is not a directory: {}",
            root.display()
        );
        let config_path = root.join("project.toml");
        ensure!(
            config_path.is_file(),
            "project.toml is missing from project root {}",
            root.display()
        );
        let bytes = fs::read(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("{} is not valid UTF-8", config_path.display()))?;
        let config: ProjectConfig = toml::from_str(text)
            .with_context(|| format!("failed to parse {}", config_path.display()))?;
        ensure!(
            config.format_version == 1,
            "unsupported project format version {}",
            config.format_version
        );
        ensure!(
            is_prefixed_uuid(config.work_id.as_str(), EntityKind::Work),
            "project.toml work_id is not a valid work UUID"
        );
        Ok(Self { root, config })
    }

    pub fn resolve_path(&self, relative: &Path) -> Result<PathBuf> {
        validate_relative_path(relative)?;
        Ok(self.root.join(relative))
    }
}

/// Loads an existing project from a path, retaining the canonical root.
pub fn load_project(root: &Path) -> Result<Project> {
    Project::open(root)
}

#[derive(Clone, Debug)]
pub struct MarkdownArtifact {
    frontmatter: Mapping,
    original_frontmatter: Mapping,
    original: Vec<u8>,
    body_offset: usize,
}

impl MarkdownArtifact {
    pub fn body(&self) -> &[u8] {
        &self.original[self.body_offset..]
    }

    pub fn frontmatter(&self) -> &Mapping {
        &self.frontmatter
    }

    pub fn frontmatter_mut(&mut self) -> &mut Mapping {
        &mut self.frontmatter
    }
}

pub fn parse_markdown(bytes: &[u8]) -> Result<MarkdownArtifact> {
    let (opening, mut cursor) = line(bytes, 0)
        .ok_or_else(|| anyhow::anyhow!("frontmatter opening delimiter is missing"))?;
    ensure!(
        delimiter_line(opening),
        "frontmatter must start with a --- delimiter"
    );

    let frontmatter_start = cursor;
    let (closing_start, body_offset) = loop {
        let (current, next) = line(bytes, cursor)
            .ok_or_else(|| anyhow::anyhow!("frontmatter closing delimiter is missing"))?;
        if delimiter_line(current) {
            break (cursor, next);
        }
        cursor = next;
    };
    let source = std::str::from_utf8(&bytes[frontmatter_start..closing_start])
        .context("frontmatter must be valid UTF-8")?;
    let frontmatter: Mapping =
        yaml_serde::from_str(source).context("frontmatter must be a YAML mapping")?;

    Ok(MarkdownArtifact {
        original_frontmatter: frontmatter.clone(),
        frontmatter,
        original: bytes.to_vec(),
        body_offset,
    })
}

pub fn render_markdown(artifact: &MarkdownArtifact) -> Result<Vec<u8>> {
    if artifact.frontmatter == artifact.original_frontmatter {
        return Ok(artifact.original.clone());
    }

    let yaml =
        yaml_serde::to_string(&artifact.frontmatter).context("failed to serialize frontmatter")?;
    let mut rendered = format!("---\n{yaml}---\n").into_bytes();
    rendered.extend_from_slice(artifact.body());
    Ok(rendered)
}

pub fn initialize_project(root: &Path, answers: &InitAnswers) -> Result<Project> {
    ensure!(
        !answers.title.trim().is_empty(),
        "project title is required"
    );
    let staging = StagingDirectory::create(root)?;
    let staging_root = staging.path();
    for directory in [
        "前提/キャラクター設定",
        "箱書き/章",
        "箱書き/構成法",
        "本文",
        "メモ",
        "資料/snapshots",
        ".phemius/records",
        ".phemius/runtime/candidates",
    ] {
        fs::create_dir_all(staging_root.join(directory))
            .with_context(|| format!("failed to create {directory}"))?;
    }

    let config = ProjectConfig {
        format_version: 1,
        work_id: prefixed_uuid(EntityKind::Work),
    };
    write_new(
        &staging_root.join("project.toml"),
        toml::to_string_pretty(&config)
            .context("failed to serialize project config")?
            .as_bytes(),
    )?;
    write_new(
        &staging_root.join(".phemius/local.toml"),
        b"# Machine-local Phemius settings.\n",
    )?;
    write_new(
        &staging_root.join("AGENTS.md"),
        b"# Phemius project guidance\n",
    )?;

    write_new_markdown(
        staging_root,
        "前提/作品.md",
        &[("id", config.work_id.as_str())],
    )?;
    write_new_markdown(
        staging_root,
        "前提/世界観設定.md",
        &[("id", prefixed_uuid(EntityKind::World).as_str())],
    )?;
    write_new_markdown(
        staging_root,
        "前提/時系列.md",
        &[("id", prefixed_uuid(EntityKind::Timeline).as_str())],
    )?;
    write_new_markdown(
        staging_root,
        "前提/伏線.md",
        &[("id", prefixed_uuid(EntityKind::Foreshadowing).as_str())],
    )?;
    write_new_markdown(
        staging_root,
        "前提/文章スタイル.md",
        &[("id", prefixed_uuid(EntityKind::Style).as_str())],
    )?;
    write_new_markdown(
        staging_root,
        "前提/執筆ルール.md",
        &[("id", prefixed_uuid(EntityKind::Rule).as_str())],
    )?;
    write_new_markdown(
        staging_root,
        "箱書き/構成.md",
        &[("id", prefixed_uuid(EntityKind::Structure).as_str())],
    )?;
    write_new_markdown(
        staging_root,
        "資料/manifest.md",
        &[("id", prefixed_uuid(EntityKind::Source).as_str())],
    )?;

    let candidate_id = prefixed_uuid(EntityKind::Changeset);
    let candidate_dir = staging_root
        .join(".phemius/runtime/candidates")
        .join(candidate_id.as_str());
    fs::create_dir(&candidate_dir).with_context(|| {
        format!(
            "failed to create initial candidate {}",
            candidate_id.as_str()
        )
    })?;
    let metadata = InitialCandidate {
        id: candidate_id,
        state: "unapproved",
        title: &answers.title,
        premise: &answers.premise,
        language: &answers.language,
        genre: &answers.genre,
        framework: &answers.framework,
        style: &answers.style,
    };
    write_new(
        &candidate_dir.join("init.toml"),
        toml::to_string_pretty(&metadata)
            .context("failed to serialize initial candidate metadata")?
            .as_bytes(),
    )?;
    staging.persist(root)?;
    let root = fs::canonicalize(root)
        .with_context(|| format!("failed to canonicalize initialized root {}", root.display()))?;

    Ok(Project { root, config })
}

struct StagingDirectory {
    path: Option<PathBuf>,
}

impl StagingDirectory {
    fn create(root: &Path) -> Result<Self> {
        ensure!(
            directory_is_empty_or_missing(root)?,
            "refusing to overwrite non-empty project directory: {}",
            root.display()
        );
        let staging_root = if root.exists() {
            fs::canonicalize(root).with_context(|| {
                format!("failed to canonicalize project root {}", root.display())
            })?
        } else {
            root.to_path_buf()
        };
        let parent = staging_root
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create project parent {}", parent.display()))?;
        let name = staging_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("phemius");
        let path = parent.join(format!(".{name}.phemius-staging-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path)
            .with_context(|| format!("failed to create staging directory {}", path.display()))?;
        Ok(Self { path: Some(path) })
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("staging directory is armed")
    }

    fn disarm(&mut self) {
        self.path = None;
    }

    fn persist(mut self, root: &Path) -> Result<()> {
        if root.exists() {
            self.move_contents_into(root)?;
        } else {
            rename_without_replacing(self.path(), root)
                .with_context(|| format!("failed to finalize project root {}", root.display()))?;
        }
        self.disarm();
        Ok(())
    }

    fn move_contents_into(&mut self, root: &Path) -> Result<()> {
        let entries = fs::read_dir(self.path())
            .with_context(|| format!("failed to read staging directory {}", self.path().display()))?
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| {
                format!(
                    "failed to enumerate staging directory {}",
                    self.path().display()
                )
            })?;
        let mut moved = Vec::with_capacity(entries.len());
        for entry in entries {
            let target = root.join(entry.file_name());
            if let Err(error) = rename_without_replacing(&entry.path(), &target) {
                return match self.rollback(&moved) {
                    Ok(()) => Err(error).with_context(|| {
                        format!(
                            "failed to initialize existing project root {}",
                            root.display()
                        )
                    }),
                    Err(rollback) => {
                        self.disarm();
                        Err(rollback).context(format!(
                            "failed to initialize existing project root {} after move error: {error}",
                            root.display()
                        ))
                    }
                };
            }
            moved.push(target);
        }
        let _ = fs::remove_dir(self.path());
        Ok(())
    }

    fn rollback(&self, moved: &[PathBuf]) -> Result<()> {
        let mut failure = None;
        for target in moved.iter().rev() {
            let source = self
                .path()
                .join(target.file_name().expect("moved path has a file name"));
            if let Err(error) = rename_without_replacing(target, &source)
                && failure.is_none()
            {
                failure = Some(error);
            }
        }
        if let Some(error) = failure {
            return Err(error).context("failed to roll back project initialization");
        }
        Ok(())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

pub(crate) fn rename_without_replacing(from: &Path, to: &Path) -> std::io::Result<()> {
    let from = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let to = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: Both pointers are valid NUL-terminated paths for the duration of the call.
    let result = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[derive(Serialize)]
struct InitialCandidate<'a> {
    id: EntityId,
    state: &'static str,
    title: &'a str,
    premise: &'a str,
    language: &'a str,
    genre: &'a str,
    framework: &'a str,
    style: &'a str,
}

fn directory_is_empty_or_missing(path: &Path) -> Result<bool> {
    match fs::read_dir(path) {
        Ok(mut entries) => Ok(entries.next().is_none()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect project root {}", path.display()))
        }
    }
}

fn write_new(path: &Path, content: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    file.write_all(content)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn write_new_markdown(root: &Path, relative: &str, fields: &[(&str, &str)]) -> Result<()> {
    let mut frontmatter = Mapping::new();
    for (key, value) in fields {
        frontmatter.insert(Value::String((*key).into()), Value::String((*value).into()));
    }
    let yaml =
        yaml_serde::to_string(&frontmatter).context("failed to serialize initial frontmatter")?;
    write_new(&root.join(relative), format!("---\n{yaml}---\n").as_bytes())
}

fn validate_relative_path(path: &Path) -> Result<()> {
    ensure!(!path.is_absolute(), "project path must be relative");
    for component in path.components() {
        match component {
            Component::Normal(name) if name != ".git" => {}
            _ => bail!("unsafe project-relative path: {}", path.display()),
        }
    }
    Ok(())
}

fn line(bytes: &[u8], start: usize) -> Option<(&[u8], usize)> {
    if start >= bytes.len() {
        return None;
    }
    let end = bytes[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| start + offset);
    Some((&bytes[start..end], (end + 1).min(bytes.len())))
}

fn delimiter_line(line: &[u8]) -> bool {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    line == b"---"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_replace_rename_preserves_an_existing_destination() {
        let root = std::env::temp_dir().join(format!("phemius-rename-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        let destination = root.join("destination");
        fs::write(&source, "candidate").unwrap();
        fs::write(&destination, "existing").unwrap();

        assert!(rename_without_replacing(&source, &destination).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"candidate");
        assert_eq!(fs::read(&destination).unwrap(), b"existing");

        fs::remove_dir_all(root).unwrap();
    }
}
