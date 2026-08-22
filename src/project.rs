use std::{
	fs::{self, OpenOptions},
	io::Write,
	path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use yaml_serde::{Mapping, Value};

use crate::domain::{EntityId, EntityKind, prefixed_uuid};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectConfig {
	pub format_version: u8,
	pub work_id: EntityId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitAnswers {
	pub title: String,
}

impl InitAnswers {
	pub fn minimal(title: impl Into<String>) -> Self {
		Self {
			title: title.into(),
		}
	}
}

#[derive(Clone, Debug)]
pub struct Project {
	pub root: PathBuf,
	pub config: ProjectConfig,
}

impl Project {
	pub fn resolve_path(&self, relative: &Path) -> Result<PathBuf> {
		validate_relative_path(relative)?;
		Ok(self.root.join(relative))
	}
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
	let opening_end = line_end(bytes, 0)
		.ok_or_else(|| anyhow::anyhow!("frontmatter opening delimiter is missing"))?;
	ensure!(
		delimiter_line(&bytes[..opening_end]),
		"frontmatter must start with a --- delimiter"
	);

	let frontmatter_start = next_line_start(bytes, opening_end);
	let mut cursor = frontmatter_start;
	let closing_start = loop {
		let end = line_end(bytes, cursor)
			.ok_or_else(|| anyhow::anyhow!("frontmatter closing delimiter is missing"))?;
		if delimiter_line(&bytes[cursor..end]) {
			break cursor;
		}
		cursor = next_line_start(bytes, end);
		if cursor >= bytes.len() {
			bail!("frontmatter closing delimiter is missing");
		}
	};
	let closing_end = line_end(bytes, closing_start).expect("closing delimiter has a line end");
	let source = std::str::from_utf8(&bytes[frontmatter_start..closing_start])
		.context("frontmatter must be valid UTF-8")?;
	let frontmatter: Mapping =
		yaml_serde::from_str(source).context("frontmatter must be a YAML mapping")?;

	Ok(MarkdownArtifact {
		original_frontmatter: frontmatter.clone(),
		frontmatter,
		original: bytes.to_vec(),
		body_offset: next_line_start(bytes, closing_end),
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
	ensure!(
		directory_is_empty_or_missing(root)?,
		"refusing to overwrite non-empty project directory: {}",
		root.display()
	);

	fs::create_dir_all(root)
		.with_context(|| format!("failed to create project root {}", root.display()))?;
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
		fs::create_dir_all(root.join(directory))
			.with_context(|| format!("failed to create {directory}"))?;
	}

	let config = ProjectConfig {
		format_version: 1,
		work_id: prefixed_uuid(EntityKind::Work),
	};
	write_new(
		&root.join("project.toml"),
		toml::to_string_pretty(&config)
			.context("failed to serialize project config")?
			.as_bytes(),
	)?;
	write_new(
		&root.join(".phemius/local.toml"),
		b"# Machine-local Phemius settings.\n",
	)?;
	write_new(&root.join("AGENTS.md"), b"# Phemius project guidance\n")?;

	write_new_markdown(root, "前提/作品.md", &[("id", config.work_id.as_str())])?;
	write_new_markdown(root, "前提/世界観設定.md", &[("id", "world_1")])?;
	write_new_markdown(root, "前提/時系列.md", &[("id", "timeline_1")])?;
	write_new_markdown(root, "前提/伏線.md", &[("id", "foreshadowing_1")])?;
	write_new_markdown(root, "前提/文章スタイル.md", &[("id", "style_1")])?;
	write_new_markdown(root, "前提/執筆ルール.md", &[("id", "rules_1")])?;
	write_new_markdown(root, "箱書き/構成.md", &[("id", "structure_1")])?;
	write_new_markdown(root, "資料/manifest.md", &[("id", "manifest_1")])?;

	let candidate_id = prefixed_uuid(EntityKind::Changeset);
	let candidate_dir = root
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
	};
	write_new(
		&candidate_dir.join("init.toml"),
		toml::to_string_pretty(&metadata)
			.context("failed to serialize initial candidate metadata")?
			.as_bytes(),
	)?;

	Ok(Project {
		root: root.to_path_buf(),
		config,
	})
}

#[derive(Serialize)]
struct InitialCandidate<'a> {
	id: EntityId,
	state: &'static str,
	title: &'a str,
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

fn line_end(bytes: &[u8], start: usize) -> Option<usize> {
	bytes[start..]
		.iter()
		.position(|byte| *byte == b'\n')
		.map(|offset| start + offset + 1)
}

fn next_line_start(bytes: &[u8], line_end: usize) -> usize {
	line_end.min(bytes.len())
}

fn delimiter_line(line: &[u8]) -> bool {
	let line = line.strip_suffix(b"\n").unwrap_or(line);
	let line = line.strip_suffix(b"\r").unwrap_or(line);
	line == b"---"
}
