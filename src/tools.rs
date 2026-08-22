//! Fixed, capability-bounded tools available to model roles.

use std::{
	collections::BTreeMap,
	fs::{self, OpenOptions},
	io::{Read, Write},
	path::{Component, Path, PathBuf},
	process::Command,
};

use anyhow::{Context, Result, bail, ensure};
use cap_std::{ambient_authority, fs::Dir};
use serde::{Deserialize, Serialize};

const MAX_VISIBLE_TOKENS: usize = 10_000;
const MAX_RESULT_BYTES: u64 = 100 * 1024 * 1024;
const MAX_SESSION_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CALLS: u64 = 64;

/// A fixed tool name. The declaration order is part of the model protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Tool {
	/// Reads one regular file below the candidate workspace.
	ReadFile,
	/// Searches regular files below the candidate workspace.
	SearchFiles,
	/// Writes a candidate file after no-follow validation.
	EditCandidate,
	/// Produces the candidate workspace diff.
	Diff,
	/// Imports a regular file through the same read boundary.
	Import,
	/// Exposes read-only Git status and diff information.
	Git,
	/// Runs an explicitly approved shell request.
	Shell,
	/// Fetches an explicitly permitted web resource.
	Web,
	/// Asks the controller to run a bounded subagent.
	Subagent,
}

impl Tool {
	const ALL: [Self; 9] = [
		Self::ReadFile,
		Self::SearchFiles,
		Self::EditCandidate,
		Self::Diff,
		Self::Import,
		Self::Git,
		Self::Shell,
		Self::Web,
		Self::Subagent,
	];

	/// Returns tools in stable protocol order.
	pub const fn all() -> &'static [Self] {
		&Self::ALL
	}

	/// Returns the stable wire name for this tool.
	pub const fn name(&self) -> &'static str {
		match self {
			Self::ReadFile => "read_file",
			Self::SearchFiles => "search_files",
			Self::EditCandidate => "edit_candidate",
			Self::Diff => "diff",
			Self::Import => "import",
			Self::Git => "git",
			Self::Shell => "shell",
			Self::Web => "web",
			Self::Subagent => "subagent",
		}
	}

	/// Returns the fixed capability set for a role.
	pub fn for_role(role: AgentRole) -> &'static [Self] {
		const CRITIC_TOOLS: &[Tool] = &[
			Tool::ReadFile,
			Tool::SearchFiles,
			Tool::Diff,
			Tool::Import,
			Tool::Git,
			Tool::Web,
		];
		match role {
			AgentRole::ConsistencyCritic | AgentRole::StyleCritic | AgentRole::FactCritic => {
				CRITIC_TOOLS
			}
			AgentRole::Author | AgentRole::Coordinator => Self::all(),
		}
	}
}

/// A controller-assigned model role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRole {
	/// Produces candidate changes.
	Author,
	/// Checks canon consistency without mutation or shell access.
	ConsistencyCritic,
	/// Checks prose style without mutation or shell access.
	StyleCritic,
	/// Checks source-grounded facts without mutation or shell access.
	FactCritic,
	/// Coordinates explicitly approved work.
	Coordinator,
}

/// A request for one fixed tool operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolRequest {
	/// Reads a file below the capability root.
	ReadFile { path: PathBuf },
	/// Searches literal text in regular files below the capability root.
	SearchFiles { query: String },
	/// Replaces a candidate file with supplied bytes.
	EditCandidate { path: PathBuf, contents: Vec<u8> },
	/// Renders the current Git diff.
	Diff,
	/// Imports bytes from one regular file below the capability root.
	Import { path: PathBuf },
	/// Runs one read-only Git query.
	Git { query: GitQuery },
}

impl ToolRequest {
	/// Returns the request's fixed tool.
	pub const fn tool(&self) -> Tool {
		match self {
			Self::ReadFile { .. } => Tool::ReadFile,
			Self::SearchFiles { .. } => Tool::SearchFiles,
			Self::EditCandidate { .. } => Tool::EditCandidate,
			Self::Diff => Tool::Diff,
			Self::Import { .. } => Tool::Import,
			Self::Git { .. } => Tool::Git,
		}
	}
}

/// The only Git commands model tools may issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitQuery {
	/// `git status --short`.
	Status,
	/// `git diff --no-ext-diff`.
	Diff,
}

/// Content-addressed output exposed to the model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolResult {
	/// SHA-256 of the complete, retained result.
	pub sha256: String,
	/// The complete byte length.
	pub total_bytes: u64,
	/// Output bounded to the visible-token budget.
	pub visible: String,
	/// True when the visible output omits retained bytes.
	pub truncated: bool,
}

/// Holds a bounded workspace capability and invocation-local artifacts.
pub struct ToolExecutor {
	root: PathBuf,
	_capability_root: Dir,
	artifacts: ArtifactStore,
}

impl ToolExecutor {
	/// Opens a candidate workspace once and keeps that capability for the invocation.
	pub fn new(candidate_workspace: &Path) -> Result<Self> {
		let root = candidate_workspace.canonicalize().with_context(|| {
			format!(
				"failed to resolve candidate workspace {}",
				candidate_workspace.display()
			)
		})?;
		ensure!(root.is_dir(), "candidate workspace must be a directory");
		let capability_root = Dir::open_ambient_dir(&root, ambient_authority())
			.context("failed to open candidate workspace capability")?;
		Ok(Self {
			root,
			_capability_root: capability_root,
			artifacts: ArtifactStore::default(),
		})
	}

	/// Executes one non-shell fixed tool request.
	pub fn execute(&mut self, request: ToolRequest) -> Result<ToolResult> {
		self.artifacts.note_call()?;
		let bytes = match request {
			ToolRequest::ReadFile { path } | ToolRequest::Import { path } => {
				self.read_file(&path)?
			}
			ToolRequest::SearchFiles { query } => self.search_files(&query)?.into_bytes(),
			ToolRequest::EditCandidate { path, contents } => {
				self.write_candidate(&path, &contents)?;
				b"candidate updated\n".to_vec()
			}
			ToolRequest::Diff
			| ToolRequest::Git {
				query: GitQuery::Diff,
			} => self.git(["diff", "--no-ext-diff"])?,
			ToolRequest::Git {
				query: GitQuery::Status,
			} => self.git(["status", "--short"])?,
		};
		self.artifacts.store(bytes)
	}

	/// Reads a retained artifact byte range and accounts it against the session limit.
	pub fn read_artifact_range(
		&mut self,
		sha256: &str,
		start: u64,
		end: u64,
	) -> Result<ToolResult> {
		self.artifacts.note_call()?;
		self.artifacts.read_range(sha256, start, end)
	}

	/// Protects an artifact while an active session or receipt references it.
	pub fn protect_artifact(&mut self, sha256: &str) -> Result<()> {
		self.artifacts.protect(sha256)
	}

	/// Releases one active-session or receipt reference.
	pub fn release_artifact(&mut self, sha256: &str) -> Result<()> {
		self.artifacts.release(sha256)
	}

	fn read_file(&self, relative: &Path) -> Result<Vec<u8>> {
		let path = self.safe_existing_file(relative)?;
		let mut options = OpenOptions::new();
		options.read(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.custom_flags(libc::O_NOFOLLOW);
		}
		let mut file = options
			.open(&path)
			.with_context(|| format!("failed to read {}", relative.display()))?;
		let mut bytes = Vec::new();
		file.read_to_end(&mut bytes)?;
		Ok(bytes)
	}

	fn write_candidate(&self, relative: &Path, contents: &[u8]) -> Result<()> {
		validate_relative(relative)?;
		ensure!(
			contents.len() as u64 <= MAX_RESULT_BYTES,
			"candidate content exceeds 100 MiB"
		);
		let path = self.root.join(relative);
		validate_parents(&self.root, relative, true)?;
		if let Ok(metadata) = fs::symlink_metadata(&path) {
			ensure!(
				metadata.file_type().is_file(),
				"candidate target is not a regular file"
			);
			ensure!(
				!metadata.file_type().is_symlink(),
				"candidate target is a symlink"
			);
		}
		let mut options = OpenOptions::new();
		options.write(true).create(true).truncate(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.custom_flags(libc::O_NOFOLLOW);
		}
		let mut file = options
			.open(&path)
			.with_context(|| format!("failed to open candidate {}", relative.display()))?;
		file.write_all(contents)?;
		file.sync_data()?;
		Ok(())
	}

	fn safe_existing_file(&self, relative: &Path) -> Result<PathBuf> {
		validate_relative(relative)?;
		validate_parents(&self.root, relative, false)?;
		let path = self.root.join(relative);
		let metadata = fs::symlink_metadata(&path)
			.with_context(|| format!("failed to inspect {}", relative.display()))?;
		ensure!(
			metadata.file_type().is_file(),
			"tool input must be a regular file"
		);
		ensure!(
			!metadata.file_type().is_symlink(),
			"tool input must not be a symlink"
		);
		Ok(path)
	}

	fn search_files(&self, query: &str) -> Result<String> {
		ensure!(!query.is_empty(), "search query must not be empty");
		let mut matches = Vec::new();
		self.search_directory(&self.root, Path::new(""), query, &mut matches)?;
		Ok(matches.join("\n"))
	}

	fn search_directory(
		&self,
		directory: &Path,
		relative: &Path,
		query: &str,
		matches: &mut Vec<String>,
	) -> Result<()> {
		for entry in fs::read_dir(directory)? {
			let entry = entry?;
			let file_type = entry.file_type()?;
			let name = entry.file_name();
			let child_relative = relative.join(&name);
			if is_forbidden_component(&name) || file_type.is_symlink() {
				continue;
			}
			if file_type.is_dir() {
				self.search_directory(&entry.path(), &child_relative, query, matches)?;
			} else if file_type.is_file() {
				let bytes = self.read_file(&child_relative)?;
				if let Ok(text) = std::str::from_utf8(&bytes) {
					for (line_number, line) in text.lines().enumerate() {
						if line.contains(query) {
							matches.push(format!(
								"{}:{}:{}",
								child_relative.display(),
								line_number + 1,
								line
							));
						}
					}
				}
			}
		}
		Ok(())
	}

	fn git<const N: usize>(&self, args: [&str; N]) -> Result<Vec<u8>> {
		let output = Command::new("/usr/bin/git")
			.arg("-C")
			.arg(&self.root)
			.args(args)
			.env_clear()
			.env("PATH", "/usr/bin:/bin")
			.env("LC_ALL", "C")
			.output()
			.context("failed to execute read-only git")?;
		ensure!(output.status.success(), "read-only git query failed");
		Ok(output.stdout)
	}
}

/// Invocation-local content-addressed artifact storage.
#[derive(Default)]
struct ArtifactStore {
	artifacts: BTreeMap<String, Artifact>,
	accounted_bytes: u64,
	calls: u64,
}

struct Artifact {
	bytes: Vec<u8>,
	references: u64,
}

impl ArtifactStore {
	fn note_call(&mut self) -> Result<()> {
		self.calls = self
			.calls
			.checked_add(1)
			.context("tool call counter overflow")?;
		ensure!(self.calls <= MAX_CALLS, "tool invocation exceeds 64 calls");
		Ok(())
	}

	fn store(&mut self, bytes: Vec<u8>) -> Result<ToolResult> {
		ensure!(
			bytes.len() as u64 <= MAX_RESULT_BYTES,
			"tool result exceeds 100 MiB"
		);
		self.account(bytes.len() as u64)?;
		let sha256 = crate::changeset::sha256_bytes(&bytes);
		let total_bytes = bytes.len() as u64;
		self.artifacts.entry(sha256.clone()).or_insert(Artifact {
			bytes,
			references: 0,
		});
		self.result_for(&sha256, 0, total_bytes)
	}

	fn read_range(&mut self, sha256: &str, start: u64, end: u64) -> Result<ToolResult> {
		let bytes = self
			.artifacts
			.get(sha256)
			.context("unknown artifact")?
			.bytes
			.clone();
		ensure!(
			start <= end && end <= bytes.len() as u64,
			"invalid artifact range"
		);
		let range = bytes[start as usize..end as usize].to_vec();
		ensure!(
			range.len() as u64 <= MAX_RESULT_BYTES,
			"tool result exceeds 100 MiB"
		);
		self.account(end - start)?;
		let range_sha256 = crate::changeset::sha256_bytes(&range);
		self.artifacts
			.entry(range_sha256.clone())
			.or_insert(Artifact {
				bytes: range,
				references: 0,
			});
		self.result_for(&range_sha256, 0, end - start)
	}

	fn protect(&mut self, sha256: &str) -> Result<()> {
		let artifact = self.artifacts.get_mut(sha256).context("unknown artifact")?;
		artifact.references = artifact
			.references
			.checked_add(1)
			.context("artifact reference overflow")?;
		Ok(())
	}

	fn release(&mut self, sha256: &str) -> Result<()> {
		let artifact = self.artifacts.get_mut(sha256).context("unknown artifact")?;
		ensure!(artifact.references > 0, "artifact is not protected");
		artifact.references -= 1;
		Ok(())
	}

	fn account(&mut self, bytes: u64) -> Result<()> {
		self.accounted_bytes = self
			.accounted_bytes
			.checked_add(bytes)
			.context("artifact byte counter overflow")?;
		ensure!(
			self.accounted_bytes <= MAX_SESSION_BYTES,
			"tool session exceeds 2 GiB"
		);
		Ok(())
	}

	fn result_for(&self, sha256: &str, start: u64, total_bytes: u64) -> Result<ToolResult> {
		let bytes = &self
			.artifacts
			.get(sha256)
			.context("unknown artifact")?
			.bytes;
		let limit = MAX_VISIBLE_TOKENS * 4;
		let visible_end = bytes.len().min(limit);
		let mut visible = String::from_utf8_lossy(&bytes[..visible_end]).into_owned();
		while !visible.is_char_boundary(visible.len()) {
			visible.pop();
		}
		Ok(ToolResult {
			sha256: sha256.to_owned(),
			total_bytes,
			visible,
			truncated: start + (visible_end as u64) < start + total_bytes,
		})
	}
}

fn validate_relative(path: &Path) -> Result<()> {
	ensure!(!path.is_absolute(), "tool paths must be relative");
	ensure!(!path.as_os_str().is_empty(), "tool path must not be empty");
	for component in path.components() {
		match component {
			Component::Normal(name) if !is_forbidden_component(name) => {}
			_ => bail!("unsafe tool path: {}", path.display()),
		}
	}
	Ok(())
}

fn validate_parents(root: &Path, relative: &Path, create_missing: bool) -> Result<()> {
	let mut current = root.to_path_buf();
	for component in relative
		.components()
		.take(relative.components().count().saturating_sub(1))
	{
		let Component::Normal(name) = component else {
			bail!("unsafe tool path: {}", relative.display());
		};
		current.push(name);
		if current.exists() {
			let metadata = fs::symlink_metadata(&current)?;
			ensure!(
				metadata.is_dir() && !metadata.file_type().is_symlink(),
				"tool path has a symlink or non-directory parent"
			);
		} else if create_missing {
			fs::create_dir(&current)?;
		} else {
			bail!("tool path parent does not exist");
		}
	}
	Ok(())
}

fn is_forbidden_component(component: &std::ffi::OsStr) -> bool {
	component == ".git"
}
