//! Fixed, capability-bounded tools available to model roles.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use anyhow::{Context, Result, bail, ensure};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions, OpenOptionsExt},
};
use serde::{Deserialize, Serialize};

const MAX_VISIBLE_TOKENS: usize = 10_000;
const MAX_RESULT_BYTES: u64 = 100 * 1024 * 1024;
const MAX_SESSION_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CALLS: u64 = 64;
const MAX_GIT_STDERR_BYTES: u64 = 64 * 1024;

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

/// A role attempted to invoke a tool outside its fixed capability set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolAccessError {
    role: AgentRole,
    tool: Tool,
}

impl ToolAccessError {
    /// Returns the denied role.
    pub const fn role(self) -> AgentRole {
        self.role
    }

    /// Returns the denied tool.
    pub const fn tool(self) -> Tool {
        self.tool
    }
}

impl fmt::Display for ToolAccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "role {:?} may not invoke {}",
            self.role,
            self.tool.name()
        )
    }
}

impl std::error::Error for ToolAccessError {}

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
    capability_root: Dir,
    role: AgentRole,
    artifacts: ArtifactStore,
}

impl ToolExecutor {
    /// Opens a candidate workspace once and keeps that capability for the invocation.
    pub fn new(candidate_workspace: &Path, role: AgentRole) -> Result<Self> {
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
            capability_root,
            role,
            artifacts: ArtifactStore::default(),
        })
    }

    /// Executes one non-shell fixed tool request.
    pub fn execute(&mut self, request: ToolRequest) -> Result<ToolResult> {
        self.require_tool(request.tool())?;
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
        let (parent, leaf) = self.open_parent(relative, false)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = parent
            .open_with(&leaf, &options)
            .with_context(|| format!("failed to read {}", relative.display()))?;
        ensure!(
            file.metadata()?.is_file(),
            "tool input must be a regular file"
        );
        read_bounded(&mut file, MAX_RESULT_BYTES, "tool input")
    }

    fn write_candidate(&self, relative: &Path, contents: &[u8]) -> Result<()> {
        validate_relative(relative)?;
        ensure!(
            contents.len() as u64 <= MAX_RESULT_BYTES,
            "candidate content exceeds 100 MiB"
        );
        let (parent, leaf) = self.open_parent(relative, true)?;
        if let Ok(metadata) = parent.symlink_metadata(&leaf) {
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
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = parent
            .open_with(&leaf, &options)
            .with_context(|| format!("failed to open candidate {}", relative.display()))?;
        file.write_all(contents)?;
        file.sync_data()?;
        Ok(())
    }

    fn search_files(&self, query: &str) -> Result<String> {
        ensure!(!query.is_empty(), "search query must not be empty");
        let mut output = String::new();
        self.search_directory(&self.capability_root, Path::new(""), query, &mut output)?;
        Ok(output)
    }

    fn search_directory(
        &self,
        directory: &Dir,
        relative: &Path,
        query: &str,
        output: &mut String,
    ) -> Result<()> {
        for entry in directory.read_dir(".")? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let name = entry.file_name();
            let child_relative = relative.join(&name);
            if is_forbidden_component(&name) || file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                let child = open_dir_no_follow(directory, &name)?;
                self.search_directory(&child, &child_relative, query, output)?;
            } else if file_type.is_file() {
                let bytes = self.read_file(&child_relative)?;
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    for (line_number, line) in text.lines().enumerate() {
                        if line.contains(query) {
                            let record = format!(
                                "{}:{}:{}",
                                child_relative.display(),
                                line_number + 1,
                                line
                            );
                            append_search_result(output, &record, MAX_RESULT_BYTES as usize)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn git<const N: usize>(&self, args: [&str; N]) -> Result<Vec<u8>> {
        let mut child = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to execute read-only git")?;
        let pid = child.id();
        let overflow = Arc::new(AtomicBool::new(false));
        let stdout = child.stdout.take().context("git stdout was not captured")?;
        let stderr = child.stderr.take().context("git stderr was not captured")?;
        let stdout_handle = bounded_git_reader(
            stdout,
            MAX_RESULT_BYTES,
            "git stdout",
            pid,
            overflow.clone(),
        );
        let stderr_handle = bounded_git_reader(
            stderr,
            MAX_GIT_STDERR_BYTES,
            "git stderr",
            pid,
            overflow.clone(),
        );
        let status = child.wait().context("failed to wait for read-only git")?;
        let stdout = stdout_handle
            .join()
            .map_err(|_| anyhow::anyhow!("git stdout reader panicked"))??;
        let _stderr = stderr_handle
            .join()
            .map_err(|_| anyhow::anyhow!("git stderr reader panicked"))??;
        ensure!(
            !overflow.load(Ordering::Acquire),
            "git output exceeds its configured bound"
        );
        ensure!(status.success(), "read-only git query failed");
        Ok(stdout)
    }

    fn require_tool(&self, tool: Tool) -> Result<()> {
        if Tool::for_role(self.role).contains(&tool) {
            Ok(())
        } else {
            Err(ToolAccessError {
                role: self.role,
                tool,
            }
            .into())
        }
    }

    fn open_parent(&self, relative: &Path, create_missing: bool) -> Result<(Dir, PathBuf)> {
        validate_relative(relative)?;
        let mut directory = self.capability_root.try_clone()?;
        let mut components = relative.components().peekable();
        let leaf = loop {
            let Component::Normal(component) = components.next().expect("validated non-empty path")
            else {
                unreachable!("validate_relative rejects non-normal components");
            };
            if components.peek().is_none() {
                break PathBuf::from(component);
            }
            directory = match open_dir_no_follow(&directory, component) {
                Ok(child) => child,
                Err(error) if create_missing && error.kind() == std::io::ErrorKind::NotFound => {
                    directory.create_dir(component)?;
                    open_dir_no_follow(&directory, component)?
                }
                Err(error) => return Err(error.into()),
            };
        };
        Ok((directory, leaf))
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

fn open_dir_no_follow(parent: &Dir, name: &OsStr) -> std::io::Result<Dir> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let file = parent.open_with(Path::new(name), &options)?;
    if !file.metadata()?.is_dir() {
        return Err(std::io::Error::other("tool path parent is not a directory"));
    }
    Ok(Dir::from_std_file(file.into_std()))
}

fn read_bounded(reader: &mut impl Read, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("failed to read {label}"))?;
        if read == 0 {
            return Ok(bytes);
        }
        let next = bytes
            .len()
            .checked_add(read)
            .context("bounded read length overflow")?;
        ensure!(next as u64 <= limit, "{label} exceeds 100 MiB");
        bytes.extend_from_slice(&buffer[..read]);
    }
}

fn append_search_result(output: &mut String, record: &str, limit: usize) -> Result<()> {
    let separator = usize::from(!output.is_empty());
    ensure!(
        output
            .len()
            .saturating_add(separator)
            .saturating_add(record.len())
            <= limit,
        "search result exceeds 100 MiB"
    );
    if separator == 1 {
        output.push('\n');
    }
    output.push_str(record);
    Ok(())
}

fn bounded_git_reader<R>(
    mut reader: R,
    limit: u64,
    label: &'static str,
    pid: u32,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let result = read_bounded(&mut reader, limit, label);
        if result.is_err() && !overflow.swap(true, Ordering::AcqRel) {
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
        result
    })
}

fn is_forbidden_component(component: &std::ffi::OsStr) -> bool {
    component == ".git"
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rstest::rstest;

    use super::{append_search_result, read_bounded};

    #[rstest]
    fn bounded_reader_rejects_the_first_byte_after_its_limit() {
        let mut input = Cursor::new(b"12345".to_vec());
        let error = read_bounded(&mut input, 4, "tool input").unwrap_err();
        assert_eq!(error.to_string(), "tool input exceeds 100 MiB");
    }

    #[rstest]
    fn search_result_limit_rejects_before_appending() {
        let mut output = String::from("1234");
        let error = append_search_result(&mut output, "5", 4).unwrap_err();
        assert_eq!(error.to_string(), "search result exceeds 100 MiB");
        assert_eq!(output, "1234");
    }
}
