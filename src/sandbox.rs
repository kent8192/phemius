//! Explicit approval and fail-closed macOS Seatbelt shell execution.

use std::{
	collections::BTreeSet,
	fmt,
	path::{Path, PathBuf},
	time::Duration,
};

use tokio::{
	io::AsyncReadExt,
	process::{Child, Command},
	time::{Instant, timeout},
};

/// The approval policy for one shell request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ApprovalMode {
	/// Return a typed approval choice before execution.
	#[default]
	Ask,
	/// Run only executables in the request's resolved allowlist.
	Allowlist,
	/// Do not ask; unrestricted execution still needs explicit trust.
	Never,
}

/// The requested execution isolation mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SandboxMode {
	/// macOS Seatbelt, with network denied and only the workspace writable.
	#[default]
	Seatbelt,
	/// Reserved for a controller-provided container runtime.
	Container,
	/// No operating-system sandbox; only explicit trusted sessions may request this.
	None,
}

/// A direct executable request or an explicitly shell-shaped command string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellRequest {
	program: PathBuf,
	arguments: Vec<String>,
	shell_command: Option<String>,
	workspace: PathBuf,
	approval: ApprovalMode,
	sandbox: SandboxMode,
	allowlisted_executables: BTreeSet<PathBuf>,
	trusted_unrestricted: bool,
	time_limit: Duration,
	output_limit: usize,
}

impl ShellRequest {
	/// Creates a direct-program request with the safe default approval and sandbox modes.
	pub fn program(program: impl Into<PathBuf>) -> Self {
		Self {
			program: program.into(),
			arguments: Vec::new(),
			shell_command: None,
			workspace: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
			approval: ApprovalMode::Ask,
			sandbox: SandboxMode::Seatbelt,
			allowlisted_executables: BTreeSet::new(),
			trusted_unrestricted: false,
			time_limit: Duration::from_secs(30),
			output_limit: 1024 * 1024,
		}
	}

	/// Creates an explicitly shell-shaped request. Only this constructor uses `zsh -lc`.
	pub fn shell(command: impl Into<String>) -> Self {
		let mut request = Self::program("/bin/zsh");
		request.shell_command = Some(command.into());
		request
	}

	/// Adds one direct program argument.
	pub fn arg(mut self, argument: impl Into<String>) -> Self {
		self.arguments.push(argument.into());
		self
	}

	/// Sets the candidate workspace allowed for writes under Seatbelt.
	pub fn in_workspace(mut self, workspace: impl Into<PathBuf>) -> Self {
		self.workspace = workspace.into();
		self
	}

	/// Sets the approval mode.
	pub fn with_approval(mut self, approval: ApprovalMode) -> Self {
		self.approval = approval;
		self
	}

	/// Sets the sandbox mode.
	pub fn with_sandbox(mut self, sandbox: SandboxMode) -> Self {
		self.sandbox = sandbox;
		self
	}

	/// Adds a resolved executable path to the allowlist policy.
	pub fn allow_executable(mut self, executable: impl Into<PathBuf>) -> Self {
		self.allowlisted_executables.insert(executable.into());
		self
	}

	/// Marks the request as an explicit trusted-unrestricted human session.
	pub fn trusted_unrestricted(mut self) -> Self {
		self.trusted_unrestricted = true;
		self
	}

	/// Sets a bounded wall-clock limit.
	pub fn with_time_limit(mut self, time_limit: Duration) -> Self {
		self.time_limit = time_limit;
		self
	}

	/// Sets a combined stdout and stderr byte limit.
	pub fn with_output_limit(mut self, output_limit: usize) -> Self {
		self.output_limit = output_limit;
		self
	}
}

/// Completed, bounded child-process output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellOutcome {
	/// Captured standard output.
	pub stdout: String,
	/// Captured standard error.
	pub stderr: String,
	/// Process exit code, if supplied by the operating system.
	pub exit_code: Option<i32>,
}

/// A fail-closed shell decision or execution failure.
#[derive(Debug)]
pub enum ShellError {
	/// A controller must request the displayed approval or sandbox choice.
	ChoiceRequired {
		/// The unresolved decision.
		reason: ChoiceReason,
		/// Resolved executable, when available.
		executable: Option<PathBuf>,
	},
	/// An invalid request was rejected before launch.
	Invalid(String),
	/// The command could not be launched or observed.
	Execution(std::io::Error),
}

impl fmt::Display for ShellError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ChoiceRequired { reason, .. } => {
				write!(formatter, "user choice required: {reason:?}")
			}
			Self::Invalid(message) => write!(formatter, "invalid shell request: {message}"),
			Self::Execution(error) => write!(formatter, "shell execution failed: {error}"),
		}
	}
}

impl std::error::Error for ShellError {}

impl From<std::io::Error> for ShellError {
	fn from(error: std::io::Error) -> Self {
		Self::Execution(error)
	}
}

/// The explicit choice which blocks execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChoiceReason {
	/// The ask policy requires a human decision.
	Approval,
	/// The resolved executable is not in the allowlist.
	Allowlist,
	/// Seatbelt is absent or could not be started.
	SandboxUnavailable,
	/// A container runtime must be selected by the controller.
	ContainerUnavailable,
	/// Unrestricted execution was not marked as trusted and explicit.
	UntrustedUnrestricted,
}

/// Runs a bounded child process, or returns a typed choice without launching it.
pub async fn run_shell(request: ShellRequest) -> Result<ShellOutcome, ShellError> {
	let workspace = request
		.workspace
		.canonicalize()
		.map_err(ShellError::Execution)?;
	if !workspace.is_dir() {
		return Err(ShellError::Invalid("workspace must be a directory".into()));
	}
	let executable = resolve_executable(&request.program)?;
	match request.approval {
		ApprovalMode::Ask => {
			return Err(ShellError::ChoiceRequired {
				reason: ChoiceReason::Approval,
				executable: Some(executable),
			});
		}
		ApprovalMode::Allowlist
			if !request.allowlisted_executables.iter().any(|candidate| {
				candidate.canonicalize().ok().as_deref() == Some(executable.as_path())
			}) =>
		{
			return Err(ShellError::ChoiceRequired {
				reason: ChoiceReason::Allowlist,
				executable: Some(executable),
			});
		}
		ApprovalMode::Allowlist | ApprovalMode::Never => {}
	}
	if request.sandbox == SandboxMode::None && !request.trusted_unrestricted {
		return Err(ShellError::ChoiceRequired {
			reason: ChoiceReason::UntrustedUnrestricted,
			executable: Some(executable),
		});
	}
	if request.sandbox == SandboxMode::Container {
		return Err(ShellError::ChoiceRequired {
			reason: ChoiceReason::ContainerUnavailable,
			executable: Some(executable),
		});
	}

	let mut command = match request.sandbox {
		SandboxMode::Seatbelt => seatbelt_command(&workspace, &executable, &request)?,
		SandboxMode::None => child_command(&executable, &request),
		SandboxMode::Container => unreachable!("container mode returned above"),
	};
	command.current_dir(&workspace);
	command.env_clear();
	command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
	command.env("LC_ALL", "C");
	command.env("LANG", "C");
	command.stdin(std::process::Stdio::null());
	command.stdout(std::process::Stdio::piped());
	command.stderr(std::process::Stdio::piped());
	#[cfg(unix)]
	{
		command.process_group(0);
	}
	let child = command.spawn().map_err(|error| {
		if request.sandbox == SandboxMode::Seatbelt {
			ShellError::ChoiceRequired {
				reason: ChoiceReason::SandboxUnavailable,
				executable: Some(executable.clone()),
			}
		} else {
			ShellError::Execution(error)
		}
	})?;
	capture_child(child, request.time_limit, request.output_limit).await
}

fn resolve_executable(program: &Path) -> Result<PathBuf, ShellError> {
	let candidate = if program.components().count() > 1 || program.is_absolute() {
		program.to_path_buf()
	} else {
		["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
			.into_iter()
			.map(|directory| Path::new(directory).join(program))
			.find(|path| path.is_file())
			.ok_or_else(|| {
				ShellError::Invalid(format!(
					"executable {} is not on the safe PATH",
					program.display()
				))
			})?
	};
	let resolved = candidate.canonicalize().map_err(ShellError::Execution)?;
	let metadata = std::fs::metadata(&resolved).map_err(ShellError::Execution)?;
	if !metadata.is_file() {
		return Err(ShellError::Invalid(
			"executable must be a regular file".into(),
		));
	}
	Ok(resolved)
}

fn seatbelt_command(
	workspace: &Path,
	executable: &Path,
	request: &ShellRequest,
) -> Result<Command, ShellError> {
	let sandbox_exec = Path::new("/usr/bin/sandbox-exec");
	if !sandbox_exec.is_file() {
		return Err(ShellError::ChoiceRequired {
			reason: ChoiceReason::SandboxUnavailable,
			executable: Some(executable.to_path_buf()),
		});
	}
	let profile = seatbelt_profile(workspace)?;
	let mut command = Command::new(sandbox_exec);
	command.arg("-p").arg(profile).arg(executable);
	append_request_arguments(&mut command, request);
	Ok(command)
}

fn child_command(executable: &Path, request: &ShellRequest) -> Command {
	let mut command = Command::new(executable);
	append_request_arguments(&mut command, request);
	command
}

fn append_request_arguments(command: &mut Command, request: &ShellRequest) {
	if let Some(shell_command) = &request.shell_command {
		command.arg("-lc").arg(shell_command);
	} else {
		command.args(&request.arguments);
	}
}

fn seatbelt_profile(workspace: &Path) -> Result<String, ShellError> {
	let workspace = workspace
		.to_str()
		.ok_or_else(|| ShellError::Invalid("workspace must be valid UTF-8".into()))?;
	if workspace.contains('"') {
		return Err(ShellError::Invalid(
			"workspace contains unsupported quote".into(),
		));
	}
	Ok(format!(
		"(version 1) \
		(deny default) \
		(import \"system.sb\") \
		(allow process*) \
		(allow process-exec) \
		(allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/System\") (subpath \"{workspace}\")) \
		(allow file-write* (subpath \"{workspace}\")) \
		(deny file-write* (subpath \"{workspace}/.git\")) \
		(deny network*)"
	))
}

async fn capture_child(
	mut child: Child,
	time_limit: Duration,
	output_limit: usize,
) -> Result<ShellOutcome, ShellError> {
	let mut stdout = child
		.stdout
		.take()
		.ok_or_else(|| ShellError::Invalid("child stdout was not captured".into()))?;
	let mut stderr = child
		.stderr
		.take()
		.ok_or_else(|| ShellError::Invalid("child stderr was not captured".into()))?;
	let deadline = Instant::now() + time_limit;
	let mut stdout_bytes = Vec::new();
	let mut stderr_bytes = Vec::new();
	let mut stdout_open = true;
	let mut stderr_open = true;
	let mut stdout_chunk = [0_u8; 8192];
	let mut stderr_chunk = [0_u8; 8192];
	let mut status = None;

	while stdout_open || stderr_open || status.is_none() {
		let remaining = deadline.saturating_duration_since(Instant::now());
		if remaining.is_zero() {
			terminate_group(&mut child).await?;
			return Err(ShellError::Invalid("shell time limit exceeded".into()));
		}
		tokio::select! {
			read = stdout.read(&mut stdout_chunk), if stdout_open => match read? {
				0 => stdout_open = false,
				n => stdout_bytes.extend_from_slice(&stdout_chunk[..n]),
			},
			read = stderr.read(&mut stderr_chunk), if stderr_open => match read? {
				0 => stderr_open = false,
				n => stderr_bytes.extend_from_slice(&stderr_chunk[..n]),
			},
			waited = child.wait(), if status.is_none() => status = Some(waited?),
			_ = tokio::time::sleep(remaining) => {
				terminate_group(&mut child).await?;
				return Err(ShellError::Invalid("shell time limit exceeded".into()));
			}
		}
		if stdout_bytes.len().saturating_add(stderr_bytes.len()) > output_limit {
			terminate_group(&mut child).await?;
			return Err(ShellError::Invalid("shell output limit exceeded".into()));
		}
	}
	let status = status.expect("loop waits for child completion");
	Ok(ShellOutcome {
		stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
		stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
		exit_code: status.code(),
	})
}

async fn terminate_group(child: &mut Child) -> Result<(), ShellError> {
	#[cfg(unix)]
	if let Some(pid) = child.id() {
		// The child is its own process-group leader, so negative PID terminates descendants too.
		let result = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
		if result != 0 {
			let error = std::io::Error::last_os_error();
			if error.kind() != std::io::ErrorKind::NotFound {
				return Err(ShellError::Execution(error));
			}
		}
	}
	let _ = timeout(Duration::from_secs(2), child.wait()).await;
	Ok(())
}
