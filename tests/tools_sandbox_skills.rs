use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    time::Duration,
};

use phemius::{
    model::ToolCall,
    sandbox::{ApprovalMode, ChoiceReason, SandboxMode, ShellError, ShellRequest, run_shell},
    skills::{SkillCatalog, load_hierarchical_instructions},
    tools::{AgentRole, Tool, ToolAccessError, ToolExecutor, ToolRequest},
};
use rstest::rstest;
use serde_json::json;

#[rstest]
fn critic_tool_set_never_contains_shell() {
    assert!(!Tool::for_role(AgentRole::ConsistencyCritic).contains(&Tool::Shell));
}

#[rstest]
fn tool_catalog_order_is_stable() {
    assert_eq!(
        Tool::all().iter().map(Tool::name).collect::<Vec<_>>(),
        vec![
            "read_file",
            "search_files",
            "edit_candidate",
            "diff",
            "import",
            "git",
            "shell",
            "web",
            "subagent",
        ]
    );
}

#[rstest]
fn model_tool_definitions_match_the_executable_read_boundary() {
    let definitions = Tool::model_definitions(AgentRole::Author);
    let names = definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        ["read_file", "search_files", "diff", "import", "git"]
    );
    let critic_definitions = Tool::model_definitions(AgentRole::ConsistencyCritic);
    assert!(
        critic_definitions
            .iter()
            .all(|definition| definition.name != "edit_candidate")
    );
}

#[rstest]
fn model_tool_calls_parse_only_fixed_requests() {
    let request = ToolRequest::from_call(&ToolCall {
        id: Some("call-1".into()),
        name: "git".into(),
        arguments: json!({"query": "status"}),
    })
    .unwrap();
    assert_eq!(
        request,
        ToolRequest::Git {
            query: phemius::tools::GitQuery::Status
        }
    );
    assert!(
        ToolRequest::from_call(&ToolCall {
            id: None,
            name: "edit_candidate".into(),
            arguments: json!({"path": "draft.md", "contents": "x"}),
        })
        .is_err()
    );
    assert!(
        ToolRequest::from_call(&ToolCall {
            id: None,
            name: "read_file".into(),
            arguments: json!({"path": "a.md", "extra": true}),
        })
        .is_err()
    );
}

#[rstest]
fn startup_skill_discovery_reads_metadata_but_not_body_or_references() {
    let fixture = SkillFixture::new();
    let catalog = SkillCatalog::discover(fixture.roots()).unwrap();
    assert_eq!(catalog.get("voice").unwrap().description, "Voice rules");
    assert_eq!(catalog.body_load_count(), 0);
    assert!(catalog.load("voice").is_err());
    assert_eq!(catalog.body_load_count(), 1);
}

#[tokio::test]
async fn child_environment_never_contains_openrouter_key() {
    let outcome = run_shell(
        AgentRole::Author,
        ShellRequest::program("/usr/bin/env")
            .with_approval(ApprovalMode::Never)
            .with_sandbox(SandboxMode::None)
            .trusted_unrestricted(),
    )
    .await
    .unwrap();
    assert!(!outcome.stdout.contains("OPENROUTER_API_KEY"));
}

#[tokio::test]
async fn seatbelt_request_runs_with_the_same_cleared_environment() {
    let outcome = run_shell(
        AgentRole::Author,
        ShellRequest::program("/usr/bin/env")
            .with_approval(ApprovalMode::Never)
            .with_sandbox(SandboxMode::Seatbelt),
    )
    .await
    .unwrap();
    assert_eq!(outcome.exit_code, Some(0));
    assert!(!outcome.stdout.contains("OPENROUTER_API_KEY"));
}

#[tokio::test]
async fn default_shell_request_returns_a_typed_approval_choice() {
    let error = run_shell(AgentRole::Author, ShellRequest::program("/usr/bin/env"))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ShellError::ChoiceRequired {
            reason: ChoiceReason::Approval,
            ..
        }
    ));
}

#[rstest]
fn capability_file_tools_reject_workspace_escapes() {
    let root = TestDirectory::new("tool-root");
    let mut tools = ToolExecutor::new(root.path(), AgentRole::Author).unwrap();
    for path in [
        PathBuf::from(".git/config"),
        PathBuf::from(".phemius/local.toml"),
        PathBuf::from("../outside"),
        PathBuf::from("/tmp/outside"),
    ] {
        assert!(
            tools
                .execute(ToolRequest::EditCandidate {
                    path,
                    contents: b"x".to_vec()
                })
                .is_err()
        );
    }
}

#[rstest]
fn oversized_file_tool_input_stops_before_artifact_retention() {
    let root = TestDirectory::new("oversized-tool-input");
    let path = root.path().join("oversized.bin");
    fs::File::create(&path)
        .unwrap()
        .set_len(100 * 1024 * 1024 + 1)
        .unwrap();
    let mut tools = ToolExecutor::new(root.path(), AgentRole::Author).unwrap();
    let error = tools
        .execute(ToolRequest::ReadFile {
            path: PathBuf::from("oversized.bin"),
        })
        .unwrap_err();
    assert!(error.to_string().contains("tool input exceeds 100 MiB"));
}

#[rstest]
fn oversized_single_search_line_stops_before_record_duplication() {
    let root = TestDirectory::new("oversized-search-line");
    let path = root.path().join("line.txt");
    fs::File::create(&path)
        .unwrap()
        .set_len(100 * 1024 * 1024)
        .unwrap();
    let mut tools = ToolExecutor::new(root.path(), AgentRole::Author).unwrap();
    let error = tools
        .execute(ToolRequest::SearchFiles {
            query: "\0".to_owned(),
        })
        .unwrap_err();
    assert!(error.to_string().contains("search result exceeds 100 MiB"));
}

#[rstest]
fn critic_directly_cannot_mutate_candidates() {
    let root = TestDirectory::new("critic-tools");
    let mut tools = ToolExecutor::new(root.path(), AgentRole::ConsistencyCritic).unwrap();
    let error = tools
        .execute(ToolRequest::EditCandidate {
            path: PathBuf::from("draft.md"),
            contents: b"forbidden".to_vec(),
        })
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<ToolAccessError>().unwrap().tool(),
        Tool::EditCandidate
    );
    assert!(!root.path().join("draft.md").exists());
}

#[tokio::test]
async fn critic_directly_cannot_launch_a_shell() {
    let error = run_shell(
        AgentRole::ConsistencyCritic,
        ShellRequest::program("/usr/bin/env")
            .with_approval(ApprovalMode::Never)
            .with_sandbox(SandboxMode::None)
            .trusted_unrestricted(),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, ShellError::ToolDenied { .. }));
}

#[tokio::test]
async fn allowlist_cannot_request_an_unrestricted_shell() {
    let error = run_shell(
        AgentRole::Author,
        ShellRequest::program("/usr/bin/env")
            .with_approval(ApprovalMode::Allowlist)
            .allow_executable("/usr/bin/env")
            .with_sandbox(SandboxMode::None)
            .trusted_unrestricted(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        ShellError::ChoiceRequired {
            reason: ChoiceReason::UntrustedUnrestricted,
            ..
        }
    ));
}

#[rstest]
fn pinned_capability_rejects_a_parent_symlink_swap() {
    let root = TestDirectory::new("pinned-capability");
    let outside = TestDirectory::new("outside");
    fs::create_dir(root.path().join("safe")).unwrap();
    fs::write(root.path().join("safe/input.txt"), "inside").unwrap();
    fs::write(outside.path().join("input.txt"), "outside").unwrap();
    let mut tools = ToolExecutor::new(root.path(), AgentRole::Author).unwrap();
    fs::remove_dir_all(root.path().join("safe")).unwrap();
    symlink(outside.path(), root.path().join("safe")).unwrap();
    assert!(
        tools
            .execute(ToolRequest::ReadFile {
                path: PathBuf::from("safe/input.txt"),
            })
            .is_err()
    );
}

#[tokio::test]
async fn cancelling_shell_execution_terminates_its_process_group() {
    let root = TestDirectory::new("cancel-shell");
    let pid_path = root.path().join("child.pid");
    let command = format!("echo $$ > {}; sleep 30", pid_path.display());
    let handle = tokio::spawn(run_shell(
        AgentRole::Author,
        ShellRequest::shell(command)
            .in_workspace(root.path())
            .with_approval(ApprovalMode::Never)
            .with_sandbox(SandboxMode::None)
            .trusted_unrestricted()
            .with_time_limit(Duration::from_secs(60)),
    ));
    for _ in 0..50 {
        if pid_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let pid: i32 = fs::read_to_string(&pid_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    handle.abort();
    let _ = handle.await;
    for _ in 0..50 {
        let alive = unsafe { libc::kill(pid, 0) == 0 };
        if !alive {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("cancelled child process group remained alive");
}

#[rstest]
fn agents_instruction_beats_claude_at_the_same_directory_level() {
    let root = TestDirectory::new("instructions");
    fs::write(root.path().join("CLAUDE.md"), "claude fallback").unwrap();
    fs::write(root.path().join("AGENTS.md"), "agents instruction").unwrap();
    let instructions = load_hierarchical_instructions(root.path(), root.path()).unwrap();
    assert_eq!(instructions.len(), 1);
    assert_eq!(instructions[0].body, "agents instruction");
}

struct SkillFixture {
    root: TestDirectory,
}

impl SkillFixture {
    fn new() -> Self {
        let root = TestDirectory::new("skills");
        fs::create_dir_all(root.path().join("voice")).unwrap();
        fs::write(
            root.path().join("voice/SKILL.md"),
            b"---\nname: voice\ndescription: Voice rules\n---\n\xff",
        )
        .unwrap();
        Self { root }
    }

    fn roots(&self) -> Vec<PathBuf> {
        vec![self.root.path().to_path_buf()]
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("phemius-{label}-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
