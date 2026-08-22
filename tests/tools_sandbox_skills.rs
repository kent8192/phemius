use std::{
    fs,
    path::{Path, PathBuf},
};

use phemius::{
    sandbox::{ApprovalMode, ChoiceReason, SandboxMode, ShellError, ShellRequest, run_shell},
    skills::{SkillCatalog, load_hierarchical_instructions},
    tools::{AgentRole, Tool, ToolExecutor, ToolRequest},
};
use rstest::rstest;

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
fn startup_skill_discovery_reads_metadata_but_not_body_or_references() {
    let fixture = SkillFixture::new();
    let catalog = SkillCatalog::discover(fixture.roots()).unwrap();
    assert_eq!(catalog.get("voice").unwrap().description, "Voice rules");
    assert!(catalog.load("voice").is_err());
}

#[tokio::test]
async fn child_environment_never_contains_openrouter_key() {
    let outcome = run_shell(
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
    let error = run_shell(ShellRequest::program("/usr/bin/env"))
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
    let mut tools = ToolExecutor::new(root.path()).unwrap();
    for path in [
        PathBuf::from(".git/config"),
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
