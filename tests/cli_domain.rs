use std::{
    fs,
    io::{Cursor, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process::{Command, Stdio},
};

use clap::Parser;
use phemius::{
    changeset::approval_record_path,
    cli::{
        Cli, ReplCommand, TopLevelCommand, parse_repl_command, run_with_input,
        run_with_input_with_backend,
    },
    domain::{EntityId, EntityKind, prefixed_uuid},
    model::{ModelBackend, ModelResponse, ScriptedModel},
    plot::{MacroBeat, StoryBox, StoryChapter, StoryPart, StoryScene, StoryStructure},
    project::{InitAnswers, Project, initialize_project},
    repl::{Repl, ReplOutcome},
    workflow::{LengthUnit, RunController},
};

#[test]
fn parses_eval_subcommand() {
    let cli = Cli::try_parse_from(["phemius", "eval", "fixtures/smoke"]).unwrap();

    assert!(matches!(cli.command, Some(TopLevelCommand::Eval { .. })));
}

#[test]
fn creates_semantically_prefixed_uuid_v7() {
    let id = prefixed_uuid(EntityKind::Chapter);

    assert!(id.as_str().starts_with("chapter_"));
    let uuid = uuid::Uuid::parse_str(id.as_str().trim_start_matches("chapter_")).unwrap();
    assert_eq!(uuid.get_version_num(), 7);
}

#[test]
fn approve_requires_an_explicit_changeset_id() {
    assert!(parse_repl_command("/approve").is_err());
    assert_eq!(
        parse_repl_command("/approve change_123").unwrap(),
        ReplCommand::Approve {
            id: "change_123".into()
        }
    );
}

#[test]
fn trusted_commands_reject_missing_required_arguments() {
    for command in [
        "/reject",
        "/resolve",
        "/resolve finding_123",
        "/resolve finding_123 false-positive",
    ] {
        assert!(parse_repl_command(command).is_err(), "{command}");
    }
}

#[test]
fn parses_each_trusted_repl_command() {
    for command in [
        "/help",
        "/status",
        "/mode consult",
        "/plan",
        "/write",
        "/review",
        "/revise",
        "/diff",
        "/reject change_123",
        "/resolve finding_123 false-positive intentional contradiction",
        "/model writer deepseek/example",
        "/cost",
        "/compact",
        "/resume",
        "/skills",
        "/clean",
        "/quit",
    ] {
        assert!(parse_repl_command(command).is_ok(), "{command}");
    }
}

#[test]
fn natural_language_cannot_be_an_approval_or_cleanup() {
    for text in [
        "approve change_123",
        "clean generated files",
        "save this model",
    ] {
        assert_eq!(
            parse_repl_command(text).unwrap(),
            ReplCommand::NaturalLanguage(text.into())
        );
    }
}

#[test]
fn dollar_prefixed_skill_selection_is_explicit() {
    assert_eq!(
        parse_repl_command("$writer").unwrap(),
        ReplCommand::Skill {
            name: "writer".into()
        }
    );
}

#[tokio::test]
async fn init_reads_a_nonempty_title_and_creates_the_project() {
    let root = std::env::temp_dir().join(format!("phemius-cli-init-{}", uuid::Uuid::now_v7()));
    let cli = Cli {
        command: Some(TopLevelCommand::Init { path: root.clone() }),
        project: PathBuf::from("."),
    };

    run_with_input(cli, &mut Cursor::new("作品名\n"))
        .await
        .unwrap();

    assert!(root.join("project.toml").is_file());
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn init_rejects_an_empty_title_without_creating_a_project() {
    let root = std::env::temp_dir().join(format!("phemius-cli-empty-{}", uuid::Uuid::now_v7()));
    let cli = Cli {
        command: Some(TopLevelCommand::Init { path: root.clone() }),
        project: PathBuf::from("."),
    };

    assert!(run_with_input(cli, &mut Cursor::new(" \n")).await.is_err());
    assert!(!root.exists());
}

#[test]
fn binary_initializes_the_current_directory_without_replacing_it() {
    let root = TestDir::new("current-directory");
    let inode = fs::metadata(root.path()).unwrap().ino();
    let mut child = Command::new(env!("CARGO_BIN_EXE_phemius"))
        .args(["init", "."])
        .current_dir(root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all("作品名\n".as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.path().join("project.toml").is_file());
    assert!(root.path().join("前提/作品.md").is_file());
    assert_eq!(fs::metadata(root.path()).unwrap().ino(), inode);
}

#[test]
fn project_open_canonicalizes_root_and_validates_work_id() {
    let root = TestDir::new("project-open");
    initialize_project(root.path(), &InitAnswers::minimal("作品")).unwrap();

    let opened = Project::open(root.path()).unwrap();
    assert_eq!(opened.root, fs::canonicalize(root.path()).unwrap());
    assert_eq!(opened.config.format_version, 1);
    assert!(opened.config.work_id.as_str().starts_with("work_"));

    fs::write(
        root.path().join("project.toml"),
        "format_version = 1\nwork_id = \"chapter_not-a-work\"\n",
    )
    .unwrap();
    assert!(Project::open(root.path()).is_err());
}

#[tokio::test]
async fn normal_project_repl_is_attached_to_a_controller() {
    let root = TestDir::new("project-repl");
    initialize_project(root.path(), &InitAnswers::minimal("作品")).unwrap();
    let cli = Cli {
        command: None,
        project: root.path().to_path_buf(),
    };

    let repl = run_with_input_with_backend(
        cli,
        &mut Cursor::new(Vec::<u8>::new()),
        ModelBackend::Scripted(phemius::model::ScriptedModel::new([])),
    )
    .await
    .unwrap();
    assert!(repl.has_controller());
}

#[tokio::test]
async fn trusted_cli_write_then_approve_applies_the_project_changeset() {
    let root = TestDir::new("cli-write-approve");
    let project = initialize_project(root.path(), &InitAnswers::minimal("作品")).unwrap();
    let part_id = prefixed_uuid(EntityKind::Part);
    let chapter_id = prefixed_uuid(EntityKind::Chapter);
    let scene_id = prefixed_uuid(EntityKind::Scene);
    let box_id = prefixed_uuid(EntityKind::Box);
    let structure = StoryStructure {
        parts: vec![StoryPart::new(part_id.as_str(), 1)],
        chapters: vec![StoryChapter::new(chapter_id.as_str(), part_id.as_str(), 1)],
        scenes: vec![StoryScene::new(scene_id.as_str(), chapter_id.as_str(), 1)],
        boxes: vec![StoryBox::new(box_id.as_str(), scene_id.as_str(), 1)],
        macro_beats: vec![MacroBeat::new("beat_1", 1, [scene_id.as_str()])],
    };
    let backend = ScriptedModel::new([
        Ok(ModelResponse {
            text: "plan".into(),
            tool_calls: Vec::new(),
            usage: None,
        }),
        Ok(ModelResponse {
            text: "本文".into(),
            tool_calls: Vec::new(),
            usage: None,
        }),
        Ok(ModelResponse {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: None,
        }),
        Ok(ModelResponse {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: None,
        }),
        Ok(ModelResponse {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: None,
        }),
        Ok(ModelResponse {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: None,
        }),
        Ok(ModelResponse {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: None,
        }),
        Ok(ModelResponse {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: None,
        }),
    ]);
    let mut controller = RunController::with_project(project.clone(), backend.into());
    controller.set_request_maximum_cost(Some(phemius::cost::MicroDollars::new(200_000)));
    controller.set_preflight(true, true, true);
    controller.set_structure(structure).unwrap();
    controller.set_plot_framework("hakogaki").unwrap();
    controller
        .set_length_bounds(LengthUnit::Graphemes, 0, usize::MAX)
        .unwrap();
    let mut repl = Repl::with_controller(controller);

    let write = repl
        .handle_async(&format!("/write {}", chapter_id.as_str()))
        .await
        .unwrap();
    let ReplOutcome::Message(write_message) = write else {
        panic!("/write did not return a candidate message: {write:?}");
    };
    let changeset_id = write_message
        .split_whitespace()
        .skip_while(|word| *word != "/approve")
        .nth(1)
        .expect("write message has changeset ID");
    assert!(write_message.contains("candidate"));

    let approved = repl.handle(&format!("/approve {changeset_id}")).unwrap();
    assert_eq!(
        approved,
        ReplOutcome::Message(format!("approved {changeset_id}"))
    );
    assert!(
        root.path()
            .join(format!("本文/{}.md", chapter_id.as_str()))
            .is_file()
    );
    let changeset_entity = EntityId::from_validated(changeset_id.to_owned()).unwrap();
    assert!(approval_record_path(root.path(), &changeset_entity).is_file());
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("phemius-{label}-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
