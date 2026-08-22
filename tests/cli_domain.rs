use std::{fs, io::Cursor, path::PathBuf};

use clap::Parser;
use phemius::{
    cli::{Cli, ReplCommand, TopLevelCommand, parse_repl_command, run_with_input},
    domain::{EntityKind, prefixed_uuid},
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
