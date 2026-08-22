use std::{fs, path::PathBuf};

use phemius::{
    changeset::{approval_record_path, validate_changeset},
    domain::{EntityKind, prefixed_uuid},
    model::{ModelFailure, ModelResponse, ScriptedModel},
    project::{InitAnswers, initialize_project},
    repl::{Repl, ReplOutcome, RoutedInput, route_input},
    workflow::{AgentRole, ChapterState, Finding, FindingDisposition, FindingKind, RunController},
};

#[tokio::test]
async fn chapter_pipeline_runs_writer_then_three_critics_at_most_then_reviser() {
    let backend = ScriptedModel::new([Ok(ModelResponse {
        text: "chapter draft".into(),
        tool_calls: Vec::new(),
    })]);
    let result = RunController::fixture(backend)
        .write_chapter("chapter_1")
        .await
        .unwrap();
    assert_eq!(result.trace.writer_calls, 1);
    assert_eq!(result.trace.architect_calls, 1);
    assert!(result.trace.max_parallel_critics <= 3);
    assert!(result.changeset.state.is_approvable());
    assert_eq!(result.trace.roles.first(), Some(&AgentRole::StoryArchitect));
}

#[test]
fn natural_language_cannot_trigger_trusted_actions() {
    for input in ["approve change_1", "clean everything", "be unrestricted"] {
        assert!(matches!(
            route_input(input).unwrap(),
            RoutedInput::AgentText(_)
        ));
    }
}

#[test]
fn upstream_edit_stales_candidates_and_revalidates_approved_descendants() {
    let mut run = RunController::continuous_fixture();
    run.note_upstream_edit("chapter_1").unwrap();
    assert_eq!(run.chapter("chapter_2").state, ChapterState::Stale);
    assert_eq!(
        run.chapter("chapter_3").state,
        ChapterState::NeedsRevalidation
    );
}

#[tokio::test]
async fn false_positive_resolution_is_trusted_and_candidate_edits_invalidate_findings() {
    let mut run = RunController::fixture(ScriptedModel::new([]));
    run.write_chapter("chapter_1").await.unwrap();
    let finding = run.add_finding(
        "chapter_1",
        FindingKind::Canon,
        "本文/chapter_1.md",
        0,
        4,
        "conflict",
    );
    assert_eq!(finding.disposition, FindingDisposition::Open);
    run.resolve_false_positive(&finding.id, "intentional reveal")
        .unwrap();
    assert!(matches!(
        run.finding(&finding.id).unwrap().disposition,
        FindingDisposition::FalsePositive { .. }
    ));
    assert_eq!(
        run.chapter_run("chapter_1").unwrap().state,
        ChapterState::Approvable
    );
    run.edit_candidate("chapter_1", "new candidate").unwrap();
    assert_eq!(
        run.finding(&finding.id).unwrap().disposition,
        FindingDisposition::Open
    );
}

#[tokio::test]
async fn preflight_requires_approved_scene_and_box_plans() {
    let mut run = RunController::fixture(ScriptedModel::new([]));
    run.set_preflight(false, true, true);
    assert!(run.write_chapter("chapter_1").await.is_err());
}

#[tokio::test]
async fn corrections_are_present_in_later_context_receipts() {
    let mut run = RunController::fixture(ScriptedModel::new([]));
    let rule = run
        .accept_human_correction("chapter_1", "old", "new", "scene", Some("scene_1"))
        .unwrap();
    let receipt = run.correction_receipt("chapter_2");
    assert_eq!(
        receipt.iter().map(|item| &item.rule_id).collect::<Vec<_>>(),
        vec![&rule.id]
    );
}

#[tokio::test]
async fn approval_is_human_only_and_follows_changeset_order() {
    let directory = TestDir::new("workflow-order");
    let project = initialize_project(directory.path(), &InitAnswers::minimal("作品")).unwrap();
    let mut run = RunController::fixture_with_project(project, ScriptedModel::new([]));
    let first = run.write_chapter("chapter_1").await.unwrap();
    let second = run.write_chapter("chapter_2").await.unwrap();
    assert!(run.approve_chapter("chapter_1").is_err());
    assert!(
        run.approve_chapter_trusted_for_test(second.changeset.id.as_str())
            .is_err()
    );
    run.approve_chapter_trusted_for_test(first.changeset.id.as_str())
        .unwrap();
    assert_eq!(run.chapter("chapter_1").state, ChapterState::Approved);
}

#[tokio::test]
async fn revision_cycles_are_bounded_and_ambiguous_requests_are_not_retried() {
    let blocker = "FINDING|canon|本文/chapter_1.md|0|4|conflict";
    let backend = ScriptedModel::new([
        Ok(ModelResponse {
            text: "draft".into(),
            tool_calls: Vec::new(),
        }),
        Ok(ModelResponse {
            text: blocker.into(),
            tool_calls: Vec::new(),
        }),
        Ok(ModelResponse {
            text: blocker.into(),
            tool_calls: Vec::new(),
        }),
        Ok(ModelResponse {
            text: blocker.into(),
            tool_calls: Vec::new(),
        }),
        Ok(ModelResponse {
            text: "revision".into(),
            tool_calls: Vec::new(),
        }),
        Ok(ModelResponse {
            text: "revision".into(),
            tool_calls: Vec::new(),
        }),
    ]);
    let result = RunController::fixture(backend)
        .write_chapter("chapter_1")
        .await
        .unwrap();
    assert_eq!(result.trace.reviser_calls, 2);
    assert_eq!(result.state, ChapterState::Candidate);

    let backend = ScriptedModel::new([Err(ModelFailure::ambiguous(
        "request may have reached provider",
    ))]);
    let error = RunController::fixture(backend)
        .write_chapter("chapter_1")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("ambiguous"));
}

#[test]
fn repl_keeps_work_mode_and_requires_slash_for_authority() {
    let mut repl = Repl::new();
    assert_eq!(repl.mode(), phemius::cli::ReplMode::Work);
    assert!(matches!(
        repl.handle("approve change_1").unwrap(),
        ReplOutcome::AgentText(_)
    ));
    assert!(matches!(
        repl.handle("/cost").unwrap(),
        ReplOutcome::Message(_)
    ));
}

#[tokio::test]
async fn consult_mode_is_read_only_for_trusted_and_coordinator_commands() {
    let mut repl = Repl::new();
    assert!(matches!(
        repl.handle("/mode consult").unwrap(),
        ReplOutcome::Message(_)
    ));
    for command in [
        "/approve change_1",
        "/reject change_1",
        "/resolve finding_1 false-positive reason",
        "/model deepseek/test",
        "/clean",
    ] {
        assert!(matches!(
            repl.handle(command).unwrap(),
            ReplOutcome::Error(_)
        ));
    }
    for command in [
        "/plan", "/review", "/revise", "/diff", "/skills", "/compact",
    ] {
        assert!(matches!(
            repl.handle(command).unwrap(),
            ReplOutcome::ReadOnly(_)
        ));
    }
    assert!(matches!(
        repl.handle_async("/write chapter_1").await.unwrap(),
        ReplOutcome::Error(_)
    ));
}

#[test]
fn finding_ids_are_deterministic_and_candidate_bound() {
    let first = Finding::new(FindingKind::Canon, "本文/chapter.md", 0, 4, "conflict", "a");
    let same = Finding::new(FindingKind::Canon, "本文/chapter.md", 0, 4, "conflict", "a");
    let changed = Finding::new(FindingKind::Canon, "本文/chapter.md", 0, 4, "conflict", "b");
    assert_eq!(first.id, same.id);
    assert_ne!(first.id, changed.id);
    assert!(first.id.starts_with("finding_"));
}

#[tokio::test]
async fn stale_chapters_are_not_regenerated_implicitly() {
    let mut run = RunController::continuous_fixture();
    run.note_upstream_edit("chapter_1").unwrap();
    assert!(run.write_chapter("chapter_2").await.is_err());
}

#[tokio::test]
async fn production_project_requires_story_structure_before_generation() {
    let directory = TestDir::new("workflow-structure");
    let project = initialize_project(directory.path(), &InitAnswers::minimal("作品")).unwrap();
    let mut controller = RunController::with_project(project, ScriptedModel::new([]).into());
    controller.set_preflight(true, true, true);
    assert!(controller.write_chapter("chapter_1").await.is_err());
}

#[tokio::test]
async fn project_approval_validates_applies_and_leaves_durable_proof() {
    let directory = TestDir::new("workflow-approval");
    let project = initialize_project(directory.path(), &InitAnswers::minimal("作品")).unwrap();
    let chapter_id = prefixed_uuid(EntityKind::Chapter);
    let backend = ScriptedModel::new([Ok(ModelResponse {
        text: "本文".into(),
        tool_calls: Vec::new(),
    })]);
    let mut controller = RunController::fixture_with_project(project.clone(), backend);
    let run = controller.write_chapter(chapter_id.as_str()).await.unwrap();
    validate_changeset(&project, &run.changeset).unwrap();
    let changeset_id = run.changeset.id.clone();

    controller
        .approve_chapter_trusted_for_test(changeset_id.as_str())
        .unwrap();

    assert_eq!(
        controller.chapter(chapter_id.as_str()).state,
        ChapterState::Approved
    );
    assert!(
        directory
            .path()
            .join(format!("本文/{}.md", chapter_id.as_str()))
            .is_file()
    );
    assert!(approval_record_path(directory.path(), &changeset_id).is_file());
    assert_eq!(
        controller
            .chapter_run(chapter_id.as_str())
            .unwrap()
            .changeset
            .state,
        phemius::changeset::ChangesetState::Approved
    );

    let second = controller.write_chapter("chapter_2").await.unwrap();
    validate_changeset(&project, &second.changeset).unwrap();
    controller
        .approve_chapter_trusted_for_test(second.changeset.id.as_str())
        .unwrap();
    assert_eq!(
        controller.chapter("chapter_2").state,
        ChapterState::Approved
    );
}

#[tokio::test]
async fn project_approval_fails_closed_when_candidate_bytes_are_missing() {
    let directory = TestDir::new("workflow-approval-failure");
    let project = initialize_project(directory.path(), &InitAnswers::minimal("作品")).unwrap();
    let chapter_id = prefixed_uuid(EntityKind::Chapter);
    let backend = ScriptedModel::new([Ok(ModelResponse {
        text: "本文".into(),
        tool_calls: Vec::new(),
    })]);
    let mut controller = RunController::fixture_with_project(project, backend);
    let run = controller.write_chapter(chapter_id.as_str()).await.unwrap();
    let candidate = run
        .changeset
        .operations
        .first()
        .and_then(|operation| operation.candidate_path.as_ref())
        .unwrap();
    fs::remove_file(directory.path().join(candidate)).unwrap();

    assert!(
        controller
            .approve_chapter_trusted_for_test(run.changeset.id.as_str())
            .is_err()
    );
    assert_ne!(
        controller
            .chapter_run(chapter_id.as_str())
            .unwrap()
            .changeset
            .state,
        phemius::changeset::ChangesetState::Approved
    );
    assert!(
        !directory
            .path()
            .join(format!("本文/{}.md", chapter_id.as_str()))
            .exists()
    );
}

#[tokio::test]
async fn project_blocker_requires_trusted_false_positive_before_apply() {
    let directory = TestDir::new("workflow-blocker");
    let project = initialize_project(directory.path(), &InitAnswers::minimal("作品")).unwrap();
    let chapter_id = prefixed_uuid(EntityKind::Chapter);
    let mut controller = RunController::fixture_with_project(project, ScriptedModel::new([]));
    let run = controller.write_chapter(chapter_id.as_str()).await.unwrap();
    let finding = controller.add_finding(
        chapter_id.as_str(),
        FindingKind::Canon,
        format!("本文/{}.md", chapter_id.as_str()),
        0,
        0,
        "intentional reveal",
    );
    assert!(
        controller
            .approve_chapter_trusted_for_test(run.changeset.id.as_str())
            .is_err()
    );
    controller
        .resolve_false_positive(&finding.id, "approved story exception")
        .unwrap();
    controller
        .approve_chapter_trusted_for_test(run.changeset.id.as_str())
        .unwrap();
    assert_eq!(
        controller.chapter(chapter_id.as_str()).state,
        ChapterState::Approved
    );
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
