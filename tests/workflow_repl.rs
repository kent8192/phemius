use phemius::{
    model::{ModelFailure, ModelResponse, ScriptedModel},
    repl::{Repl, ReplOutcome, RoutedInput, route_input},
    workflow::{AgentRole, ChapterState, FindingDisposition, FindingKind, RunController},
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
    let mut run = RunController::fixture(ScriptedModel::new([]));
    let first = run.write_chapter("chapter_1").await.unwrap();
    let second = run.write_chapter("chapter_2").await.unwrap();
    assert!(run.approve_chapter("chapter_1").is_err());
    assert!(
        run.approve_chapter_trusted_for_test(second.changeset.id.as_str())
            .is_err()
    );
    run.approve_chapter_trusted_for_test(first.changeset.id.as_str())
        .unwrap();
    run.approve_chapter_trusted_for_test(second.changeset.id.as_str())
        .unwrap();
    assert_eq!(run.chapter("chapter_2").state, ChapterState::Approved);
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
