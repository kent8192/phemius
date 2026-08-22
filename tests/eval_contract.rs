use std::path::Path;

use phemius::eval::{
    EvalReport, EvalStatus, EvalTask, Grader, Outcome, calibrate_judge, prepare_trial, run_eval,
};

fn grade_fixture(outcome: Outcome) -> EvalReport {
    Grader::default().grade(outcome)
}

#[test]
fn infrastructure_failure_is_inconclusive_not_prose_failure() {
    let report = grade_fixture(Outcome::provider_failure());
    assert_eq!(report.status, EvalStatus::Inconclusive);
}

#[test]
fn judge_requires_human_agreement_and_swap_consistency() {
    assert!(!calibrate_judge(19, 1.0, 1.0).gate_enabled);
    assert!(!calibrate_judge(20, 0.79, 1.0).gate_enabled);
    assert!(!calibrate_judge(20, 0.80, 0.89).gate_enabled);
    assert!(calibrate_judge(20, 0.80, 0.90).gate_enabled);
}

#[test]
fn hidden_expectations_are_not_copied_into_trial_workspace() {
    let task = EvalTask::load(Path::new("fixtures/eval/smoke")).unwrap();
    let trial = prepare_trial(task).unwrap();
    assert!(!trial.root.join("expect.toml").exists());
    assert!(trial.root.join("instruction.md").is_file());
}

#[test]
fn smoke_fixture_runs_offline_and_passes_deterministic_gates() {
    let report = run_eval(Path::new("fixtures/eval/smoke")).unwrap();
    assert_eq!(report.status, EvalStatus::Pass);
    assert_eq!(report.trials, 1);
}
