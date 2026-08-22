//! Offline evaluation contracts for deterministic harness regressions.
//!
//! Evaluation deliberately separates fixture expectations from the trial workspace.  A trial
//! receives only public task inputs and scripted model responses; expected outputs remain in the
//! fixture directory and are never copied into model-visible files.

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Final classification of a deterministic or subjective evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EvalStatus {
    /// Every required gate passed.
    Pass,
    /// A deterministic gate failed for the candidate.
    Fail,
    /// Infrastructure or judge uncertainty prevented a prose conclusion.
    Inconclusive,
}

/// Outcome reported by a trial runner before grading policy is applied.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Outcome {
    /// All deterministic gates passed.
    Pass,
    /// A deterministic candidate gate failed.
    Failure { reason: String },
    /// The provider or local evaluation infrastructure failed.
    ProviderFailure { reason: String },
    /// A blind judge could not establish a stable ordering.
    JudgeDisagreement { reason: String },
}

impl Outcome {
    /// Creates an infrastructure failure that must grade as inconclusive.
    pub fn provider_failure() -> Self {
        Self::ProviderFailure {
            reason: "provider or evaluation infrastructure failed".into(),
        }
    }

    /// Creates a deterministic candidate failure.
    pub fn failure(reason: impl Into<String>) -> Self {
        Self::Failure {
            reason: reason.into(),
        }
    }

    /// Creates a judge disagreement that must not be counted as a prose failure.
    pub fn judge_disagreement(reason: impl Into<String>) -> Self {
        Self::JudgeDisagreement {
            reason: reason.into(),
        }
    }
}

/// A fixture task loaded from `task.toml`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvalTask {
    /// Stable task identifier.
    pub id: String,
    /// Public instruction path relative to the fixture directory.
    pub instruction: PathBuf,
    /// Hidden expectation path relative to the fixture directory.
    pub expect: PathBuf,
    /// Offline scripted-response path relative to the fixture directory.
    pub scripted_responses: PathBuf,
    /// Number of deterministic trials required by the fixture policy.
    #[serde(default = "default_trials")]
    pub trials: usize,
    /// Directory containing `task.toml` and hidden expectations.
    #[serde(skip)]
    pub fixture_root: PathBuf,
}

fn default_trials() -> usize {
    1
}

impl EvalTask {
    /// Loads and validates one fixture task without exposing its expectation bytes.
    pub fn load(fixture_root: &Path) -> Result<Self> {
        let fixture_root = fixture_root.canonicalize().with_context(|| {
            format!(
                "failed to locate evaluation fixture {}",
                fixture_root.display()
            )
        })?;
        ensure!(
            fixture_root.is_dir(),
            "evaluation fixture is not a directory"
        );
        let task_path = fixture_root.join("task.toml");
        let task_text = fs::read_to_string(&task_path)
            .with_context(|| format!("failed to read {}", task_path.display()))?;
        let mut task: Self = toml::from_str(&task_text)
            .with_context(|| format!("failed to parse {}", task_path.display()))?;
        ensure!(!task.id.trim().is_empty(), "evaluation task ID is required");
        ensure!(
            task.trials > 0,
            "evaluation task must request at least one trial"
        );
        validate_relative(&task.instruction, "instruction")?;
        validate_relative(&task.expect, "expectation")?;
        validate_relative(&task.scripted_responses, "scripted responses")?;
        ensure!(
            fixture_root.join(&task.instruction).is_file(),
            "evaluation instruction is missing"
        );
        ensure!(
            fixture_root.join(&task.expect).is_file(),
            "evaluation expectation is missing"
        );
        task.fixture_root = fixture_root;
        Ok(task)
    }

    /// Returns the hidden expectation path, which remains outside any [`Trial`].
    pub fn expectation_path(&self) -> PathBuf {
        self.fixture_root.join(&self.expect)
    }
}

fn validate_relative(path: &Path, label: &str) -> Result<()> {
    ensure!(
        !path.is_absolute(),
        "evaluation {label} path must be relative"
    );
    ensure!(
        path.components()
            .all(|component| !matches!(component, std::path::Component::ParentDir)),
        "evaluation {label} path escapes its fixture"
    );
    Ok(())
}

struct TrialGuard(PathBuf);

impl Drop for TrialGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Isolated task workspace containing no hidden expectation file.
pub struct Trial {
    /// Temporary workspace visible to the deterministic runner.
    pub root: PathBuf,
    /// Stable task identifier associated with this trial.
    pub task_id: String,
    _guard: TrialGuard,
}

impl std::fmt::Debug for Trial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Trial")
            .field("root", &self.root)
            .field("task_id", &self.task_id)
            .finish_non_exhaustive()
    }
}

/// Copies only public fixture inputs into a clean temporary trial workspace.
pub fn prepare_trial(task: EvalTask) -> Result<Trial> {
    let root = std::env::temp_dir().join(format!("phemius-eval-trial-{}", Uuid::now_v7()));
    fs::create_dir(&root)
        .with_context(|| format!("failed to create evaluation trial {}", root.display()))?;
    let guard = TrialGuard(root.clone());
    let copy = |relative: &Path| -> Result<()> {
        let source = task.fixture_root.join(relative);
        let destination = root.join(relative.file_name().ok_or_else(|| {
            anyhow!(
                "evaluation fixture path has no file name: {}",
                relative.display()
            )
        })?);
        fs::copy(&source, &destination).with_context(|| {
            format!(
                "failed to copy public evaluation input {}",
                source.display()
            )
        })?;
        Ok(())
    };
    copy(&task.instruction)?;
    if task.fixture_root.join(&task.scripted_responses).is_file() {
        copy(&task.scripted_responses)?;
    }
    Ok(Trial {
        root,
        task_id: task.id,
        _guard: guard,
    })
}

/// A report emitted after applying the evaluation policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvalReport {
    /// Final status.
    pub status: EvalStatus,
    /// Number of trials attempted.
    pub trials: usize,
    /// Number of trials whose deterministic gates passed.
    pub passed_trials: usize,
    /// Redacted status messages suitable for JSON and Markdown output.
    pub messages: Vec<String>,
}

impl EvalReport {
    /// Renders the concise operator-facing report required by the CLI.
    pub fn to_markdown(&self) -> String {
        format!(
            "## Phemius evaluation\n\n- status: `{}`\n- trials: {}\n- passed: {}\n{}",
            status_name(self.status),
            self.trials,
            self.passed_trials,
            self.messages
                .iter()
                .map(|message| format!("- {message}\n"))
                .collect::<String>()
        )
    }
}

fn status_name(status: EvalStatus) -> &'static str {
    match status {
        EvalStatus::Pass => "pass",
        EvalStatus::Fail => "fail",
        EvalStatus::Inconclusive => "inconclusive",
    }
}

/// Applies the deterministic policy to one trial outcome.
#[derive(Clone, Copy, Debug, Default)]
pub struct Grader;

impl Grader {
    /// Grades infrastructure uncertainty as inconclusive, never as a prose failure.
    pub fn grade(&self, outcome: Outcome) -> EvalReport {
        let (status, message) = match outcome {
            Outcome::Pass => (EvalStatus::Pass, "deterministic gates passed".into()),
            Outcome::Failure { reason } => (EvalStatus::Fail, reason),
            Outcome::ProviderFailure { reason } => (EvalStatus::Inconclusive, reason),
            Outcome::JudgeDisagreement { reason } => (EvalStatus::Inconclusive, reason),
        };
        EvalReport {
            status,
            trials: 1,
            passed_trials: usize::from(status == EvalStatus::Pass),
            messages: vec![message],
        }
    }
}

/// Runs the offline deterministic fixture suite.
pub fn run_eval(fixture_root: &Path) -> Result<EvalReport> {
    let task = EvalTask::load(fixture_root)?;
    let expectation = fs::read_to_string(task.expectation_path())
        .context("failed to read hidden evaluation expectation")?;
    let expected: EvalExpectation =
        toml::from_str(&expectation).context("failed to parse hidden evaluation expectation")?;
    let mut statuses = Vec::with_capacity(task.trials);
    let mut messages = Vec::new();
    for _ in 0..task.trials {
        let trial = prepare_trial(task.clone())?;
        let outcome = evaluate_trial(&task, &expected, &trial);
        let graded = Grader.grade(outcome);
        statuses.push(graded.status);
        messages.extend(graded.messages);
    }
    let status = if statuses.contains(&EvalStatus::Inconclusive) {
        EvalStatus::Inconclusive
    } else if statuses.iter().all(|status| *status == EvalStatus::Pass) {
        EvalStatus::Pass
    } else {
        EvalStatus::Fail
    };
    Ok(EvalReport {
        status,
        trials: statuses.len(),
        passed_trials: statuses
            .iter()
            .filter(|status| **status == EvalStatus::Pass)
            .count(),
        messages,
    })
}

#[derive(Debug, Deserialize)]
struct EvalExpectation {
    #[serde(default)]
    required_response: Option<String>,
    #[serde(default)]
    forbidden_responses: Vec<String>,
    #[serde(default)]
    min_response_chars: Option<usize>,
    #[serde(default)]
    max_response_chars: Option<usize>,
    #[serde(default)]
    max_tool_calls: Option<usize>,
    #[serde(default)]
    required_tool_calls: Vec<String>,
}

fn evaluate_trial(task: &EvalTask, expected: &EvalExpectation, trial: &Trial) -> Outcome {
    let instruction_name = task
        .instruction
        .file_name()
        .unwrap_or_else(|| OsStr::new("instruction.md"));
    let instruction = match fs::read_to_string(trial.root.join(instruction_name)) {
        Ok(instruction) if !instruction.trim().is_empty() => instruction,
        Ok(_) => return Outcome::failure("instruction is empty"),
        Err(error) => return Outcome::provider_failure_with(error.to_string()),
    };
    let scripted_path = trial.root.join(
        task.scripted_responses
            .file_name()
            .unwrap_or_else(|| OsStr::new("scripted-responses.json")),
    );
    let scripted = match fs::read_to_string(scripted_path) {
        Ok(scripted) => scripted,
        Err(error) => return Outcome::provider_failure_with(error.to_string()),
    };
    let responses: serde_json::Value = match serde_json::from_str(&scripted) {
        Ok(value) => value,
        Err(error) => return Outcome::provider_failure_with(error.to_string()),
    };
    let response_values = responses
        .get("responses")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Outcome::failure("scripted response list is missing"));
    let response_values = match response_values {
        Ok(values) if !values.is_empty() => values,
        Ok(_) => return Outcome::failure("scripted response list is empty"),
        Err(outcome) => return outcome,
    };
    let mut tool_names = Vec::new();
    for response in response_values {
        let Some(response) = response.as_object() else {
            return Outcome::failure("scripted response entry is not an object");
        };
        if let Some(calls) = response.get("tool_calls") {
            let Some(calls) = calls.as_array() else {
                return Outcome::failure("scripted tool_calls is not an array");
            };
            for call in calls {
                let name = call
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| {
                        call.get("function")
                            .and_then(|function| function.get("name"))
                            .and_then(serde_json::Value::as_str)
                    });
                let Some(name) = name else {
                    return Outcome::failure("scripted tool call has no name");
                };
                tool_names.push(name.to_owned());
            }
        }
    }
    let first_response = response_values
        .first()
        .and_then(serde_json::Value::as_object)
        .and_then(|response| response.get("text"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if first_response.trim().is_empty() {
        return Outcome::failure("scripted response is empty");
    }
    if let Some(required) = &expected.required_response
        && !first_response.contains(required)
    {
        return Outcome::failure(format!(
            "required deterministic response is missing: {required}"
        ));
    }
    if let Some(minimum) = expected.min_response_chars
        && first_response.chars().count() < minimum
    {
        return Outcome::failure(format!(
            "response is shorter than the deterministic minimum: {minimum}"
        ));
    }
    if let Some(maximum) = expected.max_response_chars
        && first_response.chars().count() > maximum
    {
        return Outcome::failure(format!(
            "response exceeds the deterministic maximum: {maximum}"
        ));
    }
    if let Some(maximum) = expected.max_tool_calls
        && tool_names.len() > maximum
    {
        return Outcome::failure(format!(
            "scripted tool calls exceed the deterministic maximum: {maximum}"
        ));
    }
    for forbidden in &expected.forbidden_responses {
        if first_response.contains(forbidden) {
            return Outcome::failure(format!(
                "forbidden deterministic response is present: {forbidden}"
            ));
        }
    }
    for required_tool in &expected.required_tool_calls {
        if !tool_names.iter().any(|name| name == required_tool) {
            return Outcome::failure(format!(
                "required deterministic tool call is missing: {required_tool}"
            ));
        }
    }
    if instruction.contains("provider_failure") {
        return Outcome::provider_failure();
    }
    Outcome::Pass
}

impl Outcome {
    fn provider_failure_with(reason: impl Into<String>) -> Self {
        Self::ProviderFailure {
            reason: reason.into(),
        }
    }
}

/// Calibration result for the subjective judge gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JudgeCalibration {
    /// Number of human blind labels.
    pub labels: usize,
    /// Human agreement ratio.
    pub agreement_percent: u8,
    /// A/B swap consistency ratio.
    pub swap_consistency_percent: u8,
    /// Whether subjective results may gate release quality.
    pub gate_enabled: bool,
}

/// Applies the exact 20-label, 0.80-agreement, 0.90-swap calibration gate.
pub fn calibrate_judge(labels: usize, agreement: f64, swap_consistency: f64) -> JudgeCalibration {
    let agreement_percent = ratio_percent(agreement);
    let swap_consistency_percent = ratio_percent(swap_consistency);
    JudgeCalibration {
        labels,
        agreement_percent,
        swap_consistency_percent,
        gate_enabled: labels >= 20
            && agreement.is_finite()
            && swap_consistency.is_finite()
            && agreement >= 0.80
            && swap_consistency >= 0.90,
    }
}

fn ratio_percent(value: f64) -> u8 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    (value * 100.0).round().clamp(0.0, 100.0) as u8
}
