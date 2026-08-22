//! Deterministic chapter orchestration and human approval state.
//!
//! Models in this module can propose candidate bytes and typed findings, but they never
//! mutate the canonical project.  The only path to an approved chapter is the trusted REPL
//! branch in [`crate::repl`].

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_segmentation::UnicodeSegmentation;
use uuid::Uuid;

use crate::{
    changeset::{
        ApprovalRecord, Changeset, ChangesetDependency, ChangesetState, FileOperation,
        OperationKind, approval_record_path, calculate_candidate_hash, calculate_validation_hash,
        canon_root_hash, content_result_hash, projected_root_hash, sha256_bytes,
    },
    cli::ReplMode,
    copycheck::{AllowedSource, CopyPolicy, scan_near_copy},
    cost::{BudgetLedger, MicroDollars},
    domain::{EntityKind, prefixed_uuid},
    model::{
        ModelBackend, ModelFailureClass, ModelMessage, ModelRequest, ModelResponse, ModelResult,
        ScriptedModel,
    },
    plot::{StoryStructure, builtin_framework, validate_structure},
    project::Project,
    sources::ManifestDocument,
    tools::{AgentRole as ToolRole, Tool},
};

/// The fixed roles used by the reviewed writing pipeline.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AgentRole {
    /// Converts an approved structure into a chapter plan candidate.
    StoryArchitect,
    /// Produces a prose candidate; it has no canon-write capability.
    Writer,
    /// Reviews characters and voice.
    CharacterVoiceCritic,
    /// Reviews canon, causality, timeline, and foreshadowing.
    CanonCritic,
    /// Reviews reader pull and scene momentum.
    ReaderPullCritic,
    /// Reviews story-level structure and scene purpose.
    StoryEditorCritic,
    /// Reviews language naturalness and style.
    NaturalnessStyleCritic,
    /// Reviews required-source adherence.
    SourceAdherenceCritic,
    /// Revises a candidate after typed critiques.
    Reviser,
    /// Runs deterministic post-write validators.
    Validator,
}

impl AgentRole {
    /// Returns a stable role name suitable for model requests and receipts.
    pub const fn name(self) -> &'static str {
        match self {
            Self::StoryArchitect => "story-architect",
            Self::Writer => "writer",
            Self::CharacterVoiceCritic => "character-voice-critic",
            Self::CanonCritic => "canon-critic",
            Self::ReaderPullCritic => "reader-pull-critic",
            Self::StoryEditorCritic => "story-editor-critic",
            Self::NaturalnessStyleCritic => "naturalness-style-critic",
            Self::SourceAdherenceCritic => "source-adherence-critic",
            Self::Reviser => "reviser",
            Self::Validator => "validator",
        }
    }

    /// Returns whether this role is one of the independent critics.
    pub const fn is_critic(self) -> bool {
        matches!(
            self,
            Self::CharacterVoiceCritic
                | Self::CanonCritic
                | Self::ReaderPullCritic
                | Self::StoryEditorCritic
                | Self::NaturalnessStyleCritic
                | Self::SourceAdherenceCritic
        )
    }

    fn tool_role(self) -> ToolRole {
        match self {
            Self::CharacterVoiceCritic
            | Self::CanonCritic
            | Self::ReaderPullCritic
            | Self::StoryEditorCritic
            | Self::NaturalnessStyleCritic
            | Self::SourceAdherenceCritic => ToolRole::ConsistencyCritic,
            Self::StoryArchitect | Self::Writer | Self::Reviser => ToolRole::Author,
            Self::Validator => ToolRole::Coordinator,
        }
    }
}

/// A complete role request handed to the single shared runner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentSpec {
    /// Fixed logical role.
    pub role: AgentRole,
    /// Prompt text sent to the selected model.
    pub prompt: String,
    /// Explicit model ID; there is no implicit provider fallback.
    pub model: String,
    /// Tools available to this role.
    pub tools: Vec<Tool>,
}

impl AgentSpec {
    /// Creates a role request with the fixed capability set for that role.
    pub fn new(role: AgentRole, prompt: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            role,
            prompt: prompt.into(),
            model: model.into(),
            tools: Tool::for_role(role.tool_role()).to_vec(),
        }
    }

    /// Returns the ordered six-role critic set used by the controller.
    pub fn critic_roles() -> &'static [AgentRole] {
        &[
            AgentRole::CharacterVoiceCritic,
            AgentRole::CanonCritic,
            AgentRole::ReaderPullCritic,
            AgentRole::StoryEditorCritic,
            AgentRole::NaturalnessStyleCritic,
            AgentRole::SourceAdherenceCritic,
        ]
    }
}

/// A deterministic class of issue reported by a critic or validator.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    /// A required source was omitted from the receipt or draft.
    RequiredSource,
    /// A direct canon contradiction.
    Canon,
    /// An impossible event order.
    Timeline,
    /// A broken cause and effect chain.
    Causality,
    /// A prohibited near-copy match.
    NearCopy,
    /// A character or voice concern.
    Character,
    /// A reader-pull concern.
    ReaderPull,
    /// A language or style concern.
    Style,
    /// A source-adherence concern.
    SourceAdherence,
    /// A structural editing concern.
    StoryEdit,
    /// A non-blocking project-specific finding.
    Other,
}

impl FindingKind {
    /// Returns whether an unresolved finding of this kind blocks approval.
    pub const fn is_blocking(self) -> bool {
        matches!(
            self,
            Self::RequiredSource | Self::Canon | Self::Timeline | Self::Causality | Self::NearCopy
        )
    }
}

/// Typed failure at the trusted chapter-approval boundary.
#[derive(Debug)]
pub enum ApprovalError {
    /// No initialized project was attached to the controller.
    ProjectRequired,
    /// Candidate bytes or the changeset failed validation before any apply began.
    Validation(String),
    /// The journal could not apply the already-validated changeset.
    Apply(String),
    /// The journal returned success but its durable approval proof was absent or changed.
    DurableProof(String),
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProjectRequired => {
                formatter.write_str("approval requires an initialized project")
            }
            Self::Validation(message) => write!(formatter, "approval validation failed: {message}"),
            Self::Apply(message) => write!(formatter, "approval apply failed: {message}"),
            Self::DurableProof(message) => {
                write!(formatter, "approval durable proof failed: {message}")
            }
        }
    }
}

impl std::error::Error for ApprovalError {}

struct PreparedChange {
    operations: Vec<FileOperation>,
    base_root_hash: String,
    content_result_hash: String,
    result_root_hash: String,
    candidate_hash: String,
}

/// Trusted disposition assigned to one finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FindingDisposition {
    /// No trusted human decision has been recorded.
    Open,
    /// A human explicitly classified this finding as a false positive.
    FalsePositive { reason: String },
}

/// Stable artifact/range evidence bound to a candidate hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable finding ID.
    pub id: String,
    /// Typed finding category.
    pub kind: FindingKind,
    /// Project-relative artifact path.
    pub artifact: String,
    /// Inclusive UTF-8 byte start of the evidence range.
    pub start: usize,
    /// Exclusive UTF-8 byte end of the evidence range.
    pub end: usize,
    /// Human-readable evidence or critic message.
    pub message: String,
    /// Hash of stable evidence fields.
    pub evidence_hash: String,
    /// Candidate hash at the time the finding was created.
    pub candidate_hash: String,
    /// Current trusted disposition.
    pub disposition: FindingDisposition,
}

impl Finding {
    /// Creates a finding with a stable evidence hash.
    pub fn new(
        kind: FindingKind,
        artifact: impl Into<String>,
        start: usize,
        end: usize,
        message: impl Into<String>,
        candidate_hash: impl Into<String>,
    ) -> Self {
        let artifact = artifact.into();
        let message = message.into();
        let candidate_hash = candidate_hash.into();
        let evidence_hash =
            sha256_bytes(format!("{:?}\0{artifact}\0{start}\0{end}\0{message}", kind).as_bytes());
        Self {
            id: stable_finding_id(kind, &artifact, start, end, &message, &candidate_hash),
            kind,
            artifact,
            start,
            end,
            message,
            evidence_hash,
            candidate_hash,
            disposition: FindingDisposition::Open,
        }
    }

    /// Returns whether the finding is still bound to a candidate.
    pub fn is_valid_for(&self, candidate_hash: &str) -> bool {
        self.candidate_hash == candidate_hash
    }

    /// Returns whether this finding currently blocks approval.
    pub fn blocks(&self, candidate_hash: &str) -> bool {
        self.kind.is_blocking()
            && self.is_valid_for(candidate_hash)
            && self.disposition == FindingDisposition::Open
    }
}

/// Scope of a human correction rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorrectionScope {
    /// One exact artifact or location.
    Location,
    /// One character's later dialogue or action.
    Character,
    /// One scene.
    Scene,
    /// One chapter and its descendants.
    Chapter,
    /// All later writing in the project.
    Project,
}

/// An explicit human edit promoted into a later-generation directive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CorrectionRule {
    /// Stable rule ID.
    pub id: String,
    /// Chapter where the human correction was made.
    pub source_chapter: String,
    /// Rule scope.
    pub scope: CorrectionScope,
    /// Optional target entity for scoped rules.
    pub target: Option<String>,
    /// Before/after diff represented as a directive, not hidden prose.
    pub diff: String,
    /// Hash retained in later context receipts.
    pub hash: String,
}

/// Redacted correction evidence carried in a later context receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CorrectionReceipt {
    /// Rule identity.
    pub rule_id: String,
    /// Rule hash.
    pub hash: String,
    /// Explicit directive text.
    pub directive: String,
}

/// Chapter lifecycle independent of the changeset's file-apply lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChapterState {
    /// No candidate has been created.
    Planned,
    /// A model run is active.
    Running,
    /// Candidate exists but validation is incomplete.
    Candidate,
    /// Candidate passed all deterministic gates and has no blockers.
    Approvable,
    /// Human approval recorded and applied to canon.
    Approved,
    /// Human rejected the candidate.
    Rejected,
    /// Candidate depends on an edited upstream candidate.
    Stale,
    /// Approved descendant needs a fresh review after upstream change.
    NeedsRevalidation,
}

/// A small public projection used by continuous-run status displays.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChapterRecord {
    /// Stable chapter ID or project-local chapter key.
    pub id: String,
    /// Explicit chapter order; approval follows this value.
    pub order: u32,
    /// Current lifecycle state.
    pub state: ChapterState,
}

/// Pipeline counters and role trace for one chapter.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkflowTrace {
    /// Ordered roles entered by the controller.
    pub roles: Vec<AgentRole>,
    /// Number of architect requests.
    pub architect_calls: usize,
    /// Number of writer requests.
    pub writer_calls: usize,
    /// Maximum critic fan-out promised by the controller.
    pub max_parallel_critics: usize,
    /// Number of critic requests attempted.
    pub critic_calls: usize,
    /// Number of reviser requests attempted.
    pub reviser_calls: usize,
    /// Number of deterministic validator passes.
    pub validator_calls: usize,
}

/// Unit used by project chapter-length validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LengthUnit {
    /// Count Unicode grapheme clusters, the Japanese default.
    Graphemes,
    /// Count whitespace-delimited words.
    Words,
}

/// Deterministic preflight result shown before generation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreflightReport {
    /// Approved scene plan is present.
    pub approved_scene_plan: bool,
    /// Approved box plan is present.
    pub approved_box_plan: bool,
    /// Macro structure links at least one scene.
    pub macro_links: bool,
}

impl PreflightReport {
    fn is_ready(&self) -> bool {
        self.approved_scene_plan && self.approved_box_plan && self.macro_links
    }
}

/// One atomically approved chapter candidate and its associated evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChapterRun {
    /// Chapter key this run belongs to.
    pub chapter_id: String,
    /// One changeset for manuscript and linked state updates.
    pub changeset: Changeset,
    /// Chapter lifecycle state.
    pub state: ChapterState,
    /// Role/call trace.
    pub trace: WorkflowTrace,
    /// Typed findings sorted by stable role order.
    pub findings: Vec<Finding>,
    /// Corrections included in this run's context receipt.
    pub correction_receipts: Vec<CorrectionReceipt>,
    /// Hash-bound, run-local provisional candidates visible to later chapters.
    pub provisional_canon_hashes: Vec<(String, String)>,
    /// Redacted context receipt hash.
    pub context_receipt_hash: String,
    /// Candidate prose retained outside canon.
    pub candidate_text: String,
    /// Preflight evidence.
    pub preflight: PreflightReport,
}

impl ChapterRun {
    /// Returns true only while this changeset can pass human approval checks.
    pub fn is_approvable(&self) -> bool {
        self.state == ChapterState::Approvable
            && self.changeset.state.is_approvable()
            && self.changeset.unresolved_blocker_ids.is_empty()
            && self.findings.iter().all(|finding| {
                !finding.kind.is_blocking() || finding.disposition != FindingDisposition::Open
            })
    }

    /// Returns the current candidate hash.
    pub fn candidate_hash(&self) -> &str {
        &self.changeset.candidate_hash
    }
}

/// Cost state exposed to the REPL without exposing the durable ledger internals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CostStatus {
    /// Amount estimated or charged for the active chapter.
    pub chapter: MicroDollars,
    /// Amount estimated or charged for the continuous run.
    pub run: MicroDollars,
    /// Whether the chapter warning threshold has been crossed.
    pub warning: bool,
}

/// Shared controller for one writing session.
pub struct RunController {
    backend: ModelBackend,
    project: Option<Project>,
    model_by_role: BTreeMap<AgentRole, String>,
    chapters: BTreeMap<String, ChapterRecord>,
    chapter_runs: BTreeMap<String, ChapterRun>,
    findings: BTreeMap<String, Finding>,
    finding_chapters: BTreeMap<String, String>,
    corrections: Vec<CorrectionRule>,
    preflight: PreflightReport,
    strict_preflight: bool,
    structure_required: bool,
    length_unit: LengthUnit,
    min_length: usize,
    max_length: usize,
    max_revisions: usize,
    cost_ledger: BudgetLedger,
    request_maximum_cost: Option<MicroDollars>,
    cost_status: CostStatus,
    structure: Option<StoryStructure>,
    plot_framework: Option<String>,
    strict_backend_errors: bool,
    provisional_canon: BTreeMap<String, String>,
    run_id: String,
}

impl RunController {
    /// Builds a strict controller around a production or scripted model backend.
    pub fn new(backend: ModelBackend) -> Self {
        let mut model_by_role = BTreeMap::new();
        for role in [
            AgentRole::StoryArchitect,
            AgentRole::Writer,
            AgentRole::Reviser,
            AgentRole::Validator,
        ] {
            model_by_role.insert(role, crate::model::DEFAULT_MODEL.into());
        }
        for role in AgentSpec::critic_roles() {
            model_by_role.insert(*role, crate::model::DEFAULT_MODEL.into());
        }
        Self {
            backend,
            project: None,
            model_by_role,
            chapters: BTreeMap::new(),
            chapter_runs: BTreeMap::new(),
            findings: BTreeMap::new(),
            finding_chapters: BTreeMap::new(),
            corrections: Vec::new(),
            preflight: PreflightReport::default(),
            strict_preflight: true,
            structure_required: true,
            length_unit: LengthUnit::Graphemes,
            min_length: 8_000,
            max_length: 12_000,
            max_revisions: 2,
            cost_ledger: BudgetLedger::new(MicroDollars::zero(), MicroDollars::zero()),
            request_maximum_cost: Some(MicroDollars::new(100_000)),
            cost_status: CostStatus {
                chapter: MicroDollars::zero(),
                run: MicroDollars::zero(),
                warning: false,
            },
            structure: None,
            plot_framework: None,
            strict_backend_errors: true,
            provisional_canon: BTreeMap::new(),
            run_id: prefixed_uuid(EntityKind::Run).as_str().into(),
        }
    }

    /// Builds a deterministic evaluation controller around a scripted model.
    pub fn fixture<B: Into<ModelBackend>>(backend: B) -> Self {
        let mut controller = Self::new(backend.into());
        controller.preflight = PreflightReport {
            approved_scene_plan: true,
            approved_box_plan: true,
            macro_links: true,
        };
        controller.strict_preflight = true;
        controller.structure_required = false;
        controller.min_length = 0;
        controller.max_length = usize::MAX;
        controller.strict_backend_errors = false;
        controller.register_chapter("chapter_1", 1, ChapterState::Planned);
        controller
    }

    /// Builds a deterministic controller attached to an initialized project.
    #[doc(hidden)]
    pub fn fixture_with_project<B: Into<ModelBackend>>(project: Project, backend: B) -> Self {
        let mut controller = Self::fixture(backend);
        controller.chapters.clear();
        controller.project = Some(project);
        controller.structure_required = false;
        controller
    }

    /// Builds a production controller with a real project approval boundary.
    pub fn with_project(project: Project, backend: ModelBackend) -> Self {
        let mut controller = Self::new(backend);
        controller.project = Some(project);
        controller
    }

    /// Returns the attached project, if this controller has a durable approval boundary.
    pub fn project(&self) -> Option<&Project> {
        self.project.as_ref()
    }

    /// Builds a fixture with three chapters for stale-state tests.
    pub fn continuous_fixture() -> Self {
        let mut controller = Self::fixture(ScriptedModel::new([]));
        controller.chapters.clear();
        controller.register_chapter("chapter_1", 1, ChapterState::Approved);
        controller.register_chapter("chapter_2", 2, ChapterState::Candidate);
        controller.register_chapter("chapter_3", 3, ChapterState::Approved);
        controller
    }

    /// Registers a chapter with an explicit approval order.
    pub fn register_chapter(&mut self, id: impl Into<String>, order: u32, state: ChapterState) {
        let id = id.into();
        self.chapters
            .insert(id.clone(), ChapterRecord { id, order, state });
    }

    /// Returns one chapter record.  Callers should use [`Self::chapter_opt`] for untrusted IDs.
    pub fn chapter(&self, id: &str) -> &ChapterRecord {
        self.chapters
            .get(id)
            .unwrap_or_else(|| panic!("unknown chapter {id}"))
    }

    /// Returns one chapter record without panicking on an untrusted ID.
    pub fn chapter_opt(&self, id: &str) -> Option<&ChapterRecord> {
        self.chapters.get(id)
    }

    /// Returns one completed chapter run, if present.
    pub fn chapter_run(&self, id: &str) -> Option<&ChapterRun> {
        self.chapter_runs.get(id)
    }

    /// Returns one finding without exposing mutable approval state.
    pub fn finding(&self, id: &str) -> Option<&Finding> {
        self.findings.get(id)
    }

    /// Configures the required preflight inputs.
    pub fn set_preflight(
        &mut self,
        approved_scene_plan: bool,
        approved_box_plan: bool,
        macro_links: bool,
    ) {
        self.preflight = PreflightReport {
            approved_scene_plan,
            approved_box_plan,
            macro_links,
        };
    }

    /// Installs and validates a project structure before chapter generation.
    pub fn set_structure(&mut self, structure: StoryStructure) -> Result<()> {
        validate_structure(&structure)?;
        self.structure = Some(structure);
        Ok(())
    }

    /// Selects a built-in or project-local declarative plot framework.
    pub fn set_plot_framework(&mut self, framework: impl Into<String>) -> Result<()> {
        let framework = framework.into();
        ensure!(
            builtin_framework(&framework).is_some() || framework.starts_with("custom:"),
            "unknown plot framework {framework}"
        );
        self.plot_framework = Some(framework);
        Ok(())
    }

    /// Selects the project chapter-length unit and bounds.
    pub fn set_length_bounds(
        &mut self,
        unit: LengthUnit,
        minimum: usize,
        maximum: usize,
    ) -> Result<()> {
        ensure!(minimum <= maximum, "chapter length minimum exceeds maximum");
        self.length_unit = unit;
        self.min_length = minimum;
        self.max_length = maximum;
        Ok(())
    }

    /// Changes a role's model explicitly; no provider fallback occurs.
    pub fn set_model(&mut self, role: Option<AgentRole>, model: impl Into<String>) -> Result<()> {
        let model = model.into();
        ensure!(!model.trim().is_empty(), "model ID is required");
        match role {
            Some(role) => {
                self.model_by_role.insert(role, model);
            }
            None => {
                for value in self.model_by_role.values_mut() {
                    *value = model.clone();
                }
            }
        }
        Ok(())
    }

    /// Returns the currently selected model for a role.
    pub fn model(&self, role: AgentRole) -> &str {
        self.model_by_role
            .get(&role)
            .map(String::as_str)
            .unwrap_or(crate::model::DEFAULT_MODEL)
    }

    /// Sets the maximum reservation used before each model call.
    pub fn set_request_maximum_cost(&mut self, maximum: Option<MicroDollars>) {
        self.request_maximum_cost = maximum;
    }

    /// Returns a bounded cost projection for the REPL.
    pub fn cost_status(&self) -> CostStatus {
        self.cost_status
    }

    /// Adds a trusted typed finding to a chapter's current candidate.
    pub fn add_finding(
        &mut self,
        chapter_id: &str,
        kind: FindingKind,
        artifact: impl Into<String>,
        start: usize,
        end: usize,
        message: impl Into<String>,
    ) -> Finding {
        let candidate_hash = self
            .chapter_runs
            .get(chapter_id)
            .map(|run| run.changeset.candidate_hash.clone())
            .unwrap_or_else(|| sha256_bytes(b""));
        let finding = Finding::new(kind, artifact, start, end, message, candidate_hash);
        self.finding_chapters
            .insert(finding.id.clone(), chapter_id.into());
        self.findings.insert(finding.id.clone(), finding.clone());
        if let Some(run) = self.chapter_runs.get_mut(chapter_id) {
            run.findings.push(finding.clone());
            run.state = ChapterState::Candidate;
            run.changeset.state = ChangesetState::Reviewing;
            if kind.is_blocking()
                && let Some(entity_id) = crate::domain::EntityId::from_validated(finding.id.clone())
                && !run
                    .changeset
                    .unresolved_blocker_ids
                    .iter()
                    .any(|id| id == &entity_id)
            {
                run.changeset.unresolved_blocker_ids.push(entity_id);
            }
        }
        finding
    }

    /// Resolves exactly one finding through the trusted false-positive branch.
    ///
    /// The public method exists for deterministic harness integration, but production callers
    /// must invoke it only from the trusted `/resolve` REPL branch.  Model output and natural
    /// language routing never call this method.
    pub fn resolve_false_positive(
        &mut self,
        finding_id: &str,
        reason: impl Into<String>,
    ) -> Result<()> {
        let reason = reason.into();
        ensure!(
            !reason.trim().is_empty(),
            "false-positive reason is required"
        );
        if let Some(chapter_id) = self.finding_chapters.get(finding_id)
            && let Some(run) = self.chapter_runs.get(chapter_id)
        {
            let finding = self
                .findings
                .get(finding_id)
                .ok_or_else(|| anyhow!("finding {finding_id} was not found"))?;
            ensure!(
                finding.is_valid_for(&run.changeset.candidate_hash),
                "finding {finding_id} is stale after a candidate edit"
            );
        }
        let finding = self
            .findings
            .get_mut(finding_id)
            .ok_or_else(|| anyhow!("finding {finding_id} was not found"))?;
        ensure!(
            finding.disposition == FindingDisposition::Open,
            "finding {finding_id} is already resolved"
        );
        finding.disposition = FindingDisposition::FalsePositive { reason };
        if let Some(chapter_id) = self.finding_chapters.get(finding_id)
            && let Some(run) = self.chapter_runs.get_mut(chapter_id)
            && let Some(run_finding) = run.findings.iter_mut().find(|item| item.id == finding_id)
        {
            run_finding.disposition = finding.disposition.clone();
            run.changeset
                .unresolved_blocker_ids
                .retain(|id| id.as_str() != finding_id);
        }
        self.refresh_chapter_states();
        Ok(())
    }

    /// Changes candidate bytes and invalidates all findings tied to the old hash.
    pub fn edit_candidate(&mut self, chapter_id: &str, candidate: impl AsRef<[u8]>) -> Result<()> {
        let hash = sha256_bytes(candidate.as_ref());
        ensure!(
            self.chapter_opt(chapter_id)
                .is_some_and(|chapter| chapter.state != ChapterState::Approved),
            "approved canon cannot be edited as a candidate"
        );
        let run = self
            .chapter_runs
            .get_mut(chapter_id)
            .ok_or_else(|| anyhow!("chapter {chapter_id} has no candidate"))?;
        run.candidate_text = String::from_utf8_lossy(candidate.as_ref()).into_owned();
        run.changeset.candidate_hash = hash.clone();
        run.changeset.validation_hash = None;
        run.changeset.state = ChangesetState::Reviewing;
        run.state = ChapterState::Candidate;
        for finding in self.findings.values_mut().filter(|finding| {
            self.finding_chapters.get(&finding.id).map(String::as_str) == Some(chapter_id)
        }) {
            finding.disposition = FindingDisposition::Open;
        }
        for finding in &mut run.findings {
            finding.disposition = FindingDisposition::Open;
        }
        self.provisional_canon.insert(chapter_id.into(), hash);
        self.note_upstream_edit(chapter_id)?;
        self.refresh_chapter_states();
        Ok(())
    }

    /// Accepts a human diff as a durable, explicit correction directive.
    pub fn accept_human_correction(
        &mut self,
        source_chapter: &str,
        before: impl AsRef<str>,
        after: impl AsRef<str>,
        scope: impl AsRef<str>,
        target: Option<&str>,
    ) -> Result<CorrectionRule> {
        let source_order = self
            .chapter_opt(source_chapter)
            .ok_or_else(|| anyhow!("source chapter {source_chapter} was not found"))?
            .order;
        let scope = match scope.as_ref() {
            "location" => CorrectionScope::Location,
            "character" => CorrectionScope::Character,
            "scene" => CorrectionScope::Scene,
            "chapter" => CorrectionScope::Chapter,
            "project" => CorrectionScope::Project,
            _ => bail!("unknown correction scope"),
        };
        ensure!(
            !before.as_ref().trim().is_empty(),
            "correction before text is required"
        );
        ensure!(
            !after.as_ref().trim().is_empty(),
            "correction after text is required"
        );
        if scope == CorrectionScope::Project {
            ensure!(target.is_none(), "project corrections cannot have a target");
        } else {
            let target = target.ok_or_else(|| anyhow!("scoped corrections require a target"))?;
            ensure!(!target.trim().is_empty(), "correction target is required");
            ensure!(
                match scope {
                    CorrectionScope::Chapter => target.starts_with("chapter_"),
                    CorrectionScope::Scene => target.starts_with("scene_"),
                    CorrectionScope::Character => target.starts_with("character_"),
                    CorrectionScope::Location => target.starts_with("location_"),
                    CorrectionScope::Project => false,
                },
                "correction target does not match its scope"
            );
            if let Some(target_chapter) = self.chapter_opt(target) {
                ensure!(
                    target_chapter.order >= source_order,
                    "correction target must not precede its source chapter"
                );
            }
        }
        let diff = format!("BEFORE:\n{}\nAFTER:\n{}", before.as_ref(), after.as_ref());
        let hash = sha256_bytes(diff.as_bytes());
        let rule = CorrectionRule {
            id: prefixed_uuid(EntityKind::Rule).as_str().into(),
            source_chapter: source_chapter.into(),
            scope,
            target: target.map(str::to_owned),
            diff,
            hash,
        };
        self.corrections.push(rule.clone());
        Ok(rule)
    }

    /// Returns correction directives applicable to a later chapter.
    pub fn correction_receipt(&self, chapter_id: &str) -> Vec<CorrectionReceipt> {
        let chapter_order = self
            .chapter_opt(chapter_id)
            .map_or(u32::MAX, |chapter| chapter.order);
        self.corrections
            .iter()
            .filter(|rule| {
                let source_order = self
                    .chapter_opt(&rule.source_chapter)
                    .map_or(0, |chapter| chapter.order);
                source_order < chapter_order && correction_applies(rule, chapter_id, self)
            })
            .map(|rule| CorrectionReceipt {
                rule_id: rule.id.clone(),
                hash: rule.hash.clone(),
                directive: rule.diff.clone(),
            })
            .collect()
    }

    /// Marks all unapproved descendants stale and approved descendants revalidation-required.
    pub fn note_upstream_edit(&mut self, chapter_id: &str) -> Result<()> {
        let source_order = self
            .chapter_opt(chapter_id)
            .ok_or_else(|| anyhow!("chapter {chapter_id} was not found"))?
            .order;
        let descendant_ids = self
            .chapters
            .values()
            .filter(|chapter| chapter.order > source_order)
            .map(|chapter| chapter.id.clone())
            .collect::<Vec<_>>();
        for chapter in self.chapters.values_mut() {
            if chapter.order <= source_order {
                continue;
            }
            chapter.state = match chapter.state {
                ChapterState::Approved | ChapterState::NeedsRevalidation => {
                    ChapterState::NeedsRevalidation
                }
                _ => ChapterState::Stale,
            };
            if let Some(run) = self.chapter_runs.get_mut(&chapter.id) {
                run.state = chapter.state;
                run.changeset.state = match chapter.state {
                    ChapterState::NeedsRevalidation => ChangesetState::NeedsRevalidation,
                    _ => ChangesetState::Stale,
                };
            }
            self.provisional_canon.remove(&chapter.id);
        }
        for descendant_id in descendant_ids {
            self.invalidate_chapter_findings(&descendant_id);
        }
        Ok(())
    }

    /// Human approval in chapter order.  LLM and natural-language paths cannot call this.
    pub fn approve_chapter(&mut self, _chapter_id: &str) -> Result<()> {
        bail!("chapter approval is human-only; use the trusted /approve command")
    }

    /// Rejects one candidate through the trusted REPL branch.
    pub(crate) fn reject_chapter_trusted(&mut self, chapter_id: &str) -> Result<()> {
        ensure!(
            self.chapter_opt(chapter_id)
                .is_some_and(|chapter| chapter.state != ChapterState::Approved),
            "approved canon cannot be rejected"
        );
        let chapter = self
            .chapters
            .get_mut(chapter_id)
            .ok_or_else(|| anyhow!("chapter {chapter_id} was not found"))?;
        chapter.state = ChapterState::Rejected;
        if let Some(run) = self.chapter_runs.get_mut(chapter_id) {
            run.state = ChapterState::Rejected;
            run.changeset.state = ChangesetState::Rejected;
        }
        self.note_upstream_edit(chapter_id)
    }

    /// Applies a trusted rejection addressed by a changeset ID.
    pub(crate) fn reject_changeset_trusted(&mut self, changeset_id: &str) -> Result<()> {
        let chapter_id = self
            .chapter_runs
            .iter()
            .find(|(_, run)| run.changeset.id.as_str() == changeset_id)
            .map(|(chapter_id, _)| chapter_id.clone())
            .ok_or_else(|| anyhow!("changeset {changeset_id} was not found"))?;
        self.reject_chapter_trusted(&chapter_id)
    }

    /// Applies one explicitly trusted approval and updates only the associated chapter state.
    pub(crate) fn approve_chapter_trusted(&mut self, chapter_id: &str) -> Result<()> {
        let run = self
            .chapter_runs
            .get(chapter_id)
            .ok_or_else(|| anyhow!("chapter {chapter_id} has no candidate"))?;
        ensure!(
            run.is_approvable(),
            "chapter {chapter_id} is not approvable"
        );
        let order = self.chapter(chapter_id).order;
        if self
            .chapters
            .values()
            .any(|chapter| chapter.order < order && chapter.state != ChapterState::Approved)
        {
            bail!("chapters must be approved in order");
        }
        let Some(project) = self.project.clone() else {
            return Err(anyhow::Error::new(ApprovalError::ProjectRequired));
        };
        let mut change = run.changeset.clone();
        let dependencies = self
            .project_dependencies(change.chapter_order)
            .map_err(|error| anyhow::Error::new(ApprovalError::Validation(error.to_string())))?;
        if change.dependencies != dependencies {
            change.dependencies = dependencies;
            change.parent_changeset_id = change
                .dependencies
                .first()
                .map(|dependency| dependency.id.clone());
            change.validation_hash = Some(calculate_validation_hash(&change));
            change.result_root_hash = projected_root_hash(&project, &change).map_err(|error| {
                anyhow::Error::new(ApprovalError::Validation(error.to_string()))
            })?;
        }
        crate::changeset::validate_changeset(&project, &change)
            .map_err(|error| anyhow::Error::new(ApprovalError::Validation(error.to_string())))?;
        crate::journal::apply_changeset(&project, &change)
            .map_err(|error| anyhow::Error::new(ApprovalError::Apply(error.to_string())))?;
        let proof_path = approval_record_path(&project.root, &change.id);
        let expected_proof = crate::changeset::approval_record_bytes(&change)
            .map_err(|error| anyhow::Error::new(ApprovalError::DurableProof(error.to_string())))?;
        let actual_proof = fs::read(&proof_path).map_err(|error| {
            anyhow::Error::new(ApprovalError::DurableProof(format!(
                "{}: {error}",
                proof_path.display()
            )))
        })?;
        ensure!(
            actual_proof == expected_proof,
            ApprovalError::DurableProof(
                "approval record bytes do not match validated proof".into()
            )
        );
        File::open(&proof_path)
            .and_then(|file| file.sync_all())
            .map_err(|error| {
                anyhow::Error::new(ApprovalError::DurableProof(format!(
                    "failed to fsync {}: {error}",
                    proof_path.display()
                )))
            })?;
        let chapter = self.chapters.get_mut(chapter_id).expect("checked above");
        chapter.state = ChapterState::Approved;
        let run = self
            .chapter_runs
            .get_mut(chapter_id)
            .expect("checked above");
        run.state = ChapterState::Approved;
        run.changeset = change;
        run.changeset.state = ChangesetState::Approved;
        self.note_upstream_edit(chapter_id)?;
        Ok(())
    }

    /// Applies a trusted approval addressed by a changeset ID.
    pub(crate) fn approve_changeset_trusted(&mut self, changeset_id: &str) -> Result<()> {
        let chapter_id = self
            .chapter_runs
            .iter()
            .find(|(_, run)| run.changeset.id.as_str() == changeset_id)
            .map(|(chapter_id, _)| chapter_id.clone())
            .ok_or_else(|| anyhow!("changeset {changeset_id} was not found"))?;
        self.approve_chapter_trusted(&chapter_id)
    }

    /// Test-only façade for exercising the trusted approval boundary without a terminal.
    #[doc(hidden)]
    pub fn approve_chapter_trusted_for_test(&mut self, changeset_id: &str) -> Result<()> {
        self.approve_changeset_trusted(changeset_id)
    }

    /// Runs one chapter through architect, writer, bounded critics, reviser, and validators.
    pub async fn write_chapter(&mut self, chapter_id: &str) -> Result<ChapterRun> {
        if self.strict_preflight {
            ensure!(
                self.preflight.is_ready(),
                "approved scene, box, and macro plans are required"
            );
            if self.structure_required {
                let structure = self
                    .structure
                    .as_ref()
                    .ok_or_else(|| anyhow!("an approved story structure is required"))?;
                validate_structure(structure)?;
                ensure!(
                    !structure.scenes.is_empty()
                        && !structure.boxes.is_empty()
                        && !structure.macro_beats.is_empty(),
                    "approved scene, box, and macro structure links are required"
                );
                ensure!(
                    structure
                        .chapters
                        .iter()
                        .any(|chapter| chapter.id == chapter_id),
                    "chapter {chapter_id} is not present in the approved story structure"
                );
                ensure!(
                    self.plot_framework.is_some(),
                    "a declarative plot framework is required"
                );
            }
        }
        if self.request_maximum_cost.is_none() {
            bail!("unknown model price; generation is stopped");
        }
        if !self.chapters.contains_key(chapter_id) {
            let next = self
                .chapters
                .values()
                .map(|chapter| chapter.order)
                .max()
                .unwrap_or(0)
                + 1;
            self.register_chapter(chapter_id, next, ChapterState::Planned);
        }
        if let Some(chapter) = self.chapters.get(chapter_id)
            && matches!(
                chapter.state,
                ChapterState::Stale | ChapterState::NeedsRevalidation
            )
        {
            bail!(
                "chapter {chapter_id} is {:?}; explicit regeneration or revalidation is required",
                chapter.state
            );
        }
        self.invalidate_chapter_findings(chapter_id);
        self.chapters
            .get_mut(chapter_id)
            .expect("chapter was registered")
            .state = ChapterState::Running;

        let mut trace = WorkflowTrace::default();
        trace.roles.push(AgentRole::StoryArchitect);
        trace.architect_calls = 1;
        let architect_request = ModelRequest::new(
            AgentRole::StoryArchitect.name(),
            vec![ModelMessage::user(format!(
                "Plan chapter {chapter_id} from the approved scene, box, and macro structure. Return a plan only."
            ))],
            Vec::new(),
        )
        .with_model(self.model(AgentRole::StoryArchitect));
        self.reserve_request(chapter_id)?;
        let architect_plan = match self.backend.complete(architect_request).await {
            Ok(response) => response.text,
            Err(error)
                if !self.strict_backend_errors && error.class() == ModelFailureClass::Stopped =>
            {
                String::new()
            }
            Err(error) => return Err(model_error(error)),
        };
        trace.roles.push(AgentRole::Writer);
        let chapter_order = self.chapter(chapter_id).order;
        let provisional_canon_hashes = self
            .chapters
            .values()
            .filter(|chapter| chapter.order < chapter_order)
            .filter_map(|chapter| {
                self.provisional_canon
                    .get(&chapter.id)
                    .map(|hash| (chapter.id.clone(), hash.clone()))
            })
            .collect::<Vec<_>>();
        let correction_receipts = self.correction_receipt(chapter_id);
        let writer_request = ModelRequest::new(
            AgentRole::Writer.name(),
            vec![ModelMessage::user(format!(
                "Write chapter {chapter_id}. Approved scene and box plans are required. Architect plan: {architect_plan}. Provisional canon hashes: {}. Corrections: {}",
                provisional_canon_hashes
                    .iter()
                    .map(|(id, hash)| format!("{id}={hash}"))
                    .collect::<Vec<_>>()
                    .join(","),
                correction_receipts
                    .iter()
                    .map(|receipt| receipt.directive.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            ))],
            Vec::new(),
        )
        .with_model(self.model(AgentRole::Writer));
        self.reserve_request(chapter_id)?;
        trace.writer_calls = 1;
        let writer_text = match self.backend.complete(writer_request).await {
            Ok(response) => response.text,
            Err(error)
                if !self.strict_backend_errors && error.class() == ModelFailureClass::Stopped =>
            {
                "".into()
            }
            Err(error) => return Err(model_error(error)),
        };
        let changeset_id = prefixed_uuid(EntityKind::Changeset);
        let dependencies = self.project_dependencies(chapter_order)?;
        let mut prepared = if let Some(project) = self.project.as_ref() {
            Some(prepare_project_change(
                project,
                &changeset_id,
                chapter_id,
                chapter_order,
                &writer_text,
                dependencies.clone(),
            )?)
        } else {
            None
        };
        let mut candidate_hash = prepared.as_ref().map_or_else(
            || sha256_bytes(writer_text.as_bytes()),
            |change| change.candidate_hash.clone(),
        );
        let mut candidate_text = writer_text.clone();

        let mut findings = Vec::new();
        let role_order = AgentSpec::critic_roles().to_vec();
        trace.max_parallel_critics = 3;
        let strict_backend_errors = self.strict_backend_errors;
        let mut failing_critic_roles = BTreeSet::new();
        for role_batch in role_order.chunks(3) {
            let mut specs = Vec::with_capacity(role_batch.len());
            for role in role_batch {
                trace.roles.push(*role);
                trace.critic_calls += 1;
                specs.push((
                    *role,
                    format!(
                        "Review candidate chapter {chapter_id} without editing it.\n\nImmutable candidate:\n{candidate_text}\n\nImmutable context receipt: provisional canon hashes={provisional_canon_hashes:?}; corrections={correction_receipts:?}. Report typed evidence as FINDING|kind|artifact|start|end|message."
                    ),
                ));
            }
            for (role, result) in self.run_critic_batch(chapter_id, &specs).await? {
                match result {
                    Ok(response) => {
                        let role_findings =
                            parse_findings(&response.text, role, &candidate_hash, &candidate_text)?;
                        if role_findings
                            .iter()
                            .any(|finding| finding.blocks(&candidate_hash))
                        {
                            failing_critic_roles.insert(role);
                        }
                        findings.extend(role_findings);
                    }
                    Err(error)
                        if !strict_backend_errors
                            && error.class() == ModelFailureClass::Stopped => {}
                    Err(error) => return Err(model_error(error)),
                }
            }
        }

        let mut state = ChapterState::Candidate;
        let mut changeset_state = ChangesetState::Reviewing;
        for _ in 0..self.max_revisions.min(2) {
            let blocking = findings
                .iter()
                .any(|finding| finding.blocks(&candidate_hash));
            if !blocking {
                break;
            }
            trace.roles.push(AgentRole::Reviser);
            trace.reviser_calls += 1;
            let typed_findings = findings
                .iter()
                .map(|finding| {
                    format!(
                        "kind={:?}; artifact={}; range={}..{}; message={}",
                        finding.kind, finding.artifact, finding.start, finding.end, finding.message
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let required_facts = format!(
                "provisional canon hashes={provisional_canon_hashes:?}; correction receipts={correction_receipts:?}"
            );
            let request = ModelRequest::new(
                AgentRole::Reviser.name(),
                vec![ModelMessage::user(format!(
                    "Revise only this candidate prose and preserve every approved fact.\n\nCandidate:\n{candidate_text}\n\nTyped findings:\n{typed_findings}\n\nRequired facts and correction directives:\n{required_facts}"
                ))],
                Vec::new(),
            )
            .with_model(self.model(AgentRole::Reviser));
            self.reserve_request(chapter_id)?;
            match self.backend.complete(request).await {
                Ok(response) if !response.text.is_empty() => {
                    candidate_text = response.text;
                    self.invalidate_chapter_findings(chapter_id);
                    findings.clear();
                    if let (Some(project), Some(previous)) =
                        (self.project.as_ref(), prepared.as_ref())
                    {
                        prepared = Some(update_project_change(
                            project,
                            &changeset_id,
                            previous,
                            &candidate_text,
                            dependencies.clone(),
                            chapter_order,
                        )?);
                        candidate_hash = prepared
                            .as_ref()
                            .map(|change| change.candidate_hash.clone())
                            .unwrap_or_else(|| sha256_bytes(candidate_text.as_bytes()));
                    } else {
                        candidate_hash = sha256_bytes(candidate_text.as_bytes());
                    }
                    let rerun_roles = failing_critic_roles.iter().copied().collect::<Vec<_>>();
                    failing_critic_roles.clear();
                    for role_batch in rerun_roles.chunks(3) {
                        let mut specs = Vec::with_capacity(role_batch.len());
                        for role in role_batch {
                            trace.roles.push(*role);
                            trace.critic_calls += 1;
                            specs.push((
                                *role,
                                format!(
                                    "Re-review this revised immutable candidate chapter {chapter_id}; report only current typed evidence as FINDING|kind|artifact|start|end|message.\n\nCandidate:\n{candidate_text}\n\nRequired facts and correction directives:\n{required_facts}"
                                ),
                            ));
                        }
                        for (role, result) in self.run_critic_batch(chapter_id, &specs).await? {
                            match result {
                                Ok(response) => {
                                    let role_findings = parse_findings(
                                        &response.text,
                                        role,
                                        &candidate_hash,
                                        &candidate_text,
                                    )?;
                                    if role_findings
                                        .iter()
                                        .any(|finding| finding.blocks(&candidate_hash))
                                    {
                                        failing_critic_roles.insert(role);
                                    }
                                    findings.extend(role_findings);
                                }
                                Err(error)
                                    if !self.strict_backend_errors
                                        && error.class() == ModelFailureClass::Stopped => {}
                                Err(error) => return Err(model_error(error)),
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(error)
                    if !self.strict_backend_errors
                        && error.class() == ModelFailureClass::Stopped =>
                {
                    break;
                }
                Err(error) => return Err(model_error(error)),
            }
        }
        trace.roles.push(AgentRole::Validator);
        trace.validator_calls = 1;
        validate_length(
            &candidate_text,
            self.length_unit,
            self.min_length,
            self.max_length,
        )?;
        let blocking = findings
            .iter()
            .any(|finding| finding.blocks(&candidate_hash));
        if !blocking {
            state = ChapterState::Approvable;
            changeset_state = ChangesetState::Approvable;
        }
        self.invalidate_chapter_findings(chapter_id);
        for finding in &findings {
            self.finding_chapters
                .insert(finding.id.clone(), chapter_id.into());
            self.findings.insert(finding.id.clone(), finding.clone());
        }
        let prepared = prepared.unwrap_or_else(|| {
            let chapter_entity = prefixed_uuid(EntityKind::Chapter);
            let operations = [
                (format!("本文/{chapter_id}.md"), "manuscript"),
                ("前提/時系列.md".into(), "timeline"),
                ("前提/伏線.md".into(), "foreshadowing"),
            ]
            .into_iter()
            .map(|(path, _)| FileOperation {
                kind: OperationKind::Replace,
                path: PathBuf::from(path),
                before_sha256: Some(sha256_bytes(b"synthetic-base")),
                after_sha256: Some(candidate_hash.clone()),
                candidate_path: Some(PathBuf::from(format!(
                    ".phemius/runtime/candidates/{}/{chapter_id}.md",
                    changeset_id.as_str()
                ))),
                affected_entities: vec![chapter_entity.clone()],
            })
            .collect();
            PreparedChange {
                operations,
                base_root_hash: sha256_bytes(self.run_id.as_bytes()),
                content_result_hash: candidate_hash.clone(),
                result_root_hash: candidate_hash.clone(),
                candidate_hash: candidate_hash.clone(),
            }
        });
        let mut changeset = Changeset {
            id: changeset_id,
            parent_changeset_id: dependencies.first().map(|dependency| dependency.id.clone()),
            base_root_hash: prepared.base_root_hash,
            content_result_hash: prepared.content_result_hash,
            result_root_hash: prepared.result_root_hash,
            state: changeset_state,
            operations: prepared.operations,
            candidate_hash: prepared.candidate_hash,
            validation_hash: None,
            unresolved_blocker_ids: findings
                .iter()
                .filter(|finding| finding.blocks(&candidate_hash))
                .filter_map(|finding| crate::domain::EntityId::from_validated(finding.id.clone()))
                .collect(),
            dependencies,
            chapter_order,
        };
        changeset.validation_hash = Some(calculate_validation_hash(&changeset));
        if let Some(project) = self.project.as_ref() {
            let mut validation_candidate = changeset.clone();
            validation_candidate.state = ChangesetState::Approvable;
            validation_candidate.unresolved_blocker_ids.clear();
            if let Err(error) = crate::changeset::validate_changeset(project, &validation_candidate)
            {
                // A later provisional chapter has no durable predecessor until the earlier
                // chapter is approved; the trusted approval boundary revalidates this edge.
                if error.kind() != crate::changeset::ValidationErrorKind::DependencyOrder {
                    return Err(anyhow!("validator changeset gate failed: {error}"));
                }
            }
            validate_project_quality_gates(project, &candidate_text)?;
        }
        let context_receipt_hash = sha256_bytes(
            format!(
                "{chapter_id}:{candidate_hash}:{:?}:{:?}",
                provisional_canon_hashes, correction_receipts
            )
            .as_bytes(),
        );
        let run = ChapterRun {
            chapter_id: chapter_id.into(),
            changeset,
            state,
            trace,
            findings,
            correction_receipts,
            provisional_canon_hashes,
            context_receipt_hash,
            candidate_text,
            preflight: self.preflight.clone(),
        };
        self.provisional_canon
            .insert(chapter_id.into(), candidate_hash);
        self.chapter_runs.insert(chapter_id.into(), run.clone());
        self.chapters
            .get_mut(chapter_id)
            .expect("chapter was registered")
            .state = state;
        self.refresh_chapter_states();
        Ok(run)
    }

    /// Runs a bounded 10-12 chapter continuous generation sequence.
    pub async fn write_continuous(&mut self, chapter_ids: &[String]) -> Result<Vec<ChapterRun>> {
        ensure!(
            (10..=12).contains(&chapter_ids.len()),
            "continuous runs require 10 to 12 chapters"
        );
        let mut ids = BTreeSet::new();
        for (index, id) in chapter_ids.iter().enumerate() {
            ensure!(ids.insert(id), "duplicate chapter in continuous run");
            if let Some(previous) = self.chapters.get(id) {
                if previous.order != index as u32 + 1 {
                    bail!("chapter order must be explicit and contiguous");
                }
                if matches!(
                    previous.state,
                    ChapterState::Stale | ChapterState::NeedsRevalidation
                ) {
                    bail!(
                        "chapter {id} is {:?}; continuous generation requires explicit revalidation",
                        previous.state
                    );
                }
            }
            if !self.chapters.contains_key(id) {
                self.register_chapter(id.clone(), index as u32 + 1, ChapterState::Planned);
            }
        }
        let mut runs = Vec::with_capacity(chapter_ids.len());
        for id in chapter_ids {
            runs.push(self.write_chapter(id).await?);
        }
        Ok(runs)
    }

    async fn run_critic_batch(
        &mut self,
        chapter_id: &str,
        specs: &[(AgentRole, String)],
    ) -> Result<Vec<(AgentRole, ModelResult<ModelResponse>)>> {
        let mut requests = Vec::with_capacity(specs.len());
        for (role, prompt) in specs {
            let request = ModelRequest::new(
                role.name(),
                vec![ModelMessage::user(prompt.clone())],
                Vec::new(),
            )
            .with_model(self.model(*role));
            self.reserve_request(chapter_id)?;
            requests.push((*role, request, self.backend.clone()));
        }
        let mut results = stream::iter(requests)
            .map(|(role, request, mut backend)| async move {
                let result = backend.complete(request).await;
                (role, result)
            })
            .buffer_unordered(3)
            .collect::<Vec<_>>()
            .await;
        results.sort_by_key(|(role, _)| {
            specs
                .iter()
                .position(|(expected, _)| expected == role)
                .unwrap_or(usize::MAX)
        });
        Ok(results)
    }

    fn reserve_request(&mut self, chapter_id: &str) -> Result<()> {
        let maximum = self
            .request_maximum_cost
            .ok_or_else(|| anyhow!("unknown model price; generation is stopped"))?;
        let reservation = self.cost_ledger.reserve(chapter_id, maximum)?;
        self.cost_status.chapter = self.cost_status.chapter.checked_add_for_work(maximum)?;
        self.cost_status.run = self.cost_status.run.checked_add_for_work(maximum)?;
        self.cost_status.warning |= reservation.warning_required;
        Ok(())
    }

    fn invalidate_chapter_findings(&mut self, chapter_id: &str) {
        let ids = self
            .finding_chapters
            .iter()
            .filter(|(_, owner)| owner.as_str() == chapter_id)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in ids {
            self.finding_chapters.remove(&id);
            self.findings.remove(&id);
        }
        if let Some(run) = self.chapter_runs.get_mut(chapter_id) {
            run.findings.clear();
        }
    }

    fn project_dependencies(&self, chapter_order: u32) -> Result<Vec<ChangesetDependency>> {
        let Some(project) = self.project.as_ref() else {
            return Ok(Vec::new());
        };
        if chapter_order <= 1 {
            return Ok(Vec::new());
        }
        let directory = project.root.join(".phemius/records/approvals");
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(anyhow!(error)),
        };
        let mut previous = None;
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let record: ApprovalRecord = serde_json::from_slice(&bytes).map_err(|error| {
                anyhow!(
                    "invalid approval record {}: {error}",
                    entry.path().display()
                )
            })?;
            if record.chapter_order == chapter_order - 1 {
                ensure!(
                    previous.is_none(),
                    "multiple durable approvals exist for chapter order {}",
                    record.chapter_order
                );
                previous = Some(ChangesetDependency {
                    id: record.changeset_id,
                    approval_record_sha256: sha256_bytes(&bytes),
                    chapter_order: record.chapter_order,
                });
            }
        }
        Ok(previous.into_iter().collect())
    }

    fn refresh_chapter_states(&mut self) {
        let mut state_updates = Vec::new();
        for run in self.chapter_runs.values_mut() {
            let blocking = run
                .findings
                .iter()
                .any(|finding| finding.blocks(&run.changeset.candidate_hash));
            if run.state == ChapterState::Candidate && !blocking && run.preflight.is_ready() {
                run.state = ChapterState::Approvable;
                run.changeset.state = ChangesetState::Approvable;
            }
            state_updates.push((run.chapter_id.clone(), run.state));
        }
        for (chapter_id, state) in state_updates {
            if let Some(chapter) = self.chapters.get_mut(&chapter_id) {
                chapter.state = state;
            }
        }
    }
}

fn correction_applies(rule: &CorrectionRule, chapter_id: &str, controller: &RunController) -> bool {
    if rule.scope == CorrectionScope::Project {
        return true;
    }
    let Some(target) = rule.target.as_deref() else {
        return false;
    };
    if target == chapter_id && rule.scope == CorrectionScope::Chapter {
        return true;
    }
    match rule.scope {
        CorrectionScope::Chapter => controller
            .chapter_opt(target)
            .zip(controller.chapter_opt(chapter_id))
            .is_some_and(|(target, chapter)| target.order <= chapter.order),
        CorrectionScope::Scene => {
            if let Some(structure) = controller.structure.as_ref()
                && let Some(scene) = structure.scenes.iter().find(|scene| scene.id == target)
                && let Some(target_chapter) = controller.chapter_opt(&scene.chapter_id)
                && let Some(chapter) = controller.chapter_opt(chapter_id)
            {
                target_chapter.order >= chapter.order
            } else {
                target.starts_with("scene_") || target.starts_with("box_")
            }
        }
        CorrectionScope::Location => target.starts_with("location_"),
        CorrectionScope::Character => target.starts_with("character_"),
        CorrectionScope::Project => true,
    }
}

fn validate_project_quality_gates(project: &Project, candidate_text: &str) -> Result<()> {
    let manifest_path = project.root.join("資料/manifest.md");
    let manifest = fs::read(&manifest_path).with_context(|| {
        format!(
            "required source manifest is missing: {}",
            manifest_path.display()
        )
    })?;
    ManifestDocument::parse(&manifest)
        .map_err(|error| anyhow!("source manifest validation failed: {error}"))?;

    let mut sources = Vec::new();
    for relative in [
        "前提/作品.md",
        "前提/世界観設定.md",
        "前提/時系列.md",
        "前提/伏線.md",
        "箱書き/構成.md",
    ] {
        let path = project.root.join(relative);
        if let Ok(bytes) = fs::read(&path)
            && let Ok(text) = String::from_utf8(bytes)
        {
            sources.push(AllowedSource::plain(relative, text));
        }
    }
    let findings = scan_near_copy(candidate_text, &sources, &CopyPolicy::default())
        .map_err(|error| anyhow!("near-copy validator stopped: {error}"))?;
    ensure!(
        findings.iter().all(|finding| !finding.blocking),
        "near-copy validator found a blocking source match"
    );
    Ok(())
}

fn stable_finding_id(
    kind: FindingKind,
    artifact: &str,
    start: usize,
    end: usize,
    message: &str,
    candidate_hash: &str,
) -> String {
    let material = format!(
        "{:?}\0{artifact}\0{start}\0{end}\0{message}\0{candidate_hash}",
        kind
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&Sha256::digest(material.as_bytes())[..16]);
    // Keep the deterministic digest in the UUID-v7-shaped namespace accepted by the domain.
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{}_{}",
        EntityKind::Finding.prefix(),
        Uuid::from_bytes(bytes)
    )
}

fn validate_length(text: &str, unit: LengthUnit, minimum: usize, maximum: usize) -> Result<()> {
    let count = match unit {
        LengthUnit::Graphemes => text.graphemes(true).count(),
        LengthUnit::Words => text.split_whitespace().count(),
    };
    ensure!(
        (minimum..=maximum).contains(&count),
        "chapter length {count} is outside {minimum}..={maximum}"
    );
    Ok(())
}

fn parse_findings(
    text: &str,
    role: AgentRole,
    candidate_hash: &str,
    candidate_text: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for line in text.lines() {
        let Some(body) = line.strip_prefix("FINDING|") else {
            continue;
        };
        let parts = body.splitn(5, '|').collect::<Vec<_>>();
        let [kind, artifact, start, end, message] = parts.as_slice() else {
            bail!("malformed finding evidence from {}", role.name());
        };
        let kind = match *kind {
            "required-source" => FindingKind::RequiredSource,
            "canon" => FindingKind::Canon,
            "timeline" => FindingKind::Timeline,
            "causality" => FindingKind::Causality,
            "near-copy" => FindingKind::NearCopy,
            "character" => FindingKind::Character,
            "reader-pull" => FindingKind::ReaderPull,
            "style" => FindingKind::Style,
            "source-adherence" => FindingKind::SourceAdherence,
            "story-edit" => FindingKind::StoryEdit,
            "other" => FindingKind::Other,
            unknown => bail!("unknown finding kind {unknown} from {}", role.name()),
        };
        let start = start
            .parse::<usize>()
            .map_err(|_| anyhow!("finding start is not an integer"))?;
        let end = end
            .parse::<usize>()
            .map_err(|_| anyhow!("finding end is not an integer"))?;
        validate_finding_evidence(artifact, start, end, candidate_text)?;
        ensure!(!message.trim().is_empty(), "finding message is required");
        let mut finding = Finding::new(kind, *artifact, start, end, *message, candidate_hash);
        finding.message = format!("{}: {}", role.name(), finding.message);
        findings.push(finding);
    }
    Ok(findings)
}

fn validate_finding_evidence(
    artifact: &str,
    start: usize,
    end: usize,
    candidate_text: &str,
) -> Result<()> {
    let path = Path::new(artifact);
    ensure!(!artifact.trim().is_empty(), "finding artifact is required");
    ensure!(
        !path.is_absolute(),
        "finding artifact must be project-relative"
    );
    ensure!(!artifact.contains('\0'), "finding artifact contains NUL");
    ensure!(
        path.components()
            .all(|component| !matches!(component, std::path::Component::ParentDir)),
        "finding artifact escapes the project"
    );
    ensure!(start <= end, "finding range is inverted");
    ensure!(
        end <= candidate_text.len(),
        "finding range exceeds candidate bytes"
    );
    ensure!(
        candidate_text.is_char_boundary(start) && candidate_text.is_char_boundary(end),
        "finding range splits UTF-8"
    );
    Ok(())
}

fn model_error(error: crate::model::ModelFailure) -> anyhow::Error {
    if error.class() == ModelFailureClass::Ambiguous {
        anyhow!("ambiguous model request: {error}")
    } else {
        anyhow!(error)
    }
}

impl From<ScriptedModel> for ModelBackend {
    fn from(backend: ScriptedModel) -> Self {
        Self::Scripted(backend)
    }
}

trait CostAdd {
    fn checked_add_for_work(self, other: MicroDollars) -> Result<MicroDollars>;
}

impl CostAdd for MicroDollars {
    fn checked_add_for_work(self, other: MicroDollars) -> Result<MicroDollars> {
        self.as_u64()
            .checked_add(other.as_u64())
            .map(MicroDollars::new)
            .ok_or_else(|| anyhow!("cost arithmetic overflow"))
    }
}

impl ChangesetState {
    /// Returns whether this state can be handed to the trusted approval boundary.
    pub fn is_approvable(self) -> bool {
        matches!(self, Self::Approvable)
    }
}

impl ReplMode {
    /// Returns a stable mode name for status output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Consult => "consult",
        }
    }
}

fn prepare_project_change(
    project: &Project,
    changeset_id: &crate::domain::EntityId,
    chapter_id: &str,
    chapter_order: u32,
    writer_text: &str,
    dependencies: Vec<ChangesetDependency>,
) -> Result<PreparedChange> {
    let base_root_hash = canon_root_hash(project).map_err(anyhow::Error::new)?;
    let candidate_root = project
        .root
        .join(".phemius/runtime/candidates")
        .join(changeset_id.as_str());
    fs::create_dir_all(&candidate_root).with_context(|| {
        format!(
            "failed to create candidate directory {}",
            candidate_root.display()
        )
    })?;
    sync_directory(&candidate_root)?;

    let chapter_entity = prefixed_uuid(EntityKind::Chapter);
    let mut operations = Vec::new();
    let mut add_artifact = |target: PathBuf,
                            file_name: &str,
                            candidate: Vec<u8>,
                            entity: crate::domain::EntityId|
     -> Result<()> {
        let target_absolute = project.root.join(&target);
        let existing = match fs::symlink_metadata(&target_absolute) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file(),
                    "canon target is not a regular file: {}",
                    target.display()
                );
                Some(fs::read(&target_absolute)?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(anyhow!(error)),
        };
        let candidate_relative = PathBuf::from(".phemius/runtime/candidates")
            .join(changeset_id.as_str())
            .join(file_name);
        write_new_synced(&project.root.join(&candidate_relative), &candidate)?;
        let (kind, before_sha256) = match existing {
            Some(bytes) => (OperationKind::Replace, Some(sha256_bytes(&bytes))),
            None => (OperationKind::Create, None),
        };
        operations.push(FileOperation {
            kind,
            path: target,
            before_sha256,
            after_sha256: Some(sha256_bytes(&candidate)),
            candidate_path: Some(candidate_relative),
            affected_entities: vec![entity],
        });
        Ok(())
    };

    let manuscript_target = PathBuf::from(format!("本文/{chapter_id}.md"));
    let manuscript_absolute = project.root.join(&manuscript_target);
    let manuscript = match fs::read(&manuscript_absolute) {
        Ok(bytes) => append_candidate(bytes, writer_text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            format!("---\nid: {}\n---\n{}", chapter_entity.as_str(), writer_text).into_bytes()
        }
        Err(error) => return Err(anyhow!(error)),
    };
    add_artifact(
        manuscript_target,
        "manuscript.md",
        manuscript,
        chapter_entity.clone(),
    )?;

    for (target, file_name, entity) in [
        (
            "前提/時系列.md",
            "timeline.md",
            prefixed_uuid(EntityKind::Timeline),
        ),
        (
            "前提/伏線.md",
            "foreshadowing.md",
            prefixed_uuid(EntityKind::Foreshadowing),
        ),
    ] {
        let target_path = PathBuf::from(target);
        let base = fs::read(project.root.join(&target_path))
            .with_context(|| format!("required canon artifact is missing: {target}"))?;
        add_artifact(
            target_path,
            file_name,
            append_candidate(base, writer_text),
            entity,
        )?;
    }

    for (file_name, suffix) in [
        ("context.md", "context receipt"),
        ("critique.md", "critic summary"),
        ("basis.md", "generation basis"),
    ] {
        let entity = prefixed_uuid(EntityKind::Rule);
        add_artifact(
            PathBuf::from(format!("メモ/{chapter_id}-{file_name}")),
            file_name,
            format!(
                "---\nid: {}\n---\n# {suffix}\n\n{writer_text}\n",
                entity.as_str()
            )
            .into_bytes(),
            entity,
        )?;
    }

    let mut change = Changeset {
        id: changeset_id.clone(),
        parent_changeset_id: None,
        base_root_hash,
        content_result_hash: String::new(),
        result_root_hash: String::new(),
        state: ChangesetState::Approvable,
        operations,
        candidate_hash: String::new(),
        validation_hash: None,
        unresolved_blocker_ids: Vec::new(),
        dependencies,
        chapter_order,
    };
    change.candidate_hash =
        calculate_candidate_hash(project, &change).map_err(anyhow::Error::new)?;
    change.content_result_hash =
        content_result_hash(project, &change).map_err(anyhow::Error::new)?;
    change.validation_hash = Some(calculate_validation_hash(&change));
    change.result_root_hash = projected_root_hash(project, &change).map_err(anyhow::Error::new)?;
    sync_directory(&candidate_root)?;
    Ok(PreparedChange {
        operations: change.operations,
        base_root_hash: change.base_root_hash,
        content_result_hash: change.content_result_hash,
        result_root_hash: change.result_root_hash,
        candidate_hash: change.candidate_hash,
    })
}

fn update_project_change(
    project: &Project,
    changeset_id: &crate::domain::EntityId,
    previous: &PreparedChange,
    candidate_text: &str,
    dependencies: Vec<ChangesetDependency>,
    chapter_order: u32,
) -> Result<PreparedChange> {
    let mut operations = previous.operations.clone();
    for operation in &mut operations {
        let Some(candidate_path) = operation.candidate_path.as_ref() else {
            continue;
        };
        let absolute = project.root.join(candidate_path);
        let current = fs::read(&absolute)
            .with_context(|| format!("failed to read candidate {}", absolute.display()))?;
        let revised = if operation.path.to_string_lossy().starts_with("本文/") {
            replace_candidate_body(current, candidate_text)
        } else {
            append_candidate(current, candidate_text)
        };
        write_replaced_synced(&absolute, &revised)?;
        operation.after_sha256 = Some(sha256_bytes(&revised));
    }
    sync_directory(
        &project
            .root
            .join(".phemius/runtime/candidates")
            .join(changeset_id.as_str()),
    )?;

    let mut change = Changeset {
        id: changeset_id.clone(),
        parent_changeset_id: dependencies.first().map(|dependency| dependency.id.clone()),
        base_root_hash: previous.base_root_hash.clone(),
        content_result_hash: String::new(),
        result_root_hash: String::new(),
        state: ChangesetState::Approvable,
        operations,
        candidate_hash: String::new(),
        validation_hash: None,
        unresolved_blocker_ids: Vec::new(),
        dependencies,
        chapter_order,
    };
    change.candidate_hash =
        calculate_candidate_hash(project, &change).map_err(anyhow::Error::new)?;
    change.content_result_hash =
        content_result_hash(project, &change).map_err(anyhow::Error::new)?;
    change.validation_hash = Some(calculate_validation_hash(&change));
    change.result_root_hash = projected_root_hash(project, &change).map_err(anyhow::Error::new)?;
    Ok(PreparedChange {
        operations: change.operations,
        base_root_hash: change.base_root_hash,
        content_result_hash: change.content_result_hash,
        result_root_hash: change.result_root_hash,
        candidate_hash: change.candidate_hash,
    })
}

fn append_candidate(mut base: Vec<u8>, writer_text: &str) -> Vec<u8> {
    if !base.ends_with(b"\n") {
        base.push(b'\n');
    }
    base.extend_from_slice(b"<!-- phemius candidate -->\n");
    base.extend_from_slice(writer_text.as_bytes());
    base
}

fn replace_candidate_body(base: Vec<u8>, candidate_text: &str) -> Vec<u8> {
    if let Some(separator) = base.windows(4).position(|window| window == b"---\n")
        && separator == 0
        && let Some(body_start) = base[4..].windows(4).position(|window| window == b"---\n")
    {
        let body_start = 4 + body_start + 4;
        let mut result = base[..body_start].to_vec();
        result.extend_from_slice(candidate_text.as_bytes());
        return result;
    }
    candidate_text.as_bytes().to_vec()
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create candidate {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write candidate {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync candidate {}", path.display()))?;
    Ok(())
}

fn write_replaced_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).truncate(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to rewrite candidate {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write revised candidate {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync revised candidate {}", path.display()))?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))
}
