//! Deterministic chapter orchestration and human approval state.
//!
//! Models in this module can propose candidate bytes and typed findings, but they never
//! mutate the canonical project.  The only path to an approved chapter is the trusted REPL
//! branch in [`crate::repl`].

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions, OpenOptionsExt as CapOpenOptionsExt};
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
    context::{ContextCompiler, ContextReceipt, ContextRequest},
    copycheck::{AllowedSource, CopyPolicy, scan_near_copy},
    cost::{BudgetLedger, MicroDollars, Price, Reservation},
    domain::{EntityId, EntityKind, prefixed_uuid},
    model::{
        ModelBackend, ModelFailureClass, ModelMessage, ModelRequest, ModelResponse, ModelResult,
        ScriptedModel,
    },
    plot::{StoryStructure, builtin_framework, validate_structure},
    project::Project,
    session::{Checkpoint, ContextEpoch, SessionEvent, SessionJournal},
    sources::{ManifestDocument, Snapshot},
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
    /// Candidate prose for earlier unapproved chapters in the same continuous run.
    pub provisional_canon_texts: Vec<(String, String)>,
    /// Redacted context receipt hash.
    pub context_receipt_hash: String,
    /// Complete non-secret source coverage receipt used for this candidate.
    pub context_receipt: Option<ContextReceipt>,
    /// Role-specific source receipts used by critics and the reviser.
    pub role_context_receipts: BTreeMap<String, ContextReceipt>,
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

/// Indicates that the conservative chapter estimate crossed the warning threshold before any
/// model request was sent.
#[derive(Debug)]
pub struct CostConfirmationRequired {
    chapter_id: String,
    estimated_cost: MicroDollars,
}

impl CostConfirmationRequired {
    /// Returns the chapter whose request requires explicit confirmation.
    pub fn chapter_id(&self) -> &str {
        &self.chapter_id
    }

    /// Returns the conservative cost estimate that triggered the warning.
    pub const fn estimated_cost(&self) -> MicroDollars {
        self.estimated_cost
    }
}

impl std::fmt::Display for CostConfirmationRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "estimated chapter cost exceeds $5; explicit confirmation is required before model request ({} microdollars)",
            self.estimated_cost.as_u64()
        )
    }
}

impl std::error::Error for CostConfirmationRequired {}

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
    request_price: Option<Price>,
    cost_warning_confirmed: bool,
    cost_status: CostStatus,
    structure: Option<StoryStructure>,
    plot_framework: Option<String>,
    strict_backend_errors: bool,
    provisional_canon: BTreeMap<String, String>,
    provisional_canon_texts: BTreeMap<String, String>,
    run_id: String,
    session: Option<SessionJournal>,
    checkpoint_path: Option<PathBuf>,
    recovery_required: bool,
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
            request_maximum_cost: None,
            request_price: None,
            cost_warning_confirmed: false,
            cost_status: CostStatus {
                chapter: MicroDollars::zero(),
                run: MicroDollars::zero(),
                warning: false,
            },
            structure: None,
            plot_framework: None,
            strict_backend_errors: true,
            provisional_canon: BTreeMap::new(),
            provisional_canon_texts: BTreeMap::new(),
            run_id: prefixed_uuid(EntityKind::Run).as_str().into(),
            session: None,
            checkpoint_path: None,
            recovery_required: false,
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
        controller.request_maximum_cost = Some(MicroDollars::new(100_000));
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
        controller.load_request_maximum_from_environment();
        controller.load_request_price_from_environment();
        controller.load_declared_project_plan();
        controller
    }

    fn load_request_maximum_from_environment(&mut self) {
        let Ok(value) = std::env::var("PHEMIUS_MAX_REQUEST_MICRODOLLARS") else {
            return;
        };
        if let Ok(microdollars) = value.parse::<u64>() {
            self.request_maximum_cost = Some(MicroDollars::new(microdollars));
        }
    }

    fn load_request_price_from_environment(&mut self) {
        let (Ok(input), Ok(output)) = (
            std::env::var("PHEMIUS_INPUT_PRICE_MICRODOLLARS_PER_MILLION"),
            std::env::var("PHEMIUS_OUTPUT_PRICE_MICRODOLLARS_PER_MILLION"),
        ) else {
            return;
        };
        let Ok(input) = input.parse::<u64>() else {
            return;
        };
        let Ok(output) = output.parse::<u64>() else {
            return;
        };
        self.request_price = Some(Price {
            input_per_million: MicroDollars::new(input),
            output_per_million: MicroDollars::new(output),
        });
    }

    fn load_declared_project_plan(&mut self) {
        let Some(project) = self.project.as_ref() else {
            return;
        };
        let structure_path = project.root.join(".phemius/structure.json");
        let framework_path = project.root.join(".phemius/framework.json");
        let structure = fs::read(&structure_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<StoryStructure>(&bytes).ok());
        if let Some(structure) = structure
            && validate_structure(&structure).is_ok()
        {
            self.structure = Some(structure);
            self.preflight = PreflightReport {
                approved_scene_plan: true,
                approved_box_plan: true,
                macro_links: true,
            };
        }
        if let Ok(bytes) = fs::read(&framework_path)
            && let Ok(framework) =
                serde_json::from_slice::<crate::plot::FrameworkDefinition>(&bytes)
        {
            self.plot_framework = Some(if framework.id.starts_with("custom:") {
                framework.id
            } else {
                format!("custom:{}", framework.id)
            });
        }
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

    /// Sets optional input/output prices used to settle provider usage.
    pub fn set_request_price(&mut self, price: Option<Price>) {
        self.request_price = price;
    }

    /// Confirms the current conservative warning for the next chapter request.
    pub fn confirm_cost_warning(&mut self) {
        self.cost_warning_confirmed = true;
    }

    /// Returns a bounded cost projection for the REPL.
    pub fn cost_status(&self) -> CostStatus {
        self.cost_status
    }

    /// Records a coordinator instruction through the durable session boundary.
    ///
    /// This path never approves canon or launches a model request; executable generation remains
    /// the explicit `/write` workflow.
    pub fn record_coordinator_request(&mut self, request: impl Into<String>) -> Result<String> {
        let request = request.into();
        ensure!(!request.trim().is_empty(), "coordinator request is empty");
        if self.project.is_some() && self.session.is_none() {
            self.attach_latest_session()?;
        }
        ensure!(
            !self.recovery_required,
            "durable checkpoint requires in-memory state reconstruction; manual resolution is required"
        );
        self.ensure_durable_session()?;
        let hash = sha256_bytes(request.as_bytes());
        self.append_session_event(SessionEvent::UserInstruction {
            text: format!("coordinator: {request}"),
        })?;
        self.checkpoint(&hash)?;
        Ok(format!(
            "coordinator request recorded: {request}; canon unchanged"
        ))
    }

    /// Executes a read-only coordinator request through the selected typed role.
    pub async fn run_coordinator_request(
        &mut self,
        role: AgentRole,
        request: impl Into<String>,
    ) -> Result<String> {
        let request = request.into();
        ensure!(!request.trim().is_empty(), "coordinator request is empty");
        if self.project.is_some() && self.session.is_none() {
            self.attach_latest_session()?;
        }
        ensure!(
            !self.recovery_required,
            "durable checkpoint requires in-memory state reconstruction; manual resolution is required"
        );
        self.ensure_durable_session()?;
        self.append_session_event(SessionEvent::UserInstruction {
            text: format!("coordinator: {request}"),
        })?;
        let model_request = ModelRequest::new(
            role.name(),
            vec![ModelMessage::user(request.clone())],
            Vec::new(),
        )
        .with_model(self.model(role));
        let response = self
            .complete_model_request("coordinator", model_request)
            .await
            .map_err(model_error)?;
        let hash = sha256_bytes(response.text.as_bytes());
        self.checkpoint(&hash)?;
        Ok(response.text)
    }

    /// Opens the project-local append-only session journal and cost ledger on first use.
    ///
    /// The lazy open keeps fixture controllers in-memory while production project controllers
    /// retain crash-safe session and reservation evidence under `.phemius/records`.
    fn ensure_durable_session(&mut self) -> Result<()> {
        let Some(project) = self.project.as_ref() else {
            return Ok(());
        };
        if self.session.is_some() {
            return Ok(());
        }
        let session_relative = PathBuf::from(".phemius/records/sessions").join(&self.run_id);
        ensure_managed_directory(project, &session_relative)?;
        let records = project.root.join(&session_relative);
        let journal_path = records.join("session.jsonl");
        let session = if journal_path.exists() {
            SessionJournal::open(&journal_path)?
        } else {
            SessionJournal::create(&journal_path)?
        };
        let cost_path = records.join("cost.jsonl");
        self.cost_ledger = BudgetLedger::open(&cost_path)?;
        self.checkpoint_path = Some(records.join("checkpoint.json"));
        self.session = Some(session);
        Ok(())
    }

    fn append_session_event(&mut self, event: SessionEvent) -> Result<()> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        session.append(event)
    }

    fn checkpoint(&mut self, context_hash: &str) -> Result<()> {
        let Some(session) = self.session.as_ref() else {
            return Ok(());
        };
        let Some(path) = self.checkpoint_path.as_ref() else {
            return Ok(());
        };
        let checkpoint = Checkpoint::from_journal(
            session,
            vec![ContextEpoch {
                model: self.model(AgentRole::Writer).into(),
                checkpoint_hash: context_hash.into(),
            }],
            self.provisional_canon.values().cloned().collect(),
            Vec::new(),
            self.corrections
                .iter()
                .filter_map(|rule| EntityId::from_validated(rule.id.clone()))
                .collect(),
            self.findings
                .values()
                .filter(|finding| {
                    finding.kind.is_blocking() && finding.disposition == FindingDisposition::Open
                })
                .filter_map(|finding| EntityId::from_validated(finding.id.clone()))
                .collect(),
            self.chapter_runs
                .values()
                .filter(|run| run.state == ChapterState::NeedsRevalidation)
                .map(|run| run.changeset.id.clone())
                .collect(),
            self.cost_status.run,
        )?;
        session.write_checkpoint(path, &checkpoint)
    }

    /// Reads the latest anchored project checkpoint without resending any model request.
    pub fn resume_checkpoint(&mut self) -> Result<Option<Checkpoint>> {
        if self.session.is_none() {
            self.attach_latest_session()?;
        }
        self.ensure_durable_session()?;
        let Some(session) = self.session.as_ref() else {
            return Ok(None);
        };
        let Some(path) = self.checkpoint_path.as_ref() else {
            return Ok(None);
        };
        if !path.is_file() {
            return Ok(None);
        }
        session.read_checkpoint(path).map(Some)
    }

    fn attach_latest_session(&mut self) -> Result<()> {
        let Some(project) = self.project.as_ref() else {
            return Ok(());
        };
        let root = project.root.join(".phemius/records/sessions");
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries.collect::<std::io::Result<Vec<_>>>()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let mut candidates = entries
            .into_iter()
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(|file_type| file_type.is_dir())
                    .map(|_| entry.path())
            })
            .filter(|path| {
                path.join("session.jsonl").is_file() && path.join("cost.jsonl").is_file()
            })
            .collect::<Vec<_>>();
        candidates.sort();
        let Some(session_dir) = candidates.pop() else {
            return Ok(());
        };
        let checkpoint_path = session_dir.join("checkpoint.json");
        if !checkpoint_path.is_file() {
            bail!(
                "unfinished session {} has no durable checkpoint; manual resolution is required",
                session_dir.display()
            );
        }
        let journal_path = session_dir.join("session.jsonl");
        let cost_path = session_dir.join("cost.jsonl");
        self.session = Some(SessionJournal::open(&journal_path)?);
        self.cost_ledger = BudgetLedger::open(&cost_path)?;
        self.checkpoint_path = Some(checkpoint_path);
        self.recovery_required = true;
        Ok(())
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
        let finding_entity = EntityId::from_validated(finding_id.to_owned())
            .ok_or_else(|| anyhow!("finding ID is invalid: {finding_id}"))?;
        let reason_hash = sha256_bytes(reason.as_bytes());
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
        if self.project.is_some() {
            self.ensure_durable_session()?;
        }
        self.append_session_event(SessionEvent::FindingResolved {
            finding_id: finding_entity,
            reason_hash: reason_hash.clone(),
        })?;
        self.checkpoint(&reason_hash)?;
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
        let candidate_operations = run
            .changeset
            .operations
            .iter()
            .filter(|operation| operation.path.to_string_lossy().starts_with("本文/"))
            .filter_map(|operation| operation.candidate_path.clone())
            .collect::<Vec<_>>();
        let project = self.project.clone();
        let candidate_text = run.candidate_text.clone();
        let mut candidate_hash = hash;
        if let Some(project) = project {
            let mut updated_hashes = BTreeMap::new();
            for candidate_path in candidate_operations {
                let current = read_project_file(&project, &candidate_path)?;
                let revised = replace_candidate_body(current, &candidate_text);
                write_replaced_project_file(&project, &candidate_path, &revised)?;
                updated_hashes.insert(candidate_path, sha256_bytes(&revised));
            }
            let run = self
                .chapter_runs
                .get_mut(chapter_id)
                .expect("candidate was checked above");
            for operation in &mut run.changeset.operations {
                if let Some(candidate_path) = operation.candidate_path.as_ref()
                    && let Some(after_sha256) = updated_hashes.get(candidate_path)
                {
                    operation.after_sha256 = Some(after_sha256.clone());
                }
            }
            let recalculated = self
                .chapter_runs
                .get(chapter_id)
                .map(|candidate| calculate_candidate_hash(&project, &candidate.changeset))
                .transpose()
                .map_err(anyhow::Error::new)?;
            if let Some(recalculated) = recalculated {
                let run = self
                    .chapter_runs
                    .get_mut(chapter_id)
                    .expect("candidate was checked above");
                run.changeset.candidate_hash = recalculated;
                candidate_hash = run.changeset.candidate_hash.clone();
            }
        }
        self.provisional_canon
            .insert(chapter_id.into(), candidate_hash);
        self.provisional_canon_texts
            .insert(chapter_id.into(), candidate_text);
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
        let rule_id = EntityId::from_validated(rule.id.clone())
            .ok_or_else(|| anyhow!("generated correction rule ID is invalid"))?;
        if self.project.is_some() {
            self.ensure_durable_session()?;
        }
        self.corrections.push(rule.clone());
        self.note_upstream_edit(source_chapter)?;
        self.append_session_event(SessionEvent::CorrectionAccepted {
            rule_id,
            source_chapter: source_chapter.into(),
            hash: rule.hash.clone(),
        })?;
        self.checkpoint(&rule.hash)?;
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
            self.provisional_canon_texts.remove(&chapter.id);
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
        let (changeset_id, context_hash) = {
            let run = self
                .chapter_runs
                .get_mut(chapter_id)
                .expect("checked above");
            run.state = ChapterState::Approved;
            run.changeset = change;
            run.changeset.state = ChangesetState::Approved;
            (run.changeset.id.clone(), run.context_receipt_hash.clone())
        };
        self.ensure_durable_session()?;
        self.append_session_event(SessionEvent::ChangesetStateChanged {
            id: changeset_id,
            state: ChangesetState::Approved,
        })?;
        self.checkpoint(&context_hash)?;
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
                let chapter_scene_ids = structure
                    .scenes
                    .iter()
                    .filter(|scene| scene.chapter_id == chapter_id)
                    .map(|scene| scene.id.as_str())
                    .collect::<BTreeSet<_>>();
                ensure!(
                    !chapter_scene_ids.is_empty(),
                    "chapter {chapter_id} has no approved scenes"
                );
                for scene_id in &chapter_scene_ids {
                    ensure!(
                        structure
                            .boxes
                            .iter()
                            .any(|box_| box_.scene_id == *scene_id),
                        "scene {scene_id} has no approved box link"
                    );
                    ensure!(
                        structure
                            .macro_beats
                            .iter()
                            .any(|beat| beat.scene_ids.iter().any(|linked| linked == *scene_id)),
                        "scene {scene_id} has no approved macro link"
                    );
                }
                ensure!(
                    self.plot_framework.is_some(),
                    "a declarative plot framework is required"
                );
            }
        }
        if self.request_maximum_cost.is_none() {
            bail!("unknown model price; generation is stopped");
        }
        let maximum = self
            .request_maximum_cost
            .expect("request maximum was checked above");
        let maximum_calls = 2usize
            .saturating_add(AgentSpec::critic_roles().len())
            .saturating_add(
                self.max_revisions
                    .saturating_mul(1usize.saturating_add(AgentSpec::critic_roles().len())),
            );
        let estimated_cost = maximum
            .as_u64()
            .checked_mul(maximum_calls as u64)
            .ok_or_else(|| anyhow!("chapter cost arithmetic overflow"))?;
        ensure!(
            estimated_cost <= 10_000_000,
            "chapter budget hard stop at $10 before model reservation"
        );
        if !self.cost_warning_confirmed && estimated_cost > 5_000_000 {
            return Err(CostConfirmationRequired {
                chapter_id: chapter_id.into(),
                estimated_cost: MicroDollars::new(estimated_cost),
            }
            .into());
        }
        self.cost_warning_confirmed = false;
        if self.project.is_some() && self.session.is_none() {
            self.attach_latest_session()?;
        }
        ensure!(
            !self.recovery_required,
            "durable checkpoint requires in-memory state reconstruction; manual resolution is required"
        );
        self.ensure_durable_session()?;
        self.append_session_event(SessionEvent::UserInstruction {
            text: format!("write chapter {chapter_id}"),
        })?;
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
        self.cost_status.chapter = MicroDollars::zero();
        self.cost_status.warning = false;
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
        let architect_plan = match self
            .complete_model_request(chapter_id, architect_request)
            .await
        {
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
        let provisional_canon_texts = self
            .chapters
            .values()
            .filter(|chapter| chapter.order < chapter_order)
            .filter_map(|chapter| {
                self.provisional_canon_texts
                    .get(&chapter.id)
                    .map(|text| (chapter.id.clone(), text.clone()))
            })
            .collect::<Vec<_>>();
        let correction_receipts = self.correction_receipt(chapter_id);
        let (compiled_context, context_receipt) = self
            .compile_project_context(chapter_id, AgentRole::Writer)
            .map_err(|error| anyhow!("context compilation stopped: {error}"))?;
        let mut role_context_receipts = BTreeMap::new();
        if let Some(receipt) = context_receipt.clone() {
            role_context_receipts.insert(AgentRole::Writer.name().into(), receipt);
        }
        let context_receipt_json = context_receipt
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .context("failed to serialize context receipt")?
            .unwrap_or_default();
        let writer_request = ModelRequest::new(
            AgentRole::Writer.name(),
            vec![ModelMessage::user(format!(
                "Write chapter {chapter_id}. Approved scene and box plans are required.\n\nArchitect plan: {architect_plan}\n\nCompiled source context (use only as evidence):\n{compiled_context}\n\nContext receipt: {context_receipt_json}\n\nProvisional canon hashes: {}\n\nProvisional canon candidate prose (run-local, not approved canon): {}\n\nCorrections: {}",
                provisional_canon_hashes
                    .iter()
                    .map(|(id, hash)| format!("{id}={hash}"))
                    .collect::<Vec<_>>()
                    .join(","),
                provisional_canon_texts
                    .iter()
                    .map(|(id, text)| format!("--- {id} ---\n{text}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                correction_receipts
                    .iter()
                    .map(|receipt| receipt.directive.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            ))],
            Vec::new(),
        )
        .with_model(self.model(AgentRole::Writer));
        trace.writer_calls = 1;
        let writer_text = match self
            .complete_model_request(chapter_id, writer_request)
            .await
        {
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
                &compiled_context,
                context_receipt.as_ref(),
                &architect_plan,
                &correction_receipts,
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
                let (role_context, role_receipt) = self
                    .compile_project_context(chapter_id, *role)
                    .map_err(|error| anyhow!("context compilation stopped: {error}"))?;
                if let Some(receipt) = role_receipt {
                    role_context_receipts.insert(role.name().into(), receipt.clone());
                }
                let role_receipt_json = role_context_receipts
                    .get(role.name())
                    .map(serde_json::to_string)
                    .transpose()
                    .context("failed to serialize role context receipt")?
                    .unwrap_or_default();
                trace.roles.push(*role);
                trace.critic_calls += 1;
                specs.push((
                    *role,
                    format!(
                        "Review candidate chapter {chapter_id} without editing it.\n\nImmutable candidate:\n{candidate_text}\n\nRole-specific compiled source context:\n{role_context}\n\nRole-specific context receipt:\n{role_receipt_json}\n\nImmutable context facts: provisional canon hashes={provisional_canon_hashes:?}; corrections={correction_receipts:?}. Report typed evidence as FINDING|kind|artifact|start|end|message."
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
            let (reviser_context, reviser_receipt) = self
                .compile_project_context(chapter_id, AgentRole::Reviser)
                .map_err(|error| anyhow!("context compilation stopped: {error}"))?;
            if let Some(receipt) = reviser_receipt {
                role_context_receipts.insert(AgentRole::Reviser.name().into(), receipt);
            }
            let reviser_receipt_json = role_context_receipts
                .get(AgentRole::Reviser.name())
                .map(serde_json::to_string)
                .transpose()
                .context("failed to serialize reviser context receipt")?
                .unwrap_or_default();
            let required_facts = format!(
                "role-specific compiled source context:\n{reviser_context}\n\nrole-specific context receipt:\n{reviser_receipt_json}\n\nprovisional canon hashes={provisional_canon_hashes:?}; correction receipts={correction_receipts:?}"
            );
            let request = ModelRequest::new(
                AgentRole::Reviser.name(),
                vec![ModelMessage::user(format!(
                    "Revise only this candidate prose and preserve every approved fact.\n\nCandidate:\n{candidate_text}\n\nTyped findings:\n{typed_findings}\n\nRequired facts and correction directives:\n{required_facts}"
                ))],
                Vec::new(),
            )
            .with_model(self.model(AgentRole::Reviser));
            match self.complete_model_request(chapter_id, request).await {
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
                            let (role_context, role_receipt) = self
                                .compile_project_context(chapter_id, *role)
                                .map_err(|error| anyhow!("context compilation stopped: {error}"))?;
                            if let Some(receipt) = role_receipt {
                                role_context_receipts.insert(role.name().into(), receipt.clone());
                            }
                            let role_receipt_json = role_context_receipts
                                .get(role.name())
                                .map(serde_json::to_string)
                                .transpose()
                                .context("failed to serialize role context receipt")?
                                .unwrap_or_default();
                            trace.roles.push(*role);
                            trace.critic_calls += 1;
                            specs.push((
                                *role,
                                format!(
                                    "Re-review this revised immutable candidate chapter {chapter_id}; report only current typed evidence as FINDING|kind|artifact|start|end|message.\n\nCandidate:\n{candidate_text}\n\nRole-specific source context:\n{role_context}\n\nRole-specific context receipt:\n{role_receipt_json}\n\nCorrection directives:\n{correction_receipts:?}"
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
        let context_base_hash = context_receipt
            .as_ref()
            .and_then(|receipt| receipt.context_sha256().map(str::to_owned))
            .unwrap_or_else(|| {
                sha256_bytes(
                    format!(
                        "{chapter_id}:{candidate_hash}:{:?}:{:?}",
                        provisional_canon_hashes, correction_receipts
                    )
                    .as_bytes(),
                )
            });
        let context_receipt_hash = sha256_bytes(
            &serde_json::to_vec(&(context_base_hash, &correction_receipts))
                .context("failed to serialize context receipt hash material")?,
        );
        self.provisional_canon
            .insert(chapter_id.into(), candidate_hash);
        self.provisional_canon_texts
            .insert(chapter_id.into(), candidate_text.clone());
        let run = ChapterRun {
            chapter_id: chapter_id.into(),
            changeset,
            state,
            trace,
            findings,
            correction_receipts,
            provisional_canon_hashes,
            provisional_canon_texts,
            context_receipt_hash,
            context_receipt,
            role_context_receipts,
            candidate_text,
            preflight: self.preflight.clone(),
        };
        self.chapter_runs.insert(chapter_id.into(), run.clone());
        self.chapters
            .get_mut(chapter_id)
            .expect("chapter was registered")
            .state = state;
        self.refresh_chapter_states();
        self.append_session_event(SessionEvent::ChangesetStateChanged {
            id: run.changeset.id.clone(),
            state: run.changeset.state,
        })?;
        self.checkpoint(&run.context_receipt_hash)?;
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
            let reservation = self.reserve_request(chapter_id)?;
            let context_hash = request_context_hash(&request);
            self.append_session_event(SessionEvent::ModelCallStarted {
                request_id: reservation.request_id.clone(),
                context_hash,
            })?;
            requests.push((*role, request, self.backend.parallel_clone(), reservation));
        }
        let mut results = stream::iter(requests)
            .map(|(role, request, mut backend, reservation)| async move {
                let result = backend.complete(request).await;
                (role, reservation, result)
            })
            .buffer_unordered(3)
            .collect::<Vec<_>>()
            .await;
        for (_, reservation, result) in &results {
            match result {
                Ok(response) => self.record_model_completion(reservation, response)?,
                Err(error) if error.class() == ModelFailureClass::Ambiguous => {
                    self.append_session_event(SessionEvent::ModelCallAmbiguous {
                        request_id: reservation.request_id.clone(),
                        reserved_cost: reservation.reserved_cost,
                    })?;
                }
                Err(_) => {}
            }
        }
        results.sort_by_key(|(role, _, _)| {
            specs
                .iter()
                .position(|(expected, _)| expected == role)
                .unwrap_or(usize::MAX)
        });
        Ok(results
            .into_iter()
            .map(|(role, _, result)| (role, result))
            .collect())
    }

    fn reserve_request(&mut self, chapter_id: &str) -> Result<Reservation> {
        let maximum = self
            .request_maximum_cost
            .ok_or_else(|| anyhow!("unknown model price; generation is stopped"))?;
        let chapter_after = self
            .cost_status
            .chapter
            .as_u64()
            .checked_add(maximum.as_u64())
            .ok_or_else(|| anyhow!("chapter cost arithmetic overflow"))?;
        let run_after = self
            .cost_status
            .run
            .as_u64()
            .checked_add(maximum.as_u64())
            .ok_or_else(|| anyhow!("run cost arithmetic overflow"))?;
        ensure!(
            chapter_after <= 10_000_000,
            "chapter budget hard stop at $10 before model reservation"
        );
        ensure!(
            run_after <= 120_000_000,
            "continuous run budget hard stop at $120 before model reservation"
        );
        let reservation = self.cost_ledger.reserve(chapter_id, maximum)?;
        self.cost_ledger.retain_ambiguous(&reservation)?;
        self.cost_status.chapter = self.cost_status.chapter.checked_add_for_work(maximum)?;
        self.cost_status.run = self.cost_status.run.checked_add_for_work(maximum)?;
        self.cost_status.warning |= reservation.warning_required;
        Ok(reservation)
    }

    async fn complete_model_request(
        &mut self,
        chapter_id: &str,
        request: ModelRequest,
    ) -> ModelResult<ModelResponse> {
        let reservation = self
            .reserve_request(chapter_id)
            .map_err(|error| crate::model::ModelFailure::stopped(error.to_string()))?;
        self.append_session_event(SessionEvent::ModelCallStarted {
            request_id: reservation.request_id.clone(),
            context_hash: request_context_hash(&request),
        })
        .map_err(|error| crate::model::ModelFailure::stopped(error.to_string()))?;
        match self.backend.complete(request).await {
            Ok(response) => {
                self.record_model_completion(&reservation, &response)
                    .map_err(|error| crate::model::ModelFailure::stopped(error.to_string()))?;
                Ok(response)
            }
            Err(error) if error.class() == ModelFailureClass::Ambiguous => {
                self.append_session_event(SessionEvent::ModelCallAmbiguous {
                    request_id: reservation.request_id,
                    reserved_cost: reservation.reserved_cost,
                })
                .map_err(|event_error| {
                    crate::model::ModelFailure::stopped(event_error.to_string())
                })?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    fn record_model_completion(
        &mut self,
        reservation: &Reservation,
        response: &ModelResponse,
    ) -> Result<()> {
        let Some(usage) = response.usage else {
            return self.cost_ledger.retain_ambiguous(reservation);
        };
        self.append_session_event(SessionEvent::ModelCallCompleted {
            request_id: reservation.request_id.clone(),
            usage,
        })?;
        let Some(price) = self.request_price else {
            return self.cost_ledger.retain_ambiguous(reservation);
        };
        let actual = price.cost_for(usage)?;
        self.cost_ledger.settle(reservation, actual)?;
        let delta = reservation
            .reserved_cost
            .as_u64()
            .saturating_sub(actual.as_u64());
        self.cost_status.chapter = MicroDollars::new(
            self.cost_status
                .chapter
                .as_u64()
                .checked_sub(delta)
                .ok_or_else(|| anyhow!("chapter cost settlement underflow"))?,
        );
        self.cost_status.run = MicroDollars::new(
            self.cost_status
                .run
                .as_u64()
                .checked_sub(delta)
                .ok_or_else(|| anyhow!("run cost settlement underflow"))?,
        );
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

    fn compile_project_context(
        &self,
        chapter_id: &str,
        role: AgentRole,
    ) -> Result<(String, Option<ContextReceipt>)> {
        let Some(project) = self.project.as_ref() else {
            return Ok((String::new(), None));
        };
        let Some(target) = EntityId::from_validated(chapter_id.to_owned()) else {
            // Fixture project runs may use human-readable chapter labels. Production projects
            // use validated chapter IDs and therefore receive the complete source projection.
            return Ok((String::new(), None));
        };
        let manifest_bytes = read_project_file(project, Path::new("資料/manifest.md"))?;
        let manifest = ManifestDocument::parse(&manifest_bytes)
            .map_err(|error| anyhow!("source manifest validation failed: {error}"))?;
        let mut snapshots = Vec::new();
        for entry in manifest.manifest().entries() {
            if entry.snapshot.ephemeral {
                continue;
            }
            let raw_path = entry.snapshot.raw_artifact.as_deref().ok_or_else(|| {
                anyhow!("source {} has no raw artifact", entry.source_id.as_str())
            })?;
            let content_path = entry.snapshot.content_artifact.as_deref().ok_or_else(|| {
                anyhow!(
                    "source {} has no content artifact",
                    entry.source_id.as_str()
                )
            })?;
            let Some(raw) = read_project_file_optional(project, raw_path)? else {
                continue;
            };
            let Some(content) = read_project_file_optional(project, content_path)? else {
                continue;
            };
            snapshots.push(
                Snapshot::from_artifacts(entry.kind, raw, content, false, entry.web.clone())
                    .map_err(|error| {
                        anyhow!(
                            "source {} snapshot is invalid: {error}",
                            entry.source_id.as_str()
                        )
                    })?,
            );
        }
        let mut compiler = ContextCompiler::new(manifest.manifest().clone(), snapshots)
            .map_err(|error| anyhow!("source manifest cannot compile: {error}"))?;
        if let Some(structure) = self.structure.clone() {
            compiler = compiler.with_structure(structure);
        }
        let request = ContextRequest {
            target,
            role: role.name().into(),
            budget_tokens: 1_000_000,
            requested_output_tokens: 20_000,
        };
        let compiled = compiler
            .compile(&request)
            .map_err(|error| anyhow!("{}", error))?;
        let transmitted = compiler
            .handoff(compiled)
            .map_err(|error| anyhow!("context handoff stopped: {error}"))?;
        let (text, receipt) = transmitted.into_parts();
        Ok((text, Some(receipt)))
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
                chapter.order >= target_chapter.order
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

fn request_context_hash(request: &ModelRequest) -> String {
    let mut bytes = Vec::new();
    for message in &request.messages {
        bytes.extend_from_slice(message.role.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(message.content.as_bytes());
        bytes.push(0xff);
    }
    sha256_bytes(&bytes)
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
    compiled_context: &str,
    context_receipt: Option<&ContextReceipt>,
    architect_plan: &str,
    correction_receipts: &[CorrectionReceipt],
    dependencies: Vec<ChangesetDependency>,
) -> Result<PreparedChange> {
    let base_root_hash = canon_root_hash(project).map_err(anyhow::Error::new)?;
    let candidate_root = PathBuf::from(".phemius/runtime/candidates").join(changeset_id.as_str());
    ensure_managed_directory(project, &candidate_root)?;
    sync_managed_directory(project, &candidate_root)?;

    let chapter_entity = prefixed_uuid(EntityKind::Chapter);
    let mut operations = Vec::new();
    let mut add_artifact = |target: PathBuf,
                            file_name: &str,
                            candidate: Vec<u8>,
                            entity: crate::domain::EntityId|
     -> Result<()> {
        let existing = read_project_file_optional(project, &target)?;
        let candidate_relative = PathBuf::from(".phemius/runtime/candidates")
            .join(changeset_id.as_str())
            .join(file_name);
        write_new_project_file(project, &candidate_relative, &candidate)?;
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
    let manuscript = match read_project_file_optional(project, &manuscript_target)? {
        Some(bytes) => append_candidate(bytes, writer_text),
        None => format!("---\nid: {}\n---\n{}", chapter_entity.as_str(), writer_text).into_bytes(),
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
        let base = read_project_file(project, &target_path)
            .with_context(|| format!("required canon artifact is missing: {target}"))?;
        add_artifact(
            target_path,
            file_name,
            append_candidate(base, writer_text),
            entity,
        )?;
    }

    let character_entity = prefixed_uuid(EntityKind::Character);
    add_artifact(
        PathBuf::from(format!(
            "前提/キャラクター設定/{}.md",
            character_entity.as_str()
        )),
        "character.md",
        format!(
            "---\nid: {}\n---\n# character\n\nGenerated character state for {chapter_id}.\n",
            character_entity.as_str()
        )
        .into_bytes(),
        character_entity,
    )?;

    for (file_name, suffix, body) in [
        (
            "context.md",
            "context receipt",
            format!(
                "{}\n\n# compiled context\n{}\n\n# correction receipts\n{}",
                context_receipt
                    .map(|receipt| serde_json::to_string(receipt))
                    .transpose()
                    .context("failed to serialize context receipt")?
                    .unwrap_or_default(),
                compiled_context,
                serde_json::to_string(correction_receipts)
                    .context("failed to serialize correction receipts")?
            ),
        ),
        ("critique.md", "critic summary", "critics pending".into()),
        ("basis.md", "generation basis", architect_plan.to_owned()),
    ] {
        let entity = prefixed_uuid(EntityKind::Rule);
        add_artifact(
            PathBuf::from(format!("メモ/{chapter_id}-{file_name}")),
            file_name,
            format!("---\nid: {}\n---\n# {suffix}\n\n{body}\n", entity.as_str(),).into_bytes(),
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
    sync_managed_directory(project, &candidate_root)?;
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
        if !operation.path.to_string_lossy().starts_with("本文/") {
            continue;
        }
        let Some(candidate_path) = operation.candidate_path.as_ref() else {
            continue;
        };
        let current = read_project_file(project, candidate_path)
            .with_context(|| format!("failed to read candidate {}", candidate_path.display()))?;
        let revised = replace_candidate_body(current, candidate_text);
        write_replaced_project_file(project, candidate_path, &revised)?;
        operation.after_sha256 = Some(sha256_bytes(&revised));
    }
    sync_managed_directory(
        project,
        &PathBuf::from(".phemius/runtime/candidates").join(changeset_id.as_str()),
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

fn read_project_file(project: &Project, relative: &Path) -> Result<Vec<u8>> {
    let root = crate::changeset::open_project_root_io(&project.root)
        .with_context(|| format!("failed to open project root {}", project.root.display()))?;
    let pinned = crate::changeset::open_pinned_path_io(&root, relative)
        .with_context(|| format!("failed to open managed path {}", relative.display()))?;
    crate::changeset::read_regular_at_io(&pinned.parent, &pinned.leaf)
        .with_context(|| format!("failed to read managed path {}", relative.display()))
}

fn read_project_file_optional(project: &Project, relative: &Path) -> Result<Option<Vec<u8>>> {
    match read_project_file(project, relative) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn ensure_managed_directory(project: &Project, relative: &Path) -> Result<()> {
    ensure!(
        !relative.is_absolute(),
        "managed directory must be relative"
    );
    let root = crate::changeset::open_project_root_io(&project.root)
        .with_context(|| format!("failed to open project root {}", project.root.display()))?;
    let mut current = root;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            bail!("managed directory contains an unsafe path component");
        };
        let next = match crate::changeset::open_dir_no_follow_io(&current, name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match current.create_dir(name) {
                    Ok(()) => sync_cap_directory(&current)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(anyhow!(error)),
                }
                crate::changeset::open_dir_no_follow_io(&current, name)?
            }
            Err(error) => return Err(anyhow!(error)),
        };
        current = next;
    }
    sync_cap_directory(&current)
}

fn write_new_project_file(project: &Project, relative: &Path, bytes: &[u8]) -> Result<()> {
    let root = crate::changeset::open_project_root_io(&project.root)
        .with_context(|| format!("failed to open project root {}", project.root.display()))?;
    let pinned = crate::changeset::open_pinned_path_io(&root, relative)
        .with_context(|| format!("failed to open managed path {}", relative.display()))?;
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = pinned
        .parent
        .open_with(&pinned.leaf, &options)
        .with_context(|| format!("failed to create managed path {}", relative.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write managed path {}", relative.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync managed path {}", relative.display()))
}

fn write_replaced_project_file(project: &Project, relative: &Path, bytes: &[u8]) -> Result<()> {
    let root = crate::changeset::open_project_root_io(&project.root)
        .with_context(|| format!("failed to open project root {}", project.root.display()))?;
    let pinned = crate::changeset::open_pinned_path_io(&root, relative)
        .with_context(|| format!("failed to open managed path {}", relative.display()))?;
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = pinned
        .parent
        .open_with(&pinned.leaf, &options)
        .with_context(|| format!("failed to rewrite managed path {}", relative.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write managed path {}", relative.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync managed path {}", relative.display()))
}

fn sync_managed_directory(project: &Project, relative: &Path) -> Result<()> {
    let root = crate::changeset::open_project_root_io(&project.root)
        .with_context(|| format!("failed to open project root {}", project.root.display()))?;
    let mut current = root;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            bail!("managed directory contains an unsafe path component");
        };
        current = crate::changeset::open_dir_no_follow_io(&current, name)?;
    }
    sync_cap_directory(&current)
}

fn sync_cap_directory(directory: &Dir) -> Result<()> {
    directory
        .try_clone()
        .map_err(anyhow::Error::new)?
        .into_std_file()
        .sync_all()
        .map_err(anyhow::Error::new)
}
