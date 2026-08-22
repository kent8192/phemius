//! Deterministic chapter orchestration and human approval state.
//!
//! Models in this module can propose candidate bytes and typed findings, but they never
//! mutate the canonical project.  The only path to an approved chapter is the trusted REPL
//! branch in [`crate::repl`].

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail, ensure};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use unicode_segmentation::UnicodeSegmentation;

use crate::{
    changeset::{
        Changeset, ChangesetState, FileOperation, OperationKind, calculate_validation_hash,
        sha256_bytes,
    },
    cli::ReplMode,
    cost::{BudgetLedger, MicroDollars},
    domain::{EntityKind, prefixed_uuid},
    model::{ModelBackend, ModelFailureClass, ModelMessage, ModelRequest, ScriptedModel},
    plot::{StoryStructure, builtin_framework, validate_structure},
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
            id: prefixed_uuid(EntityKind::Finding).as_str().into(),
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
    model_by_role: BTreeMap<AgentRole, String>,
    chapters: BTreeMap<String, ChapterRecord>,
    chapter_runs: BTreeMap<String, ChapterRun>,
    findings: BTreeMap<String, Finding>,
    finding_chapters: BTreeMap<String, String>,
    corrections: Vec<CorrectionRule>,
    preflight: PreflightReport,
    strict_preflight: bool,
    length_unit: LengthUnit,
    min_length: usize,
    max_length: usize,
    max_critics: usize,
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
            model_by_role,
            chapters: BTreeMap::new(),
            chapter_runs: BTreeMap::new(),
            findings: BTreeMap::new(),
            finding_chapters: BTreeMap::new(),
            corrections: Vec::new(),
            preflight: PreflightReport::default(),
            strict_preflight: true,
            length_unit: LengthUnit::Graphemes,
            min_length: 8_000,
            max_length: 12_000,
            max_critics: 3,
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
        controller.min_length = 0;
        controller.max_length = usize::MAX;
        controller.strict_backend_errors = false;
        controller.register_chapter("chapter_1", 1, ChapterState::Planned);
        controller
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
        }
        finding
    }

    /// Resolves exactly one finding through the trusted false-positive branch.
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
        }
        self.refresh_chapter_states();
        Ok(())
    }

    /// Changes candidate bytes and invalidates all findings tied to the old hash.
    pub fn edit_candidate(&mut self, chapter_id: &str, candidate: impl AsRef<[u8]>) -> Result<()> {
        let hash = sha256_bytes(candidate.as_ref());
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
        let scope = match scope.as_ref() {
            "location" => CorrectionScope::Location,
            "character" => CorrectionScope::Character,
            "scene" => CorrectionScope::Scene,
            "chapter" => CorrectionScope::Chapter,
            "project" => CorrectionScope::Project,
            _ => bail!("unknown correction scope"),
        };
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
                source_order < chapter_order
                    && (rule.scope == CorrectionScope::Project || rule.target.is_some())
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
        Ok(())
    }

    /// Human approval in chapter order.  LLM and natural-language paths cannot call this.
    pub fn approve_chapter(&mut self, _chapter_id: &str) -> Result<()> {
        bail!("chapter approval is human-only; use the trusted /approve command")
    }

    /// Rejects one candidate through the trusted REPL branch.
    pub(crate) fn reject_chapter_trusted(&mut self, chapter_id: &str) -> Result<()> {
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
        let chapter = self.chapters.get_mut(chapter_id).expect("checked above");
        chapter.state = ChapterState::Approved;
        let run = self
            .chapter_runs
            .get_mut(chapter_id)
            .expect("checked above");
        run.state = ChapterState::Approved;
        run.changeset.state = ChangesetState::Approved;
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
        self.chapters
            .get_mut(chapter_id)
            .expect("chapter was registered")
            .state = ChapterState::Running;

        let mut trace = WorkflowTrace::default();
        trace.roles.push(AgentRole::StoryArchitect);
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
                "Write chapter {chapter_id}. Approved scene and box plans are required. Provisional canon hashes: {}. Corrections: {}",
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
        let candidate_hash = sha256_bytes(writer_text.as_bytes());

        let mut findings = Vec::new();
        let critic_count = self.max_critics.min(AgentSpec::critic_roles().len());
        trace.max_parallel_critics = critic_count;
        let role_order = AgentSpec::critic_roles()[..critic_count].to_vec();
        let mut critic_requests = Vec::with_capacity(role_order.len());
        for role in &role_order {
            trace.roles.push(*role);
            trace.critic_calls += 1;
            let request = ModelRequest::new(
                role.name(),
                vec![ModelMessage::user(format!(
                    "Review candidate chapter {chapter_id} without editing it."
                ))],
                Vec::new(),
            )
            .with_model(self.model(*role));
            self.reserve_request(chapter_id)?;
            critic_requests.push((*role, request, self.backend.clone()));
        }
        let strict_backend_errors = self.strict_backend_errors;
        let mut critic_results = stream::iter(critic_requests)
            .map(|(role, request, mut backend)| async move {
                let result = backend.complete(request).await;
                (role, result)
            })
            .buffer_unordered(3)
            .collect::<Vec<_>>()
            .await;
        critic_results.sort_by_key(|(role, _)| role_order.iter().position(|item| item == role));
        for (role, result) in critic_results {
            match result {
                Ok(response) => {
                    findings.extend(parse_findings(&response.text, role, &candidate_hash))
                }
                Err(error)
                    if !strict_backend_errors && error.class() == ModelFailureClass::Stopped => {}
                Err(error) => return Err(model_error(error)),
            }
        }
        let existing_findings = self
            .findings
            .iter()
            .filter(|(id, _)| {
                self.finding_chapters.get(*id).map(String::as_str) == Some(chapter_id)
            })
            .map(|(_, finding)| finding.clone())
            .collect::<Vec<_>>();
        for finding in existing_findings {
            if !findings.iter().any(|item: &Finding| item.id == finding.id) {
                findings.push(finding);
            }
        }
        findings.sort_by_key(|finding| finding.id.clone());
        for finding in &findings {
            self.finding_chapters
                .insert(finding.id.clone(), chapter_id.into());
            self.findings.insert(finding.id.clone(), finding.clone());
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
            let request = ModelRequest::new(
                AgentRole::Reviser.name(),
                vec![ModelMessage::user(
                    "Revise only the candidate; preserve approved facts.",
                )],
                Vec::new(),
            )
            .with_model(self.model(AgentRole::Reviser));
            self.reserve_request(chapter_id)?;
            match self.backend.complete(request).await {
                Ok(response) if !response.text.is_empty() => {}
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
            &writer_text,
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
        let id = prefixed_uuid(EntityKind::Changeset);
        let chapter_entity = prefixed_uuid(EntityKind::Chapter);
        let manuscript_path = std::path::PathBuf::from(format!("本文/{chapter_id}.md"));
        let candidate_path =
            std::path::PathBuf::from(format!(".phemius/runtime/candidates/{chapter_id}.md"));
        let operations = vec![
            FileOperation {
                kind: OperationKind::Replace,
                path: manuscript_path,
                before_sha256: Some(sha256_bytes(b"")),
                after_sha256: Some(candidate_hash.clone()),
                candidate_path: Some(candidate_path),
                affected_entities: vec![chapter_entity.clone()],
            },
            FileOperation {
                kind: OperationKind::Replace,
                path: std::path::PathBuf::from("前提/時系列.md"),
                before_sha256: Some(sha256_bytes(b"")),
                after_sha256: Some(candidate_hash.clone()),
                candidate_path: Some(std::path::PathBuf::from(format!(
                    ".phemius/runtime/candidates/{chapter_id}-timeline.md"
                ))),
                affected_entities: vec![chapter_entity.clone()],
            },
            FileOperation {
                kind: OperationKind::Replace,
                path: std::path::PathBuf::from("前提/伏線.md"),
                before_sha256: Some(sha256_bytes(b"")),
                after_sha256: Some(candidate_hash.clone()),
                candidate_path: Some(std::path::PathBuf::from(format!(
                    ".phemius/runtime/candidates/{chapter_id}-foreshadowing.md"
                ))),
                affected_entities: vec![chapter_entity],
            },
        ];
        let mut changeset = Changeset {
            id,
            parent_changeset_id: None,
            base_root_hash: sha256_bytes(self.run_id.as_bytes()),
            content_result_hash: candidate_hash.clone(),
            result_root_hash: candidate_hash.clone(),
            state: changeset_state,
            operations,
            candidate_hash: candidate_hash.clone(),
            validation_hash: None,
            unresolved_blocker_ids: findings
                .iter()
                .filter(|finding| finding.blocks(&candidate_hash))
                .filter_map(|finding| {
                    crate::domain::is_known_entity_id(&finding.id)
                        .then(|| prefixed_uuid(EntityKind::Finding))
                })
                .collect(),
            dependencies: Vec::new(),
            chapter_order,
        };
        changeset.validation_hash = Some(calculate_validation_hash(&changeset));
        let context_receipt_hash = sha256_bytes(
            format!(
                "{chapter_id}:{candidate_hash}:{:?}",
                provisional_canon_hashes
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
            candidate_text: writer_text,
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
            if let Some(previous) = self.chapters.get(id)
                && previous.order != index as u32 + 1
            {
                bail!("chapter order must be explicit and contiguous");
            }
            self.register_chapter(id.clone(), index as u32 + 1, ChapterState::Planned);
        }
        let mut runs = Vec::with_capacity(chapter_ids.len());
        for id in chapter_ids {
            runs.push(self.write_chapter(id).await?);
        }
        Ok(runs)
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

fn parse_findings(text: &str, role: AgentRole, candidate_hash: &str) -> Vec<Finding> {
    text.lines()
        .filter_map(|line| {
            let body = line.strip_prefix("FINDING|")?;
            let parts = body.splitn(5, '|').collect::<Vec<_>>();
            let [kind, artifact, start, end, message] = parts.as_slice() else {
                return None;
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
                _ => FindingKind::Other,
            };
            let start = start.parse().ok()?;
            let end = end.parse().ok()?;
            let mut finding = Finding::new(kind, *artifact, start, end, *message, candidate_hash);
            finding.message = format!("{}: {}", role.name(), finding.message);
            Some(finding)
        })
        .collect()
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
