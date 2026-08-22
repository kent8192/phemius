use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    ops::Range,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    domain::EntityId,
    plot::{StoryStructure, validate_structure},
    sources::{Snapshot, SourceEntry, SourceError, SourceManifest, SourceTier},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageDisposition {
    Raw,
    Compacted,
    Excluded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl ByteRange {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn is_valid_for(self, text: &str) -> bool {
        self.start <= self.end
            && self.end <= text.len()
            && text.is_char_boundary(self.start)
            && text.is_char_boundary(self.end)
    }
}

impl From<Range<usize>> for ByteRange {
    fn from(value: Range<usize>) -> Self {
        Self::new(value.start, value.end)
    }
}

#[derive(Clone)]
pub struct SourceSummary {
    pub source_id: EntityId,
    pub source_sha256: String,
    pub source_range: ByteRange,
    text: String,
}

pub struct SecretTransmission {
    source_id: EntityId,
    source_sha256: String,
}

impl SecretTransmission {
    /// Issues an opaque capability after the trusted in-process controller has recorded a human
    /// confirmation. External plugins cannot construct this capability.
    // The trusted runtime layer is added after this core module, so no in-crate production caller
    // exists in the current build yet.
    #[allow(dead_code)]
    pub(crate) fn after_human_confirmation(
        source_id: EntityId,
        source_sha256: impl Into<String>,
    ) -> Self {
        Self {
            source_id,
            source_sha256: source_sha256.into(),
        }
    }
}

impl fmt::Debug for SecretTransmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretTransmission")
            .field("source_id", &self.source_id)
            .field("source_sha256", &self.source_sha256)
            .finish()
    }
}

impl SourceSummary {
    pub fn new(
        source_id: EntityId,
        source_sha256: impl Into<String>,
        source_range: Range<usize>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            source_id,
            source_sha256: source_sha256.into(),
            source_range: source_range.into(),
            text: text.into(),
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for SourceSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceSummary")
            .field("source_id", &self.source_id)
            .field("source_sha256", &self.source_sha256)
            .field("source_range", &self.source_range)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextRequest {
    pub target: EntityId,
    pub role: String,
    /// Input capacity remaining after fixed prompt and output-token reserves.
    pub budget_tokens: u64,
    /// The already-reserved output budget retained for receipt evidence.
    pub requested_output_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextReceiptEntry {
    source_id: EntityId,
    source_sha256: String,
    disposition: CoverageDisposition,
    source_range: Option<ByteRange>,
    reason: String,
    truncated: bool,
    failure: Option<String>,
    secret_transmitted: bool,
}

impl ContextReceiptEntry {
    pub fn source_id(&self) -> &EntityId {
        &self.source_id
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    pub fn disposition(&self) -> CoverageDisposition {
        self.disposition
    }

    pub fn source_range(&self) -> Option<ByteRange> {
        self.source_range
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    pub fn secret_transmitted(&self) -> bool {
        self.secret_transmitted
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextReceipt {
    target: EntityId,
    role: String,
    budget_tokens: u64,
    requested_output_tokens: u64,
    context_sha256: Option<String>,
    entries: Vec<ContextReceiptEntry>,
}

impl ContextReceipt {
    pub fn target(&self) -> &EntityId {
        &self.target
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn budget_tokens(&self) -> u64 {
        self.budget_tokens
    }

    pub fn requested_output_tokens(&self) -> u64 {
        self.requested_output_tokens
    }

    pub fn context_sha256(&self) -> Option<&str> {
        self.context_sha256.as_deref()
    }

    pub fn entries(&self) -> &[ContextReceiptEntry] {
        &self.entries
    }
}

pub struct CompiledContext {
    text: String,
    sha256: String,
    estimated_tokens: u64,
    receipt: ContextReceipt,
    secret_reservation: SecretReservation,
}

impl CompiledContext {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }

    pub fn receipt(&self) -> &ContextReceipt {
        &self.receipt
    }

    fn verify_integrity(&self) -> Result<(), String> {
        let actual = crate::sources::sha256_bytes(self.text.as_bytes());
        if self.sha256 != actual || self.receipt.context_sha256.as_deref() != Some(actual.as_str())
        {
            return Err("compiled context hash no longer matches its payload".into());
        }
        Ok(())
    }
}

impl fmt::Debug for CompiledContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledContext")
            .field("estimated_tokens", &self.estimated_tokens)
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

pub struct TransmittedContext {
    text: String,
    sha256: String,
    receipt: ContextReceipt,
}

impl TransmittedContext {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn receipt(&self) -> &ContextReceipt {
        &self.receipt
    }

    pub fn into_parts(self) -> (String, ContextReceipt) {
        (self.text, self.receipt)
    }
}

impl fmt::Debug for TransmittedContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransmittedContext")
            .field("sha256", &self.sha256)
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ContextCompileError {
    message: String,
    receipt: ContextReceipt,
}

impl ContextCompileError {
    fn new(message: impl Into<String>, receipt: ContextReceipt) -> Self {
        Self {
            message: message.into(),
            receipt,
        }
    }

    pub fn receipt(&self) -> &ContextReceipt {
        &self.receipt
    }
}

impl fmt::Display for ContextCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ContextCompileError {}

pub struct ContextCompiler {
    manifest: SourceManifest,
    snapshots: BTreeMap<String, Snapshot>,
    summaries: BTreeMap<String, SourceSummary>,
    structure: Option<StoryStructure>,
    secret_transmissions: Arc<Mutex<SecretTransmissionState>>,
}

#[derive(Default)]
struct SecretTransmissionState {
    available: BTreeSet<(String, String)>,
    reserved: BTreeSet<(String, String)>,
}

struct SecretReservation {
    state: Arc<Mutex<SecretTransmissionState>>,
    keys: BTreeSet<(String, String)>,
    consumed: bool,
}

impl SecretReservation {
    fn empty(state: Arc<Mutex<SecretTransmissionState>>) -> Self {
        Self {
            state,
            keys: BTreeSet::new(),
            consumed: false,
        }
    }

    fn reserve(&mut self, entry: &SourceEntry, snapshot: &Snapshot) -> Result<(), String> {
        if !snapshot.is_secret() {
            return Ok(());
        }
        let key = (
            entry.source_id.as_str().to_owned(),
            entry.expected_sha256.clone(),
        );
        let mut state = self.state.lock().map_err(|_| {
            format!(
                "secret source {} cannot read its one-time confirmation state",
                entry.source_id.as_str()
            )
        })?;
        if !state.available.remove(&key) {
            return Err(format!(
                "secret source {} requires a one-time confirmation before transmission",
                entry.source_id.as_str()
            ));
        }
        state.reserved.insert(key.clone());
        self.keys.insert(key);
        Ok(())
    }

    fn consume(mut self) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| {
            "secret transmission confirmation state is unavailable during handoff".to_owned()
        })?;
        if self.keys.iter().any(|key| !state.reserved.contains(key)) {
            return Err("secret transmission reservation is no longer valid".into());
        }
        for key in &self.keys {
            state.reserved.remove(key);
        }
        self.consumed = true;
        Ok(())
    }
}

impl Drop for SecretReservation {
    fn drop(&mut self) {
        if self.consumed || self.keys.is_empty() {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            for key in &self.keys {
                if state.reserved.remove(key) {
                    state.available.insert(key.clone());
                }
            }
        }
    }
}

impl ContextCompiler {
    pub fn new(manifest: SourceManifest, snapshots: Vec<Snapshot>) -> Result<Self, SourceError> {
        manifest.validate()?;
        let mut by_hash = BTreeMap::<String, Vec<Snapshot>>::new();
        for snapshot in snapshots {
            by_hash
                .entry(snapshot.raw_sha256().to_owned())
                .or_default()
                .push(snapshot);
        }
        let mut source_snapshots = BTreeMap::new();
        for entry in manifest.entries() {
            if let Some(snapshots) = by_hash.get(&entry.expected_sha256) {
                let snapshot = snapshots
                    .iter()
                    .find(|snapshot| snapshot.matches_entry(entry))
                    .ok_or_else(|| {
                        SourceError::new(
                            crate::sources::SourceErrorKind::InvalidManifest,
                            format!(
                                "source {} snapshot metadata does not match the manifest",
                                entry.source_id.as_str()
                            ),
                        )
                    })?;
                source_snapshots.insert(entry.source_id.as_str().to_owned(), snapshot.clone());
            }
        }
        Ok(Self {
            manifest,
            snapshots: source_snapshots,
            summaries: BTreeMap::new(),
            structure: None,
            secret_transmissions: Arc::new(Mutex::new(SecretTransmissionState::default())),
        })
    }

    pub fn confirm_secret_transmission(
        &self,
        confirmation: SecretTransmission,
    ) -> Result<(), SourceError> {
        let entry = self
            .manifest
            .entries()
            .iter()
            .find(|entry| entry.source_id == confirmation.source_id)
            .ok_or_else(|| {
                SourceError::new(
                    crate::sources::SourceErrorKind::InvalidManifest,
                    "secret transmission confirmation names an unknown source",
                )
            })?;
        let snapshot = self
            .snapshots
            .get(entry.source_id.as_str())
            .ok_or_else(|| {
                SourceError::new(
                    crate::sources::SourceErrorKind::InvalidManifest,
                    "secret transmission confirmation source has no matching snapshot",
                )
            })?;
        if !snapshot.is_secret() || confirmation.source_sha256 != entry.expected_sha256 {
            return Err(SourceError::new(
                crate::sources::SourceErrorKind::InvalidManifest,
                "secret transmission confirmation does not match a secret snapshot",
            ));
        }
        let mut transmissions = self.secret_transmissions.lock().map_err(|_| {
            SourceError::new(
                crate::sources::SourceErrorKind::InvalidManifest,
                "secret transmission confirmation state is unavailable",
            )
        })?;
        let key = (
            confirmation.source_id.as_str().to_owned(),
            confirmation.source_sha256,
        );
        if transmissions.available.contains(&key) || transmissions.reserved.contains(&key) {
            return Err(SourceError::new(
                crate::sources::SourceErrorKind::InvalidManifest,
                "secret transmission confirmation was already recorded",
            ));
        }
        transmissions.available.insert(key);
        Ok(())
    }

    pub fn with_summary(mut self, summary: SourceSummary) -> Self {
        self.summaries
            .insert(summary.source_id.as_str().to_owned(), summary);
        self
    }

    pub fn with_structure(mut self, structure: StoryStructure) -> Self {
        self.structure = Some(structure);
        self
    }

    pub fn compile(
        &self,
        request: &ContextRequest,
    ) -> Result<CompiledContext, ContextCompileError> {
        let mut receipt = ContextReceipt {
            target: request.target.clone(),
            role: request.role.clone(),
            budget_tokens: request.budget_tokens,
            requested_output_tokens: request.requested_output_tokens,
            context_sha256: None,
            entries: Vec::new(),
        };
        let target_and_ancestors = match self.target_and_ancestors(request) {
            Ok(target_and_ancestors) => target_and_ancestors,
            Err(message) => {
                let mut unresolved = self.manifest.entries().iter().collect::<Vec<_>>();
                unresolved
                    .sort_by(|left, right| left.source_id.as_str().cmp(right.source_id.as_str()));
                return self.fail(message, receipt, &unresolved);
            }
        };
        let mut applicable = self
            .manifest
            .entries()
            .iter()
            .filter(|entry| entry.scope.applies_to(&target_and_ancestors, &request.role))
            .collect::<Vec<_>>();
        applicable.sort_by(|left, right| left.source_id.as_str().cmp(right.source_id.as_str()));
        let mut context = String::new();
        let mut used_tokens = 0_u64;
        let mut secret_reservation = SecretReservation::empty(self.secret_transmissions.clone());

        for tier in [
            SourceTier::RequiredRaw,
            SourceTier::Compactable,
            SourceTier::Optional,
        ] {
            for entry in applicable
                .iter()
                .copied()
                .filter(|entry| entry.tier == tier)
            {
                match tier {
                    SourceTier::RequiredRaw => {
                        let snapshot = match self.snapshot_for(entry) {
                            Ok(snapshot) => snapshot,
                            Err(message) => {
                                receipt.entries.push(failed_entry(entry, message.clone()));
                                return self.fail(message, receipt, &applicable);
                            }
                        };
                        let block = source_block(entry, snapshot.text());
                        let tokens = estimate_tokens(block.as_bytes());
                        if used_tokens.saturating_add(tokens) > request.budget_tokens {
                            let message = format!(
                                "required raw context for {} exceeds the input budget",
                                entry.source_id.as_str()
                            );
                            receipt.entries.push(failed_entry(entry, message.clone()));
                            return self.fail(message, receipt, &applicable);
                        }
                        match secret_reservation.reserve(entry, snapshot) {
                            Ok(()) => {}
                            Err(message) => {
                                receipt.entries.push(failed_entry(entry, message.clone()));
                                return self.fail(message, receipt, &applicable);
                            }
                        }
                        used_tokens += tokens;
                        context.push_str(&block);
                        receipt.entries.push(ContextReceiptEntry {
                            source_id: entry.source_id.clone(),
                            source_sha256: entry.expected_sha256.clone(),
                            disposition: CoverageDisposition::Raw,
                            source_range: Some(ByteRange::new(0, snapshot.text().len())),
                            reason: "required raw source".into(),
                            truncated: false,
                            failure: None,
                            secret_transmitted: false,
                        });
                    }
                    SourceTier::Compactable => {
                        let snapshot = match self.snapshot_for(entry) {
                            Ok(snapshot) => snapshot,
                            Err(message) => {
                                receipt.entries.push(failed_entry(entry, message.clone()));
                                return self.fail(message, receipt, &applicable);
                            }
                        };
                        if let Some(summary) = self.current_summary(entry, snapshot) {
                            let block = source_block(entry, summary.text());
                            let tokens = estimate_tokens(block.as_bytes());
                            if used_tokens.saturating_add(tokens) > request.budget_tokens {
                                let message = format!(
                                    "compactable context for {} exceeds the input budget",
                                    entry.source_id.as_str()
                                );
                                receipt.entries.push(failed_entry(entry, message.clone()));
                                return self.fail(message, receipt, &applicable);
                            }
                            used_tokens += tokens;
                            context.push_str(&block);
                            receipt.entries.push(ContextReceiptEntry {
                                source_id: entry.source_id.clone(),
                                source_sha256: entry.expected_sha256.clone(),
                                disposition: CoverageDisposition::Compacted,
                                source_range: Some(summary.source_range),
                                reason: "current source-anchored summary".into(),
                                truncated: false,
                                failure: None,
                                secret_transmitted: false,
                            });
                        } else {
                            let block = source_block(entry, snapshot.text());
                            let tokens = estimate_tokens(block.as_bytes());
                            if used_tokens.saturating_add(tokens) > request.budget_tokens {
                                let message = format!(
                                    "compactable source {} has no current summary and raw context does not fit",
                                    entry.source_id.as_str()
                                );
                                receipt.entries.push(failed_entry(entry, message.clone()));
                                return self.fail(message, receipt, &applicable);
                            }
                            match secret_reservation.reserve(entry, snapshot) {
                                Ok(()) => {}
                                Err(message) => {
                                    receipt.entries.push(failed_entry(entry, message.clone()));
                                    return self.fail(message, receipt, &applicable);
                                }
                            }
                            used_tokens += tokens;
                            context.push_str(&block);
                            receipt.entries.push(ContextReceiptEntry {
                                source_id: entry.source_id.clone(),
                                source_sha256: entry.expected_sha256.clone(),
                                disposition: CoverageDisposition::Raw,
                                source_range: Some(ByteRange::new(0, snapshot.text().len())),
                                reason:
                                    "complete raw fallback because the summary is missing or stale"
                                        .into(),
                                truncated: false,
                                failure: None,
                                secret_transmitted: false,
                            });
                        }
                    }
                    SourceTier::Optional => {
                        let Some(snapshot) = self.snapshots.get(entry.source_id.as_str()) else {
                            receipt.entries.push(ContextReceiptEntry {
                                source_id: entry.source_id.clone(),
                                source_sha256: entry.expected_sha256.clone(),
                                disposition: CoverageDisposition::Excluded,
                                source_range: None,
                                reason: "optional source snapshot is unavailable".into(),
                                truncated: false,
                                failure: Some("snapshot unavailable".into()),
                                secret_transmitted: false,
                            });
                            continue;
                        };
                        if let Some(summary) = self.current_summary(entry, snapshot) {
                            let block = source_block(entry, summary.text());
                            let tokens = estimate_tokens(block.as_bytes());
                            if used_tokens.saturating_add(tokens) <= request.budget_tokens {
                                used_tokens += tokens;
                                context.push_str(&block);
                                receipt.entries.push(ContextReceiptEntry {
                                    source_id: entry.source_id.clone(),
                                    source_sha256: entry.expected_sha256.clone(),
                                    disposition: CoverageDisposition::Compacted,
                                    source_range: Some(summary.source_range),
                                    reason: "current optional source summary".into(),
                                    truncated: false,
                                    failure: None,
                                    secret_transmitted: false,
                                });
                                continue;
                            }
                        }
                        let block = source_block(entry, snapshot.text());
                        let tokens = estimate_tokens(block.as_bytes());
                        if used_tokens.saturating_add(tokens) <= request.budget_tokens {
                            match secret_reservation.reserve(entry, snapshot) {
                                Ok(()) => {}
                                Err(message) => {
                                    receipt.entries.push(ContextReceiptEntry {
                                        source_id: entry.source_id.clone(),
                                        source_sha256: entry.expected_sha256.clone(),
                                        disposition: CoverageDisposition::Excluded,
                                        source_range: None,
                                        reason:
                                            "optional secret source lacks a one-time confirmation"
                                                .into(),
                                        truncated: false,
                                        failure: Some(message),
                                        secret_transmitted: false,
                                    });
                                    continue;
                                }
                            }
                            used_tokens += tokens;
                            context.push_str(&block);
                            receipt.entries.push(ContextReceiptEntry {
                                source_id: entry.source_id.clone(),
                                source_sha256: entry.expected_sha256.clone(),
                                disposition: CoverageDisposition::Raw,
                                source_range: Some(ByteRange::new(0, snapshot.text().len())),
                                reason: "complete optional raw fallback".into(),
                                truncated: false,
                                failure: None,
                                secret_transmitted: false,
                            });
                        } else {
                            receipt.entries.push(ContextReceiptEntry {
                                source_id: entry.source_id.clone(),
                                source_sha256: entry.expected_sha256.clone(),
                                disposition: CoverageDisposition::Excluded,
                                source_range: None,
                                reason: "optional source exceeds the remaining input budget".into(),
                                truncated: false,
                                failure: None,
                                secret_transmitted: false,
                            });
                        }
                    }
                }
            }
        }
        receipt
            .entries
            .sort_by(|left, right| left.source_id.as_str().cmp(right.source_id.as_str()));
        let sha256 = crate::sources::sha256_bytes(context.as_bytes());
        receipt.context_sha256 = Some(sha256.clone());
        Ok(CompiledContext {
            text: context,
            sha256,
            estimated_tokens: used_tokens,
            receipt,
            secret_reservation,
        })
    }

    pub fn handoff(
        &self,
        mut context: CompiledContext,
    ) -> Result<TransmittedContext, ContextCompileError> {
        if !Arc::ptr_eq(
            &context.secret_reservation.state,
            &self.secret_transmissions,
        ) {
            return Err(ContextCompileError::new(
                "compiled context was not created by this context compiler",
                context.receipt,
            ));
        }
        if let Err(message) = context.verify_integrity() {
            return Err(ContextCompileError::new(message, context.receipt));
        }
        let confirmed_secret_keys = context.secret_reservation.keys.clone();
        if let Err(message) = context.secret_reservation.consume() {
            for entry in &mut context.receipt.entries {
                let key = (
                    entry.source_id.as_str().to_owned(),
                    entry.source_sha256.clone(),
                );
                if confirmed_secret_keys.contains(&key) {
                    entry.failure = Some(message.clone());
                    entry.secret_transmitted = false;
                }
            }
            return Err(ContextCompileError::new(message, context.receipt));
        }
        for entry in &mut context.receipt.entries {
            let key = (
                entry.source_id.as_str().to_owned(),
                entry.source_sha256.clone(),
            );
            if entry.disposition == CoverageDisposition::Raw && confirmed_secret_keys.contains(&key)
            {
                entry.secret_transmitted = true;
            }
        }
        Ok(TransmittedContext {
            text: context.text,
            sha256: context.sha256,
            receipt: context.receipt,
        })
    }

    fn target_and_ancestors(&self, request: &ContextRequest) -> Result<BTreeSet<String>, String> {
        if !crate::domain::is_known_entity_id(request.target.as_str()) {
            return Err("context target has an invalid stable entity ID".into());
        }
        let mut ids = BTreeSet::from([request.target.as_str().to_owned()]);
        let Some(structure) = &self.structure else {
            if self.manifest.entries().iter().any(|entry| {
                matches!(
                    entry.scope,
                    crate::sources::SourceScope::Part(_)
                        | crate::sources::SourceScope::Chapter(_)
                        | crate::sources::SourceScope::Scene(_)
                )
            }) {
                return Err(
                    "hierarchy-scoped sources require a validated story structure for context compilation"
                        .into(),
                );
            }
            return Ok(ids);
        };
        if let Err(error) = validate_structure(structure) {
            return Err(format!(
                "invalid story structure for context scope matching: {error}"
            ));
        }
        let target = request.target.as_str();
        let scene_id = structure
            .boxes
            .iter()
            .find(|box_| box_.id == target)
            .map(|box_| box_.scene_id.as_str())
            .or_else(|| {
                structure
                    .scenes
                    .iter()
                    .find(|scene| scene.id == target)
                    .map(|scene| scene.id.as_str())
            });
        let chapter_id = scene_id
            .and_then(|scene_id| {
                structure
                    .scenes
                    .iter()
                    .find(|scene| scene.id == scene_id)
                    .map(|scene| scene.chapter_id.as_str())
            })
            .or_else(|| {
                structure
                    .chapters
                    .iter()
                    .find(|chapter| chapter.id == target)
                    .map(|chapter| chapter.id.as_str())
            });
        let part_id = chapter_id
            .and_then(|chapter_id| {
                structure
                    .chapters
                    .iter()
                    .find(|chapter| chapter.id == chapter_id)
                    .map(|chapter| chapter.part_id.as_str())
            })
            .or_else(|| {
                structure
                    .parts
                    .iter()
                    .find(|part| part.id == target)
                    .map(|part| part.id.as_str())
            });
        let target_is_structural = scene_id.is_some() || chapter_id.is_some() || part_id.is_some();
        let hierarchy_scoped = self.manifest.entries().iter().any(|entry| {
            matches!(
                entry.scope,
                crate::sources::SourceScope::Part(_)
                    | crate::sources::SourceScope::Chapter(_)
                    | crate::sources::SourceScope::Scene(_)
            )
        });
        if hierarchy_scoped && !target_is_structural {
            return Err("context target is not present in the validated story structure".into());
        }
        if let Some(scene_id) = scene_id {
            ids.insert(scene_id.to_owned());
        }
        if let Some(chapter_id) = chapter_id {
            ids.insert(chapter_id.to_owned());
        }
        if let Some(part_id) = part_id {
            ids.insert(part_id.to_owned());
        }
        Ok(ids)
    }

    fn snapshot_for<'a>(&'a self, entry: &SourceEntry) -> Result<&'a Snapshot, String> {
        let snapshot = self
            .snapshots
            .get(entry.source_id.as_str())
            .ok_or_else(|| {
                format!(
                    "source {} has no matching snapshot",
                    entry.source_id.as_str()
                )
            })?;
        if !snapshot.matches_entry(entry) {
            return Err(format!(
                "source {} snapshot does not match the manifest hash",
                entry.source_id.as_str()
            ));
        }
        Ok(snapshot)
    }

    fn current_summary<'a>(
        &'a self,
        entry: &SourceEntry,
        snapshot: &Snapshot,
    ) -> Option<&'a SourceSummary> {
        let summary = self.summaries.get(entry.source_id.as_str())?;
        (!snapshot.is_secret()
            && summary.source_id == entry.source_id
            && summary.source_sha256 == entry.expected_sha256
            && !summary.text.is_empty()
            && summary.source_range.start < summary.source_range.end
            && summary.source_range.is_valid_for(snapshot.text()))
        .then_some(summary)
    }

    fn fail(
        &self,
        message: String,
        mut receipt: ContextReceipt,
        applicable: &[&SourceEntry],
    ) -> Result<CompiledContext, ContextCompileError> {
        let accounted = receipt
            .entries
            .iter()
            .map(|entry| entry.source_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        for entry in applicable {
            if !accounted.contains(entry.source_id.as_str()) {
                receipt.entries.push(ContextReceiptEntry {
                    source_id: entry.source_id.clone(),
                    source_sha256: entry.expected_sha256.clone(),
                    disposition: CoverageDisposition::Excluded,
                    source_range: None,
                    reason: "context compilation stopped before source selection".into(),
                    truncated: false,
                    failure: Some(message.clone()),
                    secret_transmitted: false,
                });
            }
        }
        receipt
            .entries
            .sort_by(|left, right| left.source_id.as_str().cmp(right.source_id.as_str()));
        Err(ContextCompileError::new(message, receipt))
    }
}

fn failed_entry(entry: &SourceEntry, message: String) -> ContextReceiptEntry {
    ContextReceiptEntry {
        source_id: entry.source_id.clone(),
        source_sha256: entry.expected_sha256.clone(),
        disposition: CoverageDisposition::Excluded,
        source_range: None,
        reason: "source could not be selected".into(),
        truncated: false,
        failure: Some(message),
        secret_transmitted: false,
    }
}

fn source_block(entry: &SourceEntry, text: &str) -> String {
    format!(
        "<!-- phemius-source:{} -->\n{text}\n",
        entry.source_id.as_str()
    )
}

/// Returns a fail-closed UTF-8 byte upper bound when no model tokenizer is available.
pub fn estimate_tokens(bytes: &[u8]) -> u64 {
    bytes.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{EntityKind, prefixed_uuid},
        sources::{SourceKind, SourceScope},
    };

    #[test]
    fn secret_confirmation_is_consumed_only_by_a_successful_handoff() {
        let secret = Snapshot::from_text(SourceKind::PlainText, b"secret reference", true).unwrap();
        let oversized = Snapshot::from_text(
            SourceKind::PlainText,
            "ordinary reference ".repeat(100).as_bytes(),
            false,
        )
        .unwrap();
        let secret_id = prefixed_uuid(EntityKind::Source);
        let manifest = SourceManifest::new(vec![
            SourceEntry::from_snapshot(
                secret_id.clone(),
                SourceScope::Work,
                SourceTier::RequiredRaw,
                &secret,
            ),
            SourceEntry::from_snapshot(
                prefixed_uuid(EntityKind::Source),
                SourceScope::Work,
                SourceTier::Compactable,
                &oversized,
            ),
        ])
        .unwrap();
        let compiler = ContextCompiler::new(manifest, vec![secret.clone(), oversized]).unwrap();
        let low_budget = ContextRequest {
            target: prefixed_uuid(EntityKind::Chapter),
            role: "writer".into(),
            budget_tokens: 200,
            requested_output_tokens: 100,
        };
        compiler
            .confirm_secret_transmission(SecretTransmission::after_human_confirmation(
                secret_id,
                secret.raw_sha256(),
            ))
            .unwrap();

        let error = compiler.compile(&low_budget).unwrap_err();
        assert!(
            error
                .receipt()
                .entries()
                .iter()
                .all(|entry| !entry.secret_transmitted())
        );

        let high_budget = ContextRequest {
            target: low_budget.target.clone(),
            role: low_budget.role.clone(),
            budget_tokens: 4_000,
            requested_output_tokens: low_budget.requested_output_tokens,
        };
        let compiled = compiler.compile(&high_budget).unwrap();
        assert!(
            compiled
                .receipt()
                .entries()
                .iter()
                .all(|entry| !entry.secret_transmitted())
        );
        let transmitted = compiler.handoff(compiled).unwrap();
        assert!(
            transmitted
                .receipt()
                .entries()
                .iter()
                .any(|entry| entry.secret_transmitted())
        );
        assert!(compiler.compile(&high_budget).is_err());
    }

    #[test]
    fn handoff_rejects_context_created_by_a_different_compiler() {
        let secret = Snapshot::from_text(SourceKind::PlainText, b"secret reference", true).unwrap();
        let secret_id = prefixed_uuid(EntityKind::Source);
        let manifest = SourceManifest::new(vec![SourceEntry::from_snapshot(
            secret_id.clone(),
            SourceScope::Work,
            SourceTier::RequiredRaw,
            &secret,
        )])
        .unwrap();
        let compiler = ContextCompiler::new(manifest, vec![secret.clone()]).unwrap();
        let request = ContextRequest {
            target: prefixed_uuid(EntityKind::Chapter),
            role: "writer".into(),
            budget_tokens: 1_000,
            requested_output_tokens: 100,
        };
        compiler
            .confirm_secret_transmission(SecretTransmission::after_human_confirmation(
                secret_id,
                secret.raw_sha256(),
            ))
            .unwrap();
        let compiled = compiler.compile(&request).unwrap();
        let other =
            ContextCompiler::new(SourceManifest::new(Vec::new()).unwrap(), Vec::new()).unwrap();

        let error = other.handoff(compiled).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("not created by this context compiler")
        );
        assert!(
            error
                .receipt()
                .entries()
                .iter()
                .all(|entry| !entry.secret_transmitted())
        );

        let transmitted = compiler
            .handoff(compiler.compile(&request).unwrap())
            .unwrap();
        assert!(
            transmitted
                .receipt()
                .entries()
                .iter()
                .any(|entry| entry.secret_transmitted())
        );
    }
}
