//! Durable, redacted session evidence and derived context checkpoints.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    changeset::{ChangesetState, sha256_bytes},
    cost::{MicroDollars, Usage},
    domain::EntityId,
};

const PRESERVED_RAW_TAIL_TOKENS: u64 = 15_000;
const MINIMUM_OUTPUT_RESERVE_TOKENS: u64 = 20_000;

/// Typed facts retained in the append-only session log.
///
/// The variants intentionally exclude model payloads, URLs, routing metadata, and receipts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum SessionEvent {
    UserInstruction {
        text: String,
    },
    ModelCallStarted {
        request_id: EntityId,
        context_hash: String,
    },
    ModelCallCompleted {
        request_id: EntityId,
        usage: Usage,
    },
    ModelCallAmbiguous {
        request_id: EntityId,
        reserved_cost: MicroDollars,
    },
    ChangesetStateChanged {
        id: EntityId,
        state: ChangesetState,
    },
    ContextEpochChanged {
        model: String,
        checkpoint_hash: String,
    },
}

/// A bounded compaction decision derived from conservative token estimates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionDecision {
    pub required: bool,
    pub preserve_recent_tokens: u64,
}

impl CompactionDecision {
    pub fn for_usage(
        estimated_next_input_tokens: u64,
        model_context_tokens: u64,
        requested_output_tokens: u64,
    ) -> Self {
        let reserve = requested_output_tokens.max(MINIMUM_OUTPUT_RESERVE_TOKENS);
        Self {
            required: model_context_tokens < reserve
                || estimated_next_input_tokens > model_context_tokens.saturating_sub(reserve),
            preserve_recent_tokens: PRESERVED_RAW_TAIL_TOKENS,
        }
    }
}

/// Identifies a model context epoch without retaining its payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextEpoch {
    pub model: String,
    pub checkpoint_hash: String,
}

/// A hash-verified, derived projection of a session journal.
///
/// Lossy summary prose is deliberately not persisted here. Canon, source, correction, blocker,
/// stale-state, and cost facts remain represented by their dedicated typed fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub last_event_offset: u64,
    pub last_event_sha256: String,
    pub context_epochs: Vec<ContextEpoch>,
    pub recent_raw_tail_tokens: u64,
    pub canon_fact_hashes: Vec<String>,
    pub source_hashes: Vec<String>,
    pub correction_ids: Vec<EntityId>,
    pub blocker_ids: Vec<EntityId>,
    pub stale_changeset_ids: Vec<EntityId>,
    pub cost: MicroDollars,
}

impl Checkpoint {
    pub fn from_journal(
        journal: &SessionJournal,
        context_epochs: Vec<ContextEpoch>,
        canon_fact_hashes: Vec<String>,
        source_hashes: Vec<String>,
        correction_ids: Vec<EntityId>,
        blocker_ids: Vec<EntityId>,
        stale_changeset_ids: Vec<EntityId>,
        cost: MicroDollars,
    ) -> Result<Self> {
        let (last_event_offset, last_event_sha256) = journal
            .last_event()
            .ok_or_else(|| anyhow!("cannot checkpoint an empty session journal"))?;
        Ok(Self {
            last_event_offset,
            last_event_sha256: last_event_sha256.to_owned(),
            context_epochs,
            recent_raw_tail_tokens: PRESERVED_RAW_TAIL_TOKENS,
            canon_fact_hashes,
            source_hashes,
            correction_ids,
            blocker_ids,
            stale_changeset_ids,
            cost,
        })
    }
}

/// An append-only JSONL journal for one session.
#[derive(Debug)]
pub struct SessionJournal {
    path: PathBuf,
    events: Vec<SessionEvent>,
    last_event: Option<(u64, String)>,
}

impl SessionJournal {
    /// Creates an empty session journal. Its parent directory must already exist.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("failed to create session journal {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync session journal {}", path.display()))?;
        Ok(Self {
            path,
            events: Vec::new(),
            last_event: None,
        })
    }

    /// Opens a journal and truncates only an unterminated final write.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("failed to open session journal {}", path.display()))?;
        file.try_lock()
            .with_context(|| format!("session journal is already locked: {}", path.display()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .with_context(|| format!("failed to read session journal {}", path.display()))?;

        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let mut events = Vec::new();
        let mut last_event = None;
        let mut offset = 0_u64;
        for line in bytes[..complete_len].split_inclusive(|byte| *byte == b'\n') {
            let json = &line[..line.len() - 1];
            let event = serde_json::from_slice(json).with_context(|| {
                format!("invalid interior session JSONL event at byte offset {offset}")
            })?;
            last_event = Some((offset, sha256_bytes(json)));
            offset = offset
                .checked_add(line.len() as u64)
                .ok_or_else(|| anyhow!("session offset overflow"))?;
            events.push(event);
        }
        if complete_len != bytes.len() {
            file.set_len(complete_len as u64)
                .with_context(|| format!("failed to repair session journal {}", path.display()))?;
            file.seek(SeekFrom::Start(complete_len as u64))?;
            file.sync_data().with_context(|| {
                format!("failed to sync repaired session journal {}", path.display())
            })?;
        }
        Ok(Self {
            path,
            events,
            last_event,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn events(&self) -> &[SessionEvent] {
        &self.events
    }

    pub fn last_event(&self) -> Option<(u64, &str)> {
        self.last_event
            .as_ref()
            .map(|(offset, hash)| (*offset, hash.as_str()))
    }

    /// Appends one complete JSONL record while holding the file lock.
    pub fn append(&mut self, event: SessionEvent) -> Result<()> {
        let mut line = serde_json::to_vec(&event).context("failed to serialize session event")?;
        let event_hash = sha256_bytes(&line);
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .append(true)
            .read(true)
            .open(&self.path)
            .with_context(|| format!("failed to open session journal {}", self.path.display()))?;
        file.try_lock().with_context(|| {
            format!("session journal is already locked: {}", self.path.display())
        })?;
        let offset = file
            .metadata()
            .context("failed to inspect session journal")?
            .len();
        file.write_all(&line)
            .with_context(|| format!("failed to append session journal {}", self.path.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush session journal {}", self.path.display()))?;
        file.sync_data()
            .with_context(|| format!("failed to sync session journal {}", self.path.display()))?;
        self.last_event = Some((offset, event_hash));
        self.events.push(event);
        Ok(())
    }

    /// Atomically replaces a derived checkpoint after verifying its journal anchor.
    pub fn write_checkpoint(&self, path: impl AsRef<Path>, checkpoint: &Checkpoint) -> Result<()> {
        let path = path.as_ref();
        let Some((offset, hash)) = self.last_event() else {
            return Err(anyhow!("cannot checkpoint an empty session journal"));
        };
        ensure!(
            checkpoint.last_event_offset == offset && checkpoint.last_event_sha256 == hash,
            "checkpoint does not match the current session journal"
        );
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("checkpoint path has no parent"))?;
        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow!("checkpoint filename is not valid UTF-8"))?,
            Uuid::now_v7()
        ));
        let bytes = serde_json::to_vec(checkpoint).context("failed to serialize checkpoint")?;
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .with_context(|| format!("failed to create checkpoint {}", temporary.display()))?;
            file.write_all(&bytes)
                .with_context(|| format!("failed to write checkpoint {}", temporary.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync checkpoint {}", temporary.display()))?;
            fs::rename(&temporary, path).with_context(|| {
                format!("failed to atomically replace checkpoint {}", path.display())
            })?;
            File::open(parent)
                .with_context(|| {
                    format!("failed to open checkpoint directory {}", parent.display())
                })?
                .sync_all()
                .with_context(|| {
                    format!("failed to sync checkpoint directory {}", parent.display())
                })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// Loads a checkpoint only when its offset and event hash still anchor this journal.
    pub fn read_checkpoint(&self, path: impl AsRef<Path>) -> Result<Checkpoint> {
        let bytes = fs::read(path.as_ref())
            .with_context(|| format!("failed to read checkpoint {}", path.as_ref().display()))?;
        let checkpoint: Checkpoint =
            serde_json::from_slice(&bytes).context("invalid checkpoint")?;
        let Some((offset, hash)) = self.last_event() else {
            return Err(anyhow!("checkpoint exists for an empty session journal"));
        };
        ensure!(
            checkpoint.last_event_offset == offset && checkpoint.last_event_sha256 == hash,
            "checkpoint does not match the current session journal"
        );
        Ok(checkpoint)
    }
}
