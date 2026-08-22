//! Fail-closed integer accounting for model request budgets.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::domain::{EntityId, EntityKind, prefixed_uuid};

const MICROS_PER_DOLLAR: u64 = 1_000_000;
const TOKENS_PER_PRICE_UNIT: u64 = 1_000_000;
const CHAPTER_WARNING: MicroDollars = MicroDollars(5 * MICROS_PER_DOLLAR);
const CHAPTER_CAP: MicroDollars = MicroDollars(10 * MICROS_PER_DOLLAR);
const RUN_CAP: MicroDollars = MicroDollars(120 * MICROS_PER_DOLLAR);

/// The durable-write phase whose failure leaves an event's persistence unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CostPersistenceStage {
    /// The event write may have written a partial or complete record.
    Write,
    /// The event write completed but the stream flush failed.
    Flush,
    /// The event flush completed but the durable data sync failed.
    SyncData,
}

/// Reports that a cost event may be on disk and the ledger must be reopened or reconciled.
#[derive(Debug)]
pub struct CostDurabilityUnknown {
    stage: CostPersistenceStage,
    source: anyhow::Error,
}

impl CostDurabilityUnknown {
    fn new(stage: CostPersistenceStage, source: anyhow::Error) -> Self {
        Self { stage, source }
    }

    /// Returns the phase after which durable event presence became unknown.
    pub const fn stage(&self) -> CostPersistenceStage {
        self.stage
    }
}

impl fmt::Display for CostDurabilityUnknown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cost event durability is unknown after {:?}; reopen or reconcile before retrying: {}",
            self.stage, self.source
        )
    }
}

impl Error for CostDurabilityUnknown {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Injects a persistence interruption for an integration regression test.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestCostPersistenceInterruption {
    /// Fails before any bytes are written, so rollback remains safe.
    BeforeWrite,
    /// Fails after `write_all`, leaving the event's persistence unknown.
    AfterWrite,
    /// Fails after `flush`, leaving the event's persistence unknown.
    AfterFlush,
    /// Fails after `sync_data`, leaving the event's persistence unknown.
    AfterSyncData,
}

/// A whole number of microdollars.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MicroDollars(u64);

impl MicroDollars {
    /// Creates an amount from whole microdollars.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the zero-cost amount.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Returns the amount as whole microdollars.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or_else(|| anyhow!("microdollar arithmetic overflow"))
    }

    fn checked_sub(self, other: Self) -> Result<Self> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or_else(|| anyhow!("cost settlement exceeds its reservation"))
    }
}

/// Input and output prices in microdollars per million tokens.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Price {
    /// Dollar price converted to microdollars per million input tokens.
    pub input_per_million: MicroDollars,
    /// Dollar price converted to microdollars per million output tokens.
    pub output_per_million: MicroDollars,
}

impl Price {
    /// Parses decimal dollar prices without using binary floating point.
    pub fn parse_per_million(input: &str, output: &str) -> Result<Self> {
        Ok(Self {
            input_per_million: parse_dollar_micros(input)?,
            output_per_million: parse_dollar_micros(output)?,
        })
    }

    /// Returns the exact request price rounded up to whole microdollars.
    pub fn cost_for(&self, usage: Usage) -> Result<MicroDollars> {
        charge(usage.input_tokens, self.input_per_million)?
            .checked_add(charge(usage.output_tokens, self.output_per_million)?)
    }
}

/// Token usage supplied by a completed model response.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    /// Count of input tokens charged by the model.
    pub input_tokens: u64,
    /// Count of output tokens charged by the model.
    pub output_tokens: u64,
}

impl Usage {
    /// Creates a usage record from input and output token counts.
    pub const fn new(input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            input_tokens,
            output_tokens,
        }
    }
}

/// A held maximum cost. It remains held until an explicit settlement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    /// Stable request ID used for explicit settlement.
    pub request_id: EntityId,
    /// Chapter charged for this reservation.
    pub chapter_id: String,
    /// Maximum held cost until settlement or reconciliation.
    pub reserved_cost: MicroDollars,
    /// Whether this reservation crossed the one-time chapter warning threshold.
    pub warning_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
enum LedgerEvent {
    Reserved {
        reservation: Reservation,
    },
    Settled {
        request_id: EntityId,
        actual_cost: MicroDollars,
    },
}

enum PersistError {
    Before(anyhow::Error),
    After {
        stage: CostPersistenceStage,
        source: anyhow::Error,
    },
}

#[derive(Default)]
struct LedgerState {
    chapter_start: MicroDollars,
    run_start: MicroDollars,
    reservations: BTreeMap<String, Reservation>,
    settled_requests: BTreeSet<String>,
    warnings: BTreeSet<String>,
    durability_unknown: bool,
}

impl LedgerState {
    fn ensure_mutable(&self) -> Result<()> {
        ensure!(
            !self.durability_unknown,
            "cost ledger requires reopen or reconciliation after durability is unknown"
        );
        Ok(())
    }

    fn chapter_total(&self, chapter_id: &str) -> Result<MicroDollars> {
        self.reservations
            .values()
            .filter(|reservation| reservation.chapter_id == chapter_id)
            .try_fold(self.chapter_start, |total, reservation| {
                total.checked_add(reservation.reserved_cost)
            })
    }

    fn run_total(&self) -> Result<MicroDollars> {
        self.reservations
            .values()
            .try_fold(self.run_start, |total, reservation| {
                total.checked_add(reservation.reserved_cost)
            })
    }

    fn reserve(&mut self, chapter_id: &str, maximum_cost: MicroDollars) -> Result<Reservation> {
        ensure!(!chapter_id.is_empty(), "chapter ID is required");
        let chapter_total = self.chapter_total(chapter_id)?.checked_add(maximum_cost)?;
        ensure!(
            chapter_total <= CHAPTER_CAP,
            "chapter budget would exceed $10"
        );
        let run_total = self.run_total()?.checked_add(maximum_cost)?;
        ensure!(run_total <= RUN_CAP, "run budget would exceed $120");
        let warning_required =
            chapter_total > CHAPTER_WARNING && self.warnings.insert(chapter_id.into());
        let reservation = Reservation {
            request_id: prefixed_uuid(EntityKind::Request),
            chapter_id: chapter_id.into(),
            reserved_cost: maximum_cost,
            warning_required,
        };
        self.reservations
            .insert(reservation.request_id.as_str().into(), reservation.clone());
        Ok(reservation)
    }

    fn settle(&mut self, request_id: &EntityId, actual_cost: MicroDollars) -> Result<()> {
        ensure!(
            !self.settled_requests.contains(request_id.as_str()),
            "reservation is already settled"
        );
        let reservation = self
            .reservations
            .get_mut(request_id.as_str())
            .ok_or_else(|| anyhow!("reservation is unknown"))?;
        reservation.reserved_cost.checked_sub(actual_cost)?;
        reservation.reserved_cost = actual_cost;
        self.settled_requests.insert(request_id.as_str().into());
        Ok(())
    }

    fn apply(&mut self, event: LedgerEvent) -> Result<()> {
        match event {
            LedgerEvent::Reserved { reservation } => {
                ensure!(
                    !self
                        .reservations
                        .contains_key(reservation.request_id.as_str()),
                    "duplicate reservation event"
                );
                if reservation.warning_required {
                    self.warnings.insert(reservation.chapter_id.clone());
                }
                self.reservations
                    .insert(reservation.request_id.as_str().into(), reservation);
                Ok(())
            }
            LedgerEvent::Settled {
                request_id,
                actual_cost,
            } => self.settle(&request_id, actual_cost),
        }
    }
}

/// Thread-safe, fail-closed budget state. Reservations are never released by `Drop`.
#[derive(Clone)]
pub struct BudgetLedger {
    state: Arc<Mutex<LedgerState>>,
    journal: Option<Arc<Mutex<File>>>,
}

impl BudgetLedger {
    /// Creates an in-memory ledger with already incurred chapter and run costs.
    pub fn new(chapter_cost: MicroDollars, run_cost: MicroDollars) -> Self {
        Self {
            state: Arc::new(Mutex::new(LedgerState {
                chapter_start: chapter_cost,
                run_start: run_cost,
                ..LedgerState::default()
            })),
            journal: None,
        }
    }

    /// Opens a durable ledger and replays its append-only reservation history.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_costs(path, MicroDollars::zero(), MicroDollars::zero())
    }

    /// Opens a durable ledger with prior chapter and run costs supplied by a checkpoint.
    pub fn open_with_costs(
        path: impl AsRef<Path>,
        chapter_cost: MicroDollars,
        run_cost: MicroDollars,
    ) -> Result<Self> {
        let path = path.as_ref();
        let mut options = OpenOptions::new();
        options.read(true).append(true).create(true);
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to open cost ledger {}", path.display()))?;
        file.try_lock()
            .with_context(|| format!("cost ledger is already locked: {}", path.display()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .with_context(|| format!("failed to read cost ledger {}", path.display()))?;
        ensure!(
            bytes.is_empty() || bytes.ends_with(b"\n"),
            "cost ledger has a truncated final event"
        );
        let mut state = LedgerState {
            chapter_start: chapter_cost,
            run_start: run_cost,
            ..LedgerState::default()
        };
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            state.apply(serde_json::from_slice(line).context("invalid cost ledger event")?)?;
        }
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            journal: Some(Arc::new(Mutex::new(file))),
        })
    }

    /// Holds the maximum request cost before any network operation starts.
    pub fn reserve(&self, chapter_id: &str, maximum_cost: MicroDollars) -> Result<Reservation> {
        self.reserve_inner(chapter_id, maximum_cost, None)
    }

    /// Injects a pre-write persistence failure for an integration regression test.
    #[doc(hidden)]
    pub fn reserve_with_persist_failure_for_test(
        &self,
        chapter_id: &str,
        maximum_cost: MicroDollars,
    ) -> Result<Reservation> {
        self.reserve_inner(
            chapter_id,
            maximum_cost,
            Some(TestCostPersistenceInterruption::BeforeWrite),
        )
    }

    /// Injects a persistence interruption for an integration regression test.
    #[doc(hidden)]
    pub fn reserve_with_test_interruption(
        &self,
        chapter_id: &str,
        maximum_cost: MicroDollars,
        interruption: TestCostPersistenceInterruption,
    ) -> Result<Reservation> {
        self.reserve_inner(chapter_id, maximum_cost, Some(interruption))
    }

    fn reserve_inner(
        &self,
        chapter_id: &str,
        maximum_cost: MicroDollars,
        interruption: Option<TestCostPersistenceInterruption>,
    ) -> Result<Reservation> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("cost ledger lock poisoned"))?;
        state.ensure_mutable()?;
        let warning_was_emitted = state.warnings.contains(chapter_id);
        let reservation = state.reserve(chapter_id, maximum_cost)?;
        match self.persist(
            LedgerEvent::Reserved {
                reservation: reservation.clone(),
            },
            interruption,
        ) {
            Ok(()) => Ok(reservation),
            Err(PersistError::Before(error)) => {
                state.reservations.remove(reservation.request_id.as_str());
                if reservation.warning_required && !warning_was_emitted {
                    state.warnings.remove(chapter_id);
                }
                Err(error)
            }
            Err(PersistError::After { stage, source }) => {
                state.durability_unknown = true;
                Err(CostDurabilityUnknown::new(stage, source).into())
            }
        }
    }

    /// Replaces a reservation with the actual charged cost after a known completion.
    pub fn settle(&self, reservation: &Reservation, actual_cost: MicroDollars) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("cost ledger lock poisoned"))?;
        state.ensure_mutable()?;
        let original = state
            .reservations
            .get(reservation.request_id.as_str())
            .cloned()
            .ok_or_else(|| anyhow!("reservation is unknown"))?;
        state.settle(&reservation.request_id, actual_cost)?;
        match self.persist(
            LedgerEvent::Settled {
                request_id: reservation.request_id.clone(),
                actual_cost,
            },
            None,
        ) {
            Ok(()) => Ok(()),
            Err(PersistError::Before(error)) => {
                state
                    .reservations
                    .insert(reservation.request_id.as_str().into(), original);
                state
                    .settled_requests
                    .remove(reservation.request_id.as_str());
                Err(error)
            }
            Err(PersistError::After { stage, source }) => {
                state.durability_unknown = true;
                Err(CostDurabilityUnknown::new(stage, source).into())
            }
        }
    }

    /// Keeps an ambiguous request reserved. Reconciliation must call [`Self::settle`] explicitly.
    pub fn retain_ambiguous(&self, reservation: &Reservation) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("cost ledger lock poisoned"))?;
        state.ensure_mutable()?;
        ensure!(
            state
                .reservations
                .contains_key(reservation.request_id.as_str()),
            "reservation is unknown"
        );
        Ok(())
    }

    fn persist(
        &self,
        event: LedgerEvent,
        interruption: Option<TestCostPersistenceInterruption>,
    ) -> std::result::Result<(), PersistError> {
        if interruption == Some(TestCostPersistenceInterruption::BeforeWrite) {
            return Err(PersistError::Before(anyhow!(
                "simulated cost ledger persistence failure"
            )));
        }
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let mut file = journal
            .lock()
            .map_err(|_| PersistError::Before(anyhow!("cost journal lock poisoned")))?;
        file.try_lock()
            .context("cost ledger is already locked")
            .map_err(PersistError::Before)?;
        let mut line = serde_json::to_vec(&event)
            .context("failed to serialize cost ledger event")
            .map_err(PersistError::Before)?;
        line.push(b'\n');
        file.write_all(&line)
            .context("failed to append cost ledger event")
            .map_err(|source| PersistError::After {
                stage: CostPersistenceStage::Write,
                source,
            })?;
        if interruption == Some(TestCostPersistenceInterruption::AfterWrite) {
            return Err(PersistError::After {
                stage: CostPersistenceStage::Write,
                source: anyhow!("simulated post-write cost ledger persistence failure"),
            });
        }
        file.flush()
            .context("failed to flush cost ledger event")
            .map_err(|source| PersistError::After {
                stage: CostPersistenceStage::Flush,
                source,
            })?;
        if interruption == Some(TestCostPersistenceInterruption::AfterFlush) {
            return Err(PersistError::After {
                stage: CostPersistenceStage::Flush,
                source: anyhow!("simulated post-flush cost ledger persistence failure"),
            });
        }
        file.sync_data()
            .context("failed to sync cost ledger event")
            .map_err(|source| PersistError::After {
                stage: CostPersistenceStage::SyncData,
                source,
            })?;
        if interruption == Some(TestCostPersistenceInterruption::AfterSyncData) {
            return Err(PersistError::After {
                stage: CostPersistenceStage::SyncData,
                source: anyhow!("simulated post-sync cost ledger persistence failure"),
            });
        }
        Ok(())
    }
}

fn parse_dollar_micros(value: &str) -> Result<MicroDollars> {
    let value = value.strip_prefix('$').unwrap_or(value);
    ensure!(
        !value.is_empty() && !value.starts_with('-'),
        "price must be a non-negative decimal"
    );
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    ensure!(
        !whole.is_empty() && whole.bytes().all(|byte| byte.is_ascii_digit()),
        "price must be a non-negative decimal"
    );
    ensure!(
        fraction.bytes().all(|byte| byte.is_ascii_digit()),
        "price must be a non-negative decimal"
    );
    let whole: u64 = whole.parse().context("price is too large")?;
    let micros = whole
        .checked_mul(MICROS_PER_DOLLAR)
        .ok_or_else(|| anyhow!("price arithmetic overflow"))?;
    let retained = fraction.get(..fraction.len().min(6)).unwrap_or("");
    let scaled = if retained.is_empty() {
        0
    } else {
        retained
            .parse::<u64>()
            .context("price fraction is too large")?
            .checked_mul(10_u64.pow((6 - retained.len()) as u32))
            .ok_or_else(|| anyhow!("price arithmetic overflow"))?
    };
    let rounds_up = fraction
        .as_bytes()
        .get(6..)
        .is_some_and(|rest| rest.iter().any(|byte| *byte != b'0'));
    micros
        .checked_add(scaled)
        .and_then(|value| value.checked_add(u64::from(rounds_up)))
        .map(MicroDollars)
        .ok_or_else(|| anyhow!("price arithmetic overflow"))
}

fn charge(tokens: u64, price_per_million: MicroDollars) -> Result<MicroDollars> {
    let product = tokens
        .checked_mul(price_per_million.0)
        .ok_or_else(|| anyhow!("cost arithmetic overflow"))?;
    let rounded = product
        .checked_add(TOKENS_PER_PRICE_UNIT - 1)
        .ok_or_else(|| anyhow!("cost arithmetic overflow"))?
        / TOKENS_PER_PRICE_UNIT;
    Ok(MicroDollars(rounded))
}
