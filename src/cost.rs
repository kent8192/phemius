//! Fail-closed integer accounting for model request budgets.

use std::{
    collections::{BTreeMap, BTreeSet},
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

#[derive(Default)]
struct LedgerState {
    chapter_start: MicroDollars,
    run_start: MicroDollars,
    reservations: BTreeMap<String, Reservation>,
    settled_requests: BTreeSet<String>,
    warnings: BTreeSet<String>,
}

impl LedgerState {
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
        self.reserve_inner(chapter_id, maximum_cost, false)
    }

    /// Injects a pre-write persistence failure for an integration regression test.
    #[doc(hidden)]
    pub fn reserve_with_persist_failure_for_test(
        &self,
        chapter_id: &str,
        maximum_cost: MicroDollars,
    ) -> Result<Reservation> {
        self.reserve_inner(chapter_id, maximum_cost, true)
    }

    fn reserve_inner(
        &self,
        chapter_id: &str,
        maximum_cost: MicroDollars,
        force_persist_failure: bool,
    ) -> Result<Reservation> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("cost ledger lock poisoned"))?;
        let warning_was_emitted = state.warnings.contains(chapter_id);
        let reservation = state.reserve(chapter_id, maximum_cost)?;
        if let Err(error) = self.persist(
            LedgerEvent::Reserved {
                reservation: reservation.clone(),
            },
            force_persist_failure,
        ) {
            state.reservations.remove(reservation.request_id.as_str());
            if reservation.warning_required && !warning_was_emitted {
                state.warnings.remove(chapter_id);
            }
            return Err(error);
        }
        Ok(reservation)
    }

    /// Replaces a reservation with the actual charged cost after a known completion.
    pub fn settle(&self, reservation: &Reservation, actual_cost: MicroDollars) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("cost ledger lock poisoned"))?;
        let original = state
            .reservations
            .get(reservation.request_id.as_str())
            .cloned()
            .ok_or_else(|| anyhow!("reservation is unknown"))?;
        state.settle(&reservation.request_id, actual_cost)?;
        if let Err(error) = self.persist(
            LedgerEvent::Settled {
                request_id: reservation.request_id.clone(),
                actual_cost,
            },
            false,
        ) {
            state
                .reservations
                .insert(reservation.request_id.as_str().into(), original);
            state
                .settled_requests
                .remove(reservation.request_id.as_str());
            return Err(error);
        }
        Ok(())
    }

    /// Keeps an ambiguous request reserved. Reconciliation must call [`Self::settle`] explicitly.
    pub fn retain_ambiguous(&self, reservation: &Reservation) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("cost ledger lock poisoned"))?;
        ensure!(
            state
                .reservations
                .contains_key(reservation.request_id.as_str()),
            "reservation is unknown"
        );
        Ok(())
    }

    fn persist(&self, event: LedgerEvent, force_failure: bool) -> Result<()> {
        if force_failure {
            return Err(anyhow!("simulated cost ledger persistence failure"));
        }
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let mut file = journal
            .lock()
            .map_err(|_| anyhow!("cost journal lock poisoned"))?;
        file.try_lock().context("cost ledger is already locked")?;
        let mut line =
            serde_json::to_vec(&event).context("failed to serialize cost ledger event")?;
        line.push(b'\n');
        file.write_all(&line)
            .context("failed to append cost ledger event")?;
        file.flush().context("failed to flush cost ledger event")?;
        file.sync_data().context("failed to sync cost ledger event")
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
