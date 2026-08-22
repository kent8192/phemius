use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

use phemius::{
    changeset::canon_root_hash,
    cost::{
        BudgetLedger, CostDurabilityUnknown, CostPersistenceStage, MicroDollars, Price,
        TestCostPersistenceInterruption, Usage,
    },
    domain::{EntityKind, prefixed_uuid},
    project::{Project, ProjectConfig},
    session::{
        Checkpoint, CheckpointDurabilityUnknown, CompactionDecision, SessionEvent, SessionJournal,
        TestCheckpointInterruption,
    },
};
use rstest::*;

#[rstest]
fn crash_truncated_last_line_is_repaired_but_interior_corruption_stops() {
    let last = TestDir::new("truncated-last");
    let last_path = last.path().join("events.jsonl");
    fs::write(
        &last_path,
        format!(
            "{}\n{}",
            serde_json::to_string(&SessionEvent::UserInstruction {
                text: "first".into(),
            })
            .unwrap(),
            "{\"event\":\"user-instruction\""
        ),
    )
    .unwrap();

    let journal = SessionJournal::open(&last_path).unwrap();

    assert_eq!(journal.events().len(), 1);
    assert_eq!(fs::read(&last_path).unwrap().ends_with(b"\n"), true);

    let middle = TestDir::new("corrupt-middle");
    let middle_path = middle.path().join("events.jsonl");
    fs::write(
        &middle_path,
        format!(
            "{}\nnot-json\n{}\n",
            serde_json::to_string(&SessionEvent::UserInstruction {
                text: "first".into(),
            })
            .unwrap(),
            serde_json::to_string(&SessionEvent::UserInstruction {
                text: "last".into(),
            })
            .unwrap(),
        ),
    )
    .unwrap();

    assert!(SessionJournal::open(&middle_path).is_err());
}

#[rstest]
fn compaction_preserves_fifteen_thousand_token_tail() {
    let decision = CompactionDecision::for_usage(1_030_000, 1_048_576, 12_000);

    assert_eq!(decision.required, true);
    assert_eq!(decision.preserve_recent_tokens, 15_000);
}

#[rstest]
fn compaction_uses_the_larger_output_reserve_at_the_exact_boundary() {
    let at_boundary = CompactionDecision::for_usage(1_028_576, 1_048_576, 12_000);
    let after_boundary = CompactionDecision::for_usage(1_028_577, 1_048_576, 12_000);

    assert_eq!(at_boundary.required, false);
    assert_eq!(after_boundary.required, true);
}

#[rstest]
fn compaction_fails_closed_when_the_context_is_smaller_than_the_reserve() {
    let decision = CompactionDecision::for_usage(0, 10_000, 12_000);

    assert_eq!(decision.required, true);
}

#[rstest]
fn three_parallel_critic_reservations_cannot_cross_chapter_cap() {
    let directory = TestDir::new("parallel-reservations");
    let path = directory.path().join("costs.jsonl");
    let ledger =
        BudgetLedger::open_with_costs(&path, micros(9_000_000), micros(100_000_000)).unwrap();
    let barrier = Arc::new(Barrier::new(4));
    let workers = (0..3)
        .map(|_| {
            let ledger = ledger.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                ledger.reserve("chapter_1", micros(400_000)).is_ok()
            })
        })
        .collect::<Vec<_>>();

    barrier.wait();
    let successes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|succeeded| *succeeded)
        .count();

    assert_eq!(successes, 2);
    drop(ledger);

    let replayed =
        BudgetLedger::open_with_costs(&path, micros(9_000_000), micros(100_000_000)).unwrap();
    assert_eq!(replayed.reserve("chapter_1", micros(200_000)).is_ok(), true);
    assert_eq!(replayed.reserve("chapter_1", micros(1)).is_err(), true);
}

#[rstest]
fn decimal_price_uses_ceiling_microdollars_without_floating_point() {
    let price = Price::parse_per_million("0.000001", "0.000001").unwrap();
    let usage = Usage::new(1, 1);

    assert_eq!(price.cost_for(usage).unwrap(), micros(2));
}

#[rstest]
fn durable_reservations_replay_settlement_and_emit_each_chapter_warning_once() {
    let directory = TestDir::new("durable-ledger");
    let path = directory.path().join("costs.jsonl");
    let ledger = BudgetLedger::open(&path).unwrap();
    let first = ledger.reserve("chapter_1", micros(4_000_000)).unwrap();

    assert_eq!(first.warning_required, false);
    ledger.settle(&first, micros(1_000_000)).unwrap();
    drop(ledger);

    let replayed = BudgetLedger::open(&path).unwrap();
    let second = replayed.reserve("chapter_1", micros(5_000_000)).unwrap();

    assert_eq!(second.warning_required, true);
    drop(replayed);

    let replayed_again = BudgetLedger::open(&path).unwrap();
    let third = replayed_again
        .reserve("chapter_1", micros(1_000_000))
        .unwrap();
    assert_eq!(third.warning_required, false);
}

#[rstest]
fn failed_reservation_persistence_does_not_consume_the_chapter_warning() {
    let ledger = BudgetLedger::new(MicroDollars::zero(), MicroDollars::zero());

    assert_eq!(
        ledger
            .reserve_with_persist_failure_for_test("chapter_1", micros(6_000_000))
            .is_err(),
        true
    );

    assert_eq!(
        ledger
            .reserve("chapter_1", micros(6_000_000))
            .unwrap()
            .warning_required,
        true
    );
}

#[rstest]
fn post_write_reservation_failure_keeps_the_durable_hold_and_freezes_the_ledger() {
    let directory = TestDir::new("post-write-reservation-failure");
    let path = directory.path().join("costs.jsonl");
    let ledger = BudgetLedger::open(&path).unwrap();

    let error = ledger
        .reserve_with_test_interruption(
            "chapter_1",
            micros(6_000_000),
            TestCostPersistenceInterruption::AfterWrite,
        )
        .unwrap_err();
    let durability_unknown = error.downcast_ref::<CostDurabilityUnknown>().unwrap();

    assert_eq!(durability_unknown.stage(), CostPersistenceStage::Write);
    assert_eq!(ledger.reserve("chapter_1", micros(1)).is_err(), true);
    assert_eq!(fs::read(&path).unwrap().ends_with(b"\n"), true);
    drop(ledger);

    let replayed = BudgetLedger::open(&path).unwrap();
    assert_eq!(
        replayed.reserve("chapter_1", micros(5_000_000)).is_err(),
        true
    );
    assert_eq!(
        replayed
            .reserve("chapter_1", micros(4_000_000))
            .unwrap()
            .warning_required,
        false
    );
}

#[rstest]
fn checkpoint_is_anchored_to_the_last_durable_event() {
    let directory = TestDir::new("checkpoint");
    let journal_path = directory.path().join("events.jsonl");
    let mut journal = SessionJournal::create(&journal_path).unwrap();
    journal
        .append(SessionEvent::UserInstruction {
            text: "outline chapter one".into(),
        })
        .unwrap();
    let checkpoint = Checkpoint::from_journal(
        &journal,
        Vec::new(),
        vec!["canon-hash".into()],
        vec!["source-hash".into()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        micros(1),
    )
    .unwrap();
    let checkpoint_path = directory.path().join("checkpoint.json");

    journal
        .write_checkpoint(&checkpoint_path, &checkpoint)
        .unwrap();

    assert_eq!(
        journal.read_checkpoint(&checkpoint_path).unwrap(),
        checkpoint
    );
}

#[rstest]
fn stale_handle_cannot_replace_a_checkpoint_after_another_handle_appends() {
    let directory = TestDir::new("stale-checkpoint");
    let journal_path = directory.path().join("events.jsonl");
    let mut first = SessionJournal::create(&journal_path).unwrap();
    first
        .append(SessionEvent::UserInstruction {
            text: "first event".into(),
        })
        .unwrap();
    let stale_checkpoint = checkpoint_for(&first, micros(1));
    let second_path = journal_path.clone();

    thread::spawn(move || {
        let mut second = SessionJournal::open(second_path).unwrap();
        second
            .append(SessionEvent::UserInstruction {
                text: "second event".into(),
            })
            .unwrap();
    })
    .join()
    .unwrap();

    let checkpoint_path = directory.path().join("checkpoint.json");
    let error = first
        .write_checkpoint(&checkpoint_path, &stale_checkpoint)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "checkpoint does not match the current session journal"
    );
    assert_eq!(checkpoint_path.exists(), false);
}

#[rstest]
fn post_rename_checkpoint_sync_failure_is_durability_unknown_with_a_valid_checkpoint() {
    let directory = TestDir::new("checkpoint-durability-unknown");
    let journal_path = directory.path().join("events.jsonl");
    let mut journal = SessionJournal::create(&journal_path).unwrap();
    journal
        .append(SessionEvent::UserInstruction {
            text: "outline".into(),
        })
        .unwrap();
    let previous = checkpoint_for(&journal, micros(1));
    let replacement = checkpoint_for(&journal, micros(2));
    let checkpoint_path = directory.path().join("checkpoint.json");
    journal
        .write_checkpoint(&checkpoint_path, &previous)
        .unwrap();

    let error = journal
        .write_checkpoint_with_test_interruption(
            &checkpoint_path,
            &replacement,
            TestCheckpointInterruption::AfterRenameBeforeDirectorySync,
        )
        .unwrap_err();
    let durability_unknown = error.downcast_ref::<CheckpointDurabilityUnknown>().unwrap();

    assert_eq!(
        durability_unknown.checkpoint_path(),
        checkpoint_path.as_path()
    );
    assert_eq!(
        serde_json::from_slice::<Checkpoint>(&fs::read(&checkpoint_path).unwrap()).unwrap(),
        replacement
    );
}

#[rstest]
fn session_records_do_not_change_the_canon_root_hash() {
    let root = TestDir::new("session-canon-boundary");
    fs::create_dir_all(root.path().join(".phemius/records/sessions/run_1")).unwrap();
    let project = Project {
        root: root.path().to_path_buf(),
        config: ProjectConfig {
            format_version: 1,
            work_id: prefixed_uuid(EntityKind::Work),
        },
    };
    let before = canon_root_hash(&project).unwrap();

    fs::write(
        root.path()
            .join(".phemius/records/sessions/run_1/events.jsonl"),
        b"{\"event\":\"user-instruction\"}\n",
    )
    .unwrap();

    assert_eq!(canon_root_hash(&project).unwrap(), before);
    fs::create_dir_all(root.path().join(".phemius/records/approvals")).unwrap();
    fs::write(
        root.path().join(".phemius/records/approvals/bound.json"),
        b"{}\n",
    )
    .unwrap();
    assert_ne!(canon_root_hash(&project).unwrap(), before);
}

fn micros(value: u64) -> MicroDollars {
    MicroDollars::new(value)
}

fn checkpoint_for(journal: &SessionJournal, cost: MicroDollars) -> Checkpoint {
    Checkpoint::from_journal(
        journal,
        Vec::new(),
        vec!["canon-hash".into()],
        vec!["source-hash".into()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        cost,
    )
    .unwrap()
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "phemius-session-cost-{label}-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            panic!("failed to remove {}: {error}", self.path.display());
        }
    }
}
