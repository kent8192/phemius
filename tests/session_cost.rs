use std::{
    fs,
    path::{Path, PathBuf},
};

use phemius::{
    changeset::canon_root_hash,
    cost::{BudgetLedger, MicroDollars, Price, Usage},
    domain::{EntityKind, prefixed_uuid},
    project::{Project, ProjectConfig},
    session::{Checkpoint, CompactionDecision, SessionEvent, SessionJournal},
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
    let ledger = BudgetLedger::new(micros(9_000_000), micros(100_000_000));

    assert!(ledger.reserve("chapter_1", micros(400_000)).is_ok());
    assert!(ledger.reserve("chapter_1", micros(700_000)).is_err());
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
