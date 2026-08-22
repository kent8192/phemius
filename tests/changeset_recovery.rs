use std::{fs, path::PathBuf};

use phemius::{
    changeset::{
        ApprovalRecord, Changeset, ChangesetDependency, ChangesetState, FileOperation,
        OperationKind, ValidationErrorKind, calculate_candidate_hash, calculate_validation_hash,
        canon_root_hash, content_result_hash, mark_candidate_hash_changed, projected_root_hash,
        render_diff, sha256_bytes, validate_changeset,
    },
    domain::{EntityKind, prefixed_uuid},
    journal::{
        RecoveryOutcome, TestInterruption, TestRecoveryInterruption, apply_changeset,
        apply_changeset_for_test, apply_changeset_with_test_hook, recover_pending,
        recover_pending_for_test, recover_pending_with_root_test_hook,
    },
    project::{Project, ProjectConfig},
};

#[test]
fn stale_and_incomplete_changesets_cannot_be_approved() {
    let fixture = ApplyFixture::new();
    for (state, kind) in [
        (ChangesetState::Stale, ValidationErrorKind::Stale),
        (ChangesetState::Incomplete, ValidationErrorKind::Incomplete),
        (
            ChangesetState::NeedsRevalidation,
            ValidationErrorKind::NeedsRevalidation,
        ),
    ] {
        let mut change = fixture.change.clone();
        change.state = state;
        assert_eq!(
            validate_changeset(&fixture.project, &change)
                .unwrap_err()
                .kind(),
            kind
        );
    }
}

#[test]
fn candidate_edit_invalidates_validation_and_descendants() {
    let mut graph = ApplyFixture::new().change_chain();
    graph[2].state = ChangesetState::Approved;
    let root_id = graph[0].id.clone();

    mark_candidate_hash_changed(&mut graph, &root_id, "new-hash").unwrap();

    assert_eq!(graph[0].state, ChangesetState::Reviewing);
    assert_eq!(graph[0].validation_hash, None);
    assert_eq!(graph[1].state, ChangesetState::Stale);
    assert_eq!(graph[2].state, ChangesetState::NeedsRevalidation);
    graph[1].mark_regenerated("regenerated");
    assert_eq!(graph[1].state, ChangesetState::Candidate);
    graph[2].mark_fully_revalidated("validation");
    assert_eq!(graph[2].state, ChangesetState::Approved);
}

#[test]
fn approval_records_are_not_changeset_targets() {
    let fixture = ApplyFixture::new();
    for (operation, path) in [
        (
            0,
            format!(
                ".phemius/records/approvals/{}.json",
                fixture.change.id.as_str()
            ),
        ),
        (0, ".PHEMIUS/RECORDS/APPROVALS/future.json".into()),
        (1, ".phemius/records/approvals/past.json".into()),
        (2, ".phemius/records/approvals/past.json".into()),
    ] {
        let mut change = fixture.change.clone();
        change.operations[operation].path = PathBuf::from(path);
        assert_eq!(
            validate_changeset(&fixture.project, &change)
                .unwrap_err()
                .kind(),
            ValidationErrorKind::ApprovalNamespace
        );
    }
}

#[test]
fn create_replace_delete_apply_as_one_changeset() {
    let fixture = ApplyFixture::new();

    apply_changeset(&fixture.project, &fixture.change).unwrap();

    assert!(
        fs::read(fixture.root.join("本文/create.md"))
            .unwrap()
            .ends_with(b"new\n")
    );
    assert!(
        fs::read(fixture.root.join("本文/replace.md"))
            .unwrap()
            .ends_with(b"after\n")
    );
    assert!(!fixture.root.join("本文/delete.md").exists());
    assert!(
        fixture
            .root
            .join(format!(
                ".phemius/records/approvals/{}.json",
                fixture.change.id.as_str()
            ))
            .is_file()
    );
    assert_eq!(
        canon_root_hash(&fixture.project).unwrap(),
        fixture.change.result_root_hash
    );
}

#[test]
fn successful_and_rolled_back_transactions_retain_append_only_evidence() {
    let committed = ApplyFixture::new();
    apply_changeset(&committed.project, &committed.change).unwrap();
    let committed_transaction = committed.transaction_path();
    assert!(
        committed_transaction
            .join("journal.prepared.json")
            .is_file()
    );
    assert!(
        committed_transaction
            .join("journal.committed.json")
            .is_file()
    );
    assert_eq!(recover_pending(&committed.root).unwrap().kept_committed, 1);
    assert!(committed_transaction.is_dir());

    let rolled_back = ApplyFixture::new();
    apply_changeset_for_test(
        &rolled_back.project,
        &rolled_back.change,
        TestInterruption::AfterFirstRename,
    )
    .unwrap_err();
    assert_eq!(recover_pending(&rolled_back.root).unwrap().rolled_back, 1);
    let rolled_back_transaction = rolled_back.transaction_path();
    assert!(
        rolled_back_transaction
            .join("journal.prepared.json")
            .is_file()
    );
    assert!(
        rolled_back_transaction
            .join("journal.rolled-back.json")
            .is_file()
    );
    assert_eq!(
        recover_pending(&rolled_back.root).unwrap(),
        RecoveryOutcome::default()
    );
    assert!(rolled_back_transaction.is_dir());
}

#[test]
fn retained_committed_history_survives_later_approvals() {
    let fixture = ApplyFixture::new();
    apply_changeset(&fixture.project, &fixture.change).unwrap();
    let followup = fixture.followup_change("retained-history");
    apply_changeset(&fixture.project, &followup).unwrap();

    assert_eq!(recover_pending(&fixture.root).unwrap().kept_committed, 2);
    assert!(fixture.transaction_path().is_dir());
    assert!(fixture.transaction_path_for(&followup.id).is_dir());
}

#[test]
fn injected_or_externally_renamed_transaction_evidence_is_never_deleted() {
    let injected = ApplyFixture::new();
    apply_changeset(&injected.project, &injected.change).unwrap();
    let injected_entry = injected.transaction_path().join("external-entry");
    fs::create_dir(&injected_entry).unwrap();
    fs::write(injected_entry.join("nested-evidence"), b"external evidence").unwrap();
    assert!(recover_pending(&injected.root).is_err());
    assert_eq!(
        fs::read(injected_entry.join("nested-evidence")).unwrap(),
        b"external evidence"
    );

    let renamed = ApplyFixture::new();
    apply_changeset(&renamed.project, &renamed.change).unwrap();
    let moved = renamed.outside.join("externally-renamed-transaction");
    fs::rename(renamed.transaction_path(), &moved).unwrap();
    recover_pending(&renamed.root).unwrap();
    assert!(moved.join("journal.prepared.json").is_file());
    assert!(moved.join("journal.committed.json").is_file());
}

#[test]
fn unified_diff_is_deterministic_and_sorted_by_target_path() {
    let fixture = ApplyFixture::new();

    let first = render_diff(&fixture.project, &fixture.change).unwrap();
    let second = render_diff(&fixture.project, &fixture.change).unwrap();

    assert_eq!(first, second);
    assert!(first.contains("--- a/本文/create.md"));
    assert!(first.contains("+++ b/本文/replace.md"));
    assert!(first.find("create.md").unwrap() < first.find("delete.md").unwrap());
}

#[test]
fn approval_rejects_invalid_paths_hashes_blockers_validation_and_dependencies() {
    let fixture = ApplyFixture::new();
    let cases = [
        invalid_case(&fixture.change, |change| {
            change.operations[0].path = PathBuf::from("../escape")
        }),
        invalid_case(&fixture.change, |change| {
            change.operations[0].path = PathBuf::from(".")
        }),
        invalid_case(&fixture.change, |change| {
            change.operations[0].path = PathBuf::from("/tmp/escape")
        }),
        invalid_case(&fixture.change, |change| {
            change.operations[0].path = PathBuf::from(".phemius/runtime/escape")
        }),
        invalid_case(&fixture.change, |change| {
            change.operations[0].path = PathBuf::from(".GIT/escape")
        }),
        invalid_case(&fixture.change, |change| {
            change.operations[0].candidate_path = Some(PathBuf::from("本文/not-a-candidate.md"))
        }),
        invalid_case(&fixture.change, |change| {
            change.operations[1].before_sha256 = Some("wrong".into())
        }),
        invalid_case(&fixture.change, |change| {
            change
                .unresolved_blocker_ids
                .push(prefixed_uuid(EntityKind::Finding))
        }),
        invalid_case(&fixture.change, |change| {
            change.validation_hash = Some("wrong".into())
        }),
        invalid_case(&fixture.change, |change| {
            change.base_root_hash = "wrong".into()
        }),
        invalid_case(&fixture.change, |change| {
            change.dependencies.push(ChangesetDependency {
                id: prefixed_uuid(EntityKind::Changeset),
                approval_record_sha256: "same".into(),
                chapter_order: 1,
            })
        }),
        invalid_case(&fixture.change, |change| {
            change.dependencies.push(ChangesetDependency {
                id: prefixed_uuid(EntityKind::Changeset),
                approval_record_sha256: "self-reported-but-absent".into(),
                chapter_order: 0,
            })
        }),
        invalid_case(&fixture.change, |change| {
            change.parent_changeset_id = Some(prefixed_uuid(EntityKind::Changeset))
        }),
        invalid_case(&fixture.change, |change| {
            change.operations[1].path = PathBuf::from("本文/CREATE.md")
        }),
        invalid_case(&fixture.change, |change| {
            change.operations[1].after_sha256 = change.operations[1].before_sha256.clone()
        }),
        invalid_case(&fixture.change, |change| {
            change.id = serde_json::from_str("\"change_invalid\"").unwrap()
        }),
    ];
    let expected = [
        ValidationErrorKind::InvalidPath,
        ValidationErrorKind::InvalidPath,
        ValidationErrorKind::InvalidPath,
        ValidationErrorKind::InvalidPath,
        ValidationErrorKind::InvalidPath,
        ValidationErrorKind::CandidatePath,
        ValidationErrorKind::HashMismatch,
        ValidationErrorKind::Blockers,
        ValidationErrorKind::ValidationHash,
        ValidationErrorKind::BaseRoot,
        ValidationErrorKind::DependencyOrder,
        ValidationErrorKind::DependencyHash,
        ValidationErrorKind::DependencyOrder,
        ValidationErrorKind::InvalidOperation,
        ValidationErrorKind::InvalidOperation,
        ValidationErrorKind::InvalidOperation,
    ];

    for (change, expected) in cases.into_iter().zip(expected) {
        assert_eq!(
            validate_changeset(&fixture.project, &change)
                .unwrap_err()
                .kind(),
            expected
        );
    }
}

#[test]
fn root_hash_excludes_runtime_and_local_settings_but_includes_records() {
    let fixture = ApplyFixture::new();
    let initial = canon_root_hash(&fixture.project).unwrap();
    fs::write(fixture.root.join(".phemius/local.toml"), b"secret = true\n").unwrap();
    fs::write(fixture.root.join(".phemius/runtime/transient"), b"ignore").unwrap();
    assert_eq!(canon_root_hash(&fixture.project).unwrap(), initial);

    fs::create_dir_all(fixture.root.join(".phemius/records")).unwrap();
    fs::write(fixture.root.join(".phemius/records/basis.json"), b"{}\n").unwrap();
    assert_ne!(canon_root_hash(&fixture.project).unwrap(), initial);
}

#[test]
fn a_parent_dependency_is_proven_by_its_durable_approval_record() {
    let fixture = ApplyFixture::new();
    apply_changeset(&fixture.project, &fixture.change).unwrap();
    let parent_record = fixture.root.join(format!(
        ".phemius/records/approvals/{}.json",
        fixture.change.id.as_str()
    ));

    let id = prefixed_uuid(EntityKind::Changeset);
    let candidate_path = PathBuf::from(".phemius/runtime/candidates")
        .join(id.as_str())
        .join("followup.md");
    fs::create_dir_all(fixture.root.join(candidate_path.parent().unwrap())).unwrap();
    let followup_id = prefixed_uuid(EntityKind::Chapter);
    let followup_bytes = markdown_with_id(&followup_id, "followup");
    fs::write(fixture.root.join(&candidate_path), &followup_bytes).unwrap();
    let operations = vec![FileOperation {
        kind: OperationKind::Create,
        path: PathBuf::from("本文/followup.md"),
        before_sha256: None,
        after_sha256: Some(sha256_bytes(&followup_bytes)),
        candidate_path: Some(candidate_path),
        affected_entities: vec![followup_id],
    }];
    let mut followup = Changeset {
        id,
        parent_changeset_id: Some(fixture.change.id.clone()),
        base_root_hash: canon_root_hash(&fixture.project).unwrap(),
        content_result_hash: String::new(),
        result_root_hash: String::new(),
        state: ChangesetState::Approvable,
        operations,
        candidate_hash: String::new(),
        validation_hash: None,
        unresolved_blocker_ids: Vec::new(),
        dependencies: vec![ChangesetDependency {
            id: fixture.change.id.clone(),
            approval_record_sha256: sha256_bytes(&fs::read(parent_record).unwrap()),
            chapter_order: 1,
        }],
        chapter_order: 2,
    };
    followup.candidate_hash = calculate_candidate_hash(&fixture.project, &followup).unwrap();
    followup.content_result_hash = content_result_hash(&fixture.project, &followup).unwrap();
    followup.validation_hash = Some(calculate_validation_hash(&followup));
    followup.result_root_hash = projected_root_hash(&fixture.project, &followup).unwrap();

    validate_changeset(&fixture.project, &followup).unwrap();
}

#[test]
fn existing_approval_chain_rejects_a_fresh_chapter_one_without_dependencies() {
    let fixture = ApplyFixture::new();
    apply_changeset(&fixture.project, &fixture.change).unwrap();
    let mut replay = fixture.change.clone();
    replay.id = prefixed_uuid(EntityKind::Changeset);
    replay.base_root_hash = canon_root_hash(&fixture.project).unwrap();
    replay.chapter_order = 1;

    assert_eq!(
        validate_changeset(&fixture.project, &replay)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::DependencyOrder
    );
}

#[test]
fn approval_record_persists_auditable_content_validation_and_dependency_proof() {
    let fixture = ApplyFixture::new();
    apply_changeset(&fixture.project, &fixture.change).unwrap();

    let record: ApprovalRecord =
        serde_json::from_slice(&fs::read(fixture.approval_path()).unwrap()).unwrap();
    assert_eq!(
        record.content_result_hash,
        fixture.change.content_result_hash
    );
    assert_eq!(
        record.validation_hash,
        fixture.change.validation_hash.clone().unwrap()
    );
    assert_eq!(record.dependencies, fixture.change.dependencies);
}

#[test]
fn corrupt_filename_mismatched_and_duplicate_order_approvals_fail_closed() {
    for corruption in ["json", "filename", "duplicate-order"] {
        let fixture = ApplyFixture::new();
        apply_changeset(&fixture.project, &fixture.change).unwrap();
        let original = fs::read(fixture.approval_path()).unwrap();
        match corruption {
            "json" => fs::write(fixture.approval_path(), b"not json").unwrap(),
            "filename" => fs::write(
                fixture
                    .approval_path()
                    .parent()
                    .unwrap()
                    .join("wrong-name.json"),
                &original,
            )
            .unwrap(),
            "duplicate-order" => {
                let mut record: ApprovalRecord = serde_json::from_slice(&original).unwrap();
                record.changeset_id = prefixed_uuid(EntityKind::Changeset);
                record.validation_hash = approval_validation_hash(&record);
                fs::write(
                    fixture
                        .approval_path()
                        .parent()
                        .unwrap()
                        .join(format!("{}.json", record.changeset_id.as_str())),
                    serde_json::to_vec_pretty(&record).unwrap(),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }

        let mut next = fixture.change.clone();
        next.id = prefixed_uuid(EntityKind::Changeset);
        next.base_root_hash = canon_root_hash(&fixture.project).unwrap();
        next.chapter_order = 2;
        assert_eq!(
            validate_changeset(&fixture.project, &next)
                .unwrap_err()
                .kind(),
            ValidationErrorKind::DependencyHash
        );
    }
}

#[test]
fn unicode_and_case_aliases_are_duplicate_targets() {
    let fixture = ApplyFixture::new();
    let mut change = fixture.change.clone();
    change.operations[0].path = PathBuf::from("本文/が.md");
    change.operations[1].path = PathBuf::from("本文/か\u{3099}.md");

    assert_eq!(
        validate_changeset(&fixture.project, &change)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::InvalidOperation
    );
}

#[test]
fn projected_generic_schema_and_affected_entity_ids_are_enforced() {
    let fixture = ApplyFixture::new();

    let mut invalid_markdown = fixture.change.clone();
    let candidate = invalid_markdown.operations[0]
        .candidate_path
        .clone()
        .unwrap();
    fs::write(fixture.root.join(&candidate), b"no frontmatter").unwrap();
    invalid_markdown.operations[0].after_sha256 = Some(sha256_bytes(b"no frontmatter"));
    refresh_change(&fixture.project, &mut invalid_markdown);
    assert_eq!(
        validate_changeset(&fixture.project, &invalid_markdown)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::Schema
    );

    let fixture = ApplyFixture::new();
    let mut invalid_project = fixture.change.clone();
    invalid_project.operations[1].path = PathBuf::from("project.toml");
    invalid_project.operations[1].before_sha256 = Some(sha256_bytes(
        &fs::read(fixture.root.join("project.toml")).unwrap(),
    ));
    invalid_project.operations[1].affected_entities = vec![fixture.project.config.work_id.clone()];
    refresh_change(&fixture.project, &mut invalid_project);
    assert_eq!(
        validate_changeset(&fixture.project, &invalid_project)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::Schema
    );

    let fixture = ApplyFixture::new();
    let mut required_delete = fixture.change.clone();
    required_delete.operations[2].path = PathBuf::from("project.toml");
    required_delete.operations[2].before_sha256 = Some(sha256_bytes(
        &fs::read(fixture.root.join("project.toml")).unwrap(),
    ));
    assert_eq!(
        validate_changeset(&fixture.project, &required_delete)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::InvalidOperation
    );

    let mut invalid_entity = fixture.change.clone();
    invalid_entity.operations[0]
        .affected_entities
        .push(serde_json::from_str("\"chapter_invalid\"").unwrap());
    assert_eq!(
        validate_changeset(&fixture.project, &invalid_entity)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::InvalidOperation
    );

    let mut duplicate_entity = fixture.change.clone();
    let entity = duplicate_entity.operations[0].affected_entities[0].clone();
    duplicate_entity.operations[0]
        .affected_entities
        .push(entity);
    assert_eq!(
        validate_changeset(&fixture.project, &duplicate_entity)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::InvalidOperation
    );
}

#[test]
fn projected_schema_validates_unchanged_artifacts_and_semantic_identity() {
    let fixture = ApplyFixture::new();
    fs::write(fixture.root.join("本文/broken.md"), b"no frontmatter").unwrap();
    let mut unchanged_broken = fixture.change.clone();
    rebase_and_refresh(&fixture.project, &mut unchanged_broken);
    assert_eq!(
        validate_changeset(&fixture.project, &unchanged_broken)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::Schema
    );

    let fixture = ApplyFixture::new();
    let mut duplicate_id = fixture.change.clone();
    let existing_id = duplicate_id.operations[1].affected_entities[0].clone();
    let candidate = duplicate_id.operations[0].candidate_path.clone().unwrap();
    let duplicate_bytes = markdown_with_id(&existing_id, "duplicate");
    fs::write(fixture.root.join(&candidate), &duplicate_bytes).unwrap();
    duplicate_id.operations[0].after_sha256 = Some(sha256_bytes(&duplicate_bytes));
    duplicate_id.operations[0].affected_entities = vec![prefixed_uuid(EntityKind::Chapter)];
    refresh_change(&fixture.project, &mut duplicate_id);
    assert_eq!(
        validate_changeset(&fixture.project, &duplicate_id)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::Schema
    );

    let fixture = ApplyFixture::new();
    let mut replace_id_change = fixture.change.clone();
    let candidate = replace_id_change.operations[1]
        .candidate_path
        .clone()
        .unwrap();
    let changed_bytes = markdown(EntityKind::Chapter, "changed identity");
    fs::write(fixture.root.join(&candidate), &changed_bytes).unwrap();
    replace_id_change.operations[1].after_sha256 = Some(sha256_bytes(&changed_bytes));
    refresh_change(&fixture.project, &mut replace_id_change);
    assert_eq!(
        validate_changeset(&fixture.project, &replace_id_change)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::Schema
    );

    let fixture = ApplyFixture::new();
    let mut work_id_change = fixture.change.clone();
    let candidate = work_id_change.operations[1].candidate_path.clone().unwrap();
    let changed_config = ProjectConfig {
        format_version: 1,
        work_id: prefixed_uuid(EntityKind::Work),
    };
    let config_bytes = toml::to_string(&changed_config).unwrap().into_bytes();
    fs::write(fixture.root.join(&candidate), &config_bytes).unwrap();
    work_id_change.operations[1].path = PathBuf::from("project.toml");
    work_id_change.operations[1].before_sha256 = Some(sha256_bytes(
        &fs::read(fixture.root.join("project.toml")).unwrap(),
    ));
    work_id_change.operations[1].after_sha256 = Some(sha256_bytes(&config_bytes));
    work_id_change.operations[1].affected_entities = vec![fixture.project.config.work_id.clone()];
    refresh_change(&fixture.project, &mut work_id_change);
    assert_eq!(
        validate_changeset(&fixture.project, &work_id_change)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::Schema
    );
}

#[test]
fn projected_schema_excludes_non_artifact_markdown() {
    let fixture = ApplyFixture::new();
    for path in [
        "AGENTS.md",
        "assets/readme.md",
        "docs/readme.md",
        ".phemius/records/raw.md",
        "資料/snapshots/raw.md",
    ] {
        let path = fixture.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"not a canon artifact").unwrap();
    }
    let mut change = fixture.change.clone();
    rebase_and_refresh(&fixture.project, &mut change);
    validate_changeset(&fixture.project, &change).unwrap();
}

#[test]
fn create_targets_cannot_alias_existing_canon_paths() {
    let fixture = ApplyFixture::new();
    let mut case_alias = fixture.change.clone();
    case_alias.operations[0].path = PathBuf::from("PROJECT.TOML");
    refresh_change(&fixture.project, &mut case_alias);
    assert_eq!(
        validate_changeset(&fixture.project, &case_alias)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::InvalidOperation
    );

    let fixture = ApplyFixture::new();
    let existing_id = prefixed_uuid(EntityKind::Chapter);
    fs::write(
        fixture.root.join("本文/が.md"),
        markdown_with_id(&existing_id, "existing alias"),
    )
    .unwrap();
    let mut unicode_alias = fixture.change.clone();
    unicode_alias.operations[0].path = PathBuf::from("本文/か\u{3099}.md");
    rebase_and_refresh(&fixture.project, &mut unicode_alias);
    assert_eq!(
        validate_changeset(&fixture.project, &unicode_alias)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::InvalidOperation
    );
}

#[test]
fn affected_entities_are_required_per_operation_but_reusable_across_operations() {
    let fixture = ApplyFixture::new();
    let mut empty = fixture.change.clone();
    empty.operations[0].affected_entities.clear();
    refresh_change(&fixture.project, &mut empty);
    assert_eq!(
        validate_changeset(&fixture.project, &empty)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::InvalidOperation
    );

    let fixture = ApplyFixture::new();
    let mut shared = fixture.change.clone();
    let entity = prefixed_uuid(EntityKind::Chapter);
    for operation in &mut shared.operations {
        operation.affected_entities = vec![entity.clone()];
    }
    refresh_change(&fixture.project, &mut shared);
    validate_changeset(&fixture.project, &shared).unwrap();
}

#[test]
fn project_toml_operation_uses_the_immutable_work_id() {
    let fixture = ApplyFixture::new();
    let mut change = fixture.change.clone();
    let candidate = change.operations[1].candidate_path.clone().unwrap();
    let mut config_bytes = fs::read(fixture.root.join("project.toml")).unwrap();
    config_bytes.extend_from_slice(b"\n# retained work id\n");
    fs::write(fixture.root.join(&candidate), &config_bytes).unwrap();
    change.operations[1].path = PathBuf::from("project.toml");
    change.operations[1].before_sha256 = Some(sha256_bytes(
        &fs::read(fixture.root.join("project.toml")).unwrap(),
    ));
    change.operations[1].after_sha256 = Some(sha256_bytes(&config_bytes));
    change.operations[1].affected_entities = vec![prefixed_uuid(EntityKind::Chapter)];
    refresh_change(&fixture.project, &mut change);
    assert_eq!(
        validate_changeset(&fixture.project, &change)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::InvalidOperation
    );

    change.operations[1].affected_entities = vec![fixture.project.config.work_id.clone()];
    refresh_change(&fixture.project, &mut change);
    validate_changeset(&fixture.project, &change).unwrap();
}

#[test]
fn interrupted_apply_recovers_the_complete_old_state() {
    let fixture = ApplyFixture::new();
    let before = fixture.read_canon();

    assert!(
        apply_changeset_for_test(
            &fixture.project,
            &fixture.change,
            TestInterruption::AfterFirstRename,
        )
        .is_err()
    );
    assert_eq!(recover_pending(&fixture.root).unwrap().rolled_back, 1);
    assert_eq!(fixture.read_canon(), before);
}

#[test]
fn committed_journal_recovery_keeps_the_new_state() {
    let fixture = ApplyFixture::new();

    assert!(
        apply_changeset_for_test(
            &fixture.project,
            &fixture.change,
            TestInterruption::AfterCommit,
        )
        .is_err()
    );
    let expected = fixture.change.result_root_hash.clone();

    assert_eq!(
        recover_pending(&fixture.root).unwrap(),
        RecoveryOutcome {
            rolled_back: 0,
            kept_committed: 1,
        }
    );
    assert_eq!(canon_root_hash(&fixture.project).unwrap(), expected);
}

#[test]
fn committed_recovery_does_not_require_rollback_images() {
    let fixture = ApplyFixture::new();
    apply_changeset_for_test(
        &fixture.project,
        &fixture.change,
        TestInterruption::AfterCommit,
    )
    .unwrap_err();
    fs::remove_file(
        fixture
            .root
            .join(".phemius/runtime/journal")
            .join(fixture.change.id.as_str())
            .join("before-0001"),
    )
    .unwrap();

    assert_eq!(recover_pending(&fixture.root).unwrap().kept_committed, 1);
    assert_eq!(
        canon_root_hash(&fixture.project).unwrap(),
        fixture.change.result_root_hash
    );
}

#[test]
fn every_apply_boundary_recovers_idempotently() {
    for point in [
        TestInterruption::AfterReplacePreserve,
        TestInterruption::AfterReplaceInstall,
        TestInterruption::AfterDeletePreserve,
        TestInterruption::AfterApprovalInstall,
    ] {
        let fixture = ApplyFixture::new();
        let before = fixture.read_canon();
        assert!(apply_changeset_for_test(&fixture.project, &fixture.change, point).is_err());
        assert_eq!(recover_pending(&fixture.root).unwrap().rolled_back, 1);
        assert_eq!(fixture.read_canon(), before);
        assert_eq!(
            recover_pending(&fixture.root).unwrap(),
            RecoveryOutcome::default()
        );
    }
}

#[test]
fn committed_cleanup_pending_remains_append_only_history() {
    let fixture = ApplyFixture::new();

    apply_changeset_for_test(
        &fixture.project,
        &fixture.change,
        TestInterruption::CleanupPending,
    )
    .unwrap();

    assert_eq!(recover_pending(&fixture.root).unwrap().kept_committed, 1);
    assert_eq!(recover_pending(&fixture.root).unwrap().kept_committed, 1);
}

#[test]
fn committed_journal_sync_failure_never_rolls_back_and_requires_recovery() {
    let fixture = ApplyFixture::new();

    let error = apply_changeset_for_test(
        &fixture.project,
        &fixture.change,
        TestInterruption::CommitDurabilityUnknown,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("commit durability unknown; run recovery, do not retry")
    );
    assert_eq!(recover_pending(&fixture.root).unwrap().kept_committed, 1);
    assert_eq!(
        canon_root_hash(&fixture.project).unwrap(),
        fixture.change.result_root_hash
    );
}

#[test]
fn unknown_entries_and_multiple_pending_transactions_fail_closed() {
    for multiple in [false, true] {
        let fixture = ApplyFixture::new();
        apply_changeset_for_test(
            &fixture.project,
            &fixture.change,
            TestInterruption::AfterFirstRename,
        )
        .unwrap_err();
        let journal_root = fixture.root.join(".phemius/runtime/journal");
        if multiple {
            fs::create_dir(journal_root.join(prefixed_uuid(EntityKind::Changeset).as_str()))
                .unwrap();
        } else {
            fs::write(
                journal_root
                    .join(fixture.change.id.as_str())
                    .join("unknown-entry"),
                b"evidence",
            )
            .unwrap();
        }

        assert!(recover_pending(&fixture.root).is_err());
        assert!(fixture.root.join("本文/create.md").exists());
        assert!(journal_root.join(fixture.change.id.as_str()).exists());
    }
}

#[test]
fn approval_rollback_quarantine_never_unlinks_an_external_replacement() {
    let fixture = ApplyFixture::new();
    apply_changeset_for_test(
        &fixture.project,
        &fixture.change,
        TestInterruption::AfterApprovalInstall,
    )
    .unwrap_err();
    recover_pending_for_test(
        &fixture.root,
        TestRecoveryInterruption::AfterFirstQuarantine,
    )
    .unwrap_err();
    fs::write(fixture.approval_path(), b"external approval replacement").unwrap();

    assert!(recover_pending(&fixture.root).is_err());
    assert_eq!(
        fs::read(fixture.approval_path()).unwrap(),
        b"external approval replacement"
    );
}

#[cfg(unix)]
#[test]
fn prepared_capabilities_cannot_be_redirected_by_parent_symlink_swaps() {
    let fixture = ApplyFixture::new();

    assert!(
        apply_changeset_with_test_hook(&fixture.project, &fixture.change, swap_managed_parents)
            .is_err()
    );
    assert!(
        fs::read_dir(fixture.outside.join("本文"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        fs::read_dir(fixture.outside.join("approvals"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        fs::read_dir(fixture.outside.join("journal"))
            .unwrap()
            .next()
            .is_none()
    );

    restore_managed_parents(&fixture.project);
    assert_eq!(recover_pending(&fixture.root).unwrap().rolled_back, 1);
    assert_eq!(fixture.read_canon()[0], None);
}

#[cfg(unix)]
#[test]
fn apply_keeps_using_the_pinned_root_after_the_project_path_is_swapped() {
    let fixture = ApplyFixture::new();

    let result =
        apply_changeset_with_test_hook(&fixture.project, &fixture.change, swap_project_root);
    assert_eq!(
        fs::read(fixture.root.join("replacement-root-marker")).unwrap(),
        b"outside replacement root"
    );
    assert!(!fixture.root.join("本文/create.md").exists());
    restore_project_root(&fixture.root);

    result.unwrap();
    assert!(fixture.root.join("本文/create.md").is_file());
    assert!(fixture.transaction_path().is_dir());
}

#[cfg(unix)]
#[test]
fn recovery_keeps_using_the_pinned_root_after_the_project_path_is_swapped() {
    let fixture = ApplyFixture::new();
    let before = fixture.read_canon();
    apply_changeset_for_test(
        &fixture.project,
        &fixture.change,
        TestInterruption::AfterFirstRename,
    )
    .unwrap_err();

    let result = recover_pending_with_root_test_hook(&fixture.root, swap_project_root_path);
    assert_eq!(
        fs::read(fixture.root.join("replacement-root-marker")).unwrap(),
        b"outside replacement root"
    );
    assert!(!fixture.root.join("本文/create.md").exists());
    restore_project_root(&fixture.root);

    assert_eq!(result.unwrap().rolled_back, 1);
    assert_eq!(fixture.read_canon(), before);
    assert!(
        fixture
            .transaction_path()
            .join("journal.rolled-back.json")
            .is_file()
    );
}

#[test]
fn missing_or_corrupt_journal_evidence_is_preserved_fail_closed() {
    for corrupt in [false, true] {
        let fixture = ApplyFixture::new();
        assert!(
            apply_changeset_for_test(
                &fixture.project,
                &fixture.change,
                TestInterruption::AfterFirstRename,
            )
            .is_err()
        );
        let transaction = fixture
            .root
            .join(".phemius/runtime/journal")
            .join(fixture.change.id.as_str());
        let journal = transaction.join("journal.prepared.json");
        if corrupt {
            fs::write(&journal, b"not json").unwrap();
        } else {
            fs::remove_file(&journal).unwrap();
        }

        assert!(recover_pending(&fixture.root).is_err());
        assert!(transaction.exists());
        assert!(fixture.root.join("本文/create.md").exists());
    }
}

#[test]
fn journal_state_must_match_its_append_only_marker_name() {
    let fixture = ApplyFixture::new();
    apply_changeset(&fixture.project, &fixture.change).unwrap();
    let marker = fixture.transaction_path().join("journal.committed.json");
    let mut journal: serde_json::Value =
        serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    journal["state"] = serde_json::Value::String("rolled-back".into());
    fs::write(&marker, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();

    assert!(recover_pending(&fixture.root).is_err());
    assert!(marker.is_file());
}

#[test]
fn retained_committed_journal_must_match_its_approval_record() {
    let fixture = ApplyFixture::new();
    apply_changeset(&fixture.project, &fixture.change).unwrap();
    let followup = fixture.followup_change("journal-record-match");
    apply_changeset(&fixture.project, &followup).unwrap();
    for name in ["journal.prepared.json", "journal.committed.json"] {
        let marker = fixture.transaction_path().join(name);
        let mut journal: serde_json::Value =
            serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
        journal["chapter_order"] = serde_json::Value::Number(99.into());
        fs::write(marker, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    }

    assert!(recover_pending(&fixture.root).is_err());
    assert!(fixture.transaction_path().is_dir());
}

#[test]
fn rollback_quarantines_before_hashing_and_never_unlinks_a_replacement() {
    let fixture = ApplyFixture::new();
    assert!(
        apply_changeset_for_test(
            &fixture.project,
            &fixture.change,
            TestInterruption::AfterFirstRename,
        )
        .is_err()
    );
    assert!(
        recover_pending_for_test(
            &fixture.root,
            TestRecoveryInterruption::AfterFirstQuarantine,
        )
        .is_err()
    );
    fs::write(fixture.root.join("本文/create.md"), b"external replacement").unwrap();

    assert!(recover_pending(&fixture.root).is_err());
    assert_eq!(
        fs::read(fixture.root.join("本文/create.md")).unwrap(),
        b"external replacement"
    );
    assert!(
        fixture
            .root
            .join(".phemius/runtime/journal")
            .join(fixture.change.id.as_str())
            .exists()
    );
}

#[test]
fn an_external_edit_is_never_overwritten() {
    let fixture = ApplyFixture::new();
    fs::write(fixture.root.join("本文/replace.md"), b"external").unwrap();

    assert!(apply_changeset(&fixture.project, &fixture.change).is_err());
    assert_eq!(
        fs::read(fixture.root.join("本文/replace.md")).unwrap(),
        b"external"
    );
}

#[cfg(unix)]
#[test]
fn candidate_symlinks_are_rejected_even_when_they_resolve_inside_the_project() {
    use std::os::unix::fs::symlink;

    let fixture = ApplyFixture::new();
    let candidate = fixture.root.join(
        fixture.change.operations[0]
            .candidate_path
            .as_ref()
            .unwrap(),
    );
    fs::remove_file(&candidate).unwrap();
    symlink(fixture.root.join("本文/replace.md"), &candidate).unwrap();

    assert_eq!(
        validate_changeset(&fixture.project, &fixture.change)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::CandidatePath
    );
}

#[cfg(unix)]
#[test]
fn target_parent_symlinks_are_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = ApplyFixture::new();
    symlink(fixture.root.join("本文"), fixture.root.join("alias")).unwrap();
    let mut change = fixture.change.clone();
    change.operations[0].path = PathBuf::from("alias/create.md");

    assert_eq!(
        validate_changeset(&fixture.project, &change)
            .unwrap_err()
            .kind(),
        ValidationErrorKind::InvalidPath
    );
}

fn invalid_case(change: &Changeset, mutate: impl FnOnce(&mut Changeset)) -> Changeset {
    let mut invalid = change.clone();
    mutate(&mut invalid);
    invalid
}

struct ApplyFixture {
    root: PathBuf,
    outside: PathBuf,
    project: Project,
    change: Changeset,
}

impl ApplyFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("phemius-apply-{}", uuid::Uuid::now_v7()));
        let outside = root.with_extension("outside");
        fs::create_dir_all(root.join("本文")).unwrap();
        fs::create_dir_all(root.join(".phemius/runtime/candidates")).unwrap();
        for directory in ["本文", "approvals", "journal"] {
            fs::create_dir_all(outside.join(directory)).unwrap();
        }
        let config = ProjectConfig {
            format_version: 1,
            work_id: prefixed_uuid(EntityKind::Work),
        };
        fs::write(root.join("project.toml"), toml::to_string(&config).unwrap()).unwrap();
        let create_id = prefixed_uuid(EntityKind::Chapter);
        let replace_id = prefixed_uuid(EntityKind::Chapter);
        let delete_id = prefixed_uuid(EntityKind::Chapter);
        let create = markdown_with_id(&create_id, "new");
        let before = markdown_with_id(&replace_id, "before");
        let after = markdown_with_id(&replace_id, "after");
        let delete = markdown_with_id(&delete_id, "delete");
        fs::write(root.join("本文/replace.md"), &before).unwrap();
        fs::write(root.join("本文/delete.md"), &delete).unwrap();
        let project = Project {
            root: root.clone(),
            config,
        };
        let id = prefixed_uuid(EntityKind::Changeset);
        let candidate_root = PathBuf::from(".phemius/runtime/candidates").join(id.as_str());
        fs::create_dir_all(root.join(&candidate_root)).unwrap();
        fs::write(root.join(candidate_root.join("create.md")), &create).unwrap();
        fs::write(root.join(candidate_root.join("replace.md")), &after).unwrap();

        let operations = vec![
            FileOperation {
                kind: OperationKind::Create,
                path: PathBuf::from("本文/create.md"),
                before_sha256: None,
                after_sha256: Some(sha256_bytes(&create)),
                candidate_path: Some(candidate_root.join("create.md")),
                affected_entities: vec![create_id],
            },
            FileOperation {
                kind: OperationKind::Replace,
                path: PathBuf::from("本文/replace.md"),
                before_sha256: Some(sha256_bytes(&before)),
                after_sha256: Some(sha256_bytes(&after)),
                candidate_path: Some(candidate_root.join("replace.md")),
                affected_entities: vec![replace_id],
            },
            FileOperation {
                kind: OperationKind::Delete,
                path: PathBuf::from("本文/delete.md"),
                before_sha256: Some(sha256_bytes(&delete)),
                after_sha256: None,
                candidate_path: None,
                affected_entities: vec![delete_id],
            },
        ];
        let mut change = Changeset {
            id,
            parent_changeset_id: None,
            base_root_hash: canon_root_hash(&project).unwrap(),
            content_result_hash: String::new(),
            result_root_hash: String::new(),
            state: ChangesetState::Approvable,
            operations,
            candidate_hash: String::new(),
            validation_hash: None,
            unresolved_blocker_ids: Vec::new(),
            dependencies: Vec::new(),
            chapter_order: 1,
        };
        change.candidate_hash = calculate_candidate_hash(&project, &change).unwrap();
        change.content_result_hash = content_result_hash(&project, &change).unwrap();
        change.validation_hash = Some(calculate_validation_hash(&change));
        change.result_root_hash = projected_root_hash(&project, &change).unwrap();
        Self {
            root,
            outside,
            project,
            change,
        }
    }

    fn change_chain(&self) -> Vec<Changeset> {
        let mut graph = Vec::new();
        for index in 0..3 {
            let mut change = self.change.clone();
            change.id = prefixed_uuid(EntityKind::Changeset);
            change.parent_changeset_id = graph.last().map(|parent: &Changeset| parent.id.clone());
            change.chapter_order = index + 1;
            graph.push(change);
        }
        graph
    }

    fn read_canon(&self) -> Vec<Option<Vec<u8>>> {
        ["本文/create.md", "本文/replace.md", "本文/delete.md"]
            .into_iter()
            .map(|path| fs::read(self.root.join(path)).ok())
            .collect()
    }

    fn approval_path(&self) -> PathBuf {
        self.root
            .join(".phemius/records/approvals")
            .join(format!("{}.json", self.change.id.as_str()))
    }

    fn transaction_path(&self) -> PathBuf {
        self.transaction_path_for(&self.change.id)
    }

    fn transaction_path_for(&self, id: &phemius::domain::EntityId) -> PathBuf {
        self.root.join(".phemius/runtime/journal").join(id.as_str())
    }

    fn followup_change(&self, name: &str) -> Changeset {
        let id = prefixed_uuid(EntityKind::Changeset);
        let entity = prefixed_uuid(EntityKind::Chapter);
        let candidate_path = PathBuf::from(".phemius/runtime/candidates")
            .join(id.as_str())
            .join(format!("{name}.md"));
        fs::create_dir_all(self.root.join(candidate_path.parent().unwrap())).unwrap();
        let bytes = markdown_with_id(&entity, name);
        fs::write(self.root.join(&candidate_path), &bytes).unwrap();
        let mut change = Changeset {
            id,
            parent_changeset_id: Some(self.change.id.clone()),
            base_root_hash: canon_root_hash(&self.project).unwrap(),
            content_result_hash: String::new(),
            result_root_hash: String::new(),
            state: ChangesetState::Approvable,
            operations: vec![FileOperation {
                kind: OperationKind::Create,
                path: PathBuf::from("本文").join(format!("{name}.md")),
                before_sha256: None,
                after_sha256: Some(sha256_bytes(&bytes)),
                candidate_path: Some(candidate_path),
                affected_entities: vec![entity],
            }],
            candidate_hash: String::new(),
            validation_hash: None,
            unresolved_blocker_ids: Vec::new(),
            dependencies: vec![ChangesetDependency {
                id: self.change.id.clone(),
                approval_record_sha256: sha256_bytes(&fs::read(self.approval_path()).unwrap()),
                chapter_order: 1,
            }],
            chapter_order: 2,
        };
        refresh_change(&self.project, &mut change);
        change
    }
}

fn markdown(kind: EntityKind, body: &str) -> Vec<u8> {
    markdown_with_id(&prefixed_uuid(kind), body)
}

fn markdown_with_id(id: &phemius::domain::EntityId, body: &str) -> Vec<u8> {
    format!("---\nid: {}\n---\n{body}\n", id.as_str()).into_bytes()
}

impl Drop for ApplyFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
        fs::remove_dir_all(&self.outside).unwrap();
    }
}

fn refresh_change(project: &Project, change: &mut Changeset) {
    change.candidate_hash = calculate_candidate_hash(project, change).unwrap();
    change.content_result_hash = content_result_hash(project, change).unwrap();
    change.validation_hash = Some(calculate_validation_hash(change));
    change.result_root_hash = projected_root_hash(project, change).unwrap();
}

fn rebase_and_refresh(project: &Project, change: &mut Changeset) {
    change.base_root_hash = canon_root_hash(project).unwrap();
    refresh_change(project, change);
}

fn approval_validation_hash(record: &ApprovalRecord) -> String {
    #[derive(serde::Serialize)]
    struct Material<'a> {
        id: &'a phemius::domain::EntityId,
        base_root_hash: &'a str,
        content_result_hash: &'a str,
        operations_hash: &'a str,
        candidate_hash: &'a str,
        dependencies: &'a [ChangesetDependency],
        chapter_order: u32,
    }
    sha256_bytes(
        &serde_json::to_vec(&Material {
            id: &record.changeset_id,
            base_root_hash: &record.base_root_hash,
            content_result_hash: &record.content_result_hash,
            operations_hash: &record.operations_hash,
            candidate_hash: &record.candidate_hash,
            dependencies: &record.dependencies,
            chapter_order: record.chapter_order,
        })
        .unwrap(),
    )
}

#[cfg(unix)]
fn swap_managed_parents(project: &Project) {
    use std::os::unix::fs::symlink;

    let outside = project.root.with_extension("outside");
    fs::rename(project.root.join("本文"), project.root.join("本文-held")).unwrap();
    symlink(outside.join("本文"), project.root.join("本文")).unwrap();

    let approvals = project.root.join(".phemius/records/approvals");
    fs::rename(&approvals, approvals.with_file_name("approvals-held")).unwrap();
    symlink(outside.join("approvals"), &approvals).unwrap();

    let journal = project.root.join(".phemius/runtime/journal");
    fs::rename(&journal, journal.with_file_name("journal-held")).unwrap();
    symlink(outside.join("journal"), &journal).unwrap();
}

#[cfg(unix)]
fn restore_managed_parents(project: &Project) {
    for (path, held) in [
        (project.root.join("本文"), project.root.join("本文-held")),
        (
            project.root.join(".phemius/records/approvals"),
            project.root.join(".phemius/records/approvals-held"),
        ),
        (
            project.root.join(".phemius/runtime/journal"),
            project.root.join(".phemius/runtime/journal-held"),
        ),
    ] {
        fs::remove_file(&path).unwrap();
        fs::rename(held, path).unwrap();
    }
}

#[cfg(unix)]
fn swap_project_root(project: &Project) {
    swap_project_root_path(&project.root);
}

#[cfg(unix)]
fn swap_project_root_path(root: &std::path::Path) {
    fs::rename(root, root.with_extension("held-root")).unwrap();
    fs::create_dir(root).unwrap();
    fs::write(
        root.join("replacement-root-marker"),
        b"outside replacement root",
    )
    .unwrap();
}

#[cfg(unix)]
fn restore_project_root(root: &std::path::Path) {
    fs::remove_dir_all(root).unwrap();
    fs::rename(root.with_extension("held-root"), root).unwrap();
}
