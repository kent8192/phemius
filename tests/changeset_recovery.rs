use std::{fs, path::PathBuf};

use phemius::{
    changeset::{
        Changeset, ChangesetDependency, ChangesetState, FileOperation, OperationKind,
        ValidationErrorKind, calculate_candidate_hash, calculate_validation_hash, canon_root_hash,
        mark_candidate_hash_changed, projected_root_hash, render_diff, sha256_bytes,
        validate_changeset,
    },
    domain::{EntityKind, prefixed_uuid},
    journal::{
        RecoveryOutcome, TestInterruption, apply_changeset, apply_changeset_for_test,
        recover_pending,
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
    assert_eq!(graph[2].state, ChangesetState::Approvable);
}

#[test]
fn create_replace_delete_apply_as_one_changeset() {
    let fixture = ApplyFixture::new();

    apply_changeset(&fixture.project, &fixture.change).unwrap();

    assert_eq!(
        fs::read(fixture.root.join("本文/create.md")).unwrap(),
        b"new"
    );
    assert_eq!(
        fs::read(fixture.root.join("本文/replace.md")).unwrap(),
        b"after"
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
    fs::write(fixture.root.join(&candidate_path), b"followup").unwrap();
    let operations = vec![FileOperation {
        kind: OperationKind::Create,
        path: PathBuf::from("本文/followup.md"),
        before_sha256: None,
        after_sha256: Some(sha256_bytes(b"followup")),
        candidate_path: Some(candidate_path),
        affected_entities: Vec::new(),
    }];
    let mut followup = Changeset {
        id,
        parent_changeset_id: Some(fixture.change.id.clone()),
        base_root_hash: canon_root_hash(&fixture.project).unwrap(),
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
    followup.result_root_hash = projected_root_hash(&fixture.project, &followup).unwrap();
    followup.validation_hash = Some(calculate_validation_hash(&followup));

    validate_changeset(&fixture.project, &followup).unwrap();
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
    project: Project,
    change: Changeset,
}

impl ApplyFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("phemius-apply-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(root.join("本文")).unwrap();
        fs::create_dir_all(root.join(".phemius/runtime/candidates")).unwrap();
        fs::write(root.join("project.toml"), b"format_version = 1\n").unwrap();
        fs::write(root.join("本文/replace.md"), b"before").unwrap();
        fs::write(root.join("本文/delete.md"), b"delete").unwrap();
        let project = Project {
            root: root.clone(),
            config: ProjectConfig {
                format_version: 1,
                work_id: prefixed_uuid(EntityKind::Work),
            },
        };
        let id = prefixed_uuid(EntityKind::Changeset);
        let candidate_root = PathBuf::from(".phemius/runtime/candidates").join(id.as_str());
        fs::create_dir_all(root.join(&candidate_root)).unwrap();
        fs::write(root.join(candidate_root.join("create.md")), b"new").unwrap();
        fs::write(root.join(candidate_root.join("replace.md")), b"after").unwrap();

        let operations = vec![
            FileOperation {
                kind: OperationKind::Create,
                path: PathBuf::from("本文/create.md"),
                before_sha256: None,
                after_sha256: Some(sha256_bytes(b"new")),
                candidate_path: Some(candidate_root.join("create.md")),
                affected_entities: Vec::new(),
            },
            FileOperation {
                kind: OperationKind::Replace,
                path: PathBuf::from("本文/replace.md"),
                before_sha256: Some(sha256_bytes(b"before")),
                after_sha256: Some(sha256_bytes(b"after")),
                candidate_path: Some(candidate_root.join("replace.md")),
                affected_entities: Vec::new(),
            },
            FileOperation {
                kind: OperationKind::Delete,
                path: PathBuf::from("本文/delete.md"),
                before_sha256: Some(sha256_bytes(b"delete")),
                after_sha256: None,
                candidate_path: None,
                affected_entities: Vec::new(),
            },
        ];
        let mut change = Changeset {
            id,
            parent_changeset_id: None,
            base_root_hash: canon_root_hash(&project).unwrap(),
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
        change.result_root_hash = projected_root_hash(&project, &change).unwrap();
        change.validation_hash = Some(calculate_validation_hash(&change));
        Self {
            root,
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
}

impl Drop for ApplyFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
