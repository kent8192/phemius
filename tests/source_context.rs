use std::{
    collections::HashSet,
    ffi::CString,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use phemius::{
    context::{ByteRange, ContextCompiler, ContextRequest, CoverageDisposition, SourceSummary},
    copycheck::{
        AllowedSource, CopyPolicy, CopyRule, CopyScanError, CopyScanLimit,
        scan_near_copy as try_scan_near_copy,
    },
    domain::{EntityKind, prefixed_uuid},
    plot::{StoryChapter, StoryPart, StoryScene, StoryStructure},
    sources::{
        ManifestDocument, PathGrant, Snapshot, SourceEntry, SourceErrorKind, SourceKind,
        SourceManifest, SourceScope, SourceTier, WebResponse, WebSnapshotLimits, ingest_path,
        ingest_pdf, snapshot_web_from_responses,
    },
};
use rstest::*;

#[rstest]
fn receipt_accounts_for_every_applicable_source_once() {
    let raw = Snapshot::from_text(SourceKind::PlainText, b"required source", false).unwrap();
    let compacted =
        Snapshot::from_text(SourceKind::Markdown, b"long compactable source", false).unwrap();
    let optional = Snapshot::from_text(SourceKind::PlainText, vec![b'x'; 1_000], false).unwrap();
    let raw_id = prefixed_uuid(EntityKind::Source);
    let compacted_id = prefixed_uuid(EntityKind::Source);
    let optional_id = prefixed_uuid(EntityKind::Source);
    let manifest = SourceManifest::new(vec![
        SourceEntry::from_snapshot(
            raw_id.clone(),
            SourceScope::Work,
            SourceTier::RequiredRaw,
            &raw,
        ),
        SourceEntry::from_snapshot(
            compacted_id.clone(),
            SourceScope::Work,
            SourceTier::Compactable,
            &compacted,
        ),
        SourceEntry::from_snapshot(
            optional_id.clone(),
            SourceScope::Work,
            SourceTier::Optional,
            &optional,
        ),
    ])
    .unwrap();
    let compiled = ContextCompiler::new(manifest, vec![raw, compacted.clone(), optional])
        .unwrap()
        .with_summary(SourceSummary::new(
            compacted_id,
            compacted.raw_sha256(),
            0.."long compactable source".len(),
            "short summary",
        ))
        .compile(&ContextRequest {
            target: prefixed_uuid(EntityKind::Chapter),
            role: "writer".into(),
            budget_tokens: 300,
            requested_output_tokens: 100,
        })
        .unwrap();

    assert_eq!(compiled.receipt().entries().len(), 3);
    assert_eq!(
        compiled
            .receipt()
            .entries()
            .iter()
            .map(|entry| entry.source_id().unwrap().as_str())
            .collect::<HashSet<_>>()
            .len(),
        3
    );
    assert!(
        compiled
            .receipt()
            .entries()
            .iter()
            .any(|entry| entry.disposition() == Some(CoverageDisposition::Raw))
    );
    assert!(
        compiled
            .receipt()
            .entries()
            .iter()
            .any(|entry| entry.disposition() == Some(CoverageDisposition::Compacted))
    );
    assert!(
        compiled
            .receipt()
            .entries()
            .iter()
            .any(|entry| entry.disposition() == Some(CoverageDisposition::Excluded))
    );
}

#[rstest]
fn required_raw_overflow_stops_instead_of_truncating() {
    let snapshot = Snapshot::from_text(SourceKind::PlainText, vec![b'x'; 120], false).unwrap();
    let source_id = prefixed_uuid(EntityKind::Source);
    let manifest = SourceManifest::new(vec![SourceEntry::from_snapshot(
        source_id.clone(),
        SourceScope::Work,
        SourceTier::RequiredRaw,
        &snapshot,
    )])
    .unwrap();

    let error = ContextCompiler::new(manifest, vec![snapshot])
        .unwrap()
        .compile(&ContextRequest {
            target: prefixed_uuid(EntityKind::Chapter),
            role: "writer".into(),
            budget_tokens: 10,
            requested_output_tokens: 100,
        })
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "required raw context for {} exceeds the input budget",
            source_id.as_str()
        )
    );
    assert_eq!(error.receipt().entries().len(), 1);
    assert_eq!(error.receipt().entries()[0].truncated(), Some(false));
}

#[rstest]
fn required_raw_budget_uses_a_conservative_byte_upper_bound() {
    let snapshot = Snapshot::from_text(SourceKind::PlainText, b"x", false).unwrap();
    let source_id = prefixed_uuid(EntityKind::Source);
    let manifest = SourceManifest::new(vec![SourceEntry::from_snapshot(
        source_id.clone(),
        SourceScope::Work,
        SourceTier::RequiredRaw,
        &snapshot,
    )])
    .unwrap();

    let error = ContextCompiler::new(manifest, vec![snapshot])
        .unwrap()
        .compile(&ContextRequest {
            target: prefixed_uuid(EntityKind::Chapter),
            role: "writer".into(),
            budget_tokens: 30,
            requested_output_tokens: 100,
        })
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        format!(
            "required raw context for {} exceeds the input budget",
            source_id.as_str()
        )
    );
}

#[rstest]
fn missing_compactable_summary_stops_with_a_complete_failure_receipt() {
    let compactable = Snapshot::from_text(SourceKind::PlainText, vec![b'x'; 500], false).unwrap();
    let optional = Snapshot::from_text(SourceKind::PlainText, b"optional", false).unwrap();
    let compactable_id = prefixed_uuid(EntityKind::Source);
    let optional_id = prefixed_uuid(EntityKind::Source);
    let manifest = SourceManifest::new(vec![
        SourceEntry::from_snapshot(
            compactable_id.clone(),
            SourceScope::Work,
            SourceTier::Compactable,
            &compactable,
        ),
        SourceEntry::from_snapshot(
            optional_id,
            SourceScope::Work,
            SourceTier::Optional,
            &optional,
        ),
    ])
    .unwrap();

    let error = ContextCompiler::new(manifest, vec![compactable, optional])
        .unwrap()
        .compile(&ContextRequest {
            target: prefixed_uuid(EntityKind::Chapter),
            role: "writer".into(),
            budget_tokens: 10,
            requested_output_tokens: 100,
        })
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "compactable source {} has no current summary and raw context does not fit",
            compactable_id.as_str()
        )
    );
    assert_eq!(error.receipt().entries().len(), 2);
    assert!(
        error
            .receipt()
            .entries()
            .iter()
            .all(|entry| entry.failure().is_some())
    );
}

#[rstest]
fn exact_japanese_source_match_at_eighty_graphemes_blocks() {
    let source = "あ".repeat(80);
    let findings = scan_near_copy(
        &source,
        &[AllowedSource::plain("source_1", &source)],
        &CopyPolicy::default(),
    );
    assert_eq!(findings.len(), 1);
    assert!(findings[0].blocking);
}

#[rstest]
fn exact_korean_source_match_at_eighty_graphemes_blocks() {
    let source = "가".repeat(80);

    let findings = scan_near_copy(
        &source,
        &[AllowedSource::plain("source_1", &source)],
        &CopyPolicy::default(),
    );

    assert!(
        findings
            .iter()
            .any(|finding| { finding.blocking && finding.rule == CopyRule::ContiguousCjk })
    );
}

#[rstest]
fn declared_quote_range_is_not_a_copy_blocker() {
    let source = "quoted phrase ".repeat(45);
    let findings = scan_near_copy(
        &source,
        &[AllowedSource::declared_quote("source_1", &source)],
        &CopyPolicy::default(),
    );
    assert!(findings.is_empty());
}

#[rstest]
fn local_grants_reject_symlinks_and_secret_snapshots_have_no_artifacts() {
    let root = unique_test_dir("grant");
    let source = root.join("source.txt");
    let link = root.join("link.txt");
    fs::write(&source, "top secret").unwrap();
    std::os::unix::fs::symlink(&source, &link).unwrap();

    let link_error = PathGrant::freeze(&link).unwrap_err();
    assert_eq!(link_error.kind(), SourceErrorKind::InvalidGrant);
    let directory = root.join("directory");
    fs::create_dir(&directory).unwrap();
    std::os::unix::fs::symlink(&source, directory.join("inside-link.txt")).unwrap();
    let directory_error = PathGrant::freeze(&directory).unwrap_err();
    assert_eq!(directory_error.kind(), SourceErrorKind::InvalidGrant);
    let grant = PathGrant::freeze(&source).unwrap();
    let snapshot = ingest_path(&source, &grant, true).unwrap();
    assert!(snapshot.candidate_artifacts().is_empty());
    assert!(!format!("{snapshot:?}").contains("top secret"));
    let entry = SourceEntry::from_snapshot(
        prefixed_uuid(EntityKind::Source),
        SourceScope::Work,
        SourceTier::RequiredRaw,
        &snapshot,
    );
    assert!(
        !serde_json::to_string(&entry)
            .unwrap()
            .contains("top secret")
    );
}

#[rstest]
fn secret_sources_require_a_one_time_confirmation_and_record_transmission() {
    let snapshot = Snapshot::from_text(SourceKind::PlainText, b"secret reference", true).unwrap();
    let source_id = prefixed_uuid(EntityKind::Source);
    let manifest = SourceManifest::new(vec![SourceEntry::from_snapshot(
        source_id.clone(),
        SourceScope::Work,
        SourceTier::RequiredRaw,
        &snapshot,
    )])
    .unwrap();
    let compiler = ContextCompiler::new(manifest, vec![snapshot.clone()]).unwrap();
    let request = ContextRequest {
        target: prefixed_uuid(EntityKind::Chapter),
        role: "writer".into(),
        budget_tokens: 1_000,
        requested_output_tokens: 100,
    };

    let unconfirmed = compiler.compile(&request).unwrap_err();
    assert_eq!(
        unconfirmed.to_string(),
        format!(
            "secret source {} requires a one-time confirmation before transmission",
            source_id.as_str()
        )
    );
    assert!(
        !serde_json::to_string(unconfirmed.receipt())
            .unwrap()
            .contains("secret reference")
    );
    assert_eq!(
        serde_json::to_value(unconfirmed.receipt()).unwrap()["entries"],
        serde_json::json!([{
            "source_sha256": snapshot.raw_sha256(),
            "secret_transmitted": false,
        }])
    );
    let jsonl = serde_json::json!({ "receipt": unconfirmed.receipt() });
    let checkpoint = serde_json::json!({ "context_receipt": unconfirmed.receipt() });
    let expected_entry = serde_json::json!({
        "source_sha256": snapshot.raw_sha256(),
        "secret_transmitted": false,
    });
    assert_eq!(
        jsonl["receipt"]["entries"],
        serde_json::json!([expected_entry])
    );
    assert_eq!(
        checkpoint["context_receipt"]["entries"],
        serde_json::json!([{
            "source_sha256": snapshot.raw_sha256(),
            "secret_transmitted": false,
        }])
    );
    assert!(!format!("{:?}", unconfirmed.receipt()).contains(source_id.as_str()));
}

#[rstest]
fn secret_web_metadata_cannot_enter_a_manifest() {
    let snapshot = snapshot_web_from_responses(
        "https://example.test/secret",
        vec![WebResponse::success(
            200,
            Default::default(),
            b"<p>secret reference</p>".to_vec(),
        )],
        &WebSnapshotLimits::default(),
        true,
    )
    .unwrap();
    let mut entry = SourceEntry::from_snapshot(
        prefixed_uuid(EntityKind::Source),
        SourceScope::Work,
        SourceTier::RequiredRaw,
        &snapshot,
    );
    entry.web = Some(phemius::sources::WebSnapshotMetadata {
        initial_url: "https://example.test/secret".into(),
        final_url: "https://example.test/secret".into(),
        redirect_chain: vec!["https://example.test/secret".into()],
        selected_headers: Default::default(),
        retrieved_unix_seconds: 1,
        converter_version: "htmd-0.5".into(),
        raw_sha256: snapshot.raw_sha256().into(),
        content_sha256: snapshot.content_sha256().into(),
    });

    assert_eq!(
        SourceManifest::new(vec![entry]).unwrap_err().kind(),
        SourceErrorKind::InvalidManifest
    );
}

#[rstest]
fn local_grants_reject_symlinked_ancestor_directories() {
    let root = unique_test_dir("grant-ancestor-link");
    let external = root.join("external");
    let alias = root.join("alias");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("source.txt"), "reference").unwrap();
    std::os::unix::fs::symlink(&external, &alias).unwrap();

    let error = PathGrant::freeze(&alias.join("source.txt")).unwrap_err();

    assert_eq!(error.kind(), SourceErrorKind::InvalidGrant);
}

#[rstest]
fn local_grants_reject_fifos_without_waiting_for_a_writer() {
    let root = unique_test_dir("grant-fifo");
    let fifo = root.join("source.txt");
    let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);

    let error = PathGrant::freeze(&fifo).unwrap_err();

    assert_eq!(error.kind(), SourceErrorKind::InvalidGrant);
}

#[rstest]
fn directory_grant_uses_its_held_capability_after_a_path_swap() {
    let root = unique_test_dir("grant-held-capability");
    let granted = root.join("granted");
    let replaced = root.join("replaced");
    let external = root.join("external");
    fs::create_dir(&granted).unwrap();
    fs::create_dir(&external).unwrap();
    let requested = granted.join("source.txt");
    fs::write(&requested, "frozen reference").unwrap();
    fs::write(external.join("source.txt"), "attacker reference").unwrap();
    let grant = PathGrant::freeze(&granted).unwrap();
    assert_eq!(
        ingest_path(&requested, &grant, false).unwrap().text(),
        "frozen reference"
    );
    fs::rename(&granted, &replaced).unwrap();
    std::os::unix::fs::symlink(&external, &granted).unwrap();

    let snapshot = ingest_path(&requested, &grant, false).unwrap();

    assert_eq!(snapshot.text(), "frozen reference");
}

#[rstest]
#[tokio::test]
async fn empty_or_unextractable_pdf_returns_explicit_ocr_required() {
    let root = unique_test_dir("pdf");
    let source = root.join("scan.pdf");
    fs::write(&source, b"not a PDF").unwrap();
    let grant = PathGrant::freeze(&source).unwrap();

    let error = ingest_pdf(&source, &grant, false).await.unwrap_err();
    assert_eq!(error.kind(), SourceErrorKind::OcrRequired);
}

#[rstest]
fn web_snapshot_validates_redirects_before_conversion() {
    let error = snapshot_web_from_responses(
        "https://example.test/start",
        vec![WebResponse::redirect("http://127.0.0.1/private")],
        &WebSnapshotLimits::default(),
        false,
    )
    .unwrap_err();
    assert_eq!(error.kind(), SourceErrorKind::UnsafeUrl);
}

#[rstest]
fn web_snapshot_rejects_ipv6_loopback_literals_on_initial_and_redirect_urls() {
    let initial = snapshot_web_from_responses(
        "https://[::1]/private",
        vec![WebResponse::success(
            200,
            Default::default(),
            b"ignored".to_vec(),
        )],
        &WebSnapshotLimits::default(),
        false,
    )
    .unwrap_err();
    assert_eq!(initial.kind(), SourceErrorKind::UnsafeUrl);

    let redirect = snapshot_web_from_responses(
        "https://example.test/start",
        vec![WebResponse::redirect("https://[::ffff:127.0.0.1]/private")],
        &WebSnapshotLimits::default(),
        false,
    )
    .unwrap_err();
    assert_eq!(redirect.kind(), SourceErrorKind::UnsafeUrl);

    let compatible_initial = snapshot_web_from_responses(
        "https://[::127.0.0.1]/private",
        vec![WebResponse::success(
            200,
            Default::default(),
            b"ignored".to_vec(),
        )],
        &WebSnapshotLimits::default(),
        false,
    )
    .unwrap_err();
    assert_eq!(compatible_initial.kind(), SourceErrorKind::UnsafeUrl);

    let compatible_redirect = snapshot_web_from_responses(
        "https://example.test/start",
        vec![WebResponse::redirect("https://[::127.0.0.1]/private")],
        &WebSnapshotLimits::default(),
        false,
    )
    .unwrap_err();
    assert_eq!(compatible_redirect.kind(), SourceErrorKind::UnsafeUrl);
}

#[rstest]
fn manifest_document_preserves_unknown_frontmatter_and_body() {
    let snapshot = Snapshot::from_text(SourceKind::PlainText, b"source", false).unwrap();
    let source_id = prefixed_uuid(EntityKind::Source);
    let manifest_id = prefixed_uuid(EntityKind::Source);
    let raw = format!(
        "---\nid: {}\nunknown: preserve-me\n---\n\r\nManifest notes.\r\n",
        manifest_id.as_str()
    );
    let mut document = ManifestDocument::parse(raw.as_bytes()).unwrap();
    document
        .manifest_mut()
        .entries
        .push(SourceEntry::from_snapshot(
            source_id,
            SourceScope::Work,
            SourceTier::Compactable,
            &snapshot,
        ));
    let rendered = document.render().unwrap();
    let parsed = phemius::project::parse_markdown(&rendered).unwrap();

    assert_eq!(parsed.body(), b"\r\nManifest notes.\r\n");
    assert!(parsed.frontmatter().contains_key("unknown"));
    assert_eq!(
        ManifestDocument::parse(&rendered)
            .unwrap()
            .manifest()
            .entries()
            .len(),
        1
    );
}

#[rstest]
fn directory_grant_detects_new_files_before_ingestion() {
    let root = unique_test_dir("directory-grant");
    let sources = root.join("sources");
    fs::create_dir(&sources).unwrap();
    let first = sources.join("first.txt");
    fs::write(&first, "first").unwrap();
    let grant = PathGrant::freeze(&sources).unwrap();
    fs::write(sources.join("new.txt"), "new").unwrap();

    let error = ingest_path(&first, &grant, false).unwrap_err();
    assert_eq!(error.kind(), SourceErrorKind::GrantChanged);
}

#[rstest]
fn structure_scope_includes_chapter_sources_for_a_scene_target() {
    let part = prefixed_uuid(EntityKind::Part);
    let chapter = prefixed_uuid(EntityKind::Chapter);
    let scene = prefixed_uuid(EntityKind::Scene);
    let snapshot = Snapshot::from_text(SourceKind::PlainText, b"chapter source", false).unwrap();
    let source = SourceEntry::from_snapshot(
        prefixed_uuid(EntityKind::Source),
        SourceScope::Chapter(chapter.as_str().into()),
        SourceTier::RequiredRaw,
        &snapshot,
    );
    let compiled = ContextCompiler::new(SourceManifest::new(vec![source]).unwrap(), vec![snapshot])
        .unwrap()
        .with_structure(StoryStructure {
            parts: vec![StoryPart::new(part.as_str(), 1)],
            chapters: vec![StoryChapter::new(chapter.as_str(), part.as_str(), 1)],
            scenes: vec![StoryScene::new(scene.as_str(), chapter.as_str(), 1)],
            ..StoryStructure::default()
        })
        .compile(&ContextRequest {
            target: scene,
            role: "writer".into(),
            budget_tokens: 100,
            requested_output_tokens: 100,
        })
        .unwrap();

    assert_eq!(compiled.receipt().entries().len(), 1);
    assert_eq!(
        compiled.receipt().entries()[0].disposition(),
        Some(CoverageDisposition::Raw)
    );
    assert_eq!(compiled.receipt().context_sha256(), Some(compiled.sha256()));
}

#[rstest]
fn invalid_structure_keeps_a_complete_failure_receipt() {
    let part = prefixed_uuid(EntityKind::Part);
    let chapter = prefixed_uuid(EntityKind::Chapter);
    let scene = prefixed_uuid(EntityKind::Scene);
    let work = Snapshot::from_text(SourceKind::PlainText, b"work", false).unwrap();
    let role = Snapshot::from_text(SourceKind::PlainText, b"role", false).unwrap();
    let scene_source = Snapshot::from_text(SourceKind::PlainText, b"scene", false).unwrap();
    let manifest = SourceManifest::new(vec![
        SourceEntry::from_snapshot(
            prefixed_uuid(EntityKind::Source),
            SourceScope::Work,
            SourceTier::RequiredRaw,
            &work,
        ),
        SourceEntry::from_snapshot(
            prefixed_uuid(EntityKind::Source),
            SourceScope::Role("writer".into()),
            SourceTier::RequiredRaw,
            &role,
        ),
        SourceEntry::from_snapshot(
            prefixed_uuid(EntityKind::Source),
            SourceScope::Scene(scene.as_str().into()),
            SourceTier::RequiredRaw,
            &scene_source,
        ),
    ])
    .unwrap();
    let error = ContextCompiler::new(manifest, vec![work, role, scene_source])
        .unwrap()
        .with_structure(StoryStructure {
            parts: vec![StoryPart::new(part.as_str(), 1)],
            chapters: vec![StoryChapter::new(chapter.as_str(), part.as_str(), 1)],
            scenes: vec![StoryScene::new(scene.as_str(), chapter.as_str(), 1)],
            boxes: vec![phemius::plot::StoryBox::new(
                prefixed_uuid(EntityKind::Box).as_str(),
                prefixed_uuid(EntityKind::Scene).as_str(),
                1,
            )],
            ..StoryStructure::default()
        })
        .compile(&ContextRequest {
            target: scene,
            role: "writer".into(),
            budget_tokens: 1_000,
            requested_output_tokens: 100,
        })
        .unwrap_err();

    assert_eq!(error.receipt().entries().len(), 3);
    assert!(
        error
            .receipt()
            .entries()
            .iter()
            .all(|entry| entry.failure().is_some())
    );
}

#[rstest]
fn hierarchy_scopes_require_a_known_target_and_validated_structure() {
    let part = prefixed_uuid(EntityKind::Part);
    let chapter = prefixed_uuid(EntityKind::Chapter);
    let scene = prefixed_uuid(EntityKind::Scene);
    let snapshot = Snapshot::from_text(SourceKind::PlainText, b"chapter reference", false).unwrap();
    let source = SourceEntry::from_snapshot(
        prefixed_uuid(EntityKind::Source),
        SourceScope::Chapter(chapter.as_str().into()),
        SourceTier::RequiredRaw,
        &snapshot,
    );
    let request = ContextRequest {
        target: scene.clone(),
        role: "writer".into(),
        budget_tokens: 1_000,
        requested_output_tokens: 100,
    };

    let missing_structure = ContextCompiler::new(
        SourceManifest::new(vec![source.clone()]).unwrap(),
        vec![snapshot.clone()],
    )
    .unwrap()
    .compile(&request)
    .unwrap_err();
    assert_eq!(missing_structure.receipt().entries().len(), 1);

    let unknown_target =
        ContextCompiler::new(SourceManifest::new(vec![source]).unwrap(), vec![snapshot])
            .unwrap()
            .with_structure(StoryStructure {
                parts: vec![StoryPart::new(part.as_str(), 1)],
                chapters: vec![StoryChapter::new(chapter.as_str(), part.as_str(), 1)],
                scenes: vec![StoryScene::new(scene.as_str(), chapter.as_str(), 1)],
                ..StoryStructure::default()
            })
            .compile(&ContextRequest {
                target: prefixed_uuid(EntityKind::Scene),
                role: "writer".into(),
                budget_tokens: 1_000,
                requested_output_tokens: 100,
            })
            .unwrap_err();
    assert_eq!(unknown_target.receipt().entries().len(), 1);
}

#[rstest]
fn ngram_overlap_blocks_even_when_no_eighty_grapheme_run_is_exact() {
    let source = (0..160)
        .map(|index| char::from_u32(0x4e00 + index).unwrap())
        .collect::<String>();
    let mut manuscript = source.chars().collect::<Vec<_>>();
    manuscript[53] = '\u{9fff}';
    manuscript[106] = '\u{9ffe}';
    let manuscript = manuscript.into_iter().collect::<String>();

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &CopyPolicy::default(),
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == CopyRule::NgramOverlap)
    );
}

#[rstest]
fn ngram_overlap_survives_cjk_insertions_without_a_fixed_offset() {
    let source = (0..160)
        .map(|index| char::from_u32(0x4e00 + index).unwrap())
        .collect::<String>();
    let mut manuscript = source.chars().collect::<Vec<_>>();
    manuscript.insert(53, '\u{9fff}');
    manuscript.insert(107, '\u{9ffe}');
    let manuscript = manuscript.into_iter().collect::<String>();

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &CopyPolicy::default(),
    );

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == CopyRule::NgramOverlap)
    );
}

#[rstest]
fn ngram_overlap_survives_non_cjk_insertions_without_splitting_the_run() {
    let source = (0..160)
        .map(|index| char::from_u32(0x4e00 + index).unwrap())
        .collect::<String>();
    let mut manuscript = source.chars().collect::<Vec<_>>();
    manuscript.insert(53, 'A');
    manuscript.insert(107, 'B');
    let manuscript = manuscript.into_iter().collect::<String>();

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &CopyPolicy::default(),
    );

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == CopyRule::NgramOverlap)
    );
}

#[rstest]
fn copy_gate_ignores_format_characters_between_cjk_graphemes() {
    let source = "あ".repeat(160);
    let manuscript = "あ\u{200b}".to_string().repeat(160);

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &CopyPolicy::default(),
    );

    assert!(findings.iter().any(|finding| finding.blocking));
}

#[rstest]
fn cjk_nfkc_expansion_preserves_normalized_grapheme_boundaries() {
    let source = "㍿".repeat(80);
    let manuscript = "株式会社".repeat(80);

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &CopyPolicy::default(),
    );

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == CopyRule::ContiguousCjk)
    );
}

#[rstest]
fn character_ngrams_allow_a_short_word_window_when_words_are_long_enough() {
    let source = "abcdefghij";
    let policy = CopyPolicy {
        exact_cjk_graphemes: 160,
        exact_words: 2,
        ngram_size: 8,
        ngram_cjk_window: 160,
        ngram_word_window: 1,
        ngram_overlap_percent: 85,
    };

    let findings = scan_near_copy(source, &[AllowedSource::plain("source_1", source)], &policy);

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == CopyRule::NgramOverlap)
    );
}

#[rstest]
fn duplicate_exact_source_match_remains_blocking_outside_an_exempt_range() {
    let phrase = "あ".repeat(80);
    let source = format!("{phrase}区{phrase}");
    let findings = scan_near_copy(
        &phrase,
        &[AllowedSource::with_declared_ranges(
            "source_1",
            &source,
            vec![ByteRange::new(0, phrase.len())],
        )],
        &CopyPolicy::default(),
    );

    assert!(findings.iter().any(|finding| {
        finding.rule == CopyRule::ContiguousCjk && finding.source_range.start >= phrase.len()
    }));
}

#[rstest]
fn invalid_declared_ranges_do_not_exempt_copy_findings() {
    let source = "あ".repeat(80);
    let findings = scan_near_copy(
        &source,
        &[AllowedSource::with_declared_ranges(
            "source_1",
            &source,
            vec![ByteRange::new(0, usize::MAX)],
        )],
        &CopyPolicy::default(),
    );

    assert!(findings.iter().any(|finding| finding.blocking));
}

#[rstest]
fn supplemental_unicode_punctuation_normalizes_like_other_punctuation() {
    let manuscript = "あ".repeat(80);
    let source = format!("{}\u{2e00}{}", "あ".repeat(40), "あ".repeat(40));

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &CopyPolicy::default(),
    );

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == CopyRule::ContiguousCjk)
    );
}

#[rstest]
fn character_ngrams_cover_an_eighty_word_window() {
    let source = (0..82)
        .map(|index| format!("token{index:03}"))
        .collect::<Vec<_>>()
        .join(" ");
    let manuscript = (0..82)
        .map(|index| match index {
            30 | 60 => format!("other{index:03}"),
            _ => format!("token{index:03}"),
        })
        .collect::<Vec<_>>()
        .join(" ");

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &CopyPolicy::default(),
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == CopyRule::NgramOverlap)
    );
}

#[rstest]
fn character_ngrams_survive_word_insertions_without_a_fixed_offset() {
    let words = (0..82)
        .map(|index| format!("token{index:03}"))
        .collect::<Vec<_>>();
    let source = words.join(" ");
    let mut manuscript_words = words;
    manuscript_words.insert(30, "insertedalpha".into());
    manuscript_words.insert(61, "insertedbeta".into());
    let manuscript = manuscript_words.join(" ");

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &CopyPolicy::default(),
    );

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == CopyRule::NgramOverlap)
    );
}

#[rstest]
fn word_ngrams_survive_emoji_insertions_between_english_word_runs() {
    let words = (0..80)
        .map(|index| format!("token{index:03}"))
        .collect::<Vec<_>>();
    let source = words.join(" ");
    let mut manuscript_words = words;
    manuscript_words.insert(27, "😀".into());
    manuscript_words.insert(55, "😀".into());
    let manuscript = manuscript_words.join(" ");
    let policy = CopyPolicy {
        exact_words: 100,
        ..CopyPolicy::default()
    };

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &policy,
    );

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == CopyRule::NgramOverlap)
    );
}

#[rstest]
fn word_copy_gate_blocks_symbols_inserted_inside_each_english_word() {
    let source = (0..80)
        .map(|index| format!("token{index:03}"))
        .collect::<Vec<_>>()
        .join(" ");
    let manuscript = (0..80)
        .map(|index| format!("tok😀en{index:03}"))
        .collect::<Vec<_>>()
        .join(" ");

    let findings = scan_near_copy(
        &manuscript,
        &[AllowedSource::plain("source_1", source)],
        &CopyPolicy::default(),
    );

    assert!(findings.iter().any(|finding| finding.blocking));
}

#[rstest]
fn character_ngrams_block_punctuation_and_space_inserted_inside_english_words() {
    let source = (0..80)
        .map(|index| format!("token{index:03}"))
        .collect::<Vec<_>>()
        .join(" ");

    for separator in [",", " "] {
        let manuscript = (0..80)
            .map(|index| format!("tok{separator}en{index:03}"))
            .collect::<Vec<_>>()
            .join(" ");
        let findings = scan_near_copy(
            &manuscript,
            &[AllowedSource::plain("source_1", &source)],
            &CopyPolicy::default(),
        );

        assert!(findings.iter().any(|finding| finding.blocking));
    }
}

#[rstest]
fn oversized_ngram_class_set_stops_with_a_typed_budget_error() {
    let policy = CopyPolicy {
        exact_cjk_graphemes: 30_000,
        exact_words: 30_000,
        ..CopyPolicy::default()
    };

    let error = try_scan_near_copy(
        &"あ".repeat(20_200),
        &[AllowedSource::plain("source_1", "い".repeat(160))],
        &policy,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        CopyScanError::BudgetExceeded {
            limit: CopyScanLimit::NgramWindowClasses,
            ..
        }
    ));
}

#[rstest]
fn partial_declared_quote_range_remains_a_copy_blocker() {
    let source = "quoted phrase ".repeat(45);
    let findings = scan_near_copy(
        &source,
        &[AllowedSource::with_declared_ranges(
            "source_1",
            &source,
            vec![ByteRange::new(0, source.len() / 2)],
        )],
        &CopyPolicy::default(),
    );
    assert!(findings.iter().any(|finding| finding.blocking));
}

#[rstest]
fn web_snapshot_returns_candidate_material_without_writing_canon() {
    let snapshot = snapshot_web_from_responses(
        "https://example.test/article",
        vec![WebResponse::success(
            200,
            Default::default(),
            b"<h1>Reference</h1>".to_vec(),
        )],
        &WebSnapshotLimits::default(),
        false,
    )
    .unwrap();
    let entry = SourceEntry::from_snapshot(
        prefixed_uuid(EntityKind::Source),
        SourceScope::Work,
        SourceTier::Compactable,
        &snapshot,
    );

    assert_ne!(snapshot.raw_sha256(), snapshot.content_sha256());
    let web = entry.web.as_ref().unwrap();
    assert_eq!(web.raw_sha256, snapshot.raw_sha256());
    assert_eq!(web.content_sha256, snapshot.content_sha256());
    assert!(
        snapshot
            .candidate_artifacts()
            .iter()
            .all(|artifact| !artifact.path().exists())
    );
}

#[rstest]
fn context_rejects_web_snapshot_metadata_that_does_not_match_the_raw_snapshot() {
    let snapshot = snapshot_web_from_responses(
        "https://example.test/article",
        vec![WebResponse::success(
            200,
            Default::default(),
            b"<h1>Reference</h1>".to_vec(),
        )],
        &WebSnapshotLimits::default(),
        false,
    )
    .unwrap();
    let mut entry = SourceEntry::from_snapshot(
        prefixed_uuid(EntityKind::Source),
        SourceScope::Work,
        SourceTier::RequiredRaw,
        &snapshot,
    );
    entry.web.as_mut().unwrap().final_url = "https://example.test/forged".into();
    entry.web.as_mut().unwrap().redirect_chain = vec!["https://example.test/forged".into()];
    let manifest = SourceManifest::new(vec![entry]).unwrap();

    let error = match ContextCompiler::new(manifest, vec![snapshot]) {
        Ok(_) => panic!("forged web metadata must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), SourceErrorKind::InvalidManifest);
}

#[rstest]
fn repetitive_exact_copy_returns_a_single_bounded_witness() {
    let repeated = "あ".repeat(10_000);

    let findings = try_scan_near_copy(
        &repeated,
        &[AllowedSource::plain("source_1", &repeated)],
        &CopyPolicy::default(),
    )
    .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, CopyRule::ContiguousCjk);
}

#[rstest]
fn invalid_copy_policy_is_a_typed_fail_closed_error() {
    let policy = CopyPolicy {
        ngram_size: 0,
        ..CopyPolicy::default()
    };

    let error = try_scan_near_copy("reference", &[], &policy).unwrap_err();

    assert!(matches!(
        error,
        phemius::copycheck::CopyScanError::InvalidPolicy(_)
    ));
}

#[rstest]
fn source_entry_defaults_an_omitted_tier_to_compactable() {
    let snapshot = Snapshot::from_text(SourceKind::PlainText, b"reference", true).unwrap();
    let entry = SourceEntry::from_snapshot(
        prefixed_uuid(EntityKind::Source),
        SourceScope::Work,
        SourceTier::RequiredRaw,
        &snapshot,
    );
    let mut serialized = serde_json::to_value(entry).unwrap();
    serialized.as_object_mut().unwrap().remove("tier");

    let parsed: SourceEntry = serde_json::from_value(serialized).unwrap();

    assert_eq!(parsed.tier, SourceTier::Compactable);
    SourceManifest::new(vec![parsed]).unwrap();
}

#[rstest]
fn source_context_temporary_directory_is_removed_by_drop() {
    let root = unique_test_dir("raii-cleanup");
    let path = root.path().to_path_buf();

    drop(root);

    assert!(!path.exists());
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn path(&self) -> &Path {
        &self.path
    }

    fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            panic!(
                "failed to remove source-context temporary directory {}: {error}",
                self.path.display()
            );
        }
    }
}

fn unique_test_dir(label: &str) -> TestDirectory {
    let mut root = TestDirectory {
        path: std::env::temp_dir().join(format!(
            "phemius-source-context-{label}-{}",
            uuid::Uuid::now_v7()
        )),
    };
    fs::create_dir_all(root.path()).unwrap();
    root.path = fs::canonicalize(root.path()).unwrap();
    root
}

fn scan_near_copy(
    manuscript: &str,
    sources: &[AllowedSource],
    policy: &CopyPolicy,
) -> Vec<phemius::copycheck::CopyFinding> {
    try_scan_near_copy(manuscript, sources, policy).unwrap()
}
