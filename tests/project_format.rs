use std::{fs, path::PathBuf};

use phemius::{
    plot::{
        MacroBeat, StoryBox, StoryChapter, StoryPart, StoryScene, StoryStructure,
        builtin_framework, validate_structure,
    },
    project::{InitAnswers, initialize_project, parse_markdown, render_markdown},
};
use yaml_serde::Value;

#[test]
fn markdown_round_trip_preserves_unknown_yaml_and_body_bytes() {
    let raw = b"---\nid: chapter_018f\ncustom: keep-me\n---\n\r\nFirst line.\r\n";

    let parsed = parse_markdown(raw).unwrap();

    assert_eq!(parsed.body(), b"\r\nFirst line.\r\n");
    assert_eq!(render_markdown(&parsed).unwrap(), raw);
}

#[test]
fn markdown_accepts_eof_delimiter_and_preserves_body_when_frontmatter_changes() {
    let eof = b"---\r\nid: chapter_018f\r\n---";
    assert_eq!(render_markdown(&parse_markdown(eof).unwrap()).unwrap(), eof);

    let raw = b"---\nunknown: keep\n---\n\xffbody\r\n";
    let mut parsed = parse_markdown(raw).unwrap();
    parsed.frontmatter_mut().insert(
        Value::String("id".into()),
        Value::String("chapter_018f".into()),
    );
    let rendered = render_markdown(&parsed).unwrap();
    assert!(rendered.ends_with(b"\xffbody\r\n"));
}

#[test]
fn markdown_rejects_invalid_frontmatter_and_missing_delimiters() {
    for raw in [
        b"---\n\xff\n---\n".as_slice(),
        b"id: chapter_1\n".as_slice(),
        b"---\nid: chapter_1\n".as_slice(),
    ] {
        assert!(parse_markdown(raw).is_err());
    }
}

#[test]
fn init_creates_the_japanese_canon_tree_without_overwriting() {
    let root = TestDir::new("init");

    let project = initialize_project(root.path(), &InitAnswers::minimal("作品名")).unwrap();

    assert!(root.path().join("前提/作品.md").is_file());
    assert!(root.path().join("箱書き/構成.md").is_file());
    assert!(root.path().join("資料/manifest.md").is_file());
    assert!(root.path().join(".phemius/records").is_dir());
    assert!(root.path().join(".phemius/runtime").is_dir());
    assert!(root.path().join(".phemius/local.toml").is_file());
    for relative in [
        "前提/作品.md",
        "前提/世界観設定.md",
        "前提/時系列.md",
        "前提/伏線.md",
        "前提/文章スタイル.md",
        "前提/執筆ルール.md",
        "箱書き/構成.md",
        "資料/manifest.md",
    ] {
        let artifact = parse_markdown(&fs::read(root.path().join(relative)).unwrap()).unwrap();
        let id = artifact
            .frontmatter()
            .get("id")
            .and_then(Value::as_str)
            .unwrap();
        let uuid = uuid::Uuid::parse_str(id.split_once('_').unwrap().1).unwrap();
        assert_eq!(uuid.get_version_num(), 7, "{relative}");
    }
    let second = initialize_project(root.path(), &InitAnswers::minimal("別名"));
    assert!(second.is_err());
    assert!(
        project
            .resolve_path(std::path::Path::new("../escape"))
            .is_err()
    );
}

#[test]
fn init_interview_answers_are_retained_in_an_unapproved_candidate() {
    let root = TestDir::new("init-interview");
    initialize_project(
        root.path(),
        &InitAnswers::interview(
            "作品名",
            "海辺の町で失踪事件を追う",
            "日本語",
            "ミステリ",
            "箱書き",
            "短い場面と静かな文体",
        ),
    )
    .unwrap();

    let candidates = fs::read_dir(root.path().join(".phemius/runtime/candidates"))
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(candidates.len(), 1);
    let metadata = fs::read_to_string(candidates[0].path().join("init.toml")).unwrap();
    for answer in [
        "title = \"作品名\"",
        "premise = \"海辺の町で失踪事件を追う\"",
        "language = \"日本語\"",
        "genre = \"ミステリ\"",
        "framework = \"箱書き\"",
        "style = \"短い場面と静かな文体\"",
        "state = \"unapproved\"",
    ] {
        assert!(metadata.contains(answer), "missing {answer}");
    }
}

#[test]
fn macro_beats_can_link_multiple_scenes() {
    let structure = fixture_structure();

    assert!(validate_structure(&structure).is_ok());
}

#[test]
fn structure_rejects_invalid_ids_references_and_orders() {
    let mut invalid_id = fixture_structure();
    invalid_id.scenes[0].id = "scene_1".into();
    assert!(validate_structure(&invalid_id).is_err());

    let mut duplicate_id = fixture_structure();
    duplicate_id.chapters[0].id = duplicate_id.parts[0].id.clone();
    assert!(
        validate_structure(&duplicate_id)
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );

    let mut invalid_reference = fixture_structure();
    invalid_reference.boxes[0].scene_id = "scene_missing".into();
    assert!(validate_structure(&invalid_reference).is_err());

    let mut duplicate_order = fixture_structure();
    duplicate_order.scenes[1].order = duplicate_order.scenes[0].order;
    assert!(validate_structure(&duplicate_order).is_err());
}

#[test]
fn save_the_cat_defines_the_standard_fifteen_ordered_beats() {
    let framework = builtin_framework("save-the-cat").unwrap();
    let names = framework
        .beats
        .iter()
        .map(|beat| beat.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "Opening Image",
            "Theme Stated",
            "Set-Up",
            "Catalyst",
            "Debate",
            "Break into Two",
            "B Story",
            "Fun and Games",
            "Midpoint",
            "Bad Guys Close In",
            "All Is Lost",
            "Dark Night of the Soul",
            "Break into Three",
            "Finale",
            "Final Image"
        ]
    );
    assert!(
        framework
            .beats
            .iter()
            .enumerate()
            .all(|(index, beat)| beat.order == index as i64 + 1)
    );
    assert!(framework.beats.iter().all(|beat| {
        framework
            .stages
            .iter()
            .any(|stage| stage.id == beat.stage_id)
    }));
}

fn fixture_structure() -> StoryStructure {
    let part = id("part");
    let chapter = id("chapter");
    let scene_one = id("scene");
    let scene_two = id("scene");
    StoryStructure {
        parts: vec![StoryPart::new(&part, 1)],
        chapters: vec![StoryChapter::new(&chapter, &part, 1)],
        scenes: vec![
            StoryScene::new(&scene_one, &chapter, 1),
            StoryScene::new(&scene_two, &chapter, 2),
        ],
        boxes: vec![
            StoryBox::new(id("box"), &scene_one, 1),
            StoryBox::new(id("box"), &scene_two, 1),
        ],
        macro_beats: vec![MacroBeat::new("beat_1", 1, [&scene_one, &scene_two])],
    }
}

fn id(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::now_v7())
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("phemius-{label}-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
