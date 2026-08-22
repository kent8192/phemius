use std::{fs, path::PathBuf};

use phemius::{
	plot::{
		MacroBeat, StoryBox, StoryChapter, StoryPart, StoryScene, StoryStructure,
		validate_structure,
	},
	project::{InitAnswers, initialize_project, parse_markdown, render_markdown},
};

#[test]
fn markdown_round_trip_preserves_unknown_yaml_and_body_bytes() {
	let raw = b"---\nid: chapter_018f\ncustom: keep-me\n---\n\r\nFirst line.\r\n";

	let parsed = parse_markdown(raw).unwrap();

	assert_eq!(parsed.body(), b"\r\nFirst line.\r\n");
	assert_eq!(render_markdown(&parsed).unwrap(), raw);
}

#[test]
fn init_creates_the_japanese_canon_tree_without_overwriting() {
	let root = TestDir::new("init");

	initialize_project(root.path(), &InitAnswers::minimal("作品名")).unwrap();

	assert!(root.path().join("前提/作品.md").is_file());
	assert!(root.path().join("箱書き/構成.md").is_file());
	assert!(root.path().join("資料/manifest.md").is_file());
	assert!(root.path().join(".phemius/records").is_dir());
	assert!(root.path().join(".phemius/runtime").is_dir());
	assert!(root.path().join(".phemius/local.toml").is_file());
	assert!(initialize_project(root.path(), &InitAnswers::minimal("別名")).is_err());
}

#[test]
fn macro_beats_can_link_multiple_scenes() {
	let structure = StoryStructure {
		parts: vec![StoryPart::new("part_1", 1)],
		chapters: vec![StoryChapter::new("chapter_1", "part_1", 1)],
		scenes: vec![
			StoryScene::new("scene_1", "chapter_1", 1),
			StoryScene::new("scene_2", "chapter_1", 2),
		],
		boxes: vec![
			StoryBox::new("box_1", "scene_1", 1),
			StoryBox::new("box_2", "scene_2", 1),
		],
		macro_beats: vec![MacroBeat::new("beat_1", 1, ["scene_1", "scene_2"])],
	};

	assert!(validate_structure(&structure).is_ok());
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
