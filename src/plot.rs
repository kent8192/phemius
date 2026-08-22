use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::domain::{EntityKind, is_prefixed_uuid};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrameworkDefinition {
    pub id: String,
    pub name: String,
    pub stages: Vec<FrameworkStage>,
    pub beats: Vec<FrameworkBeat>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrameworkStage {
    pub id: String,
    pub name: String,
    pub order: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrameworkBeat {
    pub id: String,
    pub name: String,
    pub stage_id: String,
    pub order: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct StoryStructure {
    pub parts: Vec<StoryPart>,
    pub chapters: Vec<StoryChapter>,
    pub scenes: Vec<StoryScene>,
    pub boxes: Vec<StoryBox>,
    pub macro_beats: Vec<MacroBeat>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoryPart {
    pub id: String,
    pub order: i64,
}

impl StoryPart {
    pub fn new(id: impl Into<String>, order: i64) -> Self {
        Self {
            id: id.into(),
            order,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoryChapter {
    pub id: String,
    pub part_id: String,
    pub order: i64,
}

impl StoryChapter {
    pub fn new(id: impl Into<String>, part_id: impl Into<String>, order: i64) -> Self {
        Self {
            id: id.into(),
            part_id: part_id.into(),
            order,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoryScene {
    pub id: String,
    pub chapter_id: String,
    pub order: i64,
}

impl StoryScene {
    pub fn new(id: impl Into<String>, chapter_id: impl Into<String>, order: i64) -> Self {
        Self {
            id: id.into(),
            chapter_id: chapter_id.into(),
            order,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoryBox {
    pub id: String,
    pub scene_id: String,
    pub order: i64,
}

impl StoryBox {
    pub fn new(id: impl Into<String>, scene_id: impl Into<String>, order: i64) -> Self {
        Self {
            id: id.into(),
            scene_id: scene_id.into(),
            order,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MacroBeat {
    pub id: String,
    pub order: i64,
    pub scene_ids: Vec<String>,
}

impl MacroBeat {
    pub fn new<I, S>(id: impl Into<String>, order: i64, scene_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            id: id.into(),
            order,
            scene_ids: scene_ids.into_iter().map(Into::into).collect(),
        }
    }
}

pub fn validate_structure(value: &StoryStructure) -> Result<()> {
    let mut entity_ids = HashSet::new();
    validate_entity_ids(
        EntityKind::Part,
        value.parts.iter().map(|part| &part.id),
        &mut entity_ids,
    )?;
    validate_entity_ids(
        EntityKind::Chapter,
        value.chapters.iter().map(|chapter| &chapter.id),
        &mut entity_ids,
    )?;
    validate_entity_ids(
        EntityKind::Scene,
        value.scenes.iter().map(|scene| &scene.id),
        &mut entity_ids,
    )?;
    validate_entity_ids(
        EntityKind::Box,
        value.boxes.iter().map(|box_| &box_.id),
        &mut entity_ids,
    )?;
    validate_unique_ids("macro beat", value.macro_beats.iter().map(|beat| &beat.id))?;

    let part_ids = value
        .parts
        .iter()
        .map(|part| part.id.as_str())
        .collect::<HashSet<_>>();
    for chapter in &value.chapters {
        ensure!(
            part_ids.contains(chapter.part_id.as_str()),
            "chapter {} references unknown part {}",
            chapter.id,
            chapter.part_id
        );
    }
    let chapter_ids = value
        .chapters
        .iter()
        .map(|chapter| chapter.id.as_str())
        .collect::<HashSet<_>>();
    for scene in &value.scenes {
        ensure!(
            chapter_ids.contains(scene.chapter_id.as_str()),
            "scene {} references unknown chapter {}",
            scene.id,
            scene.chapter_id
        );
    }
    let scene_ids = value
        .scenes
        .iter()
        .map(|scene| scene.id.as_str())
        .collect::<HashSet<_>>();
    for box_ in &value.boxes {
        ensure!(
            scene_ids.contains(box_.scene_id.as_str()),
            "box {} references unknown scene {}",
            box_.id,
            box_.scene_id
        );
    }
    for beat in &value.macro_beats {
        ensure!(
            !beat.scene_ids.is_empty(),
            "macro beat {} must link to one or more scenes",
            beat.id
        );
        validate_unique_ids("macro beat scene link", beat.scene_ids.iter())?;
        for scene_id in &beat.scene_ids {
            ensure!(
                scene_ids.contains(scene_id.as_str()),
                "macro beat {} references unknown scene {scene_id}",
                beat.id
            );
        }
    }

    validate_sibling_orders("part", value.parts.iter().map(|part| ("work", part.order)))?;
    validate_sibling_orders(
        "chapter",
        value
            .chapters
            .iter()
            .map(|chapter| (chapter.part_id.as_str(), chapter.order)),
    )?;
    validate_sibling_orders(
        "scene",
        value
            .scenes
            .iter()
            .map(|scene| (scene.chapter_id.as_str(), scene.order)),
    )?;
    validate_sibling_orders(
        "box",
        value
            .boxes
            .iter()
            .map(|box_| (box_.scene_id.as_str(), box_.order)),
    )?;
    validate_sibling_orders(
        "macro beat",
        value.macro_beats.iter().map(|beat| ("macro", beat.order)),
    )
}

fn validate_entity_ids<'a>(
    kind: EntityKind,
    ids: impl IntoIterator<Item = &'a String>,
    all: &mut HashSet<&'a str>,
) -> Result<()> {
    let mut own = HashSet::new();
    for id in ids {
        if !all.insert(id.as_str()) {
            bail!("duplicate entity ID: {id}");
        }
        if !own.insert(id.as_str()) {
            bail!("duplicate {} ID: {id}", kind.prefix());
        }
        ensure!(
            is_prefixed_uuid(id, kind),
            "invalid {} ID: {id}",
            kind.prefix()
        );
    }
    Ok(())
}

pub fn builtin_framework(id: &str) -> Option<FrameworkDefinition> {
    let source = match id {
        "save-the-cat" => include_str!("../assets/frameworks/save-the-cat.md"),
        "three-act" => include_str!("../assets/frameworks/three-act.md"),
        "kishotenketsu" => include_str!("../assets/frameworks/kishotenketsu.md"),
        "hakogaki" => include_str!("../assets/frameworks/hakogaki.md"),
        _ => return None,
    };
    parse_framework(source).ok()
}

fn parse_framework(source: &str) -> Result<FrameworkDefinition> {
    let yaml = source
        .strip_prefix("---\n")
        .and_then(|source| source.split_once("\n---\n").map(|(yaml, _)| yaml))
        .ok_or_else(|| anyhow::anyhow!("framework must use YAML frontmatter"))?;
    let framework: FrameworkDefinition = yaml_serde::from_str(yaml)?;
    validate_framework(&framework)?;
    Ok(framework)
}

fn validate_framework(value: &FrameworkDefinition) -> Result<()> {
    ensure!(!value.id.trim().is_empty(), "framework ID is required");
    validate_unique_ids(
        "framework stage",
        value.stages.iter().map(|stage| &stage.id),
    )?;
    validate_unique_ids("framework beat", value.beats.iter().map(|beat| &beat.id))?;
    validate_sibling_orders(
        "framework stage",
        value.stages.iter().map(|stage| ("framework", stage.order)),
    )?;
    let stage_ids = value
        .stages
        .iter()
        .map(|stage| stage.id.as_str())
        .collect::<HashSet<_>>();
    for beat in &value.beats {
        ensure!(
            stage_ids.contains(beat.stage_id.as_str()),
            "framework beat {} references unknown stage {}",
            beat.id,
            beat.stage_id
        );
    }
    validate_sibling_orders(
        "framework beat",
        value
            .beats
            .iter()
            .map(|beat| (beat.stage_id.as_str(), beat.order)),
    )
}

fn validate_unique_ids<'a>(kind: &str, ids: impl IntoIterator<Item = &'a String>) -> Result<()> {
    let mut seen = HashSet::new();
    for id in ids {
        ensure!(!id.trim().is_empty(), "{kind} ID is required");
        if !seen.insert(id.as_str()) {
            bail!("duplicate {kind} ID: {id}");
        }
    }
    Ok(())
}

fn validate_sibling_orders<'a>(
    kind: &str,
    values: impl IntoIterator<Item = (&'a str, i64)>,
) -> Result<()> {
    let mut seen = HashMap::new();
    for (parent, order) in values {
        if seen.insert((parent, order), ()).is_some() {
            bail!("duplicate {kind} order {order} under {parent}");
        }
    }
    Ok(())
}
