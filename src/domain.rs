use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EntityId(String);

impl EntityId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntityKind {
    Work,
    Part,
    Chapter,
    Scene,
    Box,
    Character,
    Source,
    Changeset,
    Finding,
    Request,
    Run,
    World,
    Timeline,
    Foreshadowing,
    Style,
    Rule,
    Structure,
}

impl EntityKind {
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Part => "part",
            Self::Chapter => "chapter",
            Self::Scene => "scene",
            Self::Box => "box",
            Self::Character => "character",
            Self::Source => "source",
            Self::Changeset => "change",
            Self::Finding => "finding",
            Self::Request => "request",
            Self::Run => "run",
            Self::World => "world",
            Self::Timeline => "timeline",
            Self::Foreshadowing => "foreshadowing",
            Self::Style => "style",
            Self::Rule => "rule",
            Self::Structure => "structure",
        }
    }
}

pub fn prefixed_uuid(kind: EntityKind) -> EntityId {
    EntityId(format!("{}_{}", kind.prefix(), Uuid::now_v7()))
}

pub fn is_prefixed_uuid(value: &str, kind: EntityKind) -> bool {
    let Some(uuid_text) = value
        .strip_prefix(kind.prefix())
        .and_then(|value| value.strip_prefix('_'))
    else {
        return false;
    };
    let Ok(uuid) = Uuid::parse_str(uuid_text) else {
        return false;
    };
    uuid.get_version_num() == 7 && uuid.hyphenated().to_string() == uuid_text
}

pub fn is_known_entity_id(value: &str) -> bool {
    [
        EntityKind::Work,
        EntityKind::Part,
        EntityKind::Chapter,
        EntityKind::Scene,
        EntityKind::Box,
        EntityKind::Character,
        EntityKind::Source,
        EntityKind::Changeset,
        EntityKind::Finding,
        EntityKind::Request,
        EntityKind::Run,
        EntityKind::World,
        EntityKind::Timeline,
        EntityKind::Foreshadowing,
        EntityKind::Style,
        EntityKind::Rule,
        EntityKind::Structure,
    ]
    .into_iter()
    .any(|kind| is_prefixed_uuid(value, kind))
}
