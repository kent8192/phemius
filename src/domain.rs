use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    Run,
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
            Self::Run => "run",
        }
    }
}

pub fn prefixed_uuid(kind: EntityKind) -> EntityId {
    EntityId(format!("{}_{}", kind.prefix(), Uuid::now_v7()))
}
