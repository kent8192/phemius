#![doc = include_str!("../README.md")]

/// Creates and applies explicitly approved candidate changesets.
pub mod changeset;
/// Parses trusted CLI and REPL commands without inferring approval.
pub mod cli;
/// Compiles complete, receipt-bound source contexts for model transmission.
pub mod context;
/// Detects exact and near-copy source overlap before prose is accepted.
pub mod copycheck;
/// Defines stable IDs and core command-domain types.
pub mod domain;
/// Records append-only durable runtime evidence.
pub mod journal;
/// Validates the part, chapter, scene, and box story hierarchy.
pub mod plot;
/// Parses project artifacts and initializes the canonical project tree.
pub mod project;
/// Ingests source material and validates manifest-bound snapshots.
pub mod sources;
