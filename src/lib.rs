#![doc = include_str!("../README.md")]

/// Creates and applies explicitly approved candidate changesets.
pub mod changeset;
/// Parses trusted CLI and REPL commands without inferring approval.
pub mod cli;
/// Compiles complete, receipt-bound source contexts for model transmission.
pub mod context;
/// Detects exact and near-copy source overlap before prose is accepted.
pub mod copycheck;
/// Tracks bounded model-call costs without floating-point arithmetic.
pub mod cost;
/// Defines stable IDs and core command-domain types.
pub mod domain;
/// Records append-only durable runtime evidence.
pub mod journal;
/// Defines concrete model backends and validates returned tool calls.
pub mod model;
/// Streams strict OpenRouter chat completions without fallback or retry.
pub mod openrouter;
/// Validates the part, chapter, scene, and box story hierarchy.
pub mod plot;
/// Parses project artifacts and initializes the canonical project tree.
pub mod project;
/// Persists append-only session evidence and derived checkpoints.
pub mod session;
/// Ingests source material and validates manifest-bound snapshots.
pub mod sources;
