# Phemius

Phemius is a local-first harness for long-form fiction projects. Its library
keeps project changes behind an explicit approval boundary and makes source
material available to model calls through hash-bound, auditable contexts.

## Build

Install the pinned Rust 1.89 toolchain, then run:

```sh
cargo test --all-targets --all-features
```

## Source-complete contexts

`sources` ingests text, Markdown, PDF, approved local paths, and bounded HTTPS
snapshots into candidate material. It never writes `資料/manifest.md` or
`資料/snapshots/**`; a later approved changeset persists those canon artifacts.
`context` selects applicable source scopes, records a coverage receipt for every
applicable manifest entry, and requires an opaque one-time confirmation before secret material can
be handed to a transmitter.

## Near-copy gate

The copy gate is deterministic and fail-closed. Treat a `CopyScanError` as a
blocking result, including a scan-budget error.

```rust
use phemius::copycheck::{AllowedSource, CopyPolicy, scan_near_copy};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let findings = scan_near_copy(
    "An original draft.",
    &[AllowedSource::plain("source_example", "A short reference.")],
    &CopyPolicy::default(),
)?;
assert!(findings.is_empty());
# Ok(())
# }
```

The default policy blocks contiguous matches of 80 CJK graphemes or 40 words,
and 85% 8-gram overlap in a 160-grapheme or 80-word window. Explicit declared
source ranges are the only exemption mechanism.

## Bounded tools and skills

The model tool catalog is fixed and role-scoped. File operations remain below a
candidate workspace, complete outputs are retained by SHA-256, and model-visible
output is bounded. Shell execution defaults to human approval plus macOS
Seatbelt; it clears inherited environment variables and never falls back to an
unrestricted child process. Skills load frontmatter metadata at startup, then
load only the explicitly selected `SKILL.md` and requested relative resources.
