# Phemius

Phemius is a local-first macOS harness for long-form fiction. It keeps the
canon in human-editable Markdown, asks OpenRouter models for candidates, and
requires a human-only approval command before canon bytes change.

The name refers to Phemius, the poet in Homer's *Odyssey*. It is an
attribution, not an endorsement or affiliation.

## Status and scope

The v0.1 target is Apple-silicon macOS, Rust 1.89, and one work per project.
It supports parts, chapters, scenes, boxes/beats, character and canon files,
source receipts, deterministic validators, durable sessions, and 10–12 chapter
continuous runs. Chapter length defaults are 8,000–12,000 Japanese grapheme
clusters (the controller also accepts project-specific bounds).

The initial OpenRouter model is
`deepseek/deepseek-v4-pro-0813`. Models can be switched manually per session
or role. Provider fallback and context-compression plugins are disabled by the
client. Prices are not embedded in the binary: a request maximum must be
configured by the caller before paid generation.

## Install and configure

Install Rust with the pinned toolchain, then build locally:

```sh
rustup toolchain install 1.89.0
cargo build --release
```

The network client reads only `OPENROUTER_API_KEY` from the trusted Phemius
process. The key is never copied to child processes, prompts, receipts, or
logs. A production run therefore starts with:

```sh
export OPENROUTER_API_KEY='…'
export PHEMIUS_MAX_REQUEST_MICRODOLLARS=300000
cargo run --release -- init ./my-novel
```

The second variable is a conservative maximum reservation per model call in
microdollars. If it is missing or invalid, paid generation stops rather than
guessing a price.

`init` asks for a title and creates the project tree. It does not invent a
plot, approve a framework, or start a paid request. See
[`docs/configuration.md`](docs/configuration.md) for the two small JSON plan
files needed before writing.

## CLI and REPL

The top-level help is available with `phemius --help`. A project is opened by
placing its path before the optional subcommand:

```sh
cargo run --release -- ./my-novel
cargo run --release -- eval fixtures/eval/smoke
```

The interactive REPL starts in `work` mode. The trusted commands are:

| Command | Purpose |
| --- | --- |
| `/mode work\|consult` | Switch between mutating work and read-only consult mode |
| `/plan [request]` | Route a planning request to the coordinator boundary |
| `/write <chapter-id> [--confirm]` | Generate one candidate chapter; `$5` warnings require confirmation |
| `/review [request]`, `/revise [id]`, `/diff [id]` | Request review, revision, or a candidate diff |
| `/approve <changeset-id>` | Human-only atomic approval of a reviewed changeset |
| `/reject <changeset-id>` | Reject a candidate without changing canon |
| `/resolve <finding> false-positive <reason>` | Resolve one non-intentional finding with a reason |
| `/model [role] <model-id>` | Manually select a model for the session or role |
| `/cost`, `/compact`, `/resume`, `/skills`, `/clean`, `/quit` | Inspect limits, checkpoint, resume, load skills, request clean-up, or exit |

Natural language is ordinary coordinator input. It cannot approve, resolve,
clean, persist model settings, or enable unrestricted execution. `/approve`
never exists as a model tool.

Planning definitions are loaded from `.phemius/structure.json` and
`.phemius/framework.json`; invalid or missing definitions fail closed before
generation. Save the Cat, three-act structure, kishotenketsu, and custom
framework records are supported. Hakogaki (箱書き) is documented as a flexible
scene-planning method rather than a universal fixed beat list; no claim is
made that Shinichi Arai invented it.

## Source-complete context and copy gate

`資料/manifest.md` identifies registered sources by stable ID, tier, scope,
and expected SHA-256. Text, Markdown, PDF, approved local files, and bounded
HTTPS snapshots are ingested into candidate material; ingestion does not write
canon. A context receipt records every applicable non-secret source as raw,
compacted, or excluded with a reason. Required/raw sources are never silently
dropped. Secret sources are ephemeral and require one-time human transmission
confirmation; their durable receipt is redacted to hash and transmission fact.

The near-copy scanner is deterministic and fail-closed. It blocks 80
contiguous CJK graphemes or 40 words, and high 8-gram overlap in bounded
windows. Declared, hash-bound source ranges are the only exemption mechanism.
Budget exhaustion is a blocker, not a silent false negative.

## Workflow, corrections, and recovery

The fixed chapter pipeline is architect → writer → six parallel critics →
reviser → deterministic validators. Models write only candidate files. A
changeset contains whole-file before/after hashes, affected IDs, dependency
hashes, findings, and a source receipt. `/approve` rechecks all of those and
applies the chapter bundle atomically through a crash-safe journal.

Human edits to a candidate are re-hashed into the same changeset and invalidate
its old critique. Accepted corrections become durable correction rules and are
included in later context receipts. Editing an upstream chapter marks
unapproved descendants stale; approved descendants require revalidation.
Prepared journals and ambiguous model calls stop for manual resolution rather
than guessing or replaying a request. Sessions use append-only JSONL plus a
derived checkpoint; compaction preserves typed canon, source, correction,
blocker, stale, and cost facts instead of treating a lossy summary as truth.

The budget policy is fixed at `$5` warning, `$10` per-chapter stop, and `$120`
continuous-run stop. The warning is confirmed before the first request that
could cross it. Unknown pricing, incomplete usage, or durability uncertainty
fail closed.

## Tools, sandbox, and skills

The tool table is fixed and role-scoped. File tools stay below the candidate
workspace, retain complete output hashes, and bound model-visible output.
Shell tools use macOS Seatbelt with a cleared child environment, no inherited
API key, and network denial. `/usr/bin/sandbox-exec` is deprecated by macOS;
if the profile cannot be created, Phemius stops or asks the human to choose an
explicit session-only unrestricted mode. It never silently downgrades.

Skills are loaded progressively: metadata first, then the selected `SKILL.md`,
then explicitly requested relative resources. Loaded resource hashes appear
in receipts. There is no executable plugin SDK in v0.1.

## Offline evaluation

The smoke fixture is deterministic and needs no network:

```sh
cargo run --release -- eval fixtures/eval/smoke
```

The command prints JSON followed by a short Markdown report. Hidden expectations
stay outside the trial copy. Deterministic hard gates run before subjective
pairwise quality checks; LLM judge output remains advisory until it has at
least 20 human labels, 0.80 agreement, and 0.90 swap consistency.

## Collaboration and release

The project is ordinary Git content. The harness never stages, commits, or
pushes on its own; teams can use branches and review the generated Markdown,
JSONL records, receipts, and changesets normally. `.phemius/runtime` and
`.phemius/local.toml` are machine-local and ignored.

CI targets macOS and runs formatting, Clippy, tests, and docs. Version tags
produce Apple-silicon archives with SHA-256 checksums. v0.1 does not publish to
crates.io, Homebrew, Intel macOS, OCR, a vector database, or a plugin registry.

More detail:

- [`docs/configuration.md`](docs/configuration.md) — environment and plan files
- [`docs/project-format.md`](docs/project-format.md) — canon tree and IDs
- [`docs/security.md`](docs/security.md) — trust boundaries and recovery
- [`docs/superpowers/specs/2026-08-22-phemius-v0.1.md`](docs/superpowers/specs/2026-08-22-phemius-v0.1.md) — complete v0.1 contract

## License

MIT; see the `LICENSE` file in the repository root.
