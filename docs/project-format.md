# Project format

Phemius projects are ordinary Git directories. Canonical artifacts are UTF-8
Markdown with YAML frontmatter. The parser preserves unknown frontmatter keys
and unchanged body bytes; generated text is never written directly to canon.

## Tree

```text
project.toml
AGENTS.md
前提/
  作品.md
  キャラクター設定/<character>.md
  世界観設定.md
  時系列.md
  伏線.md
  文章スタイル.md
  執筆ルール.md
箱書き/
  構成.md
  章/<chapter>.md
  構成法/<framework>.md
本文/<chapter>.md
メモ/
資料/
  manifest.md
  snapshots/
.phemius/
  structure.json
  framework.json
  records/
  local.toml
  runtime/
```

`project.toml` contains `format_version = 1` and one immutable `work_id`.
The initializer creates the directories and a work/world/timeline/foreshadowing
seed. It does not create fictional content.

## IDs and hierarchy

IDs are UUID v7 values with semantic prefixes: `work_`, `part_`, `chapter_`,
`scene_`, `box_`, `character_`, `source_`, `timeline_`, `foreshadowing_`, and
related artifact prefixes. Ordering is an explicit integer and is never
derived from filenames or UUID sorting.

The structural relation is:

```text
work → part → chapter → scene → box/micro-beat
                         ↘ macro beat links to one or more scenes
```

One character has one Markdown file. One chapter has one manuscript file.
Chapter manuscripts may contain invisible HTML scene markers; those markers
are metadata, not prose. A chapter changeset groups its manuscript and any
linked character, timeline, foreshadowing, receipt, critique, and basis files.

## Changesets and records

Model output is stored below `.phemius/runtime/candidates/` as a candidate
changeset. A changeset lists whole-file operations, before/after SHA-256,
affected entity IDs, dependency hashes, findings, and context receipt hashes.
Candidate edits are allowed in an external editor; the next validation hashes
the edited bytes and invalidates old review evidence.

`.phemius/records/` is tracked audit evidence. Session JSONL is append-only;
checkpoints are replaceable projections. Approval records and committed
journals are retained so a later approval can prove its dependency chain.
`.phemius/runtime/` and `.phemius/local.toml` are local-only and ignored.

## Git collaboration

Git is optional to the runtime and Phemius never commits or pushes. For several
authors, use one branch/worktree per change and review candidate files,
receipts, and changeset records before `/approve`. A canon edit made outside
the trusted approval path freezes active work until its diff is explicitly
adopted or reverted.
