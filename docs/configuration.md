# Configuration

Phemius keeps project decisions in versioned Markdown/JSON and keeps machine
credentials outside the repository.

## Environment

The production client reads one variable:

```sh
export OPENROUTER_API_KEY='…'
```

Set the trusted per-request reservation maximum in whole microdollars for a
production CLI session:

```sh
export PHEMIUS_MAX_REQUEST_MICRODOLLARS=300000
```

If it is absent or not an integer, paid generation stops with an unknown-price
error. The controller reserves this maximum before every model call and still
enforces the `$5`/`$10`/`$120` limits.

The key is read by the trusted HTTP client. It is not passed to Seatbelt
children and is not serialized into session events, checkpoints, receipts, or
debug output. The endpoint, provider policy, and context-compression setting
are intentionally fixed in v0.1.

For exact post-response settlement, optionally provide both provider prices as
whole microdollars per million tokens. If either value is absent, usage is
recorded but the maximum reservation remains provisional.

```sh
export PHEMIUS_INPUT_PRICE_MICRODOLLARS_PER_MILLION=660000
export PHEMIUS_OUTPUT_PRICE_MICRODOLLARS_PER_MILLION=1980000
```

The default model is `deepseek/deepseek-v4-pro-0813`. `/model <id>` changes the
session model and `/model <role> <id>` changes one workflow role. These are
explicit human commands; natural-language text cannot persist a model choice.

## Initialize a project

```sh
cargo run -- init ./my-novel
# answer the title prompt
```

The initializer creates the canon directories and one work ID. It does not
create an approved structure or framework. Generation stops until those
definitions are valid.

## Structure declaration

Place `.phemius/structure.json` in the project root. It is a JSON encoding of
`plot::StoryStructure`:

```json
{
  "parts": [{"id": "part_…", "order": 1}],
  "chapters": [{"id": "chapter_…", "part_id": "part_…", "order": 1}],
  "scenes": [{"id": "scene_…", "chapter_id": "chapter_…", "order": 1}],
  "boxes": [{"id": "box_…", "scene_id": "scene_…", "order": 1}],
  "macro_beats": [{"id": "beat_…", "order": 1, "scene_ids": ["scene_…"]}]
}
```

IDs are stable semantic-prefix UUIDs. Orders are explicit and contiguous for
siblings. Every chapter must reference a part, every scene a chapter, every
box a scene, and every macro beat at least one scene. Invalid JSON, IDs,
references, or ordering leaves generation blocked.

## Plot framework declaration

Place `.phemius/framework.json` beside the structure file. It is a JSON
encoding of `plot::FrameworkDefinition`:

```json
{
  "id": "custom:my-framework",
  "name": "My framework",
  "stages": [{"id": "act-1", "name": "Set-up", "order": 1}],
  "beats": [{"id": "beat-1", "name": "Opening image", "stage_id": "act-1", "order": 1}]
}
```

The framework ID is retained in the run context. Built-in framework data
supports Save the Cat, three-act structure, kishotenketsu, and flexible
hakogaki. Hakogaki is a scene-by-scene planning practice whose number and
granularity of boxes can vary; it is not treated as a fixed 8-beat standard.

## Source manifest

`資料/manifest.md` is Markdown with YAML frontmatter and a `sources` list.
Each entry has a stable `source_id`, `kind`, `scope`, `tier`, expected
`sha256`, and snapshot path. Tiers are `raw`, `compactable`, or `optional`;
scope can target the work, part, chapter, scene, or role. Required sources
must be represented in every applicable context receipt. Canonical manifest or
snapshot changes go through an approved changeset rather than direct ingest.

## Cost and sessions

Before paid generation, configure a request maximum in the controller. The
runtime warns once before a chapter may cross `$5`, stops a chapter at `$10`,
and stops continuous generation at `$120`. The REPL asks for
`/write <chapter-id> --confirm` when the warning applies.

Session evidence is kept in `.phemius/records/sessions/<run-id>/` as
append-only `session.jsonl` and `cost.jsonl`, with a derived `checkpoint.json`.
If a session has events but no checkpoint, the next run stops for manual
resolution. `/resume` loads a checkpoint without resending an API request and
reports that state reconstruction is still required. A fresh process does not
regenerate from a checkpoint until its in-memory workflow state has been
reconstructed; this is a deliberate fail-closed boundary against duplicate or
authority-losing writes.

## Skills and shell

Skills are selected explicitly with `/skills` or `$skill-name`. Metadata is
loaded before the selected `SKILL.md`, and relative references must be
explicit. Shell actions require approval and run under Seatbelt with a cleared
environment and no network. See [`security.md`](security.md).
