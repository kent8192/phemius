# Security and failure boundaries

Phemius treats the project directory, model provider, child process, and human
approval as separate trust boundaries.

## Model and network

The OpenRouter client is the only production component that reads
`OPENROUTER_API_KEY`. Requests set `provider.allow_fallbacks = false`, require
provider parameters, and disable the context-compression plugin. The client
does not retry transport failures or silently switch providers. Malformed SSE,
invalid tool calls, unknown prices, and ambiguous completions stop the run.
OpenRouter web discovery, when explicitly attached to a request, is a
provider-operated `openrouter:web_search` server tool; cited pages still pass
the HTTPS snapshot and manifest hash checks before they enter manuscript context.

The actual model ID and durable usage facts belong in the run receipt; prompts
and model output are not copied into the append-only session truth. Secret
source content is ephemeral and its durable receipt contains only a hash and a
transmission fact.

## Canon and candidates

Models may propose candidate bytes but cannot call approval or mutate canon.
Only the trusted REPL `/approve <changeset-id>` path can apply a changeset. The
controller rechecks base hashes, projected schemas, IDs, dependency order,
findings, copy checks, and receipt coverage immediately before apply.

File operations use capability-rooted directories and reject absolute paths,
`..`, symlinks, aliases, special files, `.git`, and runtime paths. A journal
retains before/after evidence and uses durable markers. A prepared journal or
unknown durability state stops for manual resolution; it is never guessed back
into canon. v0.1 guarantees bytes and existence, not mode, xattrs, ACLs, or
simultaneous visibility to unrelated readers.

## Source access

Local source grants are snapshots of regular files under an approved root.
Symlinks, FIFOs, devices, sockets, root-recursive grants, and path races are
rejected. HTTPS sources require HTTPS, public routing, no userinfo, bounded
responses, and hash-bound snapshot provenance. Web metadata is not persisted
for secret sources. PDF extraction fails closed on a page error instead of
returning partial text.

The near-copy scanner has finite budgets. It reports `BudgetExceeded` as a
blocker so a large candidate cannot bypass the plagiarism gate by exhausting a
scanner.

## Child processes

Shell execution is separate from model calls. The child environment is cleared,
arguments use an absolute executable path, writes are limited to the candidate
workspace, and network access is denied. macOS `/usr/bin/sandbox-exec` is
deprecated but remains the v0.1 Seatbelt backend. Initialization failure is
fail-closed: the operator may stop, continue without shell, or explicitly
choose unrestricted execution for that session. There is no silent downgrade.

## Session and cost recovery

Session and cost ledgers are append-only. A write/flush/sync interruption marks
durability unknown and blocks automatic retry until the ledger is reopened or
reconciled. A provider response that may have been accepted retains its maximum
reservation as provisional cost. The limits are `$5` warning, `$10` chapter
stop, and `$120` continuous-run stop.

Compaction is a projection only. Durable typed facts, source hashes, correction
IDs, blocker IDs, stale IDs, and costs remain in checkpoints; lossy summary text
is not canon. Old durable messages are not silently deleted.

## v0.1 exclusions

There is no OCR, vector database, executable plugin SDK, provider fallback,
automatic Git commit/push, Intel macOS target, crates.io publication, or
Homebrew package. These exclusions are deliberate trust-boundary reductions,
not promises of compatibility.
