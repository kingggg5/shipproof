# Q05 review packets — implementation record (2026-09-15)

Status: implemented. No new public command (opt-in `--packet-out` flag only).

## What changed

- New `skills/…/scripts/review_packets.py` (shipped, allowlisted): `review-packet/1.0`
  builder. Each packet binds Q01 target/config identity (computed over the packet's
  selected files), selected findings, Q02 anchor questions for unanchored items,
  deterministic related files (same-directory siblings; impact-graph injectable via
  `related_fn`), source roles (app/test/example/rule-data/generated/unknown + basis,
  context only), redacted source text, and open questions. Bounds: ≤10 files and
  ≤128 KiB per packet, ≤20 packets; anything dropped is recorded and voids
  `complete`. Token counts labeled estimates. Lifecycle selected → scheduled →
  completed/failed/deferred; `reconcile()` folds agent responses with first-wins
  duplicates, wrong-packet/unknown-packet notes, timeout/error → failed, and missing
  responses never completing items.
- `scan_repo.py`: opt-in `--packet-out DIR` (existing directory, symlink-safe writes
  via `safe_write_text`, summary on stderr). Lazy import keeps the default path
  untouched; gate verdict and exit codes unchanged (verified identical with/without).
- `lib/cli.mjs`: `--packet-out` registered as a value option so root resolution skips it.

## Verification

- 10 tests (`tests/test_review_packets.py`): accounting, byte/file caps, redaction,
  roles, estimate labeling, reconcile (complete/dup/unknown/wrong-packet/timeout/
  missing), builder purity, CLI ledger + gate-parity, missing-dir exit 2.
- End-to-end via Python and Node CLIs; Node `cli.test.mjs` 19 pass; `ruff` clean;
  self-scan exit 0, 0 app findings. No provider adapters exist, so there is nothing
  that could send source out; any future one needs explicit opt-in per this contract.

## Follow-up (2026-10-28)

This dated addendum records the packet 1.1 orchestration contract; the 2026-09-15 implementation notes and their evidence above are retained as historical context.

- `--packet-discover` prepares source-file discovery targets, including eligible files without native findings. It does not execute an AI review or call a provider. Discovery remains context, never an SP finding or gate proof.
- Existing bounds remain 10 files, 128 KiB source per packet, and 20 packets. Additional orchestration limits are 256 review items per packet, 5,000 eligible/discovery files, and 4 MiB total bytes read for import-context parsing. Selected targets precede bounded literal-import and test context.
- `review_focus` deduplicates language-specific questions for human review. `rule_guidance` contains summaries only for rules on native findings, deduplicated by rule ID, with a 16 KiB metadata cap.
- Each review occurrence has an `item_id`, distinct from the unchanged native tracking `fingerprint`. Packet 1.1 replies echo `packet_digest` and identify decisions by `item_id`; fingerprint-only replies are accepted only when unambiguous. Legacy 1.0 unique-fingerprint replies remain supported; ambiguous repeated fingerprints stay unresolved and are never silently collapsed. Responses are bounded and validated data; model assessments do not alter native findings, native fingerprints, or gate output. `review_complete` stays false until valid replies arrive and also stays false with deferred/failed items or partial context. Completion does not establish correctness or gate proof.
- Literal import hints currently cover Python, JavaScript/TypeScript, Dart, and Lua/Luau. C#/.NET namespace/type binding and package aliases remain unresolved. This is bounded context extraction, not a complete call graph.

No precision, token-saving, or end-to-end outcome percentage is asserted by this addendum.
