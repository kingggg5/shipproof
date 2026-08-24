# Provider Adapters

Harness keeps one canonical skill and plain `.harness/` state. Provider files only make that source discoverable; they do not copy the policy.

## Invocation mapping

| Environment | Invocation |
|---|---|
| Portable/natural language | `Harness: <task>` or `Harness full: <task>` |
| Codex skill | `$best-in-code <task>` |
| Claude Code plugin | `/harness:best-in-code <task>` |
| Gemini CLI | Ask it to use the `best-in-code` skill, or use the extension's discovered skill command |
| Generic filesystem agent | Tell it to read `AGENTS.md`, then `.harness/runtime/SKILL.md` on invocation |

Do not put provider aliases in canonical project memory.

## Project instruction adapters

`adapters/project/AGENTS.md.fragment` is the canonical short project entry point. It points to `.harness/INDEX.md` and the project-pinned `.harness/runtime/SKILL.md`, loading the full skill only on invocation. The pinned snapshot gives Codex, Claude, Gemini, and generic agents the same policy version even when their global installations differ.

- Codex and AGENTS.md-aware tools read `AGENTS.md` directly.
- Claude Code project `CLAUDE.md` contains `@AGENTS.md`.
- Gemini CLI project `GEMINI.md` contains `@./AGENTS.md`.
- A generic launcher points explicitly to `AGENTS.md` and the skill.

Use `scripts/init_project.py` for a non-destructive setup. It always installs the canonical `AGENTS.md` block, adds requested provider importers, creates missing canonical files, and atomically installs one project-pinned skill snapshot. It preflights all sources and targets, rejects symlink/path escapes, preserves existing newline bytes, and never overwrites existing instruction content. If the pinned snapshot differs from a later package, it reports an update rather than silently mixing versions. If existing instructions conflict, show the conflict and obtain a human decision instead of choosing silently.

Legacy/mixed canonical schemas are never repaired piecemeal by initialization. Use the preview-bound `scripts/migrate_project.py` for the supported v1 layout. Use `scripts/upgrade_project.py` to preview and apply a newer pinned runtime plus only the delimited Harness adapter blocks; it keeps the previous verified runtime under `.harness/runtime-history/`.

Keep `AGENTS.md` concise; required team rules belong there or in checked-in documents it links. Provider auto-memory is not a substitute for versioned instructions.

## Distribution

The shared `skills/best-in-code/` tree follows the Agent Skills layout and is the portable implementation. Package manifests are thin:

- `.codex-plugin/plugin.json` for Codex;
- `.claude-plugin/plugin.json` for Claude Code;
- `gemini-extension.json` for Gemini CLI.

Validate the skill and each manifest independently. A manifest being present does not prove the corresponding CLI is installed, authenticated, or compatible; record actual validation results.

## No-filesystem models

If a model cannot read project files, it cannot provide durable cross-session project memory. Export the minimal current `INDEX`, verified record IDs, active state, and role packet through a user-controlled channel. Mark the session `DEGRADED`, prohibit canonical memory writes, and return proposed patches or records for human application.
