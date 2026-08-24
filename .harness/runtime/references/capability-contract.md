# Portable Capability Contract

Harness depends on capabilities, not vendor or model names. At intake, record only capabilities relevant to the run, their actual backend, permissions, isolation, version when material, and state: `READY`, `DEGRADED`, `UNAVAILABLE`, or `DIRTY`.

## Capability IDs

| ID | Purpose |
|---|---|
| `agents.parallel` | Run bounded role contracts concurrently. |
| `agents.isolated` | Verify with context and ownership isolated from implementation. |
| `human.ask` | Pause for a material human decision. |
| `filesystem.read` / `filesystem.write` | Inspect or mutate project files. |
| `shell.execute` | Run local diagnostics, tests, builds, and approved scripts. |
| `docs.versioned` | Retrieve current version-aware official documentation. |
| `repository.local` / `repository.remote` | Inspect local or hosted repository evidence. |
| `web.search` / `web.fetch` | Find and inspect current external evidence. |
| `browser.interactive` | Inspect or exercise a running interface. |
| `image.search` | Find public visual references with domain/source controls. |
| `memory.semantic` | Retrieve scoped candidates from a semantic index. |
| `evidence.static` / `evidence.runtime` | Produce deterministic static or runtime evidence. |

Tool and skill names are backend bindings. Examples include Context7 for `docs.versioned`, GitHub for `repository.remote`, Exa or another search service for `web.search`, Pinterest/domain-filtered image search for `image.search`, MemPalace for `memory.semantic`, and ShipProof for `evidence.static`. Never require or claim a named backend when only the capability matters.

## Fallback order

| Need | Fallback order |
|---|---|
| Role execution | Parallel isolated agent → sequential isolated session → fresh-session review → labeled same-agent pass |
| Current documentation | Versioned-doc tool → official versioned docs → official repository/tag → installed local source → ask human |
| Remote repository | Connector → local Git → official web source → user-provided evidence |
| Browser/UI verification | Browser automation → repository E2E → manual screenshot/walkthrough evidence → `Not verified` |
| Semantic memory | Scoped memory adapter → exact scan of canonical `.harness/` files → ask human |
| Human question | Interactive question tool → set `WAITING_DECISION` and return a gate packet |
| File mutation unavailable | Return a patch/artifact and state that it was not applied |
| Static audit | Selected trusted auditor → project linters/scanners → targeted manual review → `Not verified` |

The outcome must remain truthful under every fallback. Missing semantic memory may reduce retrieval convenience, and missing browser automation may reduce UI evidence, but neither permits invented results.

## Preflight record

For each selected capability record:

| Capability | Backend | Version/revision | Permission | Isolation | State | Fallback/limitation |
|---|---|---|---|---|---|---|

Installed is not the same as ready. Probe the smallest safe operation and verify output encoding, authentication/status when applicable, scope, and target project. Do not auto-install, connect an account, expand permissions, or mutate external state merely to improve a capability.

## Isolation language

- `independent QA`: different isolated context and no implementation ownership.
- `isolated review`: isolated context, independence from implementation stated.
- `self-review`: same agent or same implementation context.
- `deterministic verification`: tools/tests with reproducible inputs, regardless of reviewer isolation.

Never substitute one label for another.
