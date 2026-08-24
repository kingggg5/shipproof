# Engineering Standards

Apply these standards before implementation and review. Repository instructions and enforced toolchains remain authoritative; conflicts that would require a broad migration go to a human decision gate.

## Non-negotiable behavior

- Do not guess material requirements, credentials, production state, schema semantics, or external side effects. Investigate first; if uncertainty remains and changes the outcome, ask the human.
- Keep the codebase internally consistent. Inspect nearby patterns, module boundaries, naming, formatter, linter, tests, and error-handling conventions before editing.
- Prefer the smallest coherent change. Avoid unrelated cleanup, speculative flexibility, silent contract changes, and duplicated implementations.
- Use names that communicate domain meaning and intent. Avoid cryptic abbreviations, generic buckets such as `data` or `utils`, and misleading booleans.
- Centralize a constant, type, validation rule, configuration value, or helper when it represents one genuinely shared concept. Do not create a global dumping ground or abstract one-off behavior merely to reduce line count.
- Keep functions focused, dependencies explicit, public surfaces small, and side effects isolated. Favor readable control flow over clever compression.
- Comments explain decisions, invariants, risk, or non-obvious constraints; they do not narrate syntax.

## Indentation and formatting

Use tabs for indentation in source code under Harness control when the language and the repository's enforced formatter permit it. Configure the formatter or `.editorconfig` so the choice is reproducible. Never mix tabs and spaces within the same indentation regime.

Do not insert tabs where the format forbids them or where doing so breaks the enforced toolchain. YAML indentation must use spaces. For an existing repository that consistently enforces spaces, preserve the current style for a scoped change and ask the human before proposing a repository-wide migration to tabs. Consistency and syntactic validity take priority over an invisible partial conversion.

## Correctness and maintainability

- Validate input at trust boundaries and make invalid states hard to represent.
- Define error ownership and propagation deliberately; do not swallow failures or leak sensitive details.
- Preserve public API, schema, stored-data, and configuration compatibility unless a breaking change is approved.
- Consider empty state, partial failure, retry, cancellation, timeout, cleanup, idempotency, ordering, and concurrency when relevant.
- Add or update focused tests for changed behavior. A bug fix should include a regression test when practical.
- Keep generated files, lockfiles, migrations, snapshots, and documentation aligned with the source change when they are genuinely affected.

## Review lenses

QA selects only relevant lenses: functional correctness, invariants, contracts, security, privacy, concurrency, reliability, performance, accessibility, responsive UI, observability, migration safety, and operability. Findings must include a concrete failure scenario and practical remediation; style preference alone is not a defect unless it violates an approved convention.

## User-interface contract

- Existing product behavior, repository conventions, and the approved `DESIGN.md` outrank generic design-skill recommendations.
- Define reusable tokens and shared components only for concepts that are genuinely shared. Keep page-specific exceptions explicit instead of weakening global semantics.
- Implement complete states where relevant: default, hover, focus, active, disabled, loading, empty, error, success, partial data, and responsive variants.
- Motion must communicate change or causality, remain interruptible where appropriate, avoid layout-thrashing properties, and respect `prefers-reduced-motion`. Decorative motion requires approval in the Design Gate's motion budget.
- Visual QA must inspect the running interface, not only source code. Record viewport, interaction path, screenshot or trace location, expected behavior, and result.
