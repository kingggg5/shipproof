<!-- harness:start -->
# Harness Generic Agent Launcher

When the user invokes Harness:

1. Read the nearest `AGENTS.md`.
2. Read `.harness/INDEX.md` and validate `.harness/STATE.json` when present.
3. Read project-pinned `.harness/runtime/SKILL.md` completely. Stop and ask for a trusted Harness package only if that pinned runtime is absent.
4. Follow provider-neutral capability fallbacks; do not invent missing tools, memory, or isolated QA.

Canonical invocation: `Harness: <task>`.
<!-- harness:end -->
