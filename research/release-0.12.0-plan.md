# ShipProof 0.12.0 delivery contract — 2026-10-22

User authorization: continue a substantial update, commit, push and create the next
release; explicitly include the newly disclosed PHP2Shell advisories. Registry npm
publication, production systems, exploitation and remote code uploads are excluded.

Baseline: `dd589b5` on main, plus the preceding uncommitted TypeScript/Roblox/Rust
cohorts (651 rules). Preserve and integrate those changes; do not reset the tree.
Latest remote exact release checked: `v0.11.2`. Next minor: `0.12.0`; retain the
repository's pre-1.0 release workflow policy and immutable exact tags.

## Bounded implementation passes

1. Add an offline, dated PHP2Shell version advisory for explicit supported runtime
   declarations. Match each patched branch independently. Do not infer runtime
   versions from Composer constraints or declare vendor backports vulnerable.
2. Close known precision gaps in SP668 (syslog format-argument position) and SP670
   (DTD parsing alone is not external entity resolution). Keep findings advisory.
3. Integrate metadata/docs/contracts, update all current version identities, retain
   immutable historical release counts, and prepare release notes and migration
   limitations. Omit maintainer-only provenance from the runtime package if needed
   to stay under the existing package budgets; never raise budgets to pass.
4. Run focused tests, full `npm run check`, compile, high-gate self-scan, assurance,
   contract freshness, precision trend, dependency audit and bounded benchmarks.
   Check before/after evidence; record unavailable checks explicitly.
5. Commit reviewed source, push main without force, confirm CI on that exact SHA,
   then create and push the new exact tag and verify the Release workflow/assets.

At most three implementation cohorts and three focused repair attempts per failing
gate before revisiting the cause. No unattended recurring jobs or paid services.
Do not release with confirmed high issues, failing required checks, or unresolved
authority. Preserve a recoverable commit before any external publication. Existing
`v0` is a moving remote alias; a local alias mismatch is not permission to rewrite
immutable version tags.

## Evidence and review

Keep logs under ignored `.cache/`. Public release notes must distinguish upstream
critical CVE severity from local declared-version evidence, and source coverage
from runtime exploitability. New rules need original implementations, primary
sources, positive/negative/adversarial cases and real filesystem-walker coverage.

The primary agent owns security decisions, integration and acceptance. A bounded
read-only helper inventories version references; it does not approve the release.
Label review accurately as self-review unless an isolated review is performed.
Local checks do not substitute for remote CI, and a pushed tag is not proof that
release creation or artifact publication succeeded.

Security follow-up: a synthetic canary confirmed that newly added advisory evidence
could echo unrelated credentials. One additional bounded privacy repair was added
before commit: normalized evidence, minimized contexts and all-format regressions.
It adds no rule, dependency or execution capability. Full checks must be repeated
after this repair; its early passing results are not substituted for final gates.
