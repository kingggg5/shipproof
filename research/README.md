# ShipProof rule-research snapshots

This directory is a research backlog, not a list of enabled scanner rules.

- `annual-rule-candidates.json` contains 300 critical evidence signals for each year from 2021 through 2026. They are real CVE records selected from a bounded 300-record NVD sample in each available calendar quarter, with CISA KEV membership and vendor advisories used where available. This is a reproducible research sample, not an assertion that these are the globally most important 300 CVEs.
- `expert-rule-candidates.json` contains 1,000 weakness candidates grounded in the current MITRE CWE catalog.
- `language-rule-candidates.json` contains 5,000 deduplicated `(ecosystem, CWE)` research variants for 14 production ecosystems. It records applicability evidence, structured consequences, existing-rule overlap, risk dimensions, and official ecosystem sources.
- `community-signals.json` records Reddit, Stack Overflow, Google, and other community/industry pages used to discover recurring production questions.

Community posts never prove a rule. They only affect prioritization. Promotion requires current official documentation, a CWE/control mapping, a static-detectability decision, false-positive analysis, and the positive/negative/adversarial fixture thresholds in [`docs/rule-expansion-1000.md`](../docs/rule-expansion-1000.md).

The checked-in JSON is an offline snapshot. The default CLI, scanner, tests, and package never fetch these sources. Maintainers can deliberately refresh the NVD/CISA/CWE snapshot with:

```bash
python scripts/build-rule-research.py
python scripts/build-language-rule-research.py
```

Review the diff and source versions before accepting a refresh. A CVE is normally routed to dependency evidence; it must not be converted mechanically into a regex rule.
