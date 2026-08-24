# ShipProof rule assurance inventory

Version: `0.10.0`

| Status | Rules | Meaning |
| --- | ---: | --- |
| Complete | 620 | Meets the current executable polarity minimum |
| Partial | 0 | Has a manifest but misses at least one minimum |
| Uncontracted | 0 | No explicit machine-readable polarity manifest |
| Metadata debt | 0 | Missing CWE, remediation, or explanation fields |

Zero-debt executable-rule gate: **PASS**

Every executable rule meets the machine-readable polarity minimum. The checked-in empty debt baseline makes any future partial or uncontracted rule fail closed.

Placeholder-only `SAFE_NEGATIVE_*` and `SAFE_ADVERSARIAL_*` strings are reported but do not count as meaningful polarity evidence.

Maintainer source-checkout command: `python scripts/rule_assurance_report.py --format json --check`.
Regenerate checked-in contracts with `python scripts/build_secret_rule_contracts.py`, `python scripts/build_legacy_pattern_contracts.py`, and `python scripts/build_legacy_structural_contracts.py`; baseline updates may only shrink debt.
