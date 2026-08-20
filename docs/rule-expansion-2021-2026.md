# Rule research expansion: 2021–2026 plus expert cohort

Status: 2,800 new research candidates, zero bulk-promoted detectors.

This program extends the original 1,000-slot investigation plan without weakening its promotion gates. The annual cohorts preserve real incident/vulnerability signals. The expert cohort provides a complete, independently reviewable weakness backlog. Neither catalog claims that source code alone can prove a deployed CVE or CWE.

## Reserved ranges

| Candidate range | Count | Cohort | Evidence source |
| --- | ---: | --- | --- |
| `SP1651–SP1950` | 300 | 2021 | NVD 2021 API cohort, CISA KEV, vendor advisories |
| `SP1951–SP2250` | 300 | 2022 | NVD 2022 API cohort, CISA KEV, vendor advisories |
| `SP2251–SP2550` | 300 | 2023 | NVD 2023 API cohort, CISA KEV, vendor advisories |
| `SP2551–SP2850` | 300 | 2024 | NVD 2024 API cohort, CISA KEV, vendor advisories |
| `SP2851–SP3150` | 300 | 2025 | NVD 2025 API cohort, CISA KEV, vendor advisories |
| `SP3151–SP3450` | 300 | 2026 | NVD 2026 API cohort through snapshot date, CISA KEV, vendor advisories |
| `SP3451–SP4450` | 1,000 | Expert/model-assisted | MITRE CWE weaknesses and cross-cutting categories |
| **Total added** | **2,800** |  |  |

The earlier `SP651–SP1650` reservation remains unchanged, so ShipProof now has 3,800 research slots and only the explicitly tested rules in `RULES` are executable.

The later [5,000-candidate language expansion](rule-expansion-languages-5000.md) reserves `SP4451–SP9450` and applies the same promotion boundary.

## Selection method

Annual records come from a bounded 300-record sample of critical-severity NVD results in each available calendar quarter, respecting the public API's date-window and request-rate contracts. The combined quarterly sample is ranked deterministically by known exploitation, CVSS score, presence of a concrete CWE, and availability of a vendor advisory. Known exploitation receives the highest priority. This does not claim a global top 300. The annual year is the NVD publication year, not the CVE identifier year or the date a social post mentioned it.

The expert cohort contains every weakness in the current CWE snapshot. The remaining slots are filled by the highest-membership CWE categories. Model reasoning is used to prioritize later review and choose the appropriate verification route; model memory is never treated as evidence.

## Community and search data

Reddit and Stack Overflow expose recurring operational questions such as build-secret leakage, mutable CI actions, unsafe pull-request privilege, missing probes, destructive infrastructure operations, and build-time versus runtime environment confusion. Google security publications and other industry material add supply-chain and provenance themes.

These pages are stored only as URLs and short project-authored themes in `research/community-signals.json`; no post body, answer, or code is copied. A community signal can raise priority but cannot satisfy a promotion gate. Each retained signal links to at least one official confirmation source.

## Routing before promotion

1. A vulnerable package/version or CVE remains `dependency_evidence` and needs an offline lockfile/SBOM/advisory adapter.
2. A locally explicit unsafe value may be evaluated for a scanner rule.
3. Reachability, deployed identity, traffic behavior, capacity, and authorization state require runtime or manual evidence.
4. A CWE class or category is taxonomy, not a detector specification.
5. Duplicates extend an existing `SPxxx` rule instead of creating a second alert for the same proof.

All promotions remain subject to the corpus thresholds and zero-observed-FP wording in the original [1,000-candidate program](rule-expansion-1000.md).
