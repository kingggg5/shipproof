# Language rule research expansion: 5,000 candidates

Status: 5,000 deduplicated research candidates, zero bulk-promoted detectors.

This catalog emphasizes C#, TypeScript, PHP, React, Go, C++, Angular, JavaScript, and SQL, then adds Python, Java, Rust, Kotlin, and Swift because production repositories are commonly polyglot. Candidate IDs are review handles, not scanner findings. The executable scanner still contains only rules present in `RULES` with their required fixture coverage.

## Reserved ranges

| Candidate range | Ecosystem | Count | Main production concerns |
| --- | --- | ---: | --- |
| `SP4451–SP4850` | C# | 400 | .NET analyzer contracts, ASP.NET boundaries, async/resource lifetime |
| `SP4851–SP5300` | TypeScript | 450 | type/config boundaries, async behavior, Node/browser security |
| `SP5301–SP5650` | PHP | 350 | request/file/database boundaries and long-running worker safety |
| `SP5651–SP5950` | React | 300 | effect lifecycle, external stores, rendering and client trust |
| `SP5951–SP6300` | Go | 350 | concurrency, cancellation, resource limits and vulnerability evidence |
| `SP6301–SP6750` | C++ | 450 | memory, integer, container, I/O and concurrency safety |
| `SP6751–SP7000` | Angular | 250 | sanitization, Trusted Types, XSRF, SSR and rendering performance |
| `SP7001–SP7450` | JavaScript | 450 | runtime injection, event-loop/resource behavior and web boundaries |
| `SP7451–SP7850` | SQL | 400 | query construction, authorization, plans, locks and data volume |
| `SP7851–SP8250` | Python | 400 | unsafe parsing, concurrency, resource use and interpreter boundaries |
| `SP8251–SP8600` | Java | 350 | deserialization, cryptography, concurrency and resource exhaustion |
| `SP8601–SP8950` | Rust | 350 | unsafe contracts, FFI, panic safety, races and resource behavior |
| `SP8951–SP9200` | Kotlin | 250 | Android permissions/storage, lifecycle, coroutines and performance |
| `SP9201–SP9450` | Swift | 250 | secure decoding/storage, concurrency, memory and mobile boundaries |
| **Total added** |  | **5,000** |  |

Together with `SP651–SP4450`, ShipProof now reserves 8,800 traceable research slots. A reservation does not enlarge the executable rule count.

## How candidates are selected

The maintainer builder consumes the checked-in MITRE CWE snapshot and scores each `(ecosystem, CWE)` pair using CWE's own `Applicable_Platforms` declarations:

1. An exact language or technology match ranks highest.
2. A matching language class, such as compiled or interpreted, ranks below an exact match.
3. A `Not Language-Specific` declaration remains eligible.
4. An explicit incompatible language declaration is excluded.
5. Deprecated and obsolete CWE records are excluded.
6. Base and Variant weaknesses rank ahead of broad taxonomy classes.

Applicability is also labeled, not hidden: the current snapshot has 780 `direct` language/technology matches, 4,211 `language_independent` variants, and 9 `taxonomy_only` records. Generic records are routed to `ecosystem_semantic_review`, not treated as detector specifications. The CWE snapshot has no direct Kotlin or Swift language declarations in the selected cohort, so those two ranges are explicitly cross-cutting research variants that require Android/Kotlin or Apple/Swift semantics before promotion.

The catalog retains CWE common consequences as structured data. `risk_lane` is a conservative primary review lane; `risk_dimensions` are non-exclusive and can add reliability, scale, or performance only when CWE consequence data supports that relationship. In the current snapshot, 355 candidates carry a performance dimension, 469 carry a scale dimension, and 1,962 carry a reliability dimension. All 5,000 remain security-relevant because CWE is a security weakness taxonomy.

## Duplicate policy

There are two different concepts that must not be confused:

- An exact `(ecosystem, CWE)` pair is unique. Candidate IDs and normalized titles are also unique.
- A CWE root may intentionally have several ecosystem variants because a safe C++ detector, React detector, and SQL detector require different syntax and proof. Those records share `root_overlap_group`.

Every candidate is compared with the executable scanner's CWE mappings and suffix scope:

- `extend_or_replace_existing` means an executable rule already covers the same CWE in overlapping file types. Promotion must improve that rule instead of creating a duplicate alert.
- `distinct_ecosystem_variant` means the CWE exists in the scanner, but not for overlapping ecosystem files.
- `coverage_gap` means no current executable rule maps to the CWE.

The current snapshot contains 331 extend/replace records, 125 distinct-ecosystem variants, and 4,544 coverage gaps. These labels are recomputed from the scanner rather than maintained by hand.

## False-positive promotion gate

No record enters `RULES` until all of the following are present:

1. Ecosystem-specific semantics from current owning documentation, not only a CWE title.
2. At least one positive, two negative, and one adversarial fixture; high-severity candidates need two of each polarity.
3. A concrete source/sink/configuration model and an explanation of what the scanner cannot prove.
4. Comparison with existing rules by CWE, syntax, message, suffix scope, and finding fingerprint.
5. Zero observed false positives in the controlled negative corpus and a recorded precision result on representative repositories.
6. A choice of the correct evidence route: static/AST, dependency evidence, configuration policy, benchmark/load evidence, or manual/runtime verification.

Scale and performance candidates do not become blocking source patterns merely because code contains a loop, allocation, query, or effect. They need a locally provable missing bound, unsafe lifecycle, repeated query shape, or measured budget regression.

## Rebuild

The default scanner remains offline. Maintainers deliberately refresh the primary CWE snapshot, then rebuild the language variants:

```bash
python scripts/build-rule-research.py
python scripts/build-language-rule-research.py
```

Review the generated diff, source version/hash, allocation, risk distribution, and duplicate dispositions before accepting it.
