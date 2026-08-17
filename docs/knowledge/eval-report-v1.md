# Real-world evaluation report — v1 (2026-08-17)

Method: `python scripts/eval-realworld.py` clones each repository (depth 1)
into the gitignored `benchmarks/.work/oss-eval/` scratch area and runs the
full scanner. Two cohorts: **clean baselines** (expect quiet) and **famous
intentionally-vulnerable apps** (expect detections). 67 detectors, engine
identical to the shipped CLI.

## Results

| Repo | Files | Time | Findings | Top rules |
| --- | ---: | ---: | ---: | --- |
| expressjs/express (clean) | 158 | 3.1s | 109 (3 high) | SP401×95, SP121×4, SP407×3, SP406×3, SP101×2 |
| pallets/flask (clean) | 201 | 2.4s | 330 (330 high) | SP304×298, SP109×19, SP201×11, SP101×2 |
| psf/requests (clean) | 92 | 1.3s | 212 (212 high) | SP304×146, SP109×55, SP106×7, SP104×4 |
| juice-shop/juice-shop (vulnerable) | 941 | 16.6s | 359 (3 crit, 316 high) | SP109×199, SP003×58, SP125×29, SP126×29, SP103×12 |
| digininja/DVWA (vulnerable) | 224 | 3.8s | 37 (33 high) | SP203×13, SP101×6, SP127×6, SP128×6, SP130×3 |

## Reading the results

**Recall validated on famous vulnerable targets.** The same-day detectors
earn their keep on real code: DVWA's classic PHP lessons trip SP127 (loose
credential `==`), SP128 (interpolated SQL), and SP130 (Location redirect)
exactly where those vulnerability classes live; juice-shop trips the new
SP125 (Angular sanitizer bypass ×29) and SP126 (tokens in web storage ×29)
on real Angular/TS source, plus the expected SP003/SP103 families.

**Express baseline is healthy.** 3 high findings in a hardened codebase —
the medium flood is SP401 in benchmark/test files that deliberately build
bare Express apps (see the fix below).

**The FP story is concentrated, not diffuse.** Flask (330) and requests
(212) highs are dominated by two rules — SP304 (HTTP call without timeout)
and SP109 (localhost/metadata URLs) — firing inside **test suites and
docs examples**, not library code. Manual spot-check of samples: the calls
are real (no timeout, localhost URLs) but they sit under `tests/` or
`docs/` paths where they are intentional fixtures. This is precisely the
class Semgrep's paid tier answers with cross-file context ("is this test
code?"). Our honest L0/L1 answer does not need data-flow — it needs
**path-aware triage**.

## Actionable outcomes (ranked)

1. **Path-aware triage (next rule-engine change):** findings under
   `tests/`, `test/`, `docs/`, `examples/`, `benchmarks/` should default to
   `confidence: low` (or a `scope: test` label) instead of high, keeping
   the gate honest for application code without muting the evidence.
   Estimated effect on this cohort: flask 330→~30, requests 212→~25,
   express 109→~10 high/medium.
2. **SP304 scope:** the AST rule flags every `requests.*` call site without
   `timeout=`; libraries wrapping HTTP legitimately defer timeouts to
   callers. Consider requiring call sites outside the defining module of a
   thin wrapper (cross-function, L2) or documenting the test-path triage as
   the mitigation.
3. **SP109 refinement:** `localhost` mentions in tests/docs dominate the
   `requests` baseline; metadata-endpoint detection stays, localhost could
   join the low-confidence tier.
4. **Speed:** 941 files in 16.6s (57 files/s cold, includes clone-warm
   disk) — inside the CI regression budget; no engine work needed.

## Reproduce

```bash
python scripts/eval-realworld.py                 # the five repos above
python scripts/eval-realworld.py --repos owner/name@https://github.com/owner/name
python scripts/eval-realworld.py --json          # machine-readable
```
