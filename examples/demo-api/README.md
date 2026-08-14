# Demo API: five findings to zero

This fixture is intentionally small so a reviewer can understand ShipProof without installing or running a web service. `fixtures/before` contains five representative production risks; `fixtures/after` fixes them and includes a deterministic unit test for its query boundary.

> Never deploy or copy the intentionally vulnerable `before` fixture.

## Reproduce the flow

From the ShipProof repository root:

```bash
shipproof scan examples/demo-api/fixtures/before --format markdown --fail-on high
```

Expected evidence:

| Rule | Before | Fixed by |
| --- | --- | --- |
| `SP108` | Admin route has no visible authorization dependency | Route-level `Depends(require_admin)` |
| `SP103` | SQL text contains interpolated user input | Bound SQLite parameters |
| `SP305` | `limit` has no request-bound maximum | `Query(ge=1, le=100)` |
| `SP304` | Outbound request has no timeout | Explicit connect/read timeout |
| `SP201` | FastAPI debug mode is enabled | Production-safe application initialization |

Run the fixed boundary tests and scan again:

```bash
python -m unittest discover -s examples/demo-api/fixtures/after/tests -v
shipproof scan examples/demo-api/fixtures/after --format markdown --fail-on high
```

The checked-in contract at [`expected-findings.json`](expected-findings.json) is exercised in the repository test suite. The root self-scan excludes directories named `fixtures`, while a scan whose selected root is one of these fixture repositories still analyzes it normally.
