"""Repeatable native lexer cost and token-identity evidence; sources are not executed."""

import hashlib
import json
import statistics
import sys
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
import polyglot_checks  # noqa: E402

sources = {
    "go": 'package app\nimport "net/http"\n'
    + "".join(
        f'func handler{i}(w http.ResponseWriter, r *http.Request) {{\n                value := "text"\n                consume(value)\n}}\n'
        for i in range(700)
    ),
    "rust": "use axum::routing::get;\n"
    + "".join(
        f'fn handler{i}() {{\n                let value = "text";\n                consume(value);\n}}\n'
        for i in range(700)
    ),
    "lua": "".join(
        f'local function handler{i}()\n                local value = "text"\n                consume(value)\nend\n'
        for i in range(700)
    ),
}
rows = []
fixtures = [(language, "deep-indent", source) for language, source in sources.items()]
fixtures += [
    (
        language,
        "typical-indent",
        source.replace("                ", "\t" if language == "go" else "    "),
    )
    for language, source in sources.items()
]
for language, profile, source in fixtures:
    expected = polyglot_checks.tokens(source, language)
    samples = []
    for _ in range(9):
        started = perf_counter()
        actual = polyglot_checks.tokens(source, language)
        samples.append(perf_counter() - started)
        if actual != expected:
            raise RuntimeError("native tokens changed between benchmark samples")
    rows.append(
        {
            "language": language,
            "profile": profile,
            "source_bytes": len(source.encode()),
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "tokens": len(expected),
            "tokens_sha256": hashlib.sha256(repr(expected).encode()).hexdigest(),
            "median_seconds": statistics.median(samples),
            "samples_seconds": samples,
        }
    )
print(json.dumps({"python": sys.version.split()[0], "samples": 9, "rows": rows}, indent=2))
