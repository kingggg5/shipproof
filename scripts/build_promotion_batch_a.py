#!/usr/bin/env python3
"""Build the bounded, evidence-gated P2 batch-A decision record.

The output is research evidence, not executable scanner configuration. Narrow
prototype matchers are included only for candidates whose controlled fixtures
are ready; promotion still requires representative-repository shadow results.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
CATALOG = ROOT / "research" / "language-rule-candidates.json"
OUTPUT = ROOT / "research" / "promotion-batch-a.json"
SCANNER_SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCANNER_SCRIPTS))

from scan_repo import RULES  # noqa: E402

REVIEWED_AT = "2026-08-24"
CAPS = {
    "csharp": 3,
    "typescript": 4,
    "php": 3,
    "react": 2,
    "go": 3,
    "cpp": 4,
    "angular": 2,
    "javascript": 2,
    "sql": 2,
}


def rejected(
    candidate_id: str,
    rejection_class: str,
    reason: str,
    route: str,
    duplicates: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "batch_status": "rejected",
        "rejection_class": rejection_class,
        "decision": reason,
        "recommended_route": route,
        "duplicate_rule_ids": list(duplicates),
    }


DECISIONS = (
    rejected(
        "SP4451",
        "needs_dataflow",
        "ASP.NET upload safety depends on how IFormFile metadata and content flow into validation, storage, and execution; a generic upload regex cannot prove unrestricted dangerous-type acceptance.",
        "dotnet_analyzer_or_framework_specific_future_candidate",
    ),
    rejected(
        "SP4452",
        "policy_context",
        "ASP.NET impersonation is an intentional supported configuration. The locally visible flag proves identity selection, not unnecessary privilege, so a default security finding would be noisy.",
        "opt_in_policy_check",
    ),
    rejected(
        "SP4511",
        "candidate_duplicate",
        "CWE-556 describes the same ASP.NET identity-impersonation configuration already represented by candidate SP4452; retaining a second detector target would duplicate one root cause.",
        "merge_research_evidence_into_sp4452",
    ),
    rejected(
        "SP4851",
        "executable_duplicate",
        "SP063 already covers target=_blank links without rel=noopener across TypeScript, TSX, JavaScript, JSX, Vue, and HTML suffixes.",
        "existing_rule",
        ("SP063",),
    ),
    rejected(
        "SP4855",
        "executable_duplicate",
        "SP056 and SP159 already cover sensitive cookies missing HttpOnly in TypeScript/TSX server code; client-side JavaScript cannot add the HttpOnly attribute itself.",
        "existing_rules",
        ("SP056", "SP159"),
    ),
    rejected(
        "SP4858",
        "framework_semantics_missing",
        "The generic CWE does not identify a TypeScript WebSocket server API or an explicit always-allow origin callback. Promote only a framework-specific signature with owning documentation.",
        "framework_specific_future_candidate",
    ),
    rejected(
        "SP4900",
        "executable_duplicate",
        "SP101, SP117, and SP118 already cover direct eval, Function construction, and timer-string evaluation in TypeScript and JavaScript.",
        "existing_rules",
        ("SP101", "SP117", "SP118"),
    ),
    {
        "candidate_id": "SP5301",
        "batch_status": "fixture_ready",
        "decision": "A narrow PHP signature can observe code that treats browser-supplied upload MIME metadata as an allow/deny decision. The prototype intentionally excludes aliases and full upload-flow claims.",
        "recommended_route": "representative_shadow",
        "duplicate_rule_ids": [],
        "prototype": {
            "engine": "regex_research_only",
            "suffixes": [".php"],
            "flags": ["IGNORECASE"],
            "pattern": "(?:if\\s*\\([^\\n]*\\$_FILES\\[[^\\]]+\\]\\[['\"]type['\"]\\]|in_array\\s*\\(\\s*\\$_FILES\\[[^\\]]+\\]\\[['\"]type['\"]\\])",
            "proof_level": "direct_local_signature",
        },
        "false_positive_analysis": "Some applications compare reported MIME only for logging, analytics, or a preliminary UX branch and perform authoritative Fileinfo or content validation later. The prototype therefore cannot justify blocking severity until representative review confirms the matched branch controls acceptance or storage.",
        "cases": {
            "positive": [
                {
                    "path": "upload.php",
                    "source_parts": [
                        "if ($",
                        "_FILES['upload']['type'] === 'image/png') { move_uploaded_file($tmp, $dst); }",
                    ],
                    "expected": True,
                },
                {
                    "path": "avatar.php",
                    "source_parts": [
                        "$allowed = in_array($",
                        '_FILES["avatar"]["type"], [\'image/jpeg\'], true);',
                    ],
                    "expected": True,
                },
            ],
            "negative": [
                {
                    "path": "upload.php",
                    "source_parts": [
                        "$finfo = new finfo(FILEINFO_MIME_TYPE);\n$mime = $finfo->file($",
                        "_FILES['upload']['tmp_name']);",
                    ],
                    "expected": False,
                },
                {
                    "path": "image.php",
                    "source_parts": ["$kind = exif_imagetype($", "_FILES['image']['tmp_name']);"],
                    "expected": False,
                },
                {
                    "path": "audit.php",
                    "source_parts": ["error_log($", "_FILES['upload']['type']);"],
                    "expected": False,
                },
                {
                    "path": "validator.php",
                    "source_parts": ["$validator->validateUploadedFile($", "_FILES['upload']);"],
                    "expected": False,
                },
            ],
            "adversarial": [
                {
                    "path": "upload.php",
                    "source_parts": [
                        "$field = 'type';\nif ($",
                        "_FILES['upload'][$field] === 'image/png') { accept(); }",
                    ],
                    "expected": False,
                    "rationale": "A computed metadata key needs local data-flow and is an explicit known evasion of this narrow prototype.",
                },
                {
                    "path": "upload.php",
                    "source_parts": [
                        "$reported = $",
                        "_FILES['upload']['type'];\nif ($reported === 'image/png') { accept(); }",
                    ],
                    "expected": False,
                    "rationale": "An alias between the upload metadata and the decision needs taint propagation and is intentionally outside a regex promotion.",
                },
            ],
        },
    },
    rejected(
        "SP5302",
        "executable_duplicate",
        "SP060 already covers include/require expressions driven directly by PHP request superglobals or variables.",
        "existing_rule",
        ("SP060",),
    ),
    rejected(
        "SP5303",
        "executable_duplicate",
        "SP078 and SP184 already cover request-superglobal extraction and untrusted variable overwrite in PHP.",
        "existing_rules",
        ("SP078", "SP184"),
    ),
    rejected(
        "SP5651",
        "executable_duplicate",
        "SP063 already covers React JSX/TSX blank-target links without noopener, so a React-labelled copy would emit the same root-cause finding on the same source line.",
        "existing_rule",
        ("SP063",),
    ),
    rejected(
        "SP5656",
        "executable_duplicate",
        "React does not change eval semantics; SP101, SP117, and SP118 already cover the direct JavaScript and TypeScript sinks.",
        "existing_rules",
        ("SP101", "SP117", "SP118"),
    ),
    {
        "candidate_id": "SP5951",
        "batch_status": "fixture_ready",
        "decision": "Go exposes HttpOnly directly on http.Cookie, and a bounded literal can identify sensitive cookie names that omit an explicit true value. Helper-returned cookies and computed fields remain outside the prototype.",
        "recommended_route": "representative_shadow",
        "duplicate_rule_ids": [],
        "prototype": {
            "engine": "regex_research_only",
            "suffixes": [".go"],
            "flags": ["IGNORECASE", "DOTALL"],
            "pattern": "(?:http\\.)?SetCookie\\s*\\([^,]+,\\s*&(?:http\\.)?Cookie\\s*\\{(?=[^}]*Name\\s*:\\s*[\"'](?:session|auth|token|jwt|refresh)[\"'])(?:(?!HttpOnly\\s*:\\s*true)[^}])*\\}\\s*\\)",
            "proof_level": "direct_local_signature",
        },
        "false_positive_analysis": "A sensitive-looking cookie may be intentionally script-readable, protected by another mechanism, or built through a helper that supplies HttpOnly later. The prototype only observes one direct literal and must remain non-blocking until representative review measures how often these contexts occur.",
        "cases": {
            "positive": [
                {
                    "path": "session.go",
                    "source_parts": [
                        "http.Set",
                        'Cookie(w, &http.Cookie{Name: "session", Value: token})',
                    ],
                    "expected": True,
                },
                {
                    "path": "auth.go",
                    "source_parts": ["Set", 'Cookie(w, &Cookie{Name: "auth", Secure: true})'],
                    "expected": True,
                },
            ],
            "negative": [
                {
                    "path": "session.go",
                    "source_parts": [
                        "http.Set",
                        'Cookie(w, &http.Cookie{Name: "session", HttpOnly: true})',
                    ],
                    "expected": False,
                },
                {
                    "path": "theme.go",
                    "source_parts": [
                        "http.Set",
                        'Cookie(w, &http.Cookie{Name: "theme", Value: value})',
                    ],
                    "expected": False,
                },
                {
                    "path": "session.go",
                    "source_parts": [
                        "cookie := secureSessionCookie(token)\nhttp.Set",
                        "Cookie(w, cookie)",
                    ],
                    "expected": False,
                },
                {
                    "path": "session.go",
                    "source_parts": ["http.Set", "Cookie(w, newSessionCookie(token))"],
                    "expected": False,
                },
            ],
            "adversarial": [
                {
                    "path": "session.go",
                    "source_parts": [
                        'name := "session"\nhttp.Set',
                        "Cookie(w, &http.Cookie{Name: name, Value: token})",
                    ],
                    "expected": False,
                    "rationale": "A computed cookie name requires constant propagation and is an explicit known evasion of the narrow literal prototype.",
                },
                {
                    "path": "session.go",
                    "source_parts": [
                        'cookie := &http.Cookie{Name: "session", Value: token}\ncookie.HttpOnly = true\nhttp.Set',
                        "Cookie(w, cookie)",
                    ],
                    "expected": False,
                    "rationale": "A post-construction security assignment requires local object-flow analysis; the prototype intentionally stays silent.",
                },
            ],
        },
    },
    rejected(
        "SP5953",
        "framework_semantics_missing",
        "The generic CRLF candidate does not name a Go API and the standard HTTP stack validates header syntax. Existing SP175 covers direct supported header-injection forms; a Go extension needs an actual bypass signature.",
        "future_api_specific_candidate",
        ("SP175",),
    ),
    rejected(
        "SP5955",
        "executable_duplicate",
        "SP070 and SP189 already cover Go WebSocket upgrade callbacks that accept every origin; another CWE-labelled variant would duplicate their source signature and remediation.",
        "existing_rules",
        ("SP070", "SP189"),
    ),
    rejected(
        "SP6302",
        "needs_dataflow",
        "Determining whether a C++ array index is externally controlled and correctly range-checked requires type, range, and control-flow information unavailable to a line regex.",
        "compiler_analyzer_or_sanitizer",
    ),
    rejected(
        "SP6304",
        "needs_lifetime_analysis",
        "A missing C++ release cannot be established from allocation syntax alone because RAII, ownership transfer, smart pointers, and exceptional paths determine the lifetime.",
        "compiler_analyzer_or_sanitizer",
    ),
    rejected(
        "SP6306",
        "needs_dataflow",
        "Excessive C++ allocation requires both an untrusted size origin and an application-specific bound; matching allocation calls alone would flag normal bounded allocations.",
        "compiler_analyzer_or_resource_test",
    ),
    {
        "candidate_id": "SP6309",
        "batch_status": "fixture_ready",
        "decision": "CWE and CERT both define direct external format arguments as unsafe. The prototype is intentionally limited to command-line argv passed directly in the format position.",
        "recommended_route": "representative_shadow",
        "duplicate_rule_ids": [],
        "prototype": {
            "engine": "regex_research_only",
            "suffixes": [".c", ".cpp", ".h", ".hpp"],
            "flags": [],
            "pattern": "(?:(?:printf|syslog)\\s*\\(\\s*argv\\s*\\[[^\\]]+\\]|fprintf\\s*\\(\\s*[^,]+,\\s*argv\\s*\\[[^\\]]+\\]|sprintf\\s*\\(\\s*[^,]+,\\s*argv\\s*\\[[^\\]]+\\]|snprintf\\s*\\(\\s*[^,]+,\\s*[^,]+,\\s*argv\\s*\\[[^\\]]+\\])",
            "proof_level": "direct_local_signature",
        },
        "false_positive_analysis": "Direct argv in a format position is a strong local signature, but wrappers may constrain input before the call and nonstandard APIs may use different argument order. Aliased parameters require taint analysis, so the prototype records them as known false negatives rather than broadening to every variable format.",
        "cases": {
            "positive": [
                {"path": "main.c", "source_parts": ["print", "f(argv[1]);"], "expected": True},
                {
                    "path": "log.cpp",
                    "source_parts": ["fprint", "f(stderr, argv[2]);"],
                    "expected": True,
                },
            ],
            "negative": [
                {
                    "path": "main.c",
                    "source_parts": ["print", 'f("%s", argv[1]);'],
                    "expected": False,
                },
                {"path": "main.c", "source_parts": ["fputs(argv[1], stdout);"], "expected": False},
                {"path": "main.cpp", "source_parts": ["std::cout << argv[1];"], "expected": False},
                {
                    "path": "main.c",
                    "source_parts": ["snprint", 'f(buffer, sizeof buffer, "%s", argv[1]);'],
                    "expected": False,
                },
            ],
            "adversarial": [
                {
                    "path": "main.c",
                    "source_parts": ["const char *format = argv[1];\nprint", "f(format);"],
                    "expected": False,
                    "rationale": "The command-line value is aliased before the sink, so this case requires taint propagation beyond the direct prototype.",
                },
                {
                    "path": "log.cpp",
                    "source_parts": [
                        "void log(const char *user_input) { print",
                        "f(user_input); }",
                    ],
                    "expected": False,
                    "rationale": "A function parameter is not necessarily externally controlled; callers and interprocedural flow must establish taint.",
                },
            ],
        },
    },
    rejected(
        "SP6751",
        "executable_duplicate",
        "SP063 already covers Angular TypeScript and template-adjacent blank-target links without noopener, including the relevant .ts suffix and the same remediation boundary.",
        "existing_rule",
        ("SP063",),
    ),
    rejected(
        "SP6756",
        "executable_duplicate",
        "SP101, SP117, and SP118 cover JavaScript evaluation sinks, while SP125 and SP455 cover Angular sanitizer bypass APIs including dynamic HTML input.",
        "existing_rules",
        ("SP101", "SP117", "SP118", "SP125", "SP455"),
    ),
    rejected(
        "SP7001",
        "executable_duplicate",
        "SP063 already covers JavaScript and JSX blank-target links without noopener, so this candidate adds no distinct syntax, proof level, or remediation.",
        "existing_rule",
        ("SP063",),
    ),
    rejected(
        "SP7050",
        "executable_duplicate",
        "SP101, SP117, and SP118 already cover the locally visible JavaScript dynamic-evaluation sinks represented by this generic CWE candidate.",
        "existing_rules",
        ("SP101", "SP117", "SP118"),
    ),
    rejected(
        "SP7451",
        "executable_duplicate",
        "The scanner already has multiple ecosystem-specific CWE-89 detectors, including SP103 and SP145 for direct SQL construction and execution. A generic .sql-file rule cannot observe upstream user control.",
        "existing_rules",
        ("SP103", "SP145"),
    ),
    rejected(
        "SP7452",
        "misrouted_ecosystem",
        "Hibernate injection is expressed in Java/Kotlin HQL or query-construction code, not a standalone SQL file; this SQL ecosystem slot cannot produce a correctly routed detector.",
        "future_java_hibernate_candidate",
    ),
)


def enrich(entry: dict[str, Any], catalog_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    candidate = catalog_by_id[entry["candidate_id"]]
    sources = candidate["source_urls"]
    official = next((url for url in sources if "cwe.mitre.org" not in url), sources[-1])
    return {
        **entry,
        "ecosystem": candidate["ecosystem"],
        "source_id": candidate["source_id"],
        "catalog_status": candidate["promotion_status"],
        "applicability_tier": candidate["applicability_tier"],
        "sources": [
            {
                "url": sources[0],
                "claim": "Primary CWE taxonomy defines the weakness semantics and applicability boundary used for this disposition.",
            },
            {
                "url": official,
                "claim": "Owning ecosystem documentation was reviewed to determine whether a stable repository-visible signature exists.",
            },
        ],
    }


def build() -> dict[str, Any]:
    catalog_payload = json.loads(CATALOG.read_text(encoding="utf-8"))
    catalog_by_id = {item["candidate_id"]: item for item in catalog_payload["candidates"]}
    candidates = [enrich(dict(entry), catalog_by_id) for entry in DECISIONS]
    statuses = {
        status: sum(item["batch_status"] == status for item in candidates)
        for status in ("fixture_ready", "rejected")
    }
    executable_ids = {rule.rule_id for rule in RULES}
    promoted = sorted(
        item["candidate_id"] for item in candidates if item["candidate_id"] in executable_ids
    )
    return {
        "schema_version": 1,
        "batch": "P2-A",
        "reviewed_at": REVIEWED_AT,
        "catalog": "research/language-rule-candidates.json",
        "policy": (
            "A research ID is not an executable detector. Promotion requires current primary-source "
            "semantics, complete fixtures, duplicate analysis, representative-repository shadow "
            "measurements, and an acceptable runtime delta. Batch size is a ceiling, not a quota."
        ),
        "ecosystem_caps": CAPS,
        "candidate_count": len(candidates),
        "status_counts": statuses,
        "promoted_ids": promoted,
        "promotion_result": "no_promotions_pending_representative_shadow_evidence",
        "candidates": candidates,
        "residual_evidence": [
            {
                "id": "P2A-EXT-1",
                "requirement": "Representative repositories pinned by revision and reviewed under compatible licenses.",
                "state": "external_evidence_required",
            },
            {
                "id": "P2A-EXT-2",
                "requirement": "Per-candidate observed TP/FP/FN/TN and duplicate counts from advisory shadow runs.",
                "state": "blocked_by_P2A-EXT-1",
            },
            {
                "id": "P2A-EXT-3",
                "requirement": "Scanner wall-time and peak-RSS delta after an eligible candidate is implemented behind shadow mode.",
                "state": "blocked_by_P2A-EXT-2",
            },
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rendered = json.dumps(build(), indent=2) + "\n"
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print(f"stale: {OUTPUT.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print("promotion batch A decision record is current")
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"updated {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
