"""Original PHP2Shell and native-precision fixtures for the 0.12 release."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/rule_cases_v2.json"
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402


def case(path: str, source: str, **extra: object) -> dict:
    return {"path": path, "source": source, **extra}


def adversarial(path: str, source: str, expected: bool, rationale: str) -> dict:
    return case(path, source, expected=expected, rationale=rationale)


def records() -> list[dict]:
    format_cases = {
        "rule_id": "SP668",
        "sources": [
            {
                "url": "https://pubs.opengroup.org/onlinepubs/9799919799/functions/syslog.html",
                "claim": "POSIX syslog takes priority first and the format string second; an argv value in the priority argument is not evidence of a controlled format string.",
            },
            {
                "url": "https://cwe.mitre.org/data/definitions/134.html",
                "claim": "CWE-134 classifies externally controlled format strings; identifying the actual format argument is required before making this local finding.",
            },
        ],
        "positive": [
            case("main.c", "int main(int argc, char **argv) { printf(argv[1]); }"),
            case("logger.cpp", "void log(char **argv) { fprintf(stderr, argv[1]); }"),
            case("buffer.c", "void print(char **argv) { snprintf(buf, sizeof buf, argv[1]); }"),
            case("logger.c", "void log(char **argv) { syslog(LOG_ERR, argv[1]); }"),
            case("syslog.c", "void log(char **argv) { syslog(\n LOG_ERR | LOG_AUTH,\n argv[2]); }"),
        ],
        "negative": [
            case("main.c", 'int main(int argc, char **argv) { printf("%s", argv[1]); }'),
            case(
                "logger.cpp",
                'void log(char **argv) { const char *fmt = "%s"; printf(fmt, argv[1]); }',
            ),
            case("safe.c", 'void log(const char *user) { printf("%s", user); }'),
            case("syslog.c", 'void log(char **argv) { syslog(LOG_ERR, "%s", argv[1]); }'),
            case("priority.c", 'void log(char **argv) { syslog(argv[1], "%s", message); }'),
            case("wrapper.cpp", "void log(char **argv) { my_syslog(LOG_ERR, argv[1]); }"),
            case("wrapper.cpp", "void log(char **argv) { custom::printf(argv[1]); }"),
            case("member.cpp", "void log(char **argv) { logger.printf(argv[1]); }"),
            case("main.txt", "printf(argv[1]);"),
        ],
        "adversarial": [
            adversarial(
                "main.c",
                "int main(int argc, char **argv_safe) { printf(argv_safe[1]); }",
                False,
                "The direct source spelling is argv, not any identifier with a matching prefix; aliases require separate semantic analysis.",
            ),
            adversarial(
                "main.c",
                "int main(int argc, char **argv) { printf(argv + 1); }",
                False,
                "Pointer arithmetic is unresolved by this direct-index pattern and must not be presented as a verified format argument.",
            ),
            adversarial(
                "syslog.c",
                'const char *example = "syslog(LOG_ERR, argv[1]);";',
                False,
                "Quoted code-like data is not an executed syslog call and must remain silent even when it contains a complete unsafe-looking example.",
            ),
        ],
    }
    xml = "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };\nusing var reader = XmlReader.Create(stream, settings);\n"
    xml_cases = {
        "rule_id": "SP670",
        "sources": [
            {
                "url": "https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3075",
                "claim": "Microsoft distinguishes DTD parsing and external resource resolution. A null resolver blocks external resource access; DTD expansion needs separate limits.",
            },
            {
                "url": "https://cwe.mitre.org/data/definitions/611.html",
                "claim": "CWE-611 describes unintended external XML entity resolution; enabling an internal DTD alone is not sufficient evidence of this weakness.",
            },
            {
                "url": "https://learn.microsoft.com/en-us/dotnet/fundamentals/syslib-diagnostics/syslib0047",
                "claim": "XmlSecureResolver is obsolete in modern .NET; this detector does not equate it with the explicitly network-capable XmlUrlResolver configuration.",
            },
        ],
        "positive": [
            case("XmlParser.cs", xml),
            case(
                "XmlParser.cs",
                xml.replace("new XmlReaderSettings", "new System.Xml.XmlReaderSettings")
                .replace("DtdProcessing.Parse", "System.Xml.DtdProcessing.Parse")
                .replace("new XmlUrlResolver", "new System.Xml.XmlUrlResolver")
                .replace("XmlReader.Create", "System.Xml.XmlReader.Create"),
            ),
            case(
                "XmlParser.cs",
                xml.replace(
                    "new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver()",
                    "new XmlReaderSettings() { XmlResolver = new XmlUrlResolver(), DtdProcessing = DtdProcessing.Parse",
                ),
            ),
        ],
        "negative": [
            case("XmlParser.cs", xml.replace("new XmlUrlResolver()", "null")),
            case("XmlParser.cs", xml.replace("DtdProcessing.Parse", "DtdProcessing.Prohibit")),
            case("XmlParser.cs", xml.replace("DtdProcessing.Parse", "DtdProcessing.Ignore")),
            case(
                "XmlParser.cs", xml.replace("new XmlUrlResolver()", "XmlResolver.ThrowingResolver")
            ),
            case(
                "XmlParser.cs",
                xml.replace(
                    "new XmlUrlResolver()", "new XmlSecureResolver(new XmlUrlResolver(), policy)"
                ),
            ),
            case("XmlParser.cs", xml.replace("DtdProcessing = DtdProcessing.Parse, ", "")),
            case(
                "XmlParser.cs",
                xml.replace("using var reader", "settings.XmlResolver = null;\nusing var reader"),
            ),
            case(
                "XmlParser.cs",
                xml.replace(
                    "XmlResolver = new XmlUrlResolver()",
                    "XmlResolver = null, XmlResolver = new XmlUrlResolver()",
                ),
            ),
            case("JsonParser.cs", "var payload = JsonSerializer.Deserialize<Model>(body);"),
            case(
                "XmlParser.cs",
                "var settings = CreateHardenedSettings();\nusing var reader = XmlReader.Create(stream, settings);",
            ),
            case(
                "XmlParser.cs",
                "var settings = new XmlReaderSettings();\nsettings.DtdProcessing = DtdProcessing.Parse;\nsettings.XmlResolver = new XmlUrlResolver();\nusing var reader = XmlReader.Create(stream, settings);",
            ),
            case("XmlParser.cs", xml.replace("var settings =", "obj.settings =")),
            case("XmlParser.cs", "var XmlReader = customReaderFactory;\n" + xml),
        ],
        "adversarial": [
            adversarial(
                "XmlParser.cs",
                "/*\n" + xml + "*/",
                False,
                "Configuration-shaped prose in a block comment must not establish a parser object, its settings or consumption by XmlReader.Create.",
            ),
            adversarial(
                "XmlParser.cs",
                "class XmlReaderSettings {}\n" + xml,
                False,
                "A locally declared look-alike type makes standard-library identity ambiguous and must not create external-entity evidence.",
            ),
            adversarial(
                "XmlParser.cs",
                "using XmlReaderSettings = Custom.Settings;\n" + xml,
                False,
                "An explicit custom type alias is not System.Xml.XmlReaderSettings; this bounded detector must not infer ownership from the local name.",
            ),
        ],
    }
    php_cases = {
        "rule_id": "SP683",
        "sources": [
            {
                "url": "https://www.php.net/archive/2026.php#2026-10-21-5",
                "claim": "PHP's October 21 2026 advisory gives branch fixes 8.2.35, 8.3.36, 8.4.27 and 8.5.12, and explicitly notes that distribution vendors can backport patches.",
            },
            {
                "url": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
                "claim": "CVE-2026-109618 is a PHP runtime request/OOM cleanup memory-corruption issue, not a vulnerability established by PHP application keywords.",
            },
            {
                "url": "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
                "claim": "CVE-2026-109619 concerns persistent worker state referring to released request memory; deployment, patch provenance and runtime state matter.",
            },
        ],
        "positive": [
            case(".php-version", "8.4.26\n"),
            case(".tool-versions", "nodejs 24.15.0\nphp 8.3.35\n"),
            case("Dockerfile", "FROM php:8.5.11-fpm\nCOPY app /srv/app\n"),
            case("Containerfile", "FROM docker.io/library/php:8.2.34-apache-bookworm\n"),
            case(
                "Dockerfile", "FROM php:8.4.26-fpm-alpine AS runtime\nFROM runtime AS production\n"
            ),
            case(".php-version", "8.1.33\n"),
            case("Dockerfile", "FROM --platform=linux/amd64 php:8.4.26-fpm AS app\n"),
        ],
        "negative": [
            *[
                case(".php-version", version + "\n")
                for version in (
                    "8.2.35",
                    "8.3.36",
                    "8.4.27",
                    "8.5.12",
                    "8.4.28",
                    "8.6.0RC3",
                    "8.4",
                    "8.4.26-1+deb12u1",
                    "system",
                )
            ],
            case("Dockerfile", "FROM php:8.4.27-fpm\n"),
            case("Dockerfile", "FROM php:8.4.26-cli\n"),
            case("Dockerfile", "FROM php:8.4.26-fpm AS unused\nFROM nginx:1.27\n"),
            case("Dockerfile", "FROM php:8.4-fpm\n"),
            case("Dockerfile", "FROM custom/php:8.4.26-fpm\n"),
            case("Dockerfile", "FROM php:8.4.26-fpm-vendorfixed\n"),
            case("Dockerfile", "FROM php:8.4.26-fpm@sha256:" + "a" * 64 + "\n"),
            case(
                "composer.json", '{"require":{"php":"^8.0"},"config":{"platform":{"php":"8.4.26"}}}'
            ),
            case("app.php", '<?php $documentation = "PHP 8.4.26"; ?>'),
            case(
                "app.php",
                "<?php\nfunction supportsRuntime(): bool {\n    return PHP_VERSION_ID >= 80400;\n}\n",
            ),
            case(".tool-versions", "php 8.4.26 system\n"),
            case(".php-version", "8.4.26\n8.4.27\n"),
        ],
        "adversarial": [
            adversarial(
                "Dockerfile",
                "FROM php:8.4.27-fpm\nRUN cat <<'EOF'\nFROM php:8.4.26-fpm\nEOF\n",
                False,
                "A heredoc can contain an instruction-looking FROM line. The unsupported heredoc context stays unresolved instead of inventing a runtime stage.",
            ),
            adversarial(
                "Dockerfile",
                "FROM php:8.4.27-fpm\nRUN echo hello \\\n FROM php:8.4.26-fpm\n",
                False,
                "A continued RUN instruction contains data rather than a new FROM; physical line matching would incorrectly replace a fixed final base.",
            ),
            adversarial(
                "Dockerfile",
                "ARG PHP_IMAGE=php:8.4.26-fpm\nFROM ${PHP_IMAGE}\n",
                False,
                "Build arguments are overridable and are not resolved by this offline signature; a declared default does not establish the effective runtime image.",
            ),
            adversarial(
                ".php-version",
                "# historical 8.4.26\n8.4.27\n",
                False,
                "Comments describing historical versions do not override the single explicit current version declaration.",
            ),
        ],
    }
    for entry in (format_cases, xml_cases, php_cases):
        rule = find_rule(entry["rule_id"])
        entry.update(
            expected_severity=rule.severity,
            expected_confidence=rule.confidence,
            blocking_eligible=False,
            false_positive_analysis=RULE_EXPLANATIONS[rule.rule_id]["false_positive"],
        )
    return [format_cases, xml_cases, php_cases]


def build() -> str:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cohort = records()
    owned = {row["rule_id"] for row in cohort}
    payload["rules"] = [row for row in payload["rules"] if row["rule_id"] not in owned] + cohort
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = build()
    if args.check:
        if MANIFEST.read_text(encoding="utf-8") != rendered:
            print("stale 0.12 release contracts")
            return 1
    else:
        MANIFEST.write_text(rendered, encoding="utf-8")
    print("0.12 release contracts current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
