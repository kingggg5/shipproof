#!/usr/bin/env python3
"""Fast, local-first production risk scanner with JSON, Markdown, and SARIF output."""

from __future__ import annotations

import argparse
import ast
import contextlib
import fnmatch
import hashlib
import importlib.util
import json
import math
import os
import re
import shlex
import shutil
import stat as stat_module
import subprocess
import sys
import tempfile
import threading

try:  # Python 3.11+ ships the regex parser as a private re submodule.
    import re._constants as _sre_constants
    import re._parser as _sre_parser
except ImportError:  # pragma: no cover - Python 3.10 fallback
    import sre_constants as _sre_constants  # type: ignore[no-redef]
    import sre_parse as _sre_parser  # type: ignore[no-redef]

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
from pathlib import Path

import archive_inspect
import dart_transport_checks
import dotnet_cookie_checks
import js_config_checks
import node_advisories
import php_advisories
import polyglot_checks
import precision as precision_policy
import python_runtime_checks
import sql_checks
from rule_explanations import RULE_EXPLANATIONS

VERSION = "0.12.0"
MAX_SNIPPET_BYTES = 200_000
MAX_SCAN_LINE_CHARS = 8_192
CONTEXT_LEVELS = ("summary", "overview", "full")
JS_CONFIG_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})

SEVERITY = {"none": 99, "critical": 0, "high": 1, "medium": 2, "low": 3}
CONFIDENCE = {"high": 0, "medium": 1, "low": 2}
SEVERITY_ICON = {
    "critical": "\U0001f534",
    "high": "\U0001f534",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
}
CONFIDENCE_LABEL = {"high": "HIGH_CONFIDENCE", "medium": "LIKELY", "low": "NEEDS_REVIEW"}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    ".work",
    "benchmarks",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "fixtures",
    ".next",
    ".nuxt",
    ".cache",
    ".npm-cache",
    ".shipproof-research-cache",
    "research",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
    "__pycache__",
}
TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".vue",
    ".svelte",
    ".astro",
    ".html",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    ".go",
    ".rs",
    ".swift",
    ".dart",
    ".lua",
    ".luau",
    ".rb",
    ".erb",
    ".ex",
    ".exs",
    ".php",
    ".cs",
    ".c",
    ".m",
    ".mm",
    ".h",
    ".cpp",
    ".hpp",
    ".sh",
    ".bash",
    ".ps1",
    ".sql",
    ".graphql",
    ".gql",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".cff",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".properties",
    ".env",
    ".xml",
    ".tf",
    ".hcl",
    ".prisma",
    ".service",
    ".md",
    ".rst",
    ".txt",
}
DOCUMENT_SUFFIXES = {".md", ".rst", ".txt"}
TEXT_NAMES = {
    "dockerfile",
    "containerfile",
    "makefile",
    "procfile",
    ".dockerignore",
    ".env",
    ".gitignore",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".editorconfig",
    ".gitattributes",
    ".gitmodules",
    ".npmignore",
    ".php-version",
    ".node-version",
    ".nvmrc",
    ".tool-versions",
    ".gitkeep",
    "license",
    "codeowners",
}
PLACEHOLDERS = re.compile(
    r"(?i)(example|sample|placeholder|dummy|changeme|replace[_-]?me|your[_-]?|test[_-]?only|"
    r"not[_-]?a[_-]?real|fake|redacted|xxxx|<[^>]+>|\$\{|process\.env|os\.environ)"
)
INLINE_IGNORE_MARKER = "shipproof-ignore"
INLINE_IGNORE_IDS = re.compile(r"\bSP\d+\b")
MAX_MULTILINE_MATCH_CHARS = 20_000
MAX_MULTILINE_MATCH_LINES = 120

# --- Entropy scoring for secret confidence calibration ---
SECRET_VALUE_PATTERN = re.compile(
    r"""(?:['"])([-A-Za-z0-9+/=_.!~*'()@:;,?#\[\]{}|\\^`%]+)(?:['"])"""
)


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


ENTROPY_CALIBRATED_RULE_IDS = frozenset({"SP003", "SP004", "SP019", "SP020", "SP021"})


def is_placeholder_secret(matched_text: str) -> bool:
    """Placeholder filtering targets the credential value, not the whole match.

    SP004 matches inherently contain `os.environ` / `process.env` (the env
    indirection itself), so scanning the full matched text would suppress every
    fallback-default finding. Fall back to the whole text for unquoted shapes.
    """
    values = SECRET_VALUE_PATTERN.findall(matched_text)
    target = values[-1] if values else matched_text
    return bool(PLACEHOLDERS.search(target))


def secret_confidence(rule: Rule, matched_text: str) -> str | None:
    """Adjust secret finding confidence based on entropy of credential values.

    Calibrated rules (generic credential assignments) get full two-way
    calibration. Every other secret rule gets a demote-only gate so long but
    obviously low-entropy values - repeated characters, test filler - drop to
    low confidence while structured provider tokens stay untouched.
    """
    matches = SECRET_VALUE_PATTERN.findall(matched_text)
    if not matches:
        return None
    # Credential assignments may quote both the key and the value (JSON/YAML).
    # The final quoted token is the assigned credential, not the key name.
    value = matches[-1]
    if rule.rule_id in ENTROPY_CALIBRATED_RULE_IDS:
        if len(value) < 8:
            return "low"
        entropy = shannon_entropy(value)
        if entropy >= 4.0:
            return "high"
        if entropy >= 3.0:
            return rule.confidence
        return "low"
    if len(value) >= 8 and shannon_entropy(value) < 2.5:
        return "low"
    return None


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    pattern: re.Pattern[str]
    message: str
    remediation: str
    cwe: str
    owasp: str
    suffixes: frozenset[str] = frozenset()
    redact: bool = False


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    path: str
    line: int
    evidence: str
    message: str
    remediation: str
    cwe: str
    owasp: str
    fingerprint: str
    detection: str = "pattern"
    proof_level: str = "L0"
    scope: str = "app"
    verification_status: str = "unverified"
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    history_commit: str | None = None
    match_confidence: str = "high"
    tier: str = "gate"
    scan_profile: str | None = None


MAX_FINDINGS_PER_FILE = 5_000
MAX_FINDINGS_TOTAL = 50_000


class FindingLimitError(ValueError):
    """Hard evidence limit: the scanner must not claim a verdict after truncation."""


class BoundedFindings(list[Finding]):
    """List-compatible finding accumulator with a deterministic per-file cap."""

    def __init__(self, limit: int | None = None) -> None:
        super().__init__()
        self.limit = MAX_FINDINGS_PER_FILE if limit is None else limit

    def append(self, item: Finding) -> None:
        if len(self) >= self.limit:
            raise FindingLimitError(
                f"finding output exceeded the per-file limit of {self.limit}; "
                "reduce scope or inspect the source manually"
            )
        super().append(item)

    def extend(self, values: Iterable[Finding]) -> None:
        for value in values:
            self.append(value)


PROOF_LEVELS = {
    "pattern": "L0",
    "ast": "L1",
    "structural": "L1",
    "artifact": "L1",
    "taint": "L2",
}
PROOF_RANK = {"L0": 0, "L1": 1, "L2": 2}


def compile_pattern(value: str) -> re.Pattern[str]:
    return re.compile(value, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule(
        "SP001",
        "Private key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"""),
        "A private key appears in source control.",
        "Revoke and rotate the key, remove it from history, and use a secret manager.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset(set()),
        redact=True,
    ),
    Rule(
        "SP092",
        "Unpinned npm dependency version range",
        "supply-chain",
        "medium",
        "high",
        compile_pattern(r"""["'][^"']+["']\s*:\s*["'](?:\*|latest)["']"""),
        "A wildcard or latest version range installs whatever upstream publishes at install time, silently pulling in compromised releases.",
        "Pin exact versions or bounded ranges and commit a lockfile; upgrade deliberately through review.",
        "CWE-1104",
        "OWASP ASVS V14",
        frozenset({".json"}),
    ),
    Rule(
        "SP093",
        "Maven dependency on a SNAPSHOT version",
        "supply-chain",
        "medium",
        "high",
        compile_pattern(r"""<version>\s*[^<]*SNAPSHOT\s*</version>"""),
        "SNAPSHOT dependencies resolve to whatever was last published, so builds are not reproducible and can pick up tampered artifacts.",
        "Depend on fixed release versions from trusted repositories and rebuild against them in CI.",
        "CWE-1104",
        "OWASP ASVS V14",
        frozenset({".xml", ".pom"}),
    ),
    Rule(
        "SP094",
        "Dockerfile ADD over remote URL",
        "supply-chain",
        "medium",
        "high",
        compile_pattern(r"""(?mi)^[ \t]*ADD\s+https?://"""),
        "ADD with a remote URL downloads content at build time without integrity verification and unpacks archives implicitly.",
        "Fetch with curl or wget inside RUN and verify a published checksum, or COPY the file from build context.",
        "CWE-829",
        "OWASP ASVS V14",
        frozenset({".dockerfile", ".docker"}),
    ),
    Rule(
        "SP095",
        "Package lifecycle script fetches over network",
        "supply-chain",
        "high",
        "medium",
        compile_pattern(
            r""""(?:pre|post)?install"\s*:\s*"[^"]*(?:curl |wget |node -e|python -c)"""
        ),
        "Install lifecycle scripts that download code give compromised registries direct code execution on every developer machine and CI runner.",
        "Keep install scripts offline and reviewable; vendor any bootstrap asset into the repository instead of fetching it.",
        "CWE-494",
        "OWASP ASVS V14",
        frozenset({".json"}),
    ),
    # ------------------------------------------------------------------
    # AI Skills Security (T01-T05 equivalent)
    # ------------------------------------------------------------------
    Rule(
        "SP096",
        "Skill file with instruction injection pattern",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)|"""
            r"""disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts)|"""
            r"""you\s+are\s+now\s+(?:a|an)\s+(?:different|new)|"""
            r"""forget\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|context))"""
        ),
        "A skill file contains patterns commonly used for prompt injection or instruction hijacking.",
        "Review the skill source for malicious instruction patterns before loading it into an agent.",
        "CWE-77",
        "OWASP ASVS V5",
        frozenset({".md", ".txt", ".yaml", ".yml"}),
    ),
    Rule(
        "SP097",
        "Skill file downloads and executes remote code",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?i)(?:curl|wget|fetch|http\.get|requests\.get|axios\.get)\s*\(?\s*["']https?://[^"']+["']"""
            r"""[^;]*\|\s*(?:bash|sh|python|node|eval)"""
        ),
        "A skill file downloads remote content and pipes it directly to an interpreter.",
        "Never execute downloaded code without integrity verification; vendor dependencies instead.",
        "CWE-494",
        "OWASP ASVS V14",
        frozenset({".md", ".sh", ".bash", ".py", ".js"}),
    ),
    Rule(
        "SP098",
        "Skill file with shell execution capability",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?i)(?<![.\w])(?:exec|eval|subprocess|child_process|os\.system|shell_exec|popen)\s*\("""
        ),
        "A skill file contains shell or code execution capability that could be exploited.",
        "Review whether the skill genuinely needs code execution; sandbox or remove if not required.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".md", ".sh", ".bash"}),
    ),
    Rule(
        "SP099",
        "Skill accesses high-value environment credential",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""(?ix)(?:process\.env\s*(?:\.\s*(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY)\b|\[\s*["'](?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY)["']\s*\])|"""
            r"""os\.environ\s*\[\s*["'](?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY)["']\s*\]|"""
            r"""(?:os\.)?(?:environ\.get|getenv)\s*\(\s*["'](?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY)["'])"""
        ),
        "A Skill reads a high-value environment credential, expanding the authority available to its code.",
        "Document the credential need and provide a short-lived, audience-bound, least-privilege token only to the code that requires it.",
        "CWE-272",
        "OWASP ASVS V14",
        frozenset({".md", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}),
    ),
    Rule(
        "SP100",
        "Skill posts data to webhook endpoint",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?is)(?:(?:requests\.post|axios\.post)\s*\(?\s*["']https?://"""
            r"""[^"']*(?:hooks\.slack\.com|discord\.com/api/webhooks|(?:^|[./_-])webhooks?(?:[./?_-]|$))[^"']*["']|"""
            r"""fetch\s*\(\s*["']https?://[^"']*(?:hooks\.slack\.com|discord\.com/api/webhooks|(?:^|[./_-])webhooks?(?:[./?_-]|$))[^"']*["']"""
            r"""[\s\S]{0,300}?\bmethod\s*:\s*["']POST["'])"""
        ),
        "A Skill posts data to a webhook or relay endpoint, creating an externally visible side effect.",
        "Allowlist the destination and constrain the payload so secrets, source files, prompts, and unrelated tool output cannot be sent.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".md", ".py", ".js"}),
    ),
    # ------------------------------------------------------------------
    # MCP Server Security (T06-T09 equivalent)
    # ------------------------------------------------------------------
    Rule(
        "SP271",
        "MCP tool definition with shell execution",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?i)(?:(?:child_process|cp)\.exec(?:Sync)?\s*\(|\bos\.system\s*\(|shell_exec\s*\(|subprocess\.(?:run|call|check_output|Popen)\s*\([^)]*shell\s*=\s*True)"""
        ),
        "An MCP tool definition contains shell or code execution capability without sandbox constraints.",
        "Review whether the MCP tool genuinely needs shell execution; sandbox or remove if not required.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".mjs", ".js", ".ts", ".py"}),
    ),
    Rule(
        "SP272",
        "MCP tool with unrestricted file system access",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?i)\b(?:readFile|writeFile|readFileSync|writeFileSync|fs\.read|fs\.write|open)\s*\("""
            r"""[^)]*(?:\.\.\/|\.\.\\|process\.env|os\.path)"""
        ),
        "An MCP tool accesses file system paths that may traverse outside intended directories.",
        "Restrict file access to specific directories; validate paths before access.",
        "CWE-22",
        "OWASP ASVS V12",
        frozenset({".mjs", ".js", ".ts", ".py"}),
    ),
    Rule(
        "SP273",
        "MCP tool with network access without allowlist",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?i)(?:registerTool|server\.tool|mcp\.tool|z\.object\(\{)[^;]*"""
            r"""(?:fetch|http\.request|requests\.(?:get|post|put|delete)|axios\.(?:get|post|put|delete))"""
            r"""\s*\(\s*["']https?://(?!localhost|127\.0\.0\.1)[^"']+["']"""
        ),
        "An MCP tool makes network requests to external endpoints without an allowlist.",
        "Restrict network access to specific allowlisted endpoints; validate URLs before requests.",
        "CWE-918",
        "OWASP ASVS V5",
        frozenset({".mjs", ".js", ".ts", ".py"}),
    ),
    Rule(
        "SP274",
        "MCP tool accessing environment credentials",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?ix)(?:process\.env\s*(?:\.\s*(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL)|\[\s*["'](?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL)["']\s*\])|"""
            r"""os\.environ\s*\[\s*["'](?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL)["']\s*\]|"""
            r"""(?:os\.)?(?:environ\.get|getenv)\s*\(\s*["'](?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL)["'])"""
        ),
        "An MCP tool accesses environment credentials, potentially exfiltrating them.",
        "Review whether the MCP tool genuinely needs these credentials; scope access to minimum required.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".mjs", ".js", ".ts", ".py"}),
    ),
    Rule(
        "SP275",
        "MCP tool accepts an unbounded input schema",
        "security",
        "medium",
        "low",
        compile_pattern(
            r"""(?is)(?:registerTool|server\.tool|mcp\.tool)\s*\([\s\S]{0,1200}?"""
            r"""\b(?:inputSchema|schema)\s*:\s*z\.(?:any|unknown)\s*\(\s*\)"""
        ),
        "An MCP tool declares an unbounded input schema, allowing arbitrary values at the tool boundary.",
        "Replace z.any() or z.unknown() with a strict, size-bounded field schema and reject unknown keys.",
        "CWE-20",
        "OWASP ASVS V5",
        frozenset({".mjs", ".js", ".ts"}),
    ),
    # ------------------------------------------------------------------
    # AI framework security posture rules (Ollama, ComfyUI, vLLM).
    # These inspect local configuration; they do not claim deployed CVE matches.
    # ------------------------------------------------------------------
    Rule(
        "SP281",
        "Ollama API endpoint exposed without authentication",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?i)(?:OLLAMA_HOST|ollama_host)\s*[:=]\s*["'](?:0\.0\.0\.0|::|\*)["']"""
        ),
        "Ollama API is bound to all interfaces without authentication, exposing model endpoints.",
        "Bind Ollama to localhost or add authentication; never expose model APIs publicly.",
        "CWE-284",
        "OWASP ASVS V4",
        frozenset({".env", ".env.example", ".env.local", ".sh", ".bash", ".yaml", ".yml"}),
    ),
    Rule(
        "SP282",
        "Ollama model uses explicit non-default registry",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?i)\bollama\s+(?:pull|run)\s+(?:https?://)?"""
            r"""(?!registry\.ollama\.ai(?:/|:443/))"""
            r"""(?:localhost(?::\d+)?|(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?)/[\w./:-]+"""
        ),
        "Ollama pulls or runs a model from an explicitly named non-default registry host.",
        "Allowlist the registry host and verify the approved model digest before use.",
        "CWE-494",
        "OWASP ASVS V14",
        frozenset({".sh", ".bash", ".md", ".txt"}),
    ),
    Rule(
        "SP283",
        "ComfyUI workflow with untrusted custom node",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?i)(?:custom_nodes|custom-nodes|customnodes)\s*[:=]\s*\[[^\]]*["']https?://(?:github\.com|gitlab\.com)[^"']+["']"""
        ),
        "ComfyUI workflow loads custom nodes from external repositories without integrity verification.",
        "Verify custom node integrity before use; pin to specific commits; review code before loading.",
        "CWE-494",
        "OWASP ASVS V14",
        frozenset({".json", ".yaml", ".yml", ".json5"}),
    ),
    Rule(
        "SP284",
        "vLLM API endpoint exposed without authentication",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?i)(?:vllm|VLLM_HOST|vllm_host)\s*[:=]\s*["'](?:0\.0\.0\.0|::|\*)["']"""
        ),
        "vLLM API is bound to all interfaces without authentication, exposing model endpoints.",
        "Bind vLLM to localhost or add authentication; never expose model APIs publicly.",
        "CWE-284",
        "OWASP ASVS V4",
        frozenset({".env", ".env.example", ".env.local", ".sh", ".bash", ".yaml", ".yml"}),
    ),
    Rule(
        "SP285",
        "vLLM model loaded from untrusted source",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?i)(?:vllm|vllm serve|vllm run)\s+(?:serve|run)\s+(?!(?:meta-llama|mistralai|google|openai|huggingface))[\w\-./]+"""
        ),
        "vLLM loads a model from a non-official source, potentially loading a malicious model.",
        "Only load models from official sources; verify model integrity before use.",
        "CWE-494",
        "OWASP ASVS V14",
        frozenset({".sh", ".bash", ".md", ".txt"}),
    ),
    Rule(
        "SP051",
        "Prototype pollution via merge of request data",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""\b(?:[\w$.]*\.)?(?:deepMerge|mergeDeep|deepExtend|deepAssign|defaultsDeep|merge(?:With)?|extend|set)\s*\(\s*[^,()]{1,80},\s*(?:req(?:uest)?\s*\.\s*(?:body|query|params)|JSON\.parse\s*\(\s*req(?:uest)?\.\w+\s*\))"""
        ),
        "A merge or set helper receives request-controlled data, allowing __proto__/constructor keys to pollute object prototypes.",
        "Reject __proto__, constructor, and prototype keys before merging, or copy with an explicit key allowlist and add a pollution regression test.",
        "CWE-1321",
        "OWASP ASVS V5",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}),
    ),
    Rule(
        "SP052",
        "JWT signed with hardcoded string secret",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:jwt\.sign|jsonwebtoken\.sign|SignJWT)\s*\([^,]*,\s*["'][^"']{8,}["']"""
        ),
        "A JWT is signed with a secret literal committed to source control; anyone with repository access can forge valid tokens.",
        "Load the signing secret from a managed secret store and rotate it; verify tokens with key IDs and expiry.",
        "CWE-321",
        "OWASP ASVS V6",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP053",
        "Weak or legacy block cipher selected",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""createCipheriv\s*\(\s*["'](?:des|des3|des-ede|bf|blowfish|rc4)[^"']*["']|CryptoJS\.(?:DES|TripleDES|RC4)\.|getInstance\s*\(\s*["'](?:DES|Blowfish|RC4)|from\s+Crypto\.Cipher\s+import\s+(?:DES|ARC4)|(?:^|\n)\s*(?:DES|ARC4)\.new\s*\("""
        ),
        "DES, 3DES, Blowfish, or RC4 provide inadequate confidentiality for new data.",
        "Migrate to AES-GCM (or ChaCha20-Poly1305) with unique nonces and re-encrypt stored data.",
        "CWE-327",
        "OWASP ASVS V6",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".py", ".java"}),
    ),
    Rule(
        "SP054",
        "Shell command built with interpolation",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""os\.(?:system|popen)\s*\(\s*(?:f["']|["'][^"']*["']\s*%|\`[^\`]*\$\{)"""
        ),
        "An os.system or os.popen command appears to be built with string interpolation.",
        "Pass an argument list to subprocess without a shell and validate every externally controlled argument.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP055",
        "Node command built with template interpolation",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?<![\w.$])(?:(?:execSync|spawnSync|exec)|(?:child_process|childprocess|child|cp|proc)\s*\.\s*(?:execSync|exec))\s*\(\s*`[^`]*\$\{"""
        ),
        "A child-process call receives an interpolated template literal, which executes through a shell.",
        "Use spawn/execFile with an argument array and never interpolate input into the command string.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP056",
        "Session cookie without HttpOnly",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""\.cookie\s*\(\s*["'][^"']*(?:sess|session|token|jwt|auth|refresh)[^"']*["']\s*,(?![^)]*httpOnly\s*[:=]\s*(?:true|True|1\b))[^)]*\)"""
        ),
        "An authentication or session cookie is set without HttpOnly, exposing it to JavaScript during XSS.",
        "Set httpOnly (with Secure and SameSite) on every session-bearing cookie.",
        "CWE-1004",
        "OWASP ASVS V3",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".cs"}),
    ),
    Rule(
        "SP057",
        "Session cookie without SameSite",
        "security",
        "low",
        "medium",
        compile_pattern(
            r"""\.cookie\s*\(\s*["'][^"']*(?:sess|session|token|jwt|auth|refresh)[^"']*["']\s*,(?![^)]*[Ss]ame[Ss]ite)[^)]*\)"""
        ),
        "An authentication or session cookie is set without an explicit SameSite attribute.",
        "Set SameSite=Lax or Strict together with Secure on session cookies.",
        "CWE-1275",
        "OWASP ASVS V3",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP058",
        "Credential embedded in URL query string",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""["']https?://[^"'\s]{0,200}[?&](?<![a-z0-9_])(?:password|passwd|secret|api_?key|access_?token|auth_?token|session_?token|bearer)=[^"']*["']"""
        ),
        "A credential appears inside a URL query string, which leaks via browser history, proxies, and access logs.",
        "Move credentials into headers or request bodies and rotate any value already committed.",
        "CWE-598",
        "OWASP ASVS V14",
        frozenset(set()),
    ),
    Rule(
        "SP059",
        "MongoDB operator injection from request",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""\$\s*(?:gt|gte|lt|lte|ne|regex|where)\s*:\s*req(?:uest)?\.(?:body|query|params)"""
        ),
        "A MongoDB comparison operator receives raw request data, letting attackers append $gt/$ne style filters to bypass authentication.",
        "Validate and coerce credentials to expected scalar types before building query operators.",
        "CWE-943",
        "OWASP ASVS V4",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP060",
        "Dynamic include or require of request data",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|(?:include|require)(?:_once)?\s+\$[A-Za-z_]|(?:include|require)(?:_once)?\s*\(\s*\$[A-Za-z_]\w*\s*\)"""
        ),
        "A PHP include/require consumes request-controlled paths, allowing attackers to execute uploaded or remote files.",
        "Use an allowlist mapping identifiers to fixed file paths and reject anything containing separators or wrappers.",
        "CWE-98",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP061",
        "Overly broad exception handler",
        "correctness",
        "low",
        "high",
        compile_pattern(r"""\bexcept\s*:|except\s+Exception\s*:"""),
        "A bare except or except Exception swallows unrelated failures, masking bugs and security-relevant errors.",
        "Catch the narrowest expected exception types and let unexpected ones propagate to structured handling.",
        "CWE-396",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP062",
        "PHP preg_replace with /e evaluator modifier",
        "security",
        "critical",
        "high",
        compile_pattern(r"""preg_replace\s*\(\s*(["'])(.)((?:\\.|(?!\1).)*?)\2([a-z]*e[a-z]*)\1"""),
        "The removed /e modifier evaluates the replacement string as PHP code, turning crafted subjects into remote code execution.",
        "Replace with preg_replace_callback and never evaluate replacement strings.",
        "CWE-624",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP063",
        "Blank target link without noopener",
        "security",
        "medium",
        "high",
        compile_pattern(r"""<a\b(?![^>]*\brel\s*=)[^>]*\btarget\s*=\s*["']?_blank[^>]*>"""),
        "A target=_blank anchor without rel=noopener lets the opened page control this page through window.opener.",
        'Add rel="noopener noreferrer" to every external blank-target link.',
        "CWE-1022",
        "OWASP ASVS V14",
        frozenset({".html", ".htm", ".jsx", ".tsx", ".vue", ".js", ".ts"}),
    ),
    Rule(
        "SP064",
        "Assignment inside Java condition",
        "correctness",
        "medium",
        "medium",
        compile_pattern(r"""\bif\s*\(\s*[A-Za-z_$][\w$.<>\[\]]*\s*=\s*(?!=)"""),
        "An assignment (=) inside an if condition is usually a mistyped equality check, silently changing program state.",
        "Use == or .equals for comparison; if assignment is intended, compare explicitly against the assigned value.",
        "CWE-481",
        "OWASP ASVS V14",
        frozenset({".java"}),
    ),
    Rule(
        "SP065",
        "Expression Language evaluation of request input",
        "security",
        "critical",
        "medium",
        compile_pattern(
            r"""(?:createValueExpression|ValueExpression|evaluateExpression)\s*\([^)]*(?:getParameter|req\.|request\.|param\.)"""
        ),
        "Feeding request parameters into a Jakarta/Java EL evaluation allows attackers to execute expressions inside the application.",
        "Treat EL as code: never pass request data into expression factories; map inputs through typed DTOs.",
        "CWE-917",
        "OWASP ASVS V5",
        frozenset({".java", ".jsp"}),
    ),
    Rule(
        "SP066",
        "PHP shell call with raw superglobal",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\$_(?:GET|POST|REQUEST|COOKIE)[^\n]*(?:\bexec\b|\bshell_exec\b|\bsystem\b|\bpassthru\b|\bproc_open\b)|(?:\bexec\b|\bshell_exec\b|\bsystem\b|\bpassthru\b|\bproc_open\b)\s*\([^\n]*\$_(?:GET|POST|REQUEST|COOKIE)|(?:\bshell_exec\b|\bexec\b|\bsystem\b|\bpassthru\b)\s*\(\s*["'][^"']*["']\s*\.\s*\$"""
        ),
        "Request data reaches a PHP shell-execution function without escapeshellarg, enabling OS command injection.",
        "Reject shell calls on request input; when unavoidable, wrap every argument in escapeshellarg and allowlist values.",
        "CWE-88",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP067",
        "Credential committed in configuration file",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?im)^[ \t]*[A-Za-z0-9_.\-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)[A-Za-z0-9_.\-]*[ \t]*[:=][ \t]*(?![\"']?\{?\$)[\"']?([^\s\"'#]{4,})"""
        ),
        "A configuration file assigns a literal credential value instead of referencing a secret store placeholder.",
        "Replace the literal with an environment reference and rotate any value already committed.",
        "CWE-256",
        "OWASP ASVS V14",
        frozenset({".properties", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".toml"}),
        redact=True,
    ),
    Rule(
        "SP068",
        "World-writable file mode in Go",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:ioutil\.WriteFile|os\.WriteFile|os\.OpenFile|os\.Chmod)\s*\([^)]*0?o?777\b"""
        ),
        "Files created or chmod-ed to 0777 are writable by every user and process on the host.",
        "Grant the narrowest mode that works (0644 files, 0755 dirs) and document any exception.",
        "CWE-732",
        "OWASP ASVS V14",
        frozenset({".go"}),
    ),
    Rule(
        "SP069",
        "Go math/rand seeded from time for generated values",
        "security",
        "medium",
        "medium",
        compile_pattern(r"""rand\.New\(rand\.NewSource\(time\.(?:Now|Unix)"""),
        "math/rand reseeded from the clock is predictable; identifiers or tokens derived from it can be guessed.",
        "Use crypto/rand for security-relevant generation and keep math/rand for simulations only.",
        "CWE-330",
        "OWASP ASVS V6",
        frozenset({".go"}),
    ),
    Rule(
        "SP070",
        "WebSocket upgrader accepts every origin",
        "security",
        "medium",
        "high",
        compile_pattern(r"""CheckOrigin\s*[:=]\s*func.{0,80}?return\s+true"""),
        "A WebSocket upgrader whose CheckOrigin always returns true lets any website open cross-site sockets with user credentials.",
        "Validate req.Host (and Origin when present) against an allowlist inside CheckOrigin.",
        "CWE-1385",
        "OWASP ASVS V14",
        frozenset({".go"}),
    ),
    Rule(
        "SP071",
        "Ruby TLS verification disabled",
        "security",
        "high",
        "high",
        compile_pattern(r"""OpenSSL::SSL::VERIFY_NONE"""),
        "VERIFY_NONE accepts any certificate, opening every outbound TLS connection to interception.",
        "Keep VERIFY_PEER and configure a proper CA bundle; pin certificates for fixed endpoints.",
        "CWE-295",
        "OWASP ASVS V9",
        frozenset({".rb", ".erb"}),
    ),
    Rule(
        "SP072",
        "Ruby eval of request-controlled data",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\beval\s*\(\s*(?:params\[|request\.(?:params|raw_post)|session\[|cookies\.|cookies\[)"""
        ),
        "eval on Rails request/session data executes attacker-supplied code with full interpreter privileges.",
        "Parse input as data (JSON, typed casts) and remove every evaluation path that touches request state.",
        "CWE-95",
        "OWASP ASVS V5",
        frozenset({".rb", ".erb"}),
    ),
    Rule(
        "SP073",
        "Java cipher requested without explicit transform",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""Cipher\.getInstance\s*\(\s*"(?:AES|DES)"\s*\)|Cipher\.getInstance\s*\(\s*"DES\/ECB"""
        ),
        'getInstance("AES") silently selects AES/ECB/PKCS5Padding; ECB reveals repeated plaintext blocks.',
        "Request an explicit secure transform such as AES/GCM/NoPadding with unique nonces.",
        "CWE-327",
        "OWASP ASVS V6",
        frozenset({".java", ".jsp", ".kt"}),
    ),
    Rule(
        "SP074",
        "Java Runtime.exec built by concatenation",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""Runtime\.getRuntime\(\)\s*\.\s*exec\s*\([^)]*\+\s*[A-Za-z_$]|exec\s*\(\s*new\s*String\[\]\s*\{\s*"(?:sh"\s*,\s*"-c"|cmd\.exe"\s*,\s*"/c")"""
        ),
        "Concatenating values into a Runtime.exec command string lets shell metacharacters inject extra commands.",
        "Use ProcessBuilder with an argument array and validate each externally controlled argument.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".java", ".jsp"}),
    ),
    Rule(
        "SP075",
        "Flask file response driven by request data",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:send_file|send_from_directory)\s*\(\s*(?:request\.(?:args|form|values|files|json)\b|[A-Za-z_$][\w$.]*\s*,\s*request\.(?:form|args|values|get))"""
        ),
        "Serving files from request parameters enables path traversal into arbitrary readable locations.",
        "Map user selections to allowlisted server-side paths and never join raw request values onto filesystem paths.",
        "CWE-22",
        "OWASP ASVS V12",
        frozenset({".py"}),
    ),
    Rule(
        "SP076",
        "Express res.sendFile with request-derived path",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""sendFile\s*\(\s*(?:req(?:uest)?\.(?:query|params|body)|(?:path\.)?(?:join|resolve)\s*\([^)]*req(?:uest)?\.(?:query|params|body))"""
        ),
        "res.sendFile over request-controlled paths reads arbitrary files relative to the process.",
        "resolve the final path and require it to stay inside a dedicated public root before responding.",
        "CWE-22",
        "OWASP ASVS V12",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP077",
        "Stack trace returned to HTTP client",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""res(?:ponse)?\s*\.\s*(?:status\s*\(\s*\d{3}\s*\)\s*\.\s*)?(?:send|json)\s*\([^)]*\b[A-Za-z_$][\w$]*\.stack\b"""
        ),
        "Returning exception stacks exposes source paths, library versions, and internal topology to attackers.",
        "Log the stack server-side with an identifier and return a generic error body plus that reference.",
        "CWE-209",
        "OWASP ASVS V14",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP078",
        "PHP extract of request superglobal",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?<![\w$])extract\s*\(\s*\$_(?:GET|POST|REQUEST)(?![^)]*EXTR_(?:SKIP|PREFIX))"""
        ),
        "extract() turns query or body keys into PHP variables, letting attackers overwrite script state.",
        "Access request values explicitly by name; if extract is unavoidable, pass EXTR_SKIP and pre-seed variables.",
        "CWE-453",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP079",
        "Spring mapping without HTTP method constraint",
        "security",
        "low",
        "medium",
        compile_pattern(
            r"""@RequestMapping\s*\((?![^)]*method\s*=)[^)]*\)|@RequestMapping(?!\s*\()"""
        ),
        "A @RequestMapping without method= registers for every HTTP verb, widening CSRF and caching exposure.",
        "Constrain mappings with method = RequestMethod.GET/POST or prefer @GetMapping/@PostMapping shortcuts.",
        "CWE-650",
        "OWASP ASVS V14",
        frozenset({".java", ".jsp", ".kt"}),
    ),
    Rule(
        "SP080",
        "HTML response built from interpolated request data",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:res(?:ponse)?\s*\.\s*(?:send|write)|\.send)\s*\(\s*`[^`]*<[a-zA-Z][a-zA-Z0-9]*[^`]*\$\{"""
        ),
        "An HTTP response embeds request-derived values directly into an inline HTML template, enabling reflected cross-site scripting.",
        "Render through the framework's auto-escaping template engine and encode by output context; never concatenate HTML strings.",
        "CWE-80",
        "OWASP ASVS V5",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP081",
        "Go file serving driven by request parameters",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""http\.(?:ServeFile|ServeContent|ServeFileFS)\s*\([^)]*(?:r\.URL\.Query\(\)|FormValue\(|r\.FormValue)"""
        ),
        "Serving files from request parameters in Go enables path traversal outside the intended document root.",
        "Map identifiers to allowlisted paths, or enforce filepath.Rel containment against a dedicated root before responding.",
        "CWE-22",
        "OWASP ASVS V12",
        frozenset({".go"}),
    ),
    Rule(
        "SP082",
        "RegExp compiled from request input",
        "security",
        "high",
        "medium",
        compile_pattern(r"""new\s+RegExp\s*\([^)]*req(?:uest)?\.(?:query|body|params|headers)"""),
        "Compiling regular expressions from request data lets attackers inject catastrophic-backtracking patterns or alter match semantics.",
        "Match inputs against prebuilt allowlisted patterns; never construct RegExp text from untrusted values.",
        "CWE-1333",
        "OWASP ASVS V5",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP083",
        "Request body spread into persisted object",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:create|update|save|insert|upsert)\w*\s*\([^)]*\.\.\.\s*req(?:uest)?\.(?:body|query)"""
        ),
        "Spreading raw request bodies into create/update calls lets attackers overwrite fields such as role, tenant, or price.",
        "Pick explicit allowed fields before persistence and add a mass-assignment regression test.",
        "CWE-915",
        "OWASP ASVS V4",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"}),
    ),
    Rule(
        "SP084",
        "Session cookie without Secure flag",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""\.cookie\s*\(\s*["'][^"']*(?:sess|session|token|jwt|auth|refresh)[^"']*["']\s*,(?![^)]*[Ss]ecure\s*[:=]\s*(?:true|True|1\b))[^)]*\)"""
        ),
        "An authentication cookie without Secure travels over plaintext HTTP, exposing it to network interception.",
        "Set secure alongside HttpOnly and SameSite on every session-bearing cookie.",
        "CWE-614",
        "OWASP ASVS V3",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".cs"}),
    ),
    Rule(
        "SP085",
        "XXE protection explicitly disabled in Java parser",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""setFeature\s*\(\s*["'][^"']*(?:disallow-doctype-decl)[^"']*["']\s*,\s*false|setFeature\s*\(\s*["'][^"']*(?:external-(?:general|parameter)-entities)[^"']*["']\s*,\s*true"""
        ),
        "Explicitly disabling doctype/entity protections turns XML parsers into file-read and SSRF primitives.",
        "Keep disallow-doctype-decl=true and both external-entity features false on every factory that parses untrusted XML.",
        "CWE-611",
        "OWASP ASVS V5",
        frozenset({".java", ".jsp"}),
    ),
    Rule(
        "SP086",
        "Ruby dynamic method invocation from request",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\bsend\s*\(\s*(?:params\[|request\.(?:params|parameters)|cookies\[|session\[)"""
        ),
        "send() invokes arbitrary methods by name; request-driven names reach private or destructive methods directly.",
        "Map permitted actions through an explicit case/allowlist instead of reflecting parameter values into send().",
        "CWE-94",
        "OWASP ASVS V5",
        frozenset({".rb", ".erb"}),
    ),
    Rule(
        "SP087",
        "Go command built by concatenation",
        "security",
        "high",
        "medium",
        compile_pattern(r"""exec\.Command(?:Context)?\s*\([^)]*(?:\+\s*[A-Za-z_]|\.Join\()"""),
        "Concatenating values into exec.Command arguments can smuggle extra flags or, with a shell wrapper, entire commands.",
        "Pass fixed argv slices and validate each externally controlled argument against an allowlist.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".go"}),
    ),
    Rule(
        "SP088",
        "TLS certificate verification skipped",
        "security",
        "high",
        "high",
        compile_pattern(r"""InsecureSkipVerify\s*[:=]\s*true"""),
        "InsecureSkipVerify accepts any certificate, so every TLS connection can be intercepted silently.",
        "Remove the flag and configure a CA pool; pin certificates only for fixed internal endpoints.",
        "CWE-297",
        "OWASP ASVS V9",
        frozenset({".go"}),
    ),
    Rule(
        "SP089",
        "Request data logged without sanitization",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""log\.(?:Print|Printf|Println|Fatal|Fatalf)\s*\([^)]*(?:r\.URL\.Query|FormValue|GetHeader)"""
        ),
        "Logging raw request values lets attackers forge log entries with CRLF payloads and pollutes forensics with untrusted text.",
        "Log bounded, sanitized fields and keep raw request dumps behind structured debug flags.",
        "CWE-117",
        "OWASP ASVS V14",
        frozenset({".go"}),
    ),
    Rule(
        "SP090",
        "Hardcoded default password parameter",
        "security",
        "high",
        "medium",
        compile_pattern(r"""def \w+\([^)]*\b(?:password|passwd|pwd)\s*=\s*["'][^"']{4,}["']"""),
        "A default password literal ships the credential to every deployment of this code.",
        "Make the password a required argument or load it from configuration; rotate any committed value.",
        "CWE-259",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP091",
        "Outbound HTTP request over cleartext",
        "security",
        "high",
        "medium",
        compile_pattern(r"""http\.(?:Get|Post|Head)\s*\(\s*"http://"""),
        "http.Get/Post/Head over http:// transmits headers, query strings, and bodies unencrypted.",
        "Use https:// endpoints and verify certificates; document any intentional local exception.",
        "CWE-319",
        "OWASP ASVS V9",
        frozenset({".go"}),
    ),
    Rule(
        "SP002",
        "AWS access key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\bAKIA[0-9A-Z]{16}\b"""),
        "An AWS access key ID appears in source control.",
        "Disable and rotate the credential, inspect access logs, and purge it from history.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset(set()),
        redact=True,
    ),
    Rule(
        "SP003",
        "Credential-like value committed",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?<![A-Za-z0-9_])["']?(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)["']?\s*[:=]\s*["'][^"'\s]{16,}["']"""
        ),
        "A credential-like value is assigned directly in a file.",
        "Confirm it is real, then rotate it and load the replacement from an approved secret store.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset(set()),
        redact=True,
    ),
    Rule(
        "SP004",
        "Insecure secret fallback default",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:(?:os\.(?:environ\.)?get|getenv)\s*\(\s*["'][A-Za-z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|AUTH|PRIVATE)[A-Za-z0-9_]*["']\s*,\s*["'][^"'\s]+["']|process\.env\.[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|AUTH|PRIVATE)[A-Z0-9_]*\s*\|\|\s*["'][^"'\s]+["'])"""
        ),
        "A hardcoded fallback default is provided for an environment secret.",
        "Remove the hardcoded fallback string; require explicit environment configuration.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset(set()),
        redact=True,
    ),
    Rule(
        "SP005",
        "GCP service account private key committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r""""type"\s*:\s*"service_account"[^\n\r]*"private_key"\s*:\s*"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"""
        ),
        "A Google Cloud service account private key appears in source control.",
        "Revoke the service account key, purge it from git history, and use Workload Identity Federation.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset({".json"}),
        redact=True,
    ),
    Rule(
        "SP006",
        "GitHub access token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"""),
        "A GitHub Personal Access Token appears in source control.",
        "Revoke the token immediately, purge it from history, and load credentials from approved secret stores.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP007",
        "AWS session token or secret key committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:aws_secret_access_key|aws_session_token)\s*[:=]\s*["'][A-Za-z0-9/+=]{40,}["']"""
        ),
        "An AWS secret access key or session token is assigned directly in code.",
        "Rotate the secret key in AWS IAM and load temporary credentials via IAM roles or instance profiles.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP008",
        "Slack bot token or webhook committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:xoxb-[0-9]{11,}-[0-9]{11,}-[a-zA-Z0-9]{24}|xoxp-[0-9]{11,}-[0-9]{11,}-[a-zA-Z0-9]{24}|https://hooks\.slack\.com/services/T[A-Z0-9_]+/B[A-Z0-9_]+/[A-Za-z0-9_]+)\b"""
        ),
        "A Slack OAuth bot token or incoming webhook URL appears directly in source code.",
        "Revoke the Slack token/webhook in the Slack API dashboard and store it in environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP009",
        "Stripe live secret key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\b(?:sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})\b"""),
        "A Stripe live secret or restricted key is hardcoded in source control.",
        "Roll the API key immediately in the Stripe Dashboard and load it via secure secrets management.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP010",
        "OpenAI or Anthropic API key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\b(?:sk-[a-zA-Z0-9]{48}|sk-ant-api03-[a-zA-Z0-9_-]{80,})\b"""),
        "An OpenAI or Anthropic production API key is embedded in code.",
        "Revoke the API key in the provider console and inject it at runtime via environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP011",
        "SendGrid or Twilio API key committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}|AC[a-f0-9]{32}\b.*["'][a-f0-9]{32}["'])\b"""
        ),
        "A SendGrid API key or Twilio Account SID and auth token are hardcoded in source files.",
        "Revoke the credentials in the provider console and configure environment-based secret loading.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP012",
        "Mailgun or Postmark API token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\b(?:key-[0-9a-zA-Z]{32}|pm_server_[0-9a-zA-Z]{32})\b"""),
        "A Mailgun API key or Postmark server token is present in source control.",
        "Revoke the server token in the Mailgun/Postmark console and store it in secrets manager.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP013",
        "Discord bot token or webhook committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+|Bot\s+[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b"""
        ),
        "A Discord bot token or webhook URL is hardcoded in source control.",
        "Regenerate the Discord webhook or bot token and store it securely in environment secrets.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP014",
        "Square or PayPal credentials committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:sq0atp-[0-9A-Za-z_-]{22}|access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b"""
        ),
        "Square or PayPal production access tokens appear directly in code.",
        "Revoke the production credentials in the merchant dashboard immediately.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP015",
        "HuggingFace or Replicate token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\b(?:hf_[a-zA-Z0-9]{34}|r8_[a-zA-Z0-9]{32})\b"""),
        "A HuggingFace or Replicate inference API token is hardcoded in source files.",
        "Revoke the token in account settings and store replacement tokens in environment configuration.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP016",
        "Hardcoded Bearer JWT token",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""\bBearer\s+eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"""
        ),
        "A hardcoded JWT Bearer token is assigned or passed directly in source code.",
        "Remove static JWT strings; generate tokens dynamically or pass credentials via secure headers.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP017",
        "Package registry publish token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\b(?:npm_[A-Za-z0-9]{36}|pypi-AgEIcHlwaS5vcm[A-Za-z0-9_-]{50,})\b"""),
        "An NPM or PyPI package upload token appears in source control.",
        "Revoke the publish token immediately to prevent supply chain poisoning of your published packages.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP018",
        "Kubernetes service account token committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\beyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"""
        ),
        "A Kubernetes service account JWT token appears in source files.",
        "Revoke the service account token in Kubernetes and use pod service account mounting.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP019",
        "Database connection string with password",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""\b(?:postgres|postgresql|mysql|mariadb)://[a-zA-Z0-9_]+:[^@\s/]{3,}@[a-zA-Z0-9_.-]+(?::[0-9]+)?/[a-zA-Z0-9_.-]+"""
        ),
        "A database connection URL contains embedded plaintext credentials.",
        "Extract the password and host into environment variables (e.g. DATABASE_URL).",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP020",
        "Redis connection URI with password",
        "security",
        "high",
        "medium",
        compile_pattern(r"""\bredis(?:s)?://(?:[^:@\s]+:)?([^@\s]{3,})@[a-zA-Z0-9_.-]+:[0-9]+"""),
        "A Redis connection URI contains an embedded password.",
        "Load the Redis password from an environment secret rather than hardcoding in connection strings.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP021",
        "MongoDB connection string with password",
        "security",
        "high",
        "medium",
        compile_pattern(r"""\bmongodb(?:\+srv)?://[a-zA-Z0-9_.-]+:[^@\s/]{3,}@[a-zA-Z0-9_.-]+"""),
        "A MongoDB connection string contains plaintext credentials.",
        "Extract username and password into environment variables and connect via secret configuration.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP022",
        "Cloudflare API token committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:CLOUDFLARE_API_KEY|CLOUDFLARE_TOKEN)\s*[:=]\s*["'][a-zA-Z0-9_-]{40}["']"""
        ),
        "A Cloudflare API token or global key is assigned directly in code.",
        "Revoke the Cloudflare API token in the dashboard and restrict token permissions to specific zones.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP023",
        "Datadog or New Relic key committed",
        "security",
        "high",
        "high",
        compile_pattern(r"""\b(?:ddp_[a-zA-Z0-9]{32}|NRAK-[A-Za-z0-9]{27})\b"""),
        "A Datadog API key or New Relic user API key appears in source files.",
        "Rotate the monitoring key in the vendor portal and load it via agent configuration secrets.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP024",
        "Sentry auth token or secret DSN committed",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""\b(?:sntrys_[a-zA-Z0-9]{64}|https://[a-f0-9]{32}:[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+)\b"""
        ),
        "A Sentry authentication token or legacy secret DSN is committed in source.",
        "Revoke the Sentry token and use modern public DSNs without embedded private keys.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP025",
        "Hardcoded encryption passphrase or static salt",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:private_key_pass(?:phrase)?|encryption_key|master_salt)\s*[:=]\s*["'][^"'\s]{8,}["']"""
        ),
        "A private key passphrase, master encryption key, or static crypto salt is hardcoded.",
        "Remove hardcoded passphrases and generate dynamic salts or inject keys from a Key Management Service (KMS).",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP026",
        "Anthropic API key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""sk-ant-api03-[A-Za-z0-9_-]{80,110}"""),
        "An Anthropic Claude API key is committed in source code.",
        "Revoke and rotate the key via Anthropic console, and load it from environment variables or secrets manager.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP027",
        "Hugging Face user access token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""hf_[A-Za-z0-9]{34,40}"""),
        "A Hugging Face access token appears in source code.",
        "Revoke and rotate the token on Hugging Face settings, and use secrets management.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP028",
        "Pinecone API key committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""pcsk_[A-Za-z0-9_]{40,60}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}#pinecone"""
        ),
        "A Pinecone vector database API key appears in source code.",
        "Rotate the API key in Pinecone dashboard and load from PINECONE_API_KEY environment variable.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP029",
        "Cohere API key committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:cohere_api_key|cohere_key|COHERE_API_KEY)\s*[:=]\s*['"][A-Za-z0-9]{40}['"]"""
        ),
        "A Cohere AI API key appears in source code.",
        "Revoke and rotate the Cohere key and store in environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP030",
        "Datadog API or application key committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:dd_api_key|datadog_api_key|DD_API_KEY)\s*[:=]\s*['"][a-f0-9]{32}['"]"""
        ),
        "A Datadog API key is hardcoded in source code.",
        "Rotate the Datadog API key in organization settings and load via secrets manager.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP031",
        "New Relic license or ingest key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""NRAK-[A-Za-z0-9]{27}|NRII-[A-Za-z0-9]{32}"""),
        "A New Relic license or user API key appears in source code.",
        "Rotate the New Relic key in API keys manager and use environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP032",
        "Sentry DSN authentication token committed",
        "security",
        "high",
        "high",
        compile_pattern(r"""sntrys_[a-f0-9]{64}"""),
        "A Sentry organization authentication token is committed in source code.",
        "Revoke the auth token in Sentry settings and use environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP033",
        "Postman API key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""PMAK-[A-Za-z0-9]{56,64}"""),
        "A Postman API key appears in source code.",
        "Revoke the key in Postman account settings and load from environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP034",
        "Shopify access token or private app secret committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""shpat_[a-f0-9]{32}|shpca_[a-f0-9]{32}|shppa_[a-f0-9]{32}"""),
        "A Shopify admin access token is hardcoded in source control.",
        "Revoke the custom app token in Shopify admin and load via secrets manager.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP035",
        "Square OAuth or access token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""sq0atp-[A-Za-z0-9_-]{22}|sq0csp-[A-Za-z0-9_-]{43}"""),
        "A Square production access token appears in source code.",
        "Revoke the access token in Square developer dashboard and inject through secrets.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP036",
        "Algolia admin API key committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:algolia_admin_key|ALGOLIA_ADMIN_KEY|algolia_api_key)\s*[:=]\s*['"][a-f0-9]{32}['"]"""
        ),
        "An Algolia admin API key with full index write permissions is committed.",
        "Rotate the admin key in Algolia dashboard and only use search-only keys in client code.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP037",
        "Vault root or client token committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:hvs\.[A-Za-z0-9_-]{24,}|hvb\.[A-Za-z0-9_-]{24,}|(?:vault_token|VAULT_TOKEN)\s*[:=]\s*['"][A-Za-z0-9._-]{20,40}['"])"""
        ),
        "A HashiCorp Vault token is hardcoded in source code.",
        "Revoke the token with `vault token revoke` and use AppRole or Kubernetes auth methods.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP038",
        "Pulumi access token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""pul-[a-f0-9]{40}"""),
        "A Pulumi service access token appears in source code.",
        "Revoke the access token in Pulumi Console and use PULUMI_ACCESS_TOKEN in CI.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP039",
        "Grafana service account or API token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}|eyJrIjoi[A-Za-z0-9_-]{60,80}"""),
        "A Grafana service account token or API key is committed in source control.",
        "Delete the service account token in Grafana security settings and inject at runtime.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP040",
        "Discord bot token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}"""),
        "A Discord bot authentication token appears in source code.",
        "Reset the bot token in Discord Developer Portal and store in DISCORD_TOKEN environment variable.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP041",
        "Telegram bot API token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b"""),
        "A Telegram Bot API token is committed in source code.",
        "Revoke the token via @BotFather on Telegram and load via environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP042",
        "Slack incoming webhook URL committed",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}"""
        ),
        "A Slack incoming webhook URL is hardcoded in source control.",
        "Delete the incoming webhook in Slack App configuration and configure via environment variable.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP043",
        "Linear personal access token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""lin_api_[A-Za-z0-9]{40}"""),
        "A Linear personal API key appears in source code.",
        "Revoke the key in Linear account settings and use LINEAR_API_KEY environment variable.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP044",
        "Notion internal integration token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""ntn_[0-9]{11,13}[A-Za-z0-9]{32,36}|secret_[A-Za-z0-9]{43}"""),
        "A Notion integration secret or API token appears in source code.",
        "Rotate the internal integration secret in Notion developers portal and use secrets manager.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP045",
        "Airtable personal access token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""pat[A-Za-z0-9]{14}\.[a-f0-9]{64}"""),
        "An Airtable personal access token is committed in source control.",
        "Revoke the token in Airtable builder hub and load from environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP046",
        "Resend API key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\bre_[A-Za-z0-9]{32,40}\b"""),
        "A Resend transactional email API key appears in source code.",
        "Rotate the key in Resend dashboard and inject through RESEND_API_KEY environment variable.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP047",
        "Twilio Account SID and Auth Token committed together",
        "security",
        "critical",
        "high",
        compile_pattern(r"""AC[a-f0-9]{32}[:\s]+[a-f0-9]{32}"""),
        "Twilio account SID and secret authentication token are committed together.",
        "Rotate the secondary auth token in Twilio Console and store credentials in environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP048",
        "Firebase service account JSON committed",
        "security",
        "critical",
        "high",
        compile_pattern(r""""type":\s*"service_account".*"private_key_id":"""),
        "A Firebase or Google Cloud service account private key file is committed in source code.",
        "Delete the service account key in GCP IAM console and use Workload Identity.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP049",
        "Age encryption identity secret key committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""AGE-SECRET-KEY-1[0-9A-Z]{58}"""),
        "An Age asymmetric identity secret key appears in source control.",
        "Revoke and rotate the key, re-encrypt recipients, and load private key from a secrets manager.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP050",
        "PyPI upload token committed",
        "security",
        "critical",
        "high",
        compile_pattern(r"""pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,100}"""),
        "A PyPI package publishing token is committed in source code.",
        "Revoke the token in PyPI account settings and use Trusted Publishing with OIDC.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP101",
        "Dynamic code execution",
        "security",
        "high",
        "medium",
        compile_pattern(r"""(?<![\w.])(?:eval|exec)\s*\("""),
        "Dynamic code execution can turn untrusted input into code execution.",
        "Remove dynamic evaluation or constrain input with a safe parser and strict allowlist.",
        "CWE-95",
        "OWASP ASVS V1",
        frozenset({".php", ".py", ".ts", ".rb", ".mjs", ".jsx", ".js", ".tsx", ".cjs"}),
    ),
    Rule(
        "SP102",
        "Shell execution enabled",
        "security",
        "high",
        "high",
        compile_pattern(r"""\bshell\s*=\s*(?:true|True)\b"""),
        "Shell interpretation expands command-injection exposure.",
        "Pass an argument array without a shell and validate every externally controlled argument.",
        "CWE-78",
        "OWASP ASVS V1",
        frozenset(set()),
    ),
    Rule(
        "SP103",
        "SQL built with interpolation",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:execute|query|raw)\s*\(\s*(?:f["']|\$["'][^"']*\{|`[^`]*\$\{|["'][^"']*["']\s*%|[^,\x0a]{0,512}\.format\(|["'][^"']*["']\s*\+\s*(?:[A-Za-z_$]|["']))"""
        ),
        "A database query appears to be built with string interpolation.",
        "Use parameterized queries or the ORM's bound parameters and add an injection regression test.",
        "CWE-89",
        "OWASP ASVS V1",
        frozenset(set()),
    ),
    Rule(
        "SP104",
        "TLS verification disabled",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:\b(?:verify|rejectUnauthorized)\s*[:=]\s*(?:false|False)\b|\bbadCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true\b|\bServerCertificateCustomValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true\b|\bServerCertificateCustomValidationCallback\s*=\s*HttpClientHandler\.DangerousAcceptAnyServerCertificateValidator\b)"""
        ),
        "TLS peer verification is explicitly disabled.",
        "Restore certificate verification and configure the correct trust chain.",
        "CWE-295",
        "OWASP ASVS V12",
        frozenset(set()),
    ),
    Rule(
        "SP105",
        "JWT signature verification disabled",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:verify_signature["']?\s*[:=]\s*(?:false|False)|algorithms?\s*[:=]\s*\[["']none["']\])"""
        ),
        "JWT signature verification appears disabled.",
        "Require an allowlisted algorithm, issuer, audience, expiry, and a verified signature.",
        "CWE-347",
        "OWASP ASVS V6",
        frozenset(set()),
    ),
    Rule(
        "SP106",
        "Unsafe deserialization",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""\b(?:pickle\.loads?|yaml\.load|Marshal\.(?:load|restore)|YAML\.(?:unsafe_load|load_stream))\s*\("""
        ),
        "Unsafe deserialization can execute attacker-controlled behavior.",
        "Use a safe data format; for YAML use safe_load and constrain accepted types.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".pyi", ".rb", ".py"}),
    ),
    Rule(
        "SP107",
        "Credentialed wildcard CORS",
        "security",
        "high",
        "high",
        compile_pattern(r"""$^"""),
        "Wildcard origins and credentials create an unsafe cross-origin policy.",
        "Allowlist exact trusted origins and test preflight behavior.",
        "CWE-942",
        "OWASP ASVS V3",
        frozenset(set()),
    ),
    Rule(
        "SP108",
        "Sensitive route lacks visible authorization",
        "security",
        "high",
        "medium",
        compile_pattern(r"""$^"""),
        "An admin or internal route has no visible authorization dependency.",
        "Require an explicit authorization dependency or verify and document an application-wide control.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".py", ".js", ".mjs", ".cjs", ".ts"}),
    ),
    Rule(
        "SP109",
        "SSRF to internal network or metadata",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:(?:get|post|put|delete|request|head)\s*\(\s*["'`]https?://(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost)|(?:requests|httpx|fetch|axios|http)\.(?:get|post|put|delete|request)\s*\(\s*(?:req\.query|request\.args|req\.body|user_url|user_input)\b|(?:httpClient|_?client)\.(?:GetAsync|GetStringAsync|PostAsync|SendAsync)\s*\(\s*(?:Request|request)\.(?:Query|Form|Headers)\b|\bnew\s+HttpRequestMessage\s*\([^,]+,\s*(?:Request|request)\.(?:Query|Form|Headers)\b)"""
        ),
        "An outbound HTTP request may target internal endpoints, localhost, or cloud metadata.",
        "Validate destination URLs against an allowlist and block private IP ranges.",
        "CWE-918",
        "OWASP ASVS V5",
        frozenset(set()),
    ),
    Rule(
        "SP110",
        "Path traversal in file path",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:(?<![\w.$])open\s*\(\s*(?:f["'][^"']*\{|`[^`]*\$\{)|(?:fs\.)?(?:readFile|readFileSync|writeFileSync|createReadStream|unlink|rmSync)\s*\(\s*`[^`]*\$\{|(?<![\w.])(?:(?:os\.)?path\.)?join\s*\([^)]*(?:req\.|params|query|user_input)|(?:Path|path)\.Combine\s*\([^)]*(?:Request|request|Query|Form|Route))"""
        ),
        "A filesystem operation constructs paths directly from variables without visible normalization.",
        "Normalize with realpath/resolve and verify the path remains inside the base directory.",
        "CWE-22",
        "OWASP ASVS V5",
        frozenset(set()),
    ),
    Rule(
        "SP111",
        "Zip-Slip unsafe archive extraction",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""\b(?:zip_file|zip_ref|archive|tar|tar_file|zipfile|tarfile)\b[^\n]*\.\s*extractall\s*\("""
        ),
        "Unsanitized archive extraction without path containment validation allows arbitrary file overwrites.",
        "Validate that every extracted member path resolves within the target destination directory.",
        "CWE-22",
        "OWASP ASVS V5",
        frozenset({".js", ".py", ".java", ".ts", ".go"}),
    ),
    Rule(
        "SP112",
        "Unsanitized SVG upload accepted",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:accept\s*[:=]\s*["'][^"']*image/svg\+xml|\.svg["']\s*,\s*["']\.(?:png|jpe?g)|allowedExtensions\s*[:=]\s*\[[^\]]*["']\.?svg["'])"""
        ),
        "User file upload allows SVG files without visible sanitization, exposing users to Stored XSS.",
        "Sanitize uploaded SVGs with an XML sanitizer, serve with Content-Disposition: attachment, or convert to PNG.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset(set()),
    ),
    Rule(
        "SP113",
        "PHP object injection via unserialize",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\bunserialize\s*\(\s*(?:\$_(?:GET|POST|COOKIE|REQUEST|SERVER)|[\$a-zA-Z0-9_]+)"""
        ),
        "unserialize() on untrusted input allows object injection and arbitrary code execution.",
        "Replace unserialize() with json_decode() or use an allowlisted, signature-verified parser.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP114",
        "Catastrophic ReDoS nested quantifier",
        "security",
        "medium",
        "medium",
        compile_pattern(r"""\([a-zA-Z0-9_\.\-\^\$]+(?:\+|\*)\)(?:\+|\*)"""),
        "Nested quantifiers in regular expressions can cause exponential backtracking (ReDoS) and freeze event loops.",
        "Rewrite the regular expression without nested quantifiers or use an atomic group / non-backtracking regex.",
        "CWE-1333",
        "OWASP ASVS V5",
        frozenset(set()),
    ),
    Rule(
        "SP115",
        "XXE-capable lxml parser without entity hardening",
        "security",
        "medium",
        "low",
        compile_pattern(r"""$^"""),
        "lxml parsing is used without a parser that disables entity resolution, enabling XML external entity attacks.",
        "Construct an etree.XMLParser with resolve_entities=False (and no_network=True) or validate input before parsing.",
        "CWE-611",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP116",
        "React dangerouslySetInnerHTML with dynamic value",
        "security",
        "high",
        "medium",
        compile_pattern(r"""dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*[^"'\s}]"""),
        "dangerouslySetInnerHTML renders a dynamic value as raw HTML, which becomes XSS when the value carries user input.",
        "Render text normally, or sanitize the HTML with DOMPurify before assigning it to __html.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".jsx", ".cjs"}),
    ),
    Rule(
        "SP117",
        "Dynamic code via new Function",
        "security",
        "high",
        "medium",
        compile_pattern(r"""\bnew\s+Function\s*\("""),
        "new Function() compiles a string into executable code, turning untrusted input into arbitrary code execution.",
        "Replace dynamic compilation with explicit logic or a safe parser (e.g. JSON.parse).",
        "CWE-95",
        "OWASP ASVS V5",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".jsx", ".cjs"}),
    ),
    Rule(
        "SP118",
        "Implicit eval via timer string",
        "security",
        "medium",
        "high",
        compile_pattern(r"""\b(?:setTimeout|setInterval)\s*\(\s*["'`]"""),
        "A string passed to setTimeout/setInterval is compiled and executed as code, allowing injection.",
        "Pass a function reference instead of a string of code.",
        "CWE-95",
        "OWASP ASVS V5",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".jsx", ".cjs"}),
    ),
    Rule(
        "SP119",
        "Filesystem path joined from request input",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""path\s*\.\s*join(?:Sync)?\s*\([^)]*\breq\s*\.\s*(?:params|query|body)"""
        ),
        "A filesystem path is joined directly from request data, allowing path traversal outside the intended directory.",
        "Validate the request value against an allowlist and resolve the final path inside a fixed base directory.",
        "CWE-22",
        "OWASP ASVS V5",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".jsx", ".cjs"}),
    ),
    Rule(
        "SP120",
        "Unsafe JS deserialization via node-serialize",
        "security",
        "critical",
        "high",
        compile_pattern(r"""$^"""),
        "node-serialize unserialize() executes arbitrary code embedded in the serialized payload.",
        "Exchange JSON instead of serialized JavaScript objects and reject serialized input entirely.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".jsx", ".cjs"}),
    ),
    Rule(
        "SP121",
        "Open redirect from request value",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:redirect(?:Permanent|PreserveMethod)?\s*\(\s*(?:req|request)\s*\.|Redirect(?:Permanent|PreserveMethod)?\s*\(\s*(?:Request|request)\.(?:Query|Form|Headers)\b|Results\.Redirect\s*\(\s*(?:Request|request)\.(?:Query|Form|Headers)\b)"""
        ),
        "A redirect target is taken directly from request input, enabling open-redirect phishing attacks.",
        "Redirect only to validated allowlisted paths or relative URLs.",
        "CWE-601",
        "OWASP ASVS V5",
        frozenset({".js", ".py", ".ts", ".mjs", ".jsx", ".cjs", ".cs"}),
    ),
    Rule(
        "SP122",
        "Security value from insecure randomness",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:token|secret|api[_-]?key|password|session\w*|otp|nonce|salt|csrf\w*)\s*[:=]\s*[^;#\n]*(?:Math\.random\s*\(|\brandom\.(?:random|randint|choice|randrange|uniform)\s*\()"""
        ),
        "A security-sensitive value is generated from a predictable PRNG instead of a cryptographic source.",
        "Generate tokens and secrets with the Web Crypto API or the Python secrets module.",
        "CWE-338",
        "OWASP ASVS V6",
        frozenset(set()),
    ),
    Rule(
        "SP123",
        "Hardcoded initialization vector",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""createCipheriv\s*\([^()]*,[^()]*,\s*["'][A-Za-z0-9+/=]{8,}["']|AES\.new\s*\([^()]*,\s*[^(),]+,\s*iv\s*=\s*b?["'][A-Za-z0-9+/=]{8,}["']"""
        ),
        "A cipher is used with a hardcoded initialization vector, which defeats CBC/CTR semantic security.",
        "Generate a random IV per message with a cryptographic source and transmit it alongside the ciphertext.",
        "CWE-329",
        "OWASP ASVS V8",
        frozenset(set()),
    ),
    Rule(
        "SP124",
        "SSRF via user-controlled request URL",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:\bfetch\s*\(|\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\()\s*[^)]*\breq\s*\.\s*(?:query|params|body)"""
        ),
        "An outbound HTTP call uses a URL taken from request input, allowing SSRF against internal networks and cloud metadata.",
        "Validate target URLs against an explicit host allowlist and reject private IP ranges.",
        "CWE-918",
        "OWASP ASVS V5",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".jsx", ".cjs"}),
    ),
    Rule(
        "SP125",
        "Angular sanitizer bypass",
        "security",
        "high",
        "medium",
        compile_pattern(r"""bypassSecurityTrust(?:Html|Style|Url|ResourceUrl|Script)"""),
        "A DomSanitizer bypass method trusts user-influenced content that Angular would otherwise escape.",
        "Remove the bypass or sanitize the value first; never trust raw user content with these methods.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".jsx", ".cjs"}),
    ),
    Rule(
        "SP126",
        "Auth token stored in web storage",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*["'][^"']*(?:token|auth|jwt|secret|session)"""
        ),
        "An authentication token is stored in web storage, readable by any injected script.",
        "Keep tokens in httpOnly cookies or in-memory stores; web storage is script-accessible.",
        "CWE-922",
        "OWASP ASVS V3",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".jsx", ".cjs"}),
    ),
    Rule(
        "SP127",
        "PHP loose comparison on credential",
        "security",
        "high",
        "medium",
        compile_pattern(r"""\$(?:password|passwd|secret|token|api[_-]?key)\w*\s*==(?!=)"""),
        "PHP type juggling can make loose comparisons behave unexpectedly when validating credentials.",
        "Use === or password_verify for credential checks.",
        "CWE-480",
        "OWASP ASVS V2",
        frozenset({".php"}),
    ),
    Rule(
        "SP128",
        "PHP SQL with interpolated variables",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:mysqli?_query|->query|->exec|->prepare)\s*\([^)]*\$_(?:GET|POST|REQUEST)|["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\$[a-zA-Z_]"""
        ),
        "A PHP database call interpolates variables or superglobals into the SQL text.",
        "Use prepared statements with bound parameters.",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP129",
        "PHP reflected XSS via echoed superglobal",
        "security",
        "high",
        "medium",
        compile_pattern(r"""(?:echo|print)\s+\$_(?:GET|POST|REQUEST)\s*\["""),
        "Request data is echoed without htmlspecialchars, reflecting attacker-controlled HTML.",
        "Escape output with htmlspecialchars or render through a template engine.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP130",
        "PHP open redirect via Location header",
        "security",
        "medium",
        "medium",
        compile_pattern(r"""header\s*\(\s*["']Location\s*:[^)]*\$_(?:GET|POST|REQUEST)"""),
        "The redirect target is built from request input, enabling phishing redirects.",
        "Redirect only to allowlisted absolute paths.",
        "CWE-601",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP131",
        "Go HTTP server without timeouts",
        "reliability",
        "medium",
        "low",
        compile_pattern(r"""$^"""),
        "An http.Server is configured without read/write timeouts, exposing the service to slow-client resource exhaustion.",
        "Set ReadTimeout, WriteTimeout, ReadHeaderTimeout, and IdleTimeout on every http.Server.",
        "CWE-1088",
        "OWASP ASVS V12",
        frozenset({".go"}),
    ),
    Rule(
        "SP132",
        ".NET sync-over-async blocking",
        "reliability",
        "medium",
        "low",
        compile_pattern(r"""GetAwaiter\s*\(\s*\)\s*\.\s*GetResult\s*\(|\.Wait\s*\(\s*\)"""),
        "Blocking on a Task in a context with a synchronization context deadlocks or starves threads.",
        "Go async all the way; use await instead of blocking on tasks.",
        "CWE-667",
        "OWASP ASVS V12",
        frozenset({".cs"}),
    ),
    Rule(
        "SP133",
        "ASP.NET debug compilation enabled",
        "security",
        "medium",
        "high",
        compile_pattern(r"""debug\s*=\s*["']true["']"""),
        "ASP.NET debug mode ships verbose errors and debugging behavior to production.",
        "Set debug to false and use release configuration transforms.",
        "CWE-489",
        "OWASP ASVS V14",
        frozenset({".config"}),
    ),
    Rule(
        "SP134",
        "Assertion used as authorization",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""assert\s+[^#\n]*(?:is_admin|is_superuser|has_role|has_permission|authorized|is_owner)"""
        ),
        "assert statements are stripped under python -O, silently removing the authorization check in production.",
        "Raise an explicit 403 through application logic instead of asserting access.",
        "CWE-863",
        "OWASP ASVS V4",
        frozenset({".py"}),
    ),
    Rule(
        "SP135",
        "Unbounded C string function",
        "security",
        "high",
        "high",
        compile_pattern(r"""\b(?:strcpy|strcat|sprintf|gets|stpcpy)\s*\("""),
        "A C string function with no bound check allows buffer overflow when input length is uncontrolled.",
        "Use bounded equivalents (strncpy/snprintf/strlcpy) or explicit length-checked copies.",
        "CWE-120",
        "OWASP ASVS V5",
        frozenset({".hpp", ".h", ".cpp", ".c"}),
    ),
    Rule(
        "SP136",
        "Go err value explicitly discarded (type unresolved)",
        "reliability",
        "medium",
        "low",
        compile_pattern(r"""\b_\s*=\s*err\b"""),
        "An err value is explicitly discarded; if it is an error, a failure may be ignored. Tuple arity alone does not establish an error return.",
        "Handle the error or annotate the discard with an explicit reason comment.",
        "CWE-754",
        "OWASP ASVS V7",
        frozenset({".go"}),
    ),
    Rule(
        "SP137",
        "Server-side template injection",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""\b(?:render_template_string|jinja2\.Template)\s*\(\s*(?:f["']|["'][^"']*%[s(]|[^,]+\.format\()"""
        ),
        "Server-side template rendering from dynamic string interpolation allows arbitrary code execution.",
        "Pass data as template context variables instead of embedding dynamic strings into template markup.",
        "CWE-1336",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP138",
        "Timing-attack vulnerable comparison",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""\b(?:signature|hmac|auth_tag|token_hash|expected_sig)\s*===?\s*[a-zA-Z0-9_]+|[a-zA-Z0-9_]+\s*===?\s*(?:signature|hmac|auth_tag|token_hash|expected_sig)\b"""
        ),
        "Non-constant-time comparison of cryptographic signatures or tokens leaks timing side-channels.",
        "Use constant-time comparison functions (hmac.compare_digest in Python, crypto.timingSafeEqual in Node.js).",
        "CWE-208",
        "OWASP ASVS V3",
    ),
    Rule(
        "SP139",
        "Insecure temporary file creation",
        "security",
        "high",
        "high",
        compile_pattern(r"""\btempfile\.mktemp\s*\("""),
        "mktemp creates temporary filenames without atomic file creation, risking symlink race conditions.",
        "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() to create temporary files atomically.",
        "CWE-377",
        "OWASP ASVS V5",
        frozenset({".pyi", ".py"}),
    ),
    Rule(
        "SP140",
        "Insecure cryptographic hash algorithm (MD5/SHA1)",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:hashlib\.(?:md5|sha1)\s*\(|crypto\.createHash\s*\(\s*["'](?:md5|sha1)["']|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1)["']|(?<![A-Za-z0-9_])(?:md5|sha1)\s*\()"""
        ),
        "MD5 or SHA1 is used for cryptographic operations, which are broken and collision-vulnerable.",
        "Use SHA-256, SHA-3, or Argon2id for password hashing.",
        "CWE-328",
        "OWASP ASVS V6",
    ),
    Rule(
        "SP141",
        "Weak PRNG seeded with timestamp",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:srand\s*\(\s*(?:time|getpid)\b|random\.seed\s*\(\s*(?:time\.time(?:\s*\(\s*\))?|int\s*\(\s*time(?:\.time(?:\s*\(\s*\))?)?\s*\)|None)?\s*\))"""
        ),
        "A pseudo-random number generator is seeded with predictable timestamp values.",
        "Use cryptographically secure PRNGs without manual timestamp seeding.",
        "CWE-337",
        "OWASP ASVS V3",
    ),
    Rule(
        "SP142",
        "AES cipher in ECB mode",
        "security",
        "high",
        "high",
        compile_pattern(r"""(?:AES\.MODE_ECB|["']AES/ECB/|["']aes-(?:128|192|256)-ecb["'])"""),
        "AES is configured in Electronic Codebook (ECB) mode, which leaks plaintext block patterns.",
        "Use authenticated encryption modes such as AES-GCM or ChaCha20-Poly1305 with random nonces.",
        "CWE-327",
        "OWASP ASVS V6",
    ),
    Rule(
        "SP143",
        "Static salt in password hashing",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:salt\s*[:=]\s*["'][a-zA-Z0-9$_.+/=]{6,}["']\s*;\s*(?:bcrypt|hashpw|crypt|pbkdf2)|bcrypt\.hashpw\([^,]+,\s*["'][a-zA-Z0-9$_.+/=]{10,}['"]|hashlib\.pbkdf2_hmac\([^,]+,[^,]+,\s*b?["'][^"'\s]+["'])"""
        ),
        "A static or hardcoded salt is used for password hashing across multiple records.",
        "Generate a unique, cryptographically random salt per user (e.g. bcrypt.gensalt()).",
        "CWE-916",
        "OWASP ASVS V6",
    ),
    Rule(
        "SP144",
        "JWT verification bypassed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:jwt\.decode\([^)]*options\s*=\s*\{[^}]*["']verify_signature["']\s*:\s*False|jwt\.verify\([^)]*verify\s*:\s*false)"""
        ),
        "JWT decoding is configured to bypass signature verification entirely.",
        "Enable signature verification and specify trusted public keys or HMAC secrets.",
        "CWE-347",
        "OWASP ASVS V3",
    ),
    Rule(
        "SP145",
        "Dynamic SQL execution via exec_sql",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:exec_sql|execute_query|run_sql|raw_sql)\s*\(\s*(?:f["']|["'][^"']*%[s(]|\`[^\`]*\$\{)"""
        ),
        "Dynamic SQL string execution function called with string-interpolated arguments.",
        "Use parameterized queries with bind variables.",
        "CWE-89",
        "OWASP ASVS V5",
    ),
    Rule(
        "SP146",
        "Direct execution via document.write",
        "security",
        "high",
        "medium",
        compile_pattern(r"""\bdocument\.write\s*\("""),
        "document.write() renders unsanitized input directly into the DOM, creating XSS vectors.",
        "Use textContent, createElement, or a sanitized templating system.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".js", ".html", ".tsx", ".ts", ".jsx"}),
    ),
    Rule(
        "SP147",
        "Unsanitized innerHTML assignment",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""\.(?:innerHTML|outerHTML)\s*=\s*(?![^;\n]*DOMPurify)[a-zA-Z0-9_.]+(?:\s*\+|\s*;)"""
        ),
        "element.innerHTML is assigned a dynamic variable without DOMPurify sanitization.",
        "Use textContent or sanitize dynamic HTML with DOMPurify.sanitize().",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP148",
        "JavaScript scheme URI in navigation link",
        "security",
        "high",
        "medium",
        compile_pattern(r"""(?:href|src|action|location)\s*[:=]\s*["']javascript:"""),
        "A javascript: URI scheme is used in link href or redirect targets, allowing code execution.",
        "Use standard HTTP(S) links and event listeners rather than javascript: pseudo-protocols.",
        "CWE-601",
        "OWASP ASVS V5",
    ),
    Rule(
        "SP149",
        "XML entity resolution enabled in standard parser",
        "security",
        "high",
        "medium",
        compile_pattern(r"""(?:xml\.dom\.minidom\.parse|xml\.sax\.make_parser)\s*\("""),
        "Standard XML parsers may resolve external entities if not defensively configured.",
        "Use defusedxml package to parse untrusted XML safely.",
        "CWE-611",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP150",
        "XSLT processing with extensions enabled",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:etree\.XSLT\([^)]*enable_extensions\s*=\s*True|XSLTProcessor\(\))"""
        ),
        "XSLT processing is configured with extension functions enabled, allowing arbitrary code execution.",
        "Disable extension functions in XSLT processors when parsing untrusted stylesheets.",
        "CWE-611",
        "OWASP ASVS V5",
        frozenset({".php", ".js", ".py", ".java", ".ts"}),
    ),
    Rule(
        "SP151",
        "Python subprocess execution with shell execution",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""subprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True"""
        ),
        "subprocess called with shell execution, allowing shell command injection.",
        "Pass commands as a list of arguments with shell=False.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP152",
        "Node child_process.exec with template string",
        "security",
        "high",
        "high",
        compile_pattern(r"""child_process\.exec\s*\(\s*\`[^\`]*\$\{"""),
        "child_process.exec called with a template literal string containing variable expressions.",
        "Use child_process.execFile() or child_process.spawn() with argument arrays.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".jsx", ".cjs"}),
    ),
    Rule(
        "SP153",
        "Insecure Ruby deserialization",
        "security",
        "critical",
        "high",
        compile_pattern(r"""(?:Marshal\.load|YAML\.unsafe_load)\s*\("""),
        "Ruby Marshal.load or YAML.unsafe_load called on untrusted data.",
        "Use JSON.parse or YAML.safe_load for untrusted data serialization.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".rb"}),
    ),
    Rule(
        "SP154",
        "Java insecure ObjectInputStream deserialization",
        "security",
        "critical",
        "high",
        compile_pattern(r"""new\s+ObjectInputStream\s*\([^)]*\)\.readObject\s*\("""),
        "Java ObjectInputStream.readObject() called without an ObjectInputFilter.",
        "Use Jackson JSON, Protocol Buffers, or configure explicit ObjectInputFilter allowlists.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".java", ".kt", ".kts"}),
    ),
    Rule(
        "SP155",
        "PHP dynamic evaluation via preg_replace /e",
        "security",
        "critical",
        "high",
        compile_pattern(r"""preg_replace\s*\(\s*["']/.*/[a-z]*e[a-z]*["']"""),
        "preg_replace called with the deprecated /e eval modifier, executing replacement text as PHP.",
        "Use preg_replace_callback() with a standard closure function.",
        "CWE-95",
        "OWASP ASVS V1",
        frozenset({".php"}),
    ),
    Rule(
        "SP156",
        "LDAP query constructed with string concatenation",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:ldap\.search|ldap_search)\s*\([^)]*(?:f["']|\`[^\`]*\$\{|["'].*\+\s*[a-zA-Z0-9_]+)"""
        ),
        "An LDAP search query is constructed by concatenating unsanitized variables.",
        "Use LDAP escape filters or parameterized LDAP APIs.",
        "CWE-90",
        "OWASP ASVS V5",
        frozenset({".php", ".js", ".py", ".java", ".ts", ".cs"}),
    ),
    Rule(
        "SP157",
        "XPath query constructed with string concatenation",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:xpath\.evaluate|xpath\.select|find_by_xpath)\s*\([^)]*(?:f["']|\`[^\`]*\$\{|["'].*\+\s*[a-zA-Z0-9_]+)"""
        ),
        "An XPath query is built with unescaped string concatenation.",
        "Use parameterized XPath expressions or variable bindings.",
        "CWE-643",
        "OWASP ASVS V5",
        frozenset({".php", ".js", ".py", ".java", ".ts", ".cs"}),
    ),
    Rule(
        "SP158",
        "Hardcoded HTTP Basic Authorization header",
        "security",
        "high",
        "high",
        compile_pattern(r"""["']Authorization["']\s*:\s*["']Basic\s+[A-Za-z0-9+/=]{8,}["']"""),
        "Hardcoded Basic Authorization credentials in HTTP client headers.",
        "Load credentials from environment variables and encode dynamically.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP159",
        "Cookie generated without Secure or HttpOnly flags",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:res\.cookie|set_cookie)\s*\([^)]*(?:httpOnly\s*:\s*false|secure\s*:\s*false|httponly\s*=\s*False|secure\s*=\s*False)"""
        ),
        "A cookie is explicitly created with httpOnly or secure set to false.",
        "Set httpOnly: true and secure: true on all session and auth cookies.",
        "CWE-1004",
        "OWASP ASVS V3",
        frozenset({".php", ".js", ".py", ".tsx", ".ts", ".rb", ".jsx"}),
    ),
    Rule(
        "SP160",
        "Session token passed in URL query parameters",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:https?://[^\s"']+\?(?:token|session_id|auth_token|api_key|access_token)=[a-zA-Z0-9-_]+)"""
        ),
        "Sensitive authentication tokens appear in URL query strings.",
        "Pass authentication tokens in Authorization headers or httpOnly cookies.",
        "CWE-598",
        "OWASP ASVS V3",
        redact=True,
    ),
    Rule(
        "SP161",
        "Mass assignment via unfiltered model update",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:\.update\(\*\*req\.|\.update\(request\.(?:POST|GET|data)|\.assignAttributes\(req\.body)"""
        ),
        "Unfiltered request body passed directly to ORM model update method.",
        "Use explicit schema validation (Pydantic / Zod / strong params) to allowlist modifiable fields.",
        "CWE-915",
        "OWASP ASVS V4",
        frozenset({".js", ".ts", ".rb", ".py"}),
    ),
    Rule(
        "SP162",
        "Hardcoded localhost or private IP in webhook target",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})(?::[0-9]+)?/webhook"""
        ),
        "A production webhook target URL is hardcoded to localhost or private network IP.",
        "Configure webhook destinations via environment variables.",
        "CWE-918",
        "OWASP ASVS V5",
    ),
    Rule(
        "SP163",
        "Bypassed SSL context with unverified context",
        "security",
        "high",
        "high",
        compile_pattern(r"""ssl\.unverified_context_creation\s*\("""),
        "unverified SSL context called, disabling certificate validation globally for urllib.",
        "Use ssl.create_default_context() with valid certificate authorities.",
        "CWE-295",
        "OWASP ASVS V9",
        frozenset({".py"}),
    ),
    Rule(
        "SP164",
        "Flask debug toolbar enabled in route setup",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:DebugToolbarExtension\s*\(|app\.config\[["']DEBUG_TB_ENABLED["']\]\s*=\s*True)"""
        ),
        "Flask Debug Toolbar is enabled, which can expose SQL query logs and execute commands.",
        "Disable Flask Debug Toolbar in production environments.",
        "CWE-489",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP165",
        "Django raw query with string interpolation",
        "security",
        "high",
        "high",
        compile_pattern(r"""\.raw\s*\(\s*(?:f["']|["'][^"']*["']\s*%|[^,]+\.format\()"""),
        "Django ORM raw() query constructed with dynamic string formatting instead of query parameters.",
        "Pass query parameters as a list argument to raw(query, [params]).",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP166",
        "Server framework fingerprinting header enabled",
        "security",
        "low",
        "low",
        compile_pattern(r"""(?:app\.use\([^)]*x-powered-by|header\s*\(\s*["']X-Powered-By["'])"""),
        "Server sends X-Powered-By header, revealing underlying technology stack versions.",
        "Disable X-Powered-By headers (e.g. app.disable('x-powered-by') in Express).",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".php"}),
    ),
    Rule(
        "SP167",
        "GraphQL unauthenticated introspection enabled",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:introspection\s*:\s*true\s*,\s*playground\s*:\s*true|graphqlHTTP\([^)]*graphiql\s*:\s*true)"""
        ),
        "GraphQL introspection and playground enabled without authentication.",
        "Disable introspection in production or require administrative authentication.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP168",
        "Sensitive credential passed in GET parameter",
        "security",
        "high",
        "medium",
        compile_pattern(r"""@app\.get\([^)]*(?:password|token|secret|client_secret)\s*:"""),
        "A GET route accepts sensitive credentials in URL query parameters.",
        "Use POST/PUT request bodies for authentication credentials.",
        "CWE-598",
        "OWASP ASVS V3",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP169",
        "Insecure file permissions set on created file",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""(?:os\.chmod\([^)]*0o?777|fs\.chmodSync\([^)]*0o?777|umask\s*\(\s*0\s*\))"""
        ),
        "Files created with world-writable permissions (chmod 0777) or permissive umask 0.",
        "Use restrictive file permissions such as 0600 (owner read/write) or 0700.",
        "CWE-732",
        "OWASP ASVS V14",
        frozenset({".js", ".py", ".c", ".ts", ".cpp", ".sh"}),
    ),
    Rule(
        "SP170",
        "Cleartext unencrypted protocol for external traffic",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""\b(?:ftp://[a-zA-Z0-9_.-]+:[^@\s/]+@|telnet://[a-zA-Z0-9_.-]+|http://api\.[a-zA-Z0-9_.-]+\.[a-z]{2,})"""
        ),
        "Cleartext unencrypted protocols (such as FTP with embedded credentials or HTTP for remote APIs) used for external traffic.",
        "Use encrypted protocols (SFTP, HTTPS, SSH) for external communications.",
        "CWE-319",
        "OWASP ASVS V9",
        redact=True,
    ),
    Rule(
        "SP171",
        "GraphQL unbounded query depth or complexity",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:graphql|ApolloServer|createYoga)\s*\([^\)]*validationRules\s*:\s*\[\s*\]"""
        ),
        "A GraphQL server is instantiated without query depth or complexity limiters, exposing the server to DoS.",
        "Add graphql-depth-limit or graphql-validation-complexity to validationRules.",
        "CWE-400",
        "OWASP ASVS V13",
        frozenset({".js", ".ts", ".mjs", ".py"}),
    ),
    Rule(
        "SP172",
        "MongoDB $where clause with string concatenation",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\$where\s*:\s*(?:['"][^'"]*[\$\+]|f['"])"""),
        "A MongoDB $where query executes arbitrary JavaScript with user-controlled input.",
        "Avoid $where clauses or use structured MongoDB query operators like $eq and $in.",
        "CWE-943",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP173",
        "LDAP query built by string concatenation",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:ldap\.search|ldap_search|DirectorySearcher)\s*\([^\)]*f['"]|\.search\s*\([^\)]*\+\s*user"""
        ),
        "An LDAP filter is constructed by string interpolation, enabling LDAP injection.",
        "Escape special LDAP characters or use parameterized directory search filters.",
        "CWE-90",
        "OWASP ASVS V5",
    ),
    Rule(
        "SP174",
        "XPath query built by string concatenation",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:xpath|selectNodes|evaluateXPath)\s*\([^\)]*f['"]|\.xpath\s*\([^\)]*\+\s*"""
        ),
        "An XPath expression is built using string concatenation, enabling XPath injection.",
        "Use parameterized XPath variables or safe XML navigation APIs.",
        "CWE-643",
        "OWASP ASVS V5",
    ),
    Rule(
        "SP175",
        "HTTP header injection via unvalidated CRLF characters",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:setHeader|appendHeader|add_header)\s*\([^\)]*[\r\n]|res\.set\s*\([^\)]*\+\s*req\."""
        ),
        "HTTP response headers are constructed with unsanitized user input containing potential newlines (CRLF).",
        "Strip CR (\\r) and LF (\\n) characters from header values before writing to response.",
        "CWE-113",
        "OWASP ASVS V5",
        frozenset({".js", ".py", ".java", ".ts", ".go"}),
    ),
    Rule(
        "SP176",
        "Prototype pollution via unsafe object merge",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:lodash\.merge|_\.merge|Object\.assign)\s*\(\s*\{\}\s*,\s*(?:req\.body|JSON\.parse)"""
        ),
        "Merging unvalidated request body directly into object targets may cause prototype pollution.",
        "Validate input against an explicit schema or freeze Object.prototype.",
        "CWE-1321",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP177",
        "Insecure window.postMessage with wildcard targetOrigin",
        "security",
        "high",
        "high",
        compile_pattern(r"""postMessage\s*\([^\)]*,\s*['"]\*['"]\s*\)"""),
        "postMessage is called with targetOrigin set to '*', which allows any malicious origin to intercept the payload.",
        "Specify the exact expected origin URL instead of wildcard '*' in targetOrigin parameter.",
        "CWE-345",
        "OWASP ASVS V14",
        frozenset({".js", ".html", ".tsx", ".ts", ".jsx"}),
    ),
    Rule(
        "SP178",
        "External script tag missing Subresource Integrity (SRI)",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""<script\s+[^>]*src=["']https?://(?:cdn|unpkg|cdnjs)[^"']*["'](?![^>]*integrity=)"""
        ),
        "An external script tag loads third-party CDN code without Subresource Integrity verification.",
        "Add integrity='sha384-...' and crossorigin='anonymous' attributes to external script tags.",
        "CWE-353",
        "OWASP ASVS V14",
        frozenset({".php", ".html", ".tsx", ".vue", ".jsx"}),
    ),
    Rule(
        "SP179",
        "Dynamic class instantiation from user input",
        "security",
        "critical",
        "high",
        compile_pattern(r"""Class\.forName\s*\(\s*(?:request|req\.getParameter|params\[)"""),
        "Class.forName dynamically loads a class specified by untrusted input, risking arbitrary code execution.",
        "Allowlist safe class names against an immutable lookup dictionary.",
        "CWE-470",
        "OWASP ASVS V5",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP180",
        "Frame inclusion allowed globally without frame-ancestors CSP",
        "security",
        "medium",
        "high",
        compile_pattern(r"""X-Frame-Options["']\s*,\s*["']ALLOWALL["']|frame-ancestors\s+\*"""),
        "The application explicitly allows clickjacking by permitting embedding inside arbitrary iframes.",
        "Set X-Frame-Options to DENY or SAMEORIGIN, and configure CSP frame-ancestors 'self'.",
        "CWE-1021",
        "OWASP ASVS V3",
    ),
    Rule(
        "SP181",
        "Django raw SQL query with f-string interpolation",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\.objects\.raw\s*\(\s*f['"]|\.raw\s*\(\s*f['"]"""),
        "Django Model.objects.raw() is called with an f-string instead of parameterized query arguments.",
        "Pass query parameters as a list: Model.objects.raw with query parameters.",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP182",
        "Spring Expression Language (SpEL) expression injection",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""SpelExpressionParser[^\)]*\.parseExpression\s*\(\s*(?:request|params|#\{)"""
        ),
        "User-controlled input is parsed directly as a Spring Expression Language (SpEL) expression.",
        "Do not evaluate untrusted input in SpEL expressions, or use a SimpleEvaluationContext.",
        "CWE-95",
        "OWASP ASVS V5",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP183",
        "Ruby ERB template rendering user string directly",
        "security",
        "critical",
        "high",
        compile_pattern(r"""ERB\.new\s*\(\s*(?:params\[|request\.|user_input)"""),
        "An ERB template is instantiated directly with user input, causing server-side template injection.",
        "Render static template files and pass user input only as template variables.",
        "CWE-1336",
        "OWASP ASVS V5",
        frozenset({".rb"}),
    ),
    Rule(
        "SP184",
        "PHP extract on untrusted input enabling variable overwrite",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"""),
        "Calling extract() on superglobal request arrays allows attackers to overwrite arbitrary local variables and bypass auth checks.",
        "Avoid extract() on request data; access parameters explicitly via $_GET or $_POST arrays.",
        "CWE-621",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP185",
        "PHP dangerous assert with string expression",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\bassert\s*\(\s*\$_(?:GET|POST|REQUEST)"""),
        "PHP assert() called with user-controlled string argument evaluates arbitrary PHP code.",
        "Disable assert string execution (zend.assertions = -1) or use strict boolean conditions.",
        "CWE-95",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP186",
        "Insecure .NET BinaryFormatter deserialization",
        "security",
        "critical",
        "high",
        compile_pattern(r"""BinaryFormatter[^\)]*\.Deserialize\s*\("""),
        "BinaryFormatter deserialization is fundamentally insecure and vulnerable to RCE gadget chains.",
        "Use System.Text.Json or XmlSerializer with explicit target types.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".cs"}),
    ),
    Rule(
        "SP187",
        "ASP.NET Request Validation explicitly disabled",
        "security",
        "high",
        "high",
        compile_pattern(r"""validateRequest\s*=\s*["']false["']|\[ValidateInput\(false\)\]"""),
        "ASP.NET built-in request validation is disabled, exposing handlers to unencoded XSS and injection payloads.",
        "Enable request validation and sanitize HTML inputs using an allowlisted HTML sanitizer.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".cs", ".config", ".aspx"}),
    ),
    Rule(
        "SP188",
        "Go html/template unescaped HTML type conversion",
        "security",
        "high",
        "high",
        compile_pattern(r"""template\.HTML\s*\(\s*(?:r\.FormValue|r\.URL|c\.Query|c\.Param)"""),
        "Converting untrusted user input directly to template.HTML bypasses Go's contextual XSS auto-escaping.",
        "Pass strings to templates as plain strings so html/template auto-escapes them safely.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".go"}),
    ),
    Rule(
        "SP189",
        "WebSocket server accepting arbitrary origin without check",
        "security",
        "high",
        "high",
        compile_pattern(r"""CheckOrigin\s*:\s*func\([^)]*\)\s*bool\s*\{\s*return\s+true"""),
        "A Go WebSocket upgrader accepts all incoming origins unconditionally, enabling Cross-Site WebSocket Hijacking.",
        "Validate the Origin header against an allowlist of trusted domain names.",
        "CWE-346",
        "OWASP ASVS V3",
        frozenset({".go"}),
    ),
    Rule(
        "SP190",
        "CORS policy reflecting null origin",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""Access-Control-Allow-Origin["']\s*,\s*["']null["']|origin\s*:\s*['"]null['"]"""
        ),
        "CORS policy reflects 'null' origin, which sandboxed iframes and local files can exploit to bypass SOP.",
        "Never allow 'null' origin in CORS configuration; specify exact trusted origins.",
        "CWE-942",
        "OWASP ASVS V3",
    ),
    Rule(
        "SP191",
        "Insecure cookie SameSite None without Secure flag",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""SameSite\s*=\s*None(?![^;]*Secure)|sameSite\s*:\s*['"]none['"]\s*,\s*secure\s*:\s*false"""
        ),
        "A cookie is configured with SameSite None without the required Secure flag, causing browsers to reject or leak it.",
        "Always set Secure=true whenever SameSite None is specified.",
        "CWE-614",
        "OWASP ASVS V3",
        frozenset({".php", ".js", ".py", ".java", ".ts", ".go"}),
    ),
    Rule(
        "SP192",
        "OAuth 2.0 PKCE code_challenge verification omitted",
        "security",
        "high",
        "high",
        compile_pattern(r"""code_challenge_method\s*:\s*['"]plain['"]|pkce\s*:\s*false"""),
        "OAuth authentication uses plain code_challenge or disables PKCE, leaving public clients vulnerable to auth code interception.",
        "Enforce PKCE with code_challenge_method='S256' for all OAuth authorization flows.",
        "CWE-347",
        "OWASP ASVS V3",
    ),
    Rule(
        "SP193",
        "OpenID Connect authentication nonce verification skipped",
        "security",
        "high",
        "high",
        compile_pattern(r"""verifyNonce\s*:\s*false|ignoreNonce\s*:\s*true"""),
        "OpenID Connect ID token verification skips nonce validation, making the login flow vulnerable to replay attacks.",
        "Generate cryptographic nonce in authorization request and verify matching claim in ID token.",
        "CWE-347",
        "OWASP ASVS V3",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP194",
        "SAML response assertion signature verification disabled",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""wantAssertionsSigned\s*:\s*false|wantAuthnResponseSigned\s*:\s*false"""
        ),
        "SAML SSO configuration disables assertion signature verification, allowing attackers to forge identity claims.",
        "Set wantAssertionsSigned: true and validate the IDP X.509 certificate on every SAML assertion.",
        "CWE-347",
        "OWASP ASVS V3",
    ),
    Rule(
        "SP195",
        "Insecure gRPC channel created without transport security",
        "security",
        "high",
        "high",
        compile_pattern(r"""grpc\.insecure_channel\s*\(|grpc\.WithInsecure\s*\(\)"""),
        "A gRPC client creates an insecure, unencrypted channel over the network.",
        "Use grpc.ssl_channel_credentials() or credentials.NewClientTLSFromCert() for production traffic.",
        "CWE-319",
        "OWASP ASVS V9",
        frozenset({".js", ".ts", ".go", ".py"}),
    ),
    Rule(
        "SP196",
        "Redis connection without TLS encryption",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""redis:\/\/(?![^:]*:\/\/[^@]*@127\.0\.0\.1|[^:]*:\/\/[^@]*@localhost)[^\s"']+:\d{4,5}(?!\?ssl=true|\?tls=true)"""
        ),
        "A remote Redis instance connection URL does not specify rediss:// or SSL/TLS parameters.",
        "Use rediss:// URL scheme and enable TLS certificates for remote managed Redis instances.",
        "CWE-319",
        "OWASP ASVS V9",
    ),
    Rule(
        "SP197",
        "Elasticsearch query constructed with raw JSON string interpolation",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:es\.search|client\.search)\s*\([^\)]*body\s*:\s*f['"]|\.search\s*\([^\)]*f['"]\{"""
        ),
        "Elasticsearch query DSL is assembled with f-strings instead of structured query dictionaries, risking injection.",
        "Use structured query dicts or bodybuilder libraries to build Elasticsearch queries safely.",
        "CWE-943",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP198",
        "Mongoose mass assignment from raw request body",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:Model|User|Account)\.create\s*\(\s*req\.body\s*\)|new\s+(?:User|Account)\s*\(\s*req\.body\s*\)"""
        ),
        "Mongoose model is created directly with entire req.body without field filtering, allowing privilege escalation.",
        "Extract only allowed fields explicitly or use schema-level picking (e.g. _.pick(req.body, ['name', 'email'])).",
        "CWE-915",
        "OWASP ASVS V5",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP199",
        "Sequelize mass update with unconstrained request body",
        "security",
        "high",
        "high",
        compile_pattern(r"""\.update\s*\(\s*req\.body\s*,\s*\{"""),
        "Sequelize update receives req.body directly without 'fields' option allowlist, risking mass assignment.",
        "Specify allowed fields in update options: { fields: ['name', 'bio'], where: ... }.",
        "CWE-915",
        "OWASP ASVS V5",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP200",
        "TypeORM repository save with unsanitized request body",
        "security",
        "high",
        "high",
        compile_pattern(r"""\.save\s*\(\s*req\.body\s*\)|\.preload\s*\(\s*req\.body\s*\)"""),
        "TypeORM entity is populated directly from raw request body without DTO validation and property whitelist.",
        "Use class-validator with plainToInstance and forbidNonWhitelisted: true before repository operations.",
        "CWE-915",
        "OWASP ASVS V5",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP201",
        "Debug mode enabled",
        "security",
        "high",
        "high",
        compile_pattern(r"""[(,]\s*(?:debug|DEBUG)\s*[:=]\s*(?:true|True|1)\b"""),
        "Debug mode may expose internals or interactive execution in production.",
        "Make production fail closed and enable debug only in an explicit local environment.",
        "CWE-489",
        "OWASP ASVS V13",
        frozenset(set()),
    ),
    Rule(
        "SP202",
        "Floating container base image",
        "supply-chain",
        "medium",
        "high",
        compile_pattern(
            r"""^\s*FROM\s+(?:(?:--platform=\S+)\s+)?(?!\S+@sha256:[0-9a-f]{64}\b)(?!scratch(?:\s|$))\S+(?:\s+AS\s+\S+)?\s*$"""
        ),
        "The container base image is not pinned to an immutable digest.",
        "Pin the reviewed image by digest and update it through an automated, reviewed process.",
        "CWE-1104",
        "NIST SSDF PS.3",
        frozenset(set()),
    ),
    Rule(
        "SP203",
        "Unpinned GitHub Action",
        "supply-chain",
        "high",
        "high",
        compile_pattern(r"""^\s*-?\s*uses:\s*(?!\./)([^\s@]+)@(?![0-9a-f]{40}\b)[^\s#]+"""),
        "A third-party GitHub Action is referenced by a mutable tag or branch.",
        "Pin the action to a reviewed 40-character commit SHA and retain the release tag in a comment.",
        "CWE-829",
        "NIST SSDF PS.3",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP204",
        "Sensitive data or credential logging",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:console\.log|logger\.(?:info|debug|warn|error)|logging\.(?:info|debug|warn|error)|print)\s*\(\s*.*(?:password|user\.password|client_secret|private_key|auth_token)\b"""
        ),
        "Sensitive credentials or authentication payloads appear to be logged directly.",
        "Mask or redact sensitive fields before writing messages to logs.",
        "CWE-532",
        "OWASP ASVS V7",
        frozenset(set()),
    ),
    Rule(
        "SP205",
        "Dockerfile running container as root",
        "supply-chain",
        "medium",
        "medium",
        compile_pattern(r"""(?:FROM\s+[^\n]+\n(?:(?!USER\s+).)*\Z)"""),
        "Dockerfile does not specify a non-root USER, causing container processes to run with root privileges.",
        "Add a non-root user (e.g. USER appuser or USER 10001) in the final container image stage.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({"containerfile", "dockerfile", ".dockerfile"}),
    ),
    Rule(
        "SP206",
        "Dockerfile package install via curl piped to shell",
        "supply-chain",
        "high",
        "high",
        compile_pattern(r"""(?:curl|wget)\s+[^|\n]+\|\s*(?:ba)?sh"""),
        "Dockerfile executes external scripts directly by piping curl or wget into a shell interpreter.",
        "Download the installer file, verify its cryptographic checksum (SHA256), and execute it.",
        "CWE-829",
        "OWASP ASVS V14",
        frozenset({"containerfile", "dockerfile", ".dockerfile"}),
    ),
    Rule(
        "SP207",
        "Dockerfile copying sensitive environment files",
        "security",
        "high",
        "high",
        compile_pattern(r"""COPY\s+[^#\n]*\.(?:env|git|npmrc|pypirc|aws)\b"""),
        "Dockerfile copies sensitive configuration files (.env, .git, .npmrc) into image layers.",
        "Add sensitive files to .dockerignore and inject secrets at runtime.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({"containerfile", "dockerfile", ".dockerfile"}),
    ),
    Rule(
        "SP208",
        "Dockerfile exposing privileged ports",
        "security",
        "low",
        "low",
        compile_pattern(r"""EXPOSE\s+(?:21|22|23|25|53|110|143)\b"""),
        "Dockerfile exposes privileged low ports or insecure legacy network protocols.",
        "Use unprivileged high ports (>1024) such as 8080 or 8443 for container services.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({"containerfile", "dockerfile", ".dockerfile"}),
    ),
    Rule(
        "SP209",
        "GitHub Actions pull_request_target checkout of PR head",
        "supply-chain",
        "high",
        "high",
        compile_pattern(
            r"""pull_request_target:\s*\n(?:(?!uses:).)*uses:\s*actions/checkout@[^\n]+\n\s*with:\s*\n\s*ref:\s*\${{\s*github\.event\.pull_request\.head\.sha\s*}}"""
        ),
        "GitHub Actions workflow triggers on pull_request_target and checks out untrusted fork pull request head.",
        "Use pull_request trigger instead of pull_request_target when checking out fork code.",
        "CWE-829",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP210",
        "GitHub Actions workflow script injection",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""\${{\s*github\.event\.(?:issue\.title|pull_request\.title|comment\.body|issue\.body)\s*}}"""
        ),
        "GitHub context expression is inserted directly into an inline shell script block.",
        "Pass GitHub context variables as environment variables (env:) rather than inline expressions.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP211",
        "GitHub Actions workflow missing explicit permissions",
        "security",
        "medium",
        "medium",
        compile_pattern(r"""^name:[^\n]+\non:[^\n]+\njobs:"""),
        "GitHub Actions workflow lacks a top-level permissions block, inheriting permissive default token permissions.",
        "Add explicit top-level permissions: read-all or permissions: contents: read block.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP212",
        "CI/CD step printing environment variables to console",
        "security",
        "high",
        "high",
        compile_pattern(r"""run:\s*[^#\n]*(?:\bprintenv\b|\benv\b(?!\s*=)|\bset\b(?!\s*-[eu]))"""),
        "A CI/CD workflow step executes printenv or env, dumping all environment secrets to build logs.",
        "Remove full environment dump commands; log only specific non-sensitive variable names.",
        "CWE-532",
        "OWASP ASVS V7",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP213",
        "npm script with unsafe-perm",
        "supply-chain",
        "high",
        "high",
        compile_pattern(r"""\b(?:npm\s+install|yarn\s+add)[^\n]*--unsafe-perm\b"""),
        "npm install configured with unsafe permissions, causing postinstall scripts to run as root.",
        "Remove the unsafe flag and execute npm installs under unprivileged service users.",
        "CWE-829",
        "OWASP ASVS V14",
    ),
    Rule(
        "SP214",
        "Pip install without pinned versions",
        "supply-chain",
        "medium",
        "medium",
        compile_pattern(
            r"""pip\s+install\s+(?:-r\s+requirements\.txt|[a-zA-Z0-9_-]+)(?!\s*==|\s*--require-hashes)"""
        ),
        "pip install called without pinned package versions or hash-checking mode.",
        "Use pip install with pinned versions (package==1.2.3) and generate pip-tools / poetry lockfiles.",
        "CWE-829",
        "OWASP ASVS V14",
        frozenset({".dockerfile", ".bash", ".sh", "containerfile", "dockerfile"}),
    ),
    Rule(
        "SP215",
        "Terraform AWS S3 bucket with public ACL",
        "security",
        "high",
        "high",
        compile_pattern(r"""acl\s*=\s*["']public-(?:read|read-write)["']"""),
        "Terraform configuration provisions an AWS S3 bucket with public-read or public-read-write ACL.",
        "Set acl = 'private' and use aws_s3_bucket_public_access_block resources.",
        "CWE-732",
        "OWASP ASVS V14",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP216",
        "Terraform security group with unrestricted ingress",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""cidr_blocks\s*=\s*\[["']0\.0\.0\.0/0["']\][^\n]*from_port\s*=\s*(?:22|3389|5432|3306|27017|6379)"""
        ),
        "Terraform security group opens sensitive ports (SSH, RDP, DBs) to the entire public internet (0.0.0.0/0).",
        "Restrict ingress CIDR blocks to specific VPN or bastion subnet IP ranges.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP217",
        "Kubernetes pod configured with privileged mode",
        "security",
        "high",
        "high",
        compile_pattern(r"""(?:privileged\s*:\s*true|hostPID\s*:\s*true|hostNetwork\s*:\s*true)"""),
        "Kubernetes pod securityContext has privileged: true or host namespaces enabled.",
        "Disable privileged mode and drop all unnecessary Linux capabilities (capabilities: drop: ['ALL']).",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP218",
        "Kubernetes container missing resource limits",
        "reliability",
        "medium",
        "medium",
        compile_pattern(r"""containers:\s*\n(?:(?!resources:).)*\Z"""),
        "Kubernetes container specification is missing CPU and memory requests/limits.",
        "Define explicit resources.requests and resources.limits for CPU and memory.",
        "CWE-400",
        "Capacity",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP219",
        "Kubernetes service exposing unauthenticated NodePort",
        "security",
        "high",
        "high",
        compile_pattern(r"""type\s*:\s*NodePort"""),
        "Kubernetes Service exposes a NodePort directly across all cluster worker nodes.",
        "Use ClusterIP services behind an authenticated Ingress controller or internal LoadBalancer.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP220",
        "Sensitive environment file tracked in git",
        "security",
        "high",
        "high",
        compile_pattern(r"""\.env(?:\.local|\.production|\.secret|\.staging)?$"""),
        "Git evidence contains a sensitive environment filename. Verify whether the file contains secrets and whether it was published.",
        "Ignore private environment files and remove them from the Git index. git rm --cached does not erase history; rotate confirmed exposed credentials and assess history cleanup separately.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP221",
        "Unpinned git dependency in package manifest",
        "supply-chain",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:["'](?!url["']\s*:)(?!repository["']\s*:)[^"'\n]+["']\s*:\s*|^[A-Za-z0-9_.-]+\s*=\s*)["'](?:git\+https?://[^#"'\n]+|git://[^#"'\n]+)(?:#(?![0-9a-fA-F]{40}(?:["']|$))[a-zA-Z0-9_.-]+)?["']\s*(?:,|\})?"""
        ),
        "Package dependency references a git repository URL without an immutable 40-character commit hash.",
        "Pin git dependencies to an exact commit SHA: git+https://...#<commit-sha>.",
        "CWE-829",
        "OWASP ASVS V14",
        frozenset({".json", ".toml", ".txt"}),
    ),
    Rule(
        "SP222",
        "Docker Compose mounting Docker socket",
        "security",
        "critical",
        "high",
        compile_pattern(r"""/var/run/docker\.sock\s*:\s*/var/run/docker\.sock"""),
        "Docker socket (/var/run/docker.sock) is mounted into a container, granting full host root access.",
        "Avoid mounting the Docker daemon socket; use Docker API proxies with restricted read-only permissions.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP223",
        "Nginx configuration with deprecated SSL/TLS protocols",
        "security",
        "high",
        "high",
        compile_pattern(r"""ssl_protocols\s+[^;\n]*(?:SSLv2|SSLv3|TLSv1\b|TLSv1\.1\b)"""),
        "Nginx configuration enables deprecated SSL/TLS protocols (SSLv3, TLSv1.0, TLSv1.1).",
        "Configure ssl_protocols to only allow modern TLS versions: ssl_protocols TLSv1.2 TLSv1.3;.",
        "CWE-327",
        "OWASP ASVS V9",
        frozenset({".conf", ".cfg"}),
    ),
    Rule(
        "SP224",
        "Nginx configuration missing security headers",
        "security",
        "medium",
        "medium",
        compile_pattern(r"""server\s*\{[^}]*(?!add_header\s+X-Frame-Options)[^}]*location"""),
        "Nginx server block is missing standard security response headers (X-Frame-Options, X-Content-Type-Options).",
        "Add security headers: add_header X-Frame-Options DENY; add_header X-Content-Type-Options nosniff;.",
        "CWE-693",
        "OWASP ASVS V14",
        frozenset({".conf", ".cfg"}),
    ),
    Rule(
        "SP225",
        "Logging HTTP request headers with credentials",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:logger\.(?:info|debug|error)|console\.(?:log|error))\s*\([^)]*(?:req\.headers|request\.headers|headers\[["']Authorization["']\])"""
        ),
        "Full HTTP request headers object is logged, recording Authorization tokens and Cookie headers.",
        "Sanitize request headers before logging, explicitly masking Authorization and Cookie values.",
        "CWE-532",
        "OWASP ASVS V7",
        frozenset({".js", ".py", ".ts", ".rb", ".go"}),
    ),
    Rule(
        "SP226",
        "Dockerfile container missing non-root USER directive",
        "security",
        "medium",
        "high",
        compile_pattern(r"""^FROM\s+[^\n]+(?![\s\S]*\nUSER\s+[a-zA-Z0-9_-]+)"""),
        "The Dockerfile does not specify a non-root USER, causing the application to execute as root inside the container.",
        "Add a dedicated non-root user (e.g. `USER appuser` or `USER 10001`) before the ENTRYPOINT/CMD directive.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({"containerfile", "dockerfile", ".dockerfile"}),
    ),
    Rule(
        "SP227",
        "Dockerfile container missing HEALTHCHECK instruction",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""^FROM\s+[^\n]+(?![\s\S]*\nHEALTHCHECK\s+)"""),
        "The container image does not define a HEALTHCHECK instruction for orchestrator health monitoring.",
        "Add a HEALTHCHECK instruction (e.g. `HEALTHCHECK --interval=30s --timeout=5s CMD wget -q -O - /health || exit 1`).",
        "CWE-400",
        "Reliability",
        frozenset({"containerfile", "dockerfile", ".dockerfile"}),
    ),
    Rule(
        "SP228",
        "Dockerfile using unpinned latest base image tag",
        "correctness",
        "high",
        "high",
        compile_pattern(r"""^FROM\s+[a-zA-Z0-9_./-]+:latest\b"""),
        "Using :latest as a base image tag introduces non-deterministic builds and breaking upstream changes.",
        "Pin the base image to an immutable digest (e.g. `node:20.11-alpine@sha256:...`) or specific patch version tag.",
        "CWE-1104",
        "Supply Chain",
        frozenset({"containerfile", "dockerfile", ".dockerfile"}),
    ),
    Rule(
        "SP229",
        "Dockerfile executing untrusted curl piped to shell",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""curl\s+-[a-zA-Z]*s[a-zA-Z]*\s+https?://[^\s|]+\s*\|\s*(?:bash|sh|sudo)"""
        ),
        "Piping curl directly to a shell inside a container build risks executing compromised or hijacked third-party code.",
        "Download the installer file, verify its SHA256 checksum against an immutable hash, then execute.",
        "CWE-829",
        "Supply Chain",
        frozenset({".dockerfile", ".bash", "containerfile", "dockerfile", ".sh"}),
    ),
    Rule(
        "SP230",
        "Docker daemon socket exposed in container compose",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\/var\/run\/docker\.sock\s*:\s*\/var\/run\/docker\.sock"""),
        "Mounting the host Docker daemon socket into a container grants container escape and full root control over host.",
        "Do not mount docker.sock into application containers; use dedicated rootless container builders or APIs.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP231",
        "Dockerfile blanket host copy without .dockerignore",
        "security",
        "medium",
        "high",
        compile_pattern(r"""^COPY\s+\.\s+\.\s*$"""),
        "Copying entire repository directory (.) directly into container image risks baking .env and credentials into image layers.",
        "Use explicit file copies (`explicit file copies`) and ensure .dockerignore excludes .git, .env, and secrets.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({"containerfile", "dockerfile", ".dockerfile"}),
    ),
    Rule(
        "SP232",
        "Docker compose container running in privileged mode",
        "security",
        "critical",
        "high",
        compile_pattern(r"""privileged\s*:\s*true"""),
        "Running a container in privileged mode disables all security isolation boundaries and grants full kernel access.",
        "Remove `privileged: true` and grant only specific required Linux capabilities (e.g. `cap_add: [NET_BIND_SERVICE]`).",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP233",
        "Docker compose container sharing host network namespace",
        "security",
        "high",
        "high",
        compile_pattern(r"""network_mode\s*:\s*["']?host["']?"""),
        "Sharing the host network namespace exposes host network interfaces and internal loopback services to the container.",
        "Use isolated bridge networks (`networks: [app_net]`) and explicitly publish only necessary ports.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP234",
        "Docker compose container sharing host PID namespace",
        "security",
        "high",
        "high",
        compile_pattern(r"""pid\s*:\s*["']?host["']?"""),
        "Sharing the host PID namespace allows the container process to view, signal, and debug all processes on the host.",
        "Remove `pid: host` to maintain process tree isolation.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP235",
        "Docker compose mounting host root filesystem",
        "security",
        "critical",
        "high",
        compile_pattern(r"""-\s*["']?\/:[^\s"']+"""),
        "Mounting the entire host root filesystem (/) gives the container write and read access to all host operating system files.",
        "Mount only dedicated, scoped application data subdirectories instead of host root.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP236",
        "Kubernetes privileged container execution enabled",
        "security",
        "critical",
        "high",
        compile_pattern(r"""securityContext:\s*\n\s*privileged:\s*true"""),
        "A Kubernetes pod specifies privileged: true, bypassing all container sandboxing and security profiles.",
        "Set `securityContext.privileged: false` and restrict capabilities via Pod Security Standards.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP237",
        "Kubernetes allowPrivilegeEscalation permitted",
        "security",
        "high",
        "high",
        compile_pattern(r"""allowPrivilegeEscalation:\s*true"""),
        "A Kubernetes container permits privilege escalation, allowing child processes to gain more privileges than parent.",
        "Set `securityContext.allowPrivilegeEscalation: false`.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP238",
        "Kubernetes container missing CPU or memory limit",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""containers:\s*\n\s*-\s*name:[^\n]+(?![\s\S]*resources:\s*\n\s*limits:)"""
        ),
        "A Kubernetes container does not specify resource limits, allowing a single pod to exhaust node CPU/memory.",
        "Define explicit `resources.limits.cpu` and `resources.limits.memory` for all containers.",
        "CWE-400",
        "Capacity",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP239",
        "Kubernetes container missing resource requests",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""containers:\s*\n\s*-\s*name:[^\n]+(?![\s\S]*resources:\s*\n\s*requests:)"""
        ),
        "A Kubernetes container omits resource requests, preventing the scheduler from accurately balancing cluster load.",
        "Define explicit `resources.requests.cpu` and `resources.requests.memory`.",
        "CWE-400",
        "Capacity",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP240",
        "Kubernetes container root filesystem writable",
        "security",
        "medium",
        "high",
        compile_pattern(r"""readOnlyRootFilesystem:\s*false"""),
        "The container root filesystem is writable, allowing attackers who achieve RCE to modify binaries and persist payloads.",
        "Set `securityContext.readOnlyRootFilesystem: true` and mount emptyDir volumes for temporary write paths.",
        "CWE-732",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP241",
        "Kubernetes container configured to run as root",
        "security",
        "high",
        "high",
        compile_pattern(r"""runAsNonRoot:\s*false|runAsUser:\s*0\b"""),
        "The Kubernetes pod is explicitly configured to run as root user (UID 0).",
        "Set `securityContext.runAsNonRoot: true` and `securityContext.runAsUser: 10001`.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP242",
        "Kubernetes Pod running on hostNetwork",
        "security",
        "high",
        "high",
        compile_pattern(r"""hostNetwork:\s*true"""),
        "A Kubernetes pod binds directly to the host network namespace, bypassing NetworkPolicies and exposing host ports.",
        "Set `hostNetwork: false` and expose pod services through Kubernetes Service or Ingress.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP243",
        "Kubernetes Pod running with hostPID or hostIPC",
        "security",
        "high",
        "high",
        compile_pattern(r"""hostPID:\s*true|hostIPC:\s*true"""),
        "A Kubernetes pod shares host PID or IPC namespace, breaking process and shared memory isolation.",
        "Set `hostPID: false` and `hostIPC: false`.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP244",
        "Kubernetes Pod mounting docker.sock hostPath volume",
        "security",
        "critical",
        "high",
        compile_pattern(r"""hostPath:\s*\n\s*path:\s*\/var\/run\/docker\.sock"""),
        "A Kubernetes pod mounts the host Docker daemon socket, granting pod containers root access over the host node.",
        "Remove docker.sock volume mounts; use non-daemon container builders like Kaniko or Buildah.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP245",
        "Kubernetes ServiceAccount automatic token mounting enabled",
        "security",
        "medium",
        "high",
        compile_pattern(r"""automountServiceAccountToken:\s*true"""),
        "ServiceAccount automatically mounts API credentials in pods that may not require Kubernetes API access.",
        "Set `automountServiceAccountToken: false` on ServiceAccount or Pod specs unless API access is required.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP246",
        "Kubernetes Ingress missing TLS configuration",
        "security",
        "high",
        "high",
        compile_pattern(r"""kind:\s*Ingress[^\n]+(?![\s\S]*\ntls:\s*\n\s*-\s*hosts:)"""),
        "A Kubernetes Ingress resource defines HTTP routing without an explicit TLS secret and certificate configuration.",
        "Add a `spec.tls` section with `hosts` and `secretName` to enforce encrypted HTTPS traffic.",
        "CWE-319",
        "OWASP ASVS V9",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP247",
        "Kubernetes namespace missing default deny NetworkPolicy",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""kind:\s*NetworkPolicy[^\n]+policyTypes:\s*\n\s*-\s*Ingress[^\n]+(?![\s\S]*podSelector:\s*\{\})"""
        ),
        "A NetworkPolicy is defined without a default-deny ingress selector for the namespace.",
        "Create a namespace-wide default deny NetworkPolicy with `podSelector: {}` and `policyTypes: [Ingress, Egress]`.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP248",
        "Terraform S3 bucket missing server-side encryption",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""resource\s+["']aws_s3_bucket["'][^\{]+\{(?![\s\S]*server_side_encryption_configuration)"""
        ),
        "An S3 bucket resource in Terraform does not configure default server-side encryption.",
        "Add an `aws_s3_bucket_server_side_encryption_configuration` resource specifying AES256 or aws:kms.",
        "CWE-311",
        "OWASP ASVS V9",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP249",
        "Terraform S3 bucket configured with public ACL",
        "security",
        "critical",
        "high",
        compile_pattern(r"""acl\s*=\s*["'](?:public-read|public-read-write|website)["']"""),
        "An S3 bucket is configured with a public read/write ACL in Terraform, risking public data exposure.",
        'Set `acl = "private"` and configure explicit bucket policies with least privilege.',
        "CWE-732",
        "OWASP ASVS V14",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP250",
        "Terraform S3 bucket missing public access block",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""resource\s+["']aws_s3_bucket["'][^\{]+\{(?![\s\S]*aws_s3_bucket_public_access_block)"""
        ),
        "An S3 bucket resource is defined without an accompanying `aws_s3_bucket_public_access_block`.",
        "Attach an `aws_s3_bucket_public_access_block` resource with all block flags set to true.",
        "CWE-732",
        "OWASP ASVS V14",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP251",
        "Terraform EBS volume created without encryption",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""resource\s+["']aws_ebs_volume["'][^\{]+\{(?![\s\S]*encrypted\s*=\s*true)|encrypted\s*=\s*false"""
        ),
        "An Amazon EBS volume in Terraform is configured without data-at-rest encryption.",
        "Set `encrypted = true` and specify a customer managed KMS key.",
        "CWE-311",
        "OWASP ASVS V9",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP252",
        "Terraform RDS instance missing storage encryption",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""resource\s+["']aws_db_instance["'][^\{]+\{(?![\s\S]*storage_encrypted\s*=\s*true)|storage_encrypted\s*=\s*false"""
        ),
        "An Amazon RDS database instance in Terraform does not enable storage encryption at rest.",
        "Set `storage_encrypted = true` in the `aws_db_instance` configuration.",
        "CWE-311",
        "OWASP ASVS V9",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP253",
        "Terraform RDS database instance publicly accessible",
        "security",
        "critical",
        "high",
        compile_pattern(r"""publicly_accessible\s*=\s*true"""),
        "An RDS database instance in Terraform has `publicly_accessible = true`, exposing the database endpoint to the Internet.",
        "Set `publicly_accessible = false` and place the database in private subnets behind a bastion/VPN.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP254",
        "Terraform Security Group open SSH ingress from 0.0.0.0/0",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""from_port\s*=\s*22[\s\S]*cidr_blocks\s*=\s*\[["']0\.0\.0\.0\/0["']\]"""
        ),
        "A Security Group rule permits unrestricted inbound SSH (port 22) from the entire Internet (0.0.0.0/0).",
        "Restrict SSH access to trusted corporate CIDR blocks, VPN gateways, or use AWS Systems Manager Session Manager.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP255",
        "Terraform Security Group open RDP ingress from 0.0.0.0/0",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""from_port\s*=\s*3389[\s\S]*cidr_blocks\s*=\s*\[["']0\.0\.0\.0\/0["']\]"""
        ),
        "A Security Group rule permits unrestricted inbound RDP (port 3389) from the entire Internet (0.0.0.0/0).",
        "Restrict RDP access to trusted management IP ranges or deploy behind an identity-aware proxy.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP256",
        "Terraform IAM policy granting full administrator wildcard",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""["']Action["']\s*:\s*["']\*["'][\s\S]*["']Resource["']\s*:\s*["']\*["']"""
        ),
        "An IAM policy grants broad Action:* on Resource:*, granting unrestricted administrative control.",
        "Apply the principle of least privilege by specifying exact required actions and specific resource ARNs.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".hcl", ".json", ".tf"}),
    ),
    Rule(
        "SP257",
        "Terraform CloudFront distribution viewer_protocol_policy allow-all",
        "security",
        "high",
        "high",
        compile_pattern(r"""viewer_protocol_policy\s*=\s*["']allow-all["']"""),
        "CloudFront distribution permits plain unencrypted HTTP requests without redirecting to HTTPS.",
        'Set `viewer_protocol_policy = "redirect-to-https"` or `"https-only"`.',
        "CWE-319",
        "OWASP ASVS V9",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP258",
        "Terraform DynamoDB table point-in-time recovery disabled",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""point_in_time_recovery\s*\{\s*enabled\s*=\s*false"""),
        "A DynamoDB table disables Point-in-Time Recovery (PITR), exposing the database to accidental data loss or corruption.",
        "Enable point-in-time recovery: `point_in_time_recovery { enabled = true }`.",
        "CWE-400",
        "Reliability",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP259",
        "Terraform EKS cluster public endpoint access unrestricted",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""endpoint_public_access\s*=\s*true[\s\S]*public_access_cidrs\s*=\s*\[["']0\.0\.0\.0\/0["']\]"""
        ),
        "The Amazon EKS Kubernetes API server endpoint is open to the entire Internet without CIDR restriction.",
        "Set `endpoint_private_access = true` and restrict `public_access_cidrs` to authorized corporate CIDRs.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP260",
        "GitHub Actions inline script injection from untrusted event context",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""run:\s*[^\n]*\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|head_commit\.message)"""
        ),
        "Untrusted user-supplied GitHub event context is interpolated directly into a bash `run:` step, causing command injection.",
        "Pass the context value via an environment variable (`env: TITLE: ${{ github.event.issue.title }}`) and reference `$TITLE` in the script.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP261",
        "GitHub Actions pull_request_target checking out untrusted pull request code",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""on:\s*\n\s*pull_request_target:[^\n]*(?![\s\S]*ref:\s*\$\{\{\s*github\.event\.pull_request\.base\.ref)[\s\S]*uses:\s*actions\/checkout"""
        ),
        "The workflow triggers on pull_request_target with write permissions and checks out the fork pull request code.",
        "Checkout the base branch instead or use the unprivileged `pull_request` event for untrusted code builds.",
        "CWE-829",
        "Supply Chain",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP262",
        "GitHub Actions third-party action referenced without immutable commit SHA",
        "correctness",
        "medium",
        "high",
        compile_pattern(
            r"""uses:\s*(?!actions\/|github\/|docker\/)[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+@v\d+"""
        ),
        "A third-party GitHub Action is referenced by a mutable tag (e.g. @v1) instead of an immutable 40-character commit SHA.",
        "Pin third-party actions to an exact full commit hash (e.g. `uses: author/action@1234567890abcdef... # v1.2.3`).",
        "CWE-829",
        "Supply Chain",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP263",
        "GitHub Actions echo statement printing secret token",
        "security",
        "critical",
        "high",
        compile_pattern(r"""echo\s+["']?[^\n]*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}"""),
        "A workflow run step attempts to echo a repository secret to the terminal log.",
        "Never echo secrets in workflow scripts; GitHub Actions will mask known tokens but partial values may leak.",
        "CWE-532",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP264",
        "GitHub Actions workflow granting broad write-all permissions",
        "security",
        "high",
        "high",
        compile_pattern(r"""permissions:\s*write-all"""),
        "The workflow declares `permissions: write-all`, granting unnecessary write access to repository contents, packages, and issues.",
        "Follow least privilege: set `permissions: read-all` at workflow level and grant write permissions only to specific jobs.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP265",
        "GitHub Actions public repository using self-hosted runner",
        "security",
        "high",
        "high",
        compile_pattern(r"""runs-on:\s*\[?self-hosted\]?"""),
        "A public repository workflow executes on a self-hosted runner, allowing pull request authors to execute code on local machines.",
        "Use GitHub-hosted runners (`runs-on: ubuntu-latest`) or require approval for external fork pull requests.",
        "CWE-829",
        "Supply Chain",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP266",
        "Helm values file containing hardcoded plaintext database password",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:db_password|database_password|dbPassword|db_pass)\s*:\s*["'][^"'\n\$\{]{6,64}["']"""
        ),
        "A Helm values.yaml file contains a hardcoded plaintext database password.",
        "Use external Kubernetes secrets (`existingSecret: my-db-secret`) or a secrets injection operator.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP267",
        "Nginx configuration enabling obsolete SSLv3 or TLSv1 protocols",
        "security",
        "high",
        "high",
        compile_pattern(r"""ssl_protocols\s+[^;]*(?:SSLv2|SSLv3|TLSv1\s|TLSv1\.1\s)"""),
        "Nginx SSL configuration enables deprecated TLS 1.0, 1.1, or SSLv3 protocols vulnerable to POODLE and BEAST attacks.",
        "Configure `ssl_protocols TLSv1.2 TLSv1.3;` exclusively in Nginx server blocks.",
        "CWE-326",
        "OWASP ASVS V9",
        frozenset({"nginx.conf", ".config", ".conf"}),
    ),
    Rule(
        "SP268",
        "Nginx configuration missing X-Content-Type-Options nosniff header",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""server\s*\{[^\}]+(?![\s\S]*add_header\s+X-Content-Type-Options\s+["']?nosniff)"""
        ),
        "Nginx configuration does not include the X-Content-Type-Options: nosniff header, risking MIME-sniffing attacks.",
        'Add `add_header X-Content-Type-Options "nosniff" always;` in the Nginx http or server configuration.',
        "CWE-430",
        "OWASP ASVS V14",
        frozenset({"nginx.conf", ".config", ".conf"}),
    ),
    Rule(
        "SP269",
        "Systemd unit service running as root without User directive",
        "security",
        "medium",
        "high",
        compile_pattern(r"""\[Service\]\s*\n(?![\s\S]*User\s*=)"""),
        "A systemd service unit executes by default as root without specifying a restricted User account.",
        "Add `User=appuser` and `Group=appgroup` under the `[Service]` section in the systemd unit file.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".service"}),
    ),
    Rule(
        "SP270",
        "Systemd unit service configured with unrestricted Restart=always",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""Restart\s*=\s*always(?![\s\S]*RestartSec\s*=)"""),
        "A systemd unit specifies Restart=always without RestartSec backoff, risking high CPU spinning on crash loops.",
        "Configure `RestartSec=5s` and `StartLimitIntervalSec=60s` to prevent rapid crash-loop storms.",
        "CWE-400",
        "Reliability",
        frozenset({".service"}),
    ),
    Rule(
        "SP301",
        "Redis KEYS in application path",
        "scale",
        "high",
        "medium",
        compile_pattern(r"""\b(?:redis|redis_client|r)\.keys\s*\("""),
        "Redis KEYS can block the server while scanning the full keyspace.",
        "Use cursor-based SCAN, a purpose-built index, or a bounded key namespace.",
        "CWE-400",
        "Capacity",
        frozenset(set()),
    ),
    Rule(
        "SP302",
        "Unbounded SQL result",
        "scale",
        "medium",
        "low",
        compile_pattern(r"""\bSELECT\s+\*\s+FROM\b(?![^;\x0a]{0,512}\bLIMIT\b)"""),
        "A query may return an unbounded, over-wide result set.",
        "Select required columns and enforce pagination or a defensible upper bound.",
        "CWE-400",
        "Capacity",
        frozenset({".sql"}),
    ),
    Rule(
        "SP303",
        "Blocking sleep in async code",
        "correctness",
        "high",
        "high",
        compile_pattern(r"""\btime\.sleep\s*\("""),
        "Blocking sleep may stall an async event loop.",
        "Use the runtime's non-blocking sleep or move blocking work to a bounded worker.",
        "CWE-400",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP304",
        "Outbound request without timeout",
        "correctness",
        "high",
        "high",
        compile_pattern(r"""$^"""),
        "An outbound request has no explicit deadline and can exhaust workers or connections.",
        "Set connect and read deadlines, bound retries, and test dependency failure.",
        "CWE-400",
        "Reliability",
        frozenset(set()),
    ),
    Rule(
        "SP305",
        "Unbounded pagination input",
        "scale",
        "medium",
        "high",
        compile_pattern(r"""$^"""),
        "A route accepts a page-size parameter without a visible upper bound.",
        "Enforce a positive maximum at the request boundary and retain a database LIMIT.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP306",
        "Unbounded concurrency in collection",
        "scale",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:Promise\.all\s*\(\s*(?:[A-Za-z0-9_]+\.map|items\.map)|asyncio\.gather\s*\(\s*\*\s*\[)"""
        ),
        "Unbounded concurrent tasks over a collection may exhaust memory or connection pools.",
        "Throttle concurrent execution using a semaphore, p-limit, or batch queue.",
        "CWE-400",
        "Capacity",
        frozenset(set()),
    ),
    Rule(
        "SP307",
        "N+1 database query in loop",
        "scale",
        "high",
        "high",
        compile_pattern(r"""$^"""),
        "A database query is executed inside an iteration loop, multiplying query volume and latency.",
        "Fetch required rows in a single batch query (e.g. using WHERE id IN (...)) or eager loading before the loop.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP308",
        "Unbounded in-memory global cache",
        "scale",
        "medium",
        "medium",
        compile_pattern(
            r"""(?:^\s*global\s+[A-Za-z0-9_]*(?:CACHE|STORE|LOOKUP)\b|^[A-Z0-9_]*(?:CACHE|STORE|LOOKUP)\s*=\s*\{\})"""
        ),
        "An in-memory dictionary or map is used as an unbounded global cache without size bounds or TTL eviction policies.",
        "Use an LRU cache with explicit maxsize (e.g. functools.lru_cache, cachetools.TTLCache) or an external cache store.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP309",
        "Goroutine spawned without context",
        "reliability",
        "medium",
        "medium",
        compile_pattern(r"""\bgo\s+func\s*\(\s*\)\s*\{"""),
        "Goroutines spawned directly without request context or cancellation tokens risk resource leaks.",
        "Pass request context to goroutines and bind them to worker pools or cancellation lifecycles.",
        "CWE-772",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP310",
        "Busy-wait spin loop without backoff",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""while\s+(?:True|1)\s*:\s*(?:pass|continue)"""),
        "An unyielding loop repeatedly checks condition without sleep or await, causing 100% CPU lock.",
        "Add time.sleep(), asyncio.sleep(), or event-driven waiting mechanisms.",
        "CWE-834",
        "Reliability",
    ),
    Rule(
        "SP311",
        "Event listener registered in request scope",
        "scale",
        "medium",
        "medium",
        compile_pattern(r"""(?:req|res|app|server)\.on\s*\(\s*["'][a-zA-Z0-9_]+["']"""),
        "Registering event listeners on persistent emitters within request scopes causes memory leaks.",
        "Use once() or remove listeners on request termination.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".cjs"}),
    ),
    Rule(
        "SP312",
        "Retry loop without exponential backoff",
        "reliability",
        "medium",
        "medium",
        compile_pattern(r"""except\s*(?:Exception)?\s*:\s*time\.sleep\(0\)"""),
        "Immediate retries upon failure risk compounding downstream outages (Retry Storm).",
        "Implement exponential backoff with jitter and an explicit retry limit.",
        "CWE-398",
        "Reliability",
    ),
    Rule(
        "SP313",
        "Non-singleton database client in serverless",
        "scale",
        "high",
        "medium",
        compile_pattern(r"""new\s+PrismaClient\s*\(\s*\)"""),
        "Instantiating database clients inside serverless route files can rapidly exhaust database connection limits.",
        "Use a global singleton instance (e.g. globalThis.prisma) and connect through a connection pooler.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".tsx", ".ts", ".mjs", ".cjs"}),
    ),
    Rule(
        "SP314",
        "Committed SQLite database file",
        "security",
        "high",
        "high",
        compile_pattern(r"""$^"""),
        "An SQLite database file is tracked in source control, which may expose private data or tokens.",
        "Remove the database file from git history, add *.sqlite, *.sqlite3, *.db to .gitignore, and use migrations.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset(set()),
    ),
    Rule(
        "SP315",
        "Go HTTP request missing response body close",
        "correctness",
        "high",
        "medium",
        compile_pattern(r"""(?:resp|res),\s*(?:err|_)\s*:=\s*http\.(?:Get|Post|Head)\s*\("""),
        "An HTTP response body in Go is not visibly closed, which can leak TCP connections and goroutines.",
        "Add defer resp.Body.Close() immediately after error checking and drain the body if unread.",
        "CWE-400",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP316",
        "Outbound HTTP call inside database transaction",
        "scale",
        "high",
        "medium",
        compile_pattern(r"""$^"""),
        "An outbound HTTP network call is executed inside a database transaction block, risking connection pool starvation.",
        "Move external network requests outside the database transaction boundary.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP317",
        "Blocking call in async def coroutine",
        "scale",
        "high",
        "high",
        compile_pattern(r"""$^"""),
        "A synchronous blocking operation (e.g. time.sleep or requests.get) is called directly inside an async def coroutine.",
        "Use non-blocking async equivalents (e.g. asyncio.sleep, httpx.AsyncClient) or wrap in asyncio.to_thread().",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP318",
        "Retry policy without a stop condition",
        "reliability",
        "medium",
        "medium",
        compile_pattern(r"""$^"""),
        "A retry loop is configured without a bound, so a failing dependency amplifies load into a retry storm.",
        "Add an explicit stop condition (tenacity stop_after_attempt, bounded retries) and backoff with jitter.",
        "CWE-770",
        "OWASP ASVS V14",
        frozenset(set()),
    ),
    Rule(
        "SP319",
        "Redis SMEMBERS or HGETALL on unbounded keys",
        "scale",
        "high",
        "medium",
        compile_pattern(r"""\.(?:smembers|hgetall|lrange\([^)]*0,\s*-1\))\s*\("""),
        "Redis SMEMBERS or HGETALL retrieves entire collections at once, blocking the server on large datasets.",
        "Use SSCAN, HSCAN, or limit range queries to retrieve items incrementally.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP320",
        "Redis cache key stored without TTL",
        "scale",
        "medium",
        "medium",
        compile_pattern(r"""(?:redis\.set|client\.set)\s*\(\s*["'][^"']+["'],\s*[^,\)]+\)"""),
        "A cache entry is set in Redis without an expiration TTL (EX/PX), causing memory accumulation over time.",
        "Provide an explicit expiration TTL (e.g. ex=3600 or EX: 3600) on all cached keys.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".py", ".ts", ".rb", ".go"}),
    ),
    Rule(
        "SP321",
        "Blocking filesystem I/O in async loop",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""(?:for\s*\([^)]*\)|while\s*\([^)]*\))[\s\S]{0,120}?fs\.(?:readFileSync|writeFileSync)|(?:fs\.(?:readFileSync|writeFileSync))[^\n]*(?:for\s*\(|while\s*\()|(?:open\s*\([^)]*\)\s*\.\s*read\s*\(\))"""
        ),
        "Synchronous filesystem I/O is called directly inside an async event loop, blocking request handling.",
        "Use async filesystem APIs (e.g. fs.promises.readFile or aiofiles) or run in a threadpool.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP322",
        "SQL query with leading wildcard",
        "scale",
        "medium",
        "medium",
        compile_pattern(r"""LIKE\s+["']%[a-zA-Z0-9_]+"""),
        "SQL query contains a leading wildcard, which invalidates B-Tree index lookups.",
        "Use full-text search (PostgreSQL tsvector, MySQL FULLTEXT) or trigram indexes (pg_trgm).",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP323",
        "SQL query with random sorting",
        "scale",
        "medium",
        "medium",
        compile_pattern(r"""ORDER\s+BY\s+(?:RAND\(\)|RANDOM\(\))"""),
        "Sorting by random function assigns random numbers to all rows and sorts the entire table in memory.",
        "Use TABLESAMPLE, ID range sampling, or fetch random IDs via application logic.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP324",
        "SQL NOT IN subquery on nullable column",
        "correctness",
        "medium",
        "medium",
        compile_pattern(r"""NOT\s+IN\s*\(\s*SELECT\b"""),
        "NOT IN with a nullable subquery column returns 0 rows if any NULL is present, causing logic bugs.",
        "Use NOT EXISTS (SELECT 1 FROM ...) or LEFT JOIN ... WHERE ... IS NULL.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP326",
        "Transaction committed per row in bulk loop",
        "scale",
        "medium",
        "medium",
        compile_pattern(
            r"""for\s+[a-zA-Z0-9_]+\s+in\s+[^:]+:\s*\n\s*(?:with\s+(?:db|connection)\.transaction\(|db\.session\.commit\(\))"""
        ),
        "A database transaction is committed per row inside a loop, causing excessive fsync overhead.",
        "Batch row operations into chunks (e.g. 500-1000 rows) and commit once per batch.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP327",
        "Monolithic single transaction on large table",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:DELETE|UPDATE)\s+FROM\s+[a-zA-Z0-9_]+\s+WHERE\s+[^\n;]+;\s*--\s*bulk"""
        ),
        "A single mass DELETE or UPDATE query modifies millions of rows in one transaction without batching.",
        "Break bulk deletions/updates into chunks with LIMIT and pause between batches.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP328",
        "Missing connection pool max limit or acquire timeout",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:create_pool|createPool|new\s+Pool)\s*\([^)]*(?!max)(?!connectionTimeoutMillis)"""
        ),
        "Database connection pool created without explicit maximum pool size or acquire timeout.",
        "Configure max connections (e.g. max: 20) and an acquire timeout (e.g. connectionTimeoutMillis: 5000).",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP329",
        "Synchronous large JSON parsing in request thread",
        "scale",
        "high",
        "medium",
        compile_pattern(
            r"""(?:JSON\.parse|json\.loads)\s*\(\s*(?:large_payload|bigData|file_content|huge_json)\b"""
        ),
        "Parsing multi-megabyte JSON payloads synchronously blocks the JavaScript or Python event loop.",
        "Use streaming JSON parsers (e.g. stream-json, ijson) or offload parsing to worker threads.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP330",
        "Regex compiled repeatedly inside tight loop",
        "performance",
        "low",
        "medium",
        compile_pattern(
            r"""for\s+[a-zA-Z0-9_]+\s+in\s+[^:]+:\s*\n\s*(?:re\.compile|new\s+RegExp)\s*\("""
        ),
        "A regular expression is recompiled on every iteration of a loop instead of being precompiled.",
        "Precompile regular expressions once at the module level using re.compile().",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP331",
        "Go HTTP client missing idle connection limits",
        "reliability",
        "medium",
        "medium",
        compile_pattern(r"""&http\.Client\{\s*(?:Timeout:[^,]+)?\s*\}\s*//\s*no-transport"""),
        "Go http.Client uses DefaultTransport without explicit MaxIdleConnsPerHost tuning.",
        "Configure a custom http.Transport with explicit MaxIdleConns and MaxIdleConnsPerHost limits.",
        "CWE-400",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP332",
        "Go unbuffered channel send without consumer",
        "reliability",
        "high",
        "medium",
        compile_pattern(
            r"""(?:go\s+func\(\)\s*\{[^}]*|\bfunc\s+[a-zA-Z0-9_]+\([^)]*\)\s*\{[^}]*)\bch\s*<-\s*[a-zA-Z0-9_]+\s*//\s*unbuffered"""
        ),
        "An unbuffered channel send inside a goroutine may block forever if no receiver is active, leaking goroutines.",
        "Use a buffered channel or select statement with a default/timeout case.",
        "CWE-772",
        "Reliability",
    ),
    Rule(
        "SP333",
        "Go sync.WaitGroup counter incremented in goroutine",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""go\s+func\s*\(\s*\)\s*\{[^}]*wg\.Add\s*\(\s*1\s*\)"""),
        "Calling wg.Add(1) inside the launched goroutine creates a race condition where wg.Wait() can return prematurely.",
        "Call wg.Add(1) in the parent goroutine before launching the go func().",
        "CWE-662",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP335",
        "Python asyncio task created without reference",
        "reliability",
        "high",
        "medium",
        compile_pattern(r"""task\s*=\s*None\s*;\s*asyncio\.create_task\s*\("""),
        "Background async tasks created without holding a strong reference can be garbage collected prematurely.",
        "Store created tasks in a background task set until completion.",
        "CWE-772",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP336",
        "Node inline file stream has no source error handler",
        "reliability",
        "high",
        "high",
        compile_pattern(r"$^"),
        "Inline imported fs read/write streams are piped without attaching a source error handler.",
        "Use awaited stream/promises.pipeline or attach source error handling and cleanup before piping.",
        "CWE-754",
        "Reliability",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP337",
        "In-memory session store in web cluster",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:session\(\{[^}]*store:\s*new\s+(?:express-session\.)?MemoryStore\(\)|session\({\s*secret:[^}]+}\))"""
        ),
        "Default in-memory session store used in web applications, which cannot share sessions across cluster nodes.",
        "Use a distributed session store such as connect-redis or connect-pg-simple.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP338",
        "External network call missing circuit breaker",
        "reliability",
        "medium",
        "medium",
        compile_pattern(
            r"""async\s+function\s+callExternalService\([^)]*\)\s*\{[^}]*await\s+fetch\([^)]+\)[^}]*//\s*no-breaker"""
        ),
        "Critical external service call is made without a circuit breaker or fallback strategy.",
        "Wrap external API calls with a circuit breaker (e.g. opossum in Node.js or pybreaker in Python).",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP339",
        "Synchronous heavy crypto in async request thread",
        "scale",
        "high",
        "high",
        compile_pattern(r"""(?:bcrypt\.hashSync|bcrypt\.compareSync|crypto\.pbkdf2Sync)\s*\("""),
        "Synchronous password hashing (bcrypt.hashSync) blocks the event loop for hundreds of milliseconds.",
        "Use async versions (bcrypt.hash, bcrypt.compare) to offload computation to libuv thread pool.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP340",
        "Deep offset pagination on large table",
        "scale",
        "medium",
        "medium",
        compile_pattern(r"""OFFSET\s+[0-9]{5,}"""),
        "SQL query uses large numerical offsets (10,000+), requiring the database to scan and discard thousands of rows.",
        "Use cursor-based or keyset pagination (WHERE id > last_seen_id ORDER BY id LIMIT 50).",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP341",
        "Unbuffered file read into memory",
        "scale",
        "high",
        "medium",
        compile_pattern(
            r"""(?:res\.send\s*\(\s*fs\.readFileSync|res\.end\s*\(\s*fs\.readFileSync|return\s+Response\s*\(\s*open\([^)]+\)\.read\(\)\))"""
        ),
        "An entire file is read synchronously into memory before sending in HTTP response, causing high RAM consumption.",
        "Use streaming responses (fs.createReadStream().pipe(res) or StreamingResponse).",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP342",
        "Synchronous heavy processing in webhook listener",
        "scale",
        "medium",
        "medium",
        compile_pattern(
            r"""app\.post\s*\(\s*["'][^"']*webhook["'],\s*async\s*\([^)]*\)\s*=>\s*\{[^}]*await\s+(?:processVideo|generateReport|syncFullCatalog)\b"""
        ),
        "Heavy business logic is executed synchronously inside the webhook receiver handler.",
        "Acknowledge the webhook immediately (HTTP 200) and enqueue the payload to a background worker queue.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP343",
        "process.exit called inside request handler",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""app\.(?:get|post|put|delete|use)\s*\([^)]*process\.exit\s*\("""),
        "process.exit() is invoked directly inside an HTTP request handler, abruptly killing the server process.",
        "Throw an error or return an HTTP error status response instead of terminating the node process.",
        "CWE-398",
        "Reliability",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP344",
        "ThreadPoolExecutor instantiated per request",
        "scale",
        "medium",
        "medium",
        compile_pattern(
            r"""def\s+[a-zA-Z0-9_]+\([^)]*\):[^\n]*\n\s*with\s+ThreadPoolExecutor\s*\("""
        ),
        "ThreadPoolExecutor is created inside a request handler function, spawning and tearing down threads per request.",
        "Instantiate a single shared ThreadPoolExecutor at the application or module level.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP345",
        "Global lock held across async I/O call",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:async\s+with\s+[a-zA-Z0-9_]*lock:\s*\n\s*await\s+(?:fetch|requests|httpx|http|axios))"""
        ),
        "An asynchronous lock or mutex is held while performing an outbound network request or slow I/O.",
        "Release locks before initiating network calls; only acquire locks when mutating in-memory state.",
        "CWE-667",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP346",
        "Python asyncio create_task reference dropped causing garbage collection",
        "reliability",
        "high",
        "high",
        compile_pattern(r"$^"),
        "asyncio.create_task() called without retaining a reference to the task, risking premature garbage collection.",
        "Assign the created task to a variable or add to a background_tasks set: `task = asyncio.create_task(...)`.",
        "CWE-400",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP349",
        "Python ProcessPoolExecutor created inside async request handler",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:async\s+def\s+[a-zA-Z0-9_]+[^\n]*\n[\s\S]*?)ProcessPoolExecutor\s*\("""
        ),
        "Instantiating ProcessPoolExecutor inside an async route creates high OS fork overhead on every request.",
        "Use a global singleton ProcessPoolExecutor instance managed by application lifespan events.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP351",
        "Python SQLAlchemy session created without scoped session or context manager",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""(?:scoped_session|sessionmaker)\s*\(\s*\)|db\.Session\s*\(\s*\)"""),
        "SQLAlchemy Session is instantiated without a context manager or explicit close in a finally block, leaking connections.",
        "Use `with SessionLocal() as session:` context managers to guarantee session cleanup.",
        "CWE-400",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP352",
        "Python Redis client created without socket timeout",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""redis\.(?:Redis|from_url)\s*\([^\)]+(?!socket_timeout\s*=)[^\)]*\)"""),
        "Redis client connection omits socket_timeout, allowing network partitions to hang worker threads indefinitely.",
        "Set `socket_timeout=5.0` and `socket_connect_timeout=2.0` in Redis connection parameters.",
        "CWE-400",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP353",
        "Python Redis pub/sub listener without reconnect loop",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""\.pubsub\s*\(\s*\)[\s\S]*\.listen\s*\(\s*\)"""),
        "Redis pubsub.listen() loop is executed without reconnection and backoff error handling.",
        "Wrap the pubsub listener loop in a retry with exponential backoff on ConnectionError.",
        "CWE-400",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP354",
        "Python Celery task missing explicit time_limit or soft_time_limit",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""@(?:app|celery)\.task\s*\([^\)]*(?!time_limit\s*=)[^\)]*\)"""),
        "A Celery task does not define a time_limit, allowing stuck external API calls to lock workers forever.",
        "Set `time_limit=300` and `soft_time_limit=240` in @app.task decorator.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP355",
        "Python Celery task with bind=True mutating global state",
        "reliability",
        "medium",
        "high",
        compile_pattern(
            r"""@(?:app|celery)\.task\s*\([^\)]*bind\s*=\s*True[^\)]*\)\s*\ndef\s+[a-zA-Z0-9_]+\s*\([^)]*\):\s*\n[\s\S]*?global\s+[a-zA-Z0-9_]+"""
        ),
        "A bound Celery task mutates global variables, causing race conditions in multi-threaded worker pools.",
        "Keep tasks stateless and pass all state explicitly through task parameters or database records.",
        "CWE-362",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP356",
        "Python Pydantic model string field without max_length constraint",
        "scale",
        "medium",
        "high",
        compile_pattern(
            r"""class\s+[a-zA-Z0-9_]+\s*\((?:BaseModel|Schema)\):\s*\n[\s\S]*?[a-zA-Z0-9_]+\s*:\s*str\s*=\s*Field\s*\([^\)]*(?!max_length\s*=)[^\)]*\)"""
        ),
        "A Pydantic schema declares an unconstrained string field, allowing memory exhaustion via unbounded payload sizes.",
        "Add `max_length=255` (or appropriate business limit) to Field() definitions.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP357",
        "Python naive datetime comparison with datetime.now without timezone",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"""datetime\.now\s*\(\s*\)"""),
        "Using naive datetime instances produces timezone-naive timestamps, causing comparison bugs and daylight saving offsets.",
        "Use `datetime.now(timezone.utc)` or `datetime.fromtimestamp(ts, tz=timezone.utc)`.",
        "CWE-682",
        "Correctness",
        frozenset({".py"}),
    ),
    Rule(
        "SP358",
        "Python floating point direct equality comparison",
        "correctness",
        "medium",
        "high",
        compile_pattern(
            r"""(?:float\(|price|amount|rate|balance)\s*==\s*0\.\d+|0\.\d+\s*==\s*(?:float\(|price|amount)"""
        ),
        "Direct equality comparison on float numbers causes precision bugs due to IEEE 754 rounding.",
        "Use `math.isclose(a, b)` or the `decimal.Decimal` class for financial arithmetic.",
        "CWE-682",
        "Correctness",
        frozenset({".py"}),
    ),
    Rule(
        "SP360",
        "Node.js EventEmitter listener added inside request handler without removal",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""app\.(?:get|post|put|delete)\s*\([^\)]*\=>\s*\{[\s\S]*?(?:emitter|socket|stream)\.on\s*\("""
        ),
        "Registering EventEmitter listeners inside a request handler causes unbounded memory leaks on every request.",
        "Register listeners once globally or remove them in response finish: `res.on('finish', () => emitter.off(...))`.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP361",
        "Node.js synchronous file read inside route handler blocking event loop",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:app|router)\.(?:get|post|put|delete)\s*\([^\)]*=>\s*\{[\s\S]*?fs\.readFileSync\s*\("""
        ),
        "fs synchronous read inside a request handler halts the entire Node.js event loop for all concurrent requests.",
        "Use async `await fs.promises.readFile()` or stream the file with `fs.createReadStream()`.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP362",
        "Node.js synchronous crypto PBKDF2 inside route handler",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:app|router)\.(?:get|post|put|delete)\s*\([^\)]*=>\s*\{[\s\S]*?crypto\.pbkdf2Sync\s*\("""
        ),
        "crypto.pbkdf2Sync blocks the Node.js V8 event loop during CPU-intensive key derivation.",
        "Use asynchronous `util.promisify(crypto.pbkdf2)()` to run computation in libuv thread pool.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP364",
        "Node.js Axios or Got HTTP client request without timeout",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""axios\.(?:get|post|put|delete|request)\s*\([^\)]+(?!timeout\s*:)[^\)]*\)|axios\.create\s*\(\s*\{[^\}]*(?!timeout\s*:)[^\}]*\}"""
        ),
        "Axios HTTP request or client instance does not specify a timeout, risking socket pool starvation on upstream hangs.",
        "Set `timeout: 10000` (10 seconds) in Axios request config.",
        "CWE-400",
        "Reliability",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP365",
        "Node.js Prisma database query inside Array.forEach",
        "correctness",
        "high",
        "high",
        compile_pattern(
            r"""\.forEach\s*\(\s*async\s*\([^\)]*\)\s*=>\s*\{[\s\S]*?prisma\.[a-zA-Z0-9_]+\.(?:create|update|find|delete)"""
        ),
        "Calling async Prisma operations inside Array.forEach does not await execution, causing race conditions and unhandled errors.",
        "Use sequential `for (const item of items)` loop or chunked batching for database queries.",
        "CWE-362",
        "Correctness",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP366",
        "Node.js Mongoose read-only query missing lean optimization",
        "scale",
        "medium",
        "high",
        compile_pattern(
            r"""(?:Model|User|Item)\.find\s*\([^\)]*\)(?!\s*\.lean\(\))\s*\.exec\s*\(\)"""
        ),
        "Mongoose .find() queries in read-only endpoints hydrate heavy Mongoose Documents, consuming 5-10x more memory.",
        "Append `.lean()` to query chains for read-only responses.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP368",
        "Node.js process.exit called inside request handler",
        "reliability",
        "critical",
        "high",
        compile_pattern(
            r"""(?:app|router)\.(?:get|post|put|delete)\s*\([^\)]*=>\s*\{[\s\S]*?process\.exit\s*\("""
        ),
        "Calling process.exit() directly inside an HTTP route terminates the entire server instance.",
        "Throw an error or pass it to `next(err)` to trigger the error handling middleware instead.",
        "CWE-703",
        "Reliability",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP369",
        "Node.js setTimeout delay exceeding 32-bit integer maximum",
        "correctness",
        "medium",
        "high",
        compile_pattern(
            r"""setTimeout\s*\([^\)]*,\s*(?:214748364[89]|21474836[5-9]\d|2147483[7-9]\d{2}|[3-9]\d{9,})"""
        ),
        "Node.js setTimeout with delay > 2147483647ms (24.8 days) overflows 32-bit signed int and fires immediately.",
        "Use cron schedulers or database task queues for long-duration delays.",
        "CWE-682",
        "Correctness",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP370",
        "Node.js JSON.parse on raw payload without try/catch",
        "reliability",
        "medium",
        "high",
        compile_pattern(
            r"""const\s+[a-zA-Z0-9_]+\s*=\s*JSON\.parse\s*\(\s*(?:req\.body|data|rawPayload)\s*\)(?![^;]*catch)"""
        ),
        "JSON.parse throws SyntaxError on malformed JSON, crashing unhandled request handlers.",
        "Wrap JSON.parse in a try/catch block or use a validated JSON middleware.",
        "CWE-703",
        "Reliability",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP371",
        "Go goroutine spawning inside loop capturing loop variable",
        "correctness",
        "high",
        "high",
        compile_pattern(
            r"""for\s+[a-zA-Z0-9_]+,\s*([a-zA-Z0-9_]+)\s*:=\s*range\s+[a-zA-Z0-9_]+\s*\{[\s\S]*?go\s+func\s*\(\s*\)\s*\{[\s\S]*?\b\1\b"""
        ),
        "A Go goroutine launched inside a loop captures the loop iterator variable by reference instead of by value.",
        "Pass the loop variable as an argument: `go func(v Type) { ... }(val)`.",
        "CWE-362",
        "Correctness",
        frozenset({".go"}),
    ),
    Rule(
        "SP372",
        "Go unbuffered channel receive without context cancellation select",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""<-[a-zA-Z0-9_]+Chan(?!\s*;|\s*case)"""),
        "Reading from an unbuffered channel without a `select` with `case <-ctx.Done():` can block goroutines permanently.",
        "Use `select { case val := <-ch: ... case <-ctx.Done(): return ctx.Err() }`.",
        "CWE-400",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP373",
        "Go time.Tick called inside function scope causing memory leak",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""for\s+range\s+time\.Tick\s*\("""),
        "time.Tick cannot be garbage collected or stopped, leaking the underlying Ticker when called inside functions.",
        "Use `ticker := time.NewTicker(...)` and `defer ticker.Stop()`.",
        "CWE-400",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP374",
        "Go sync.WaitGroup Wait called inside spawned goroutine causing deadlock",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""go\s+func\s*\(\s*\)\s*\{[\s\S]*?wg\.Wait\s*\(\s*\)"""),
        "Calling wg.Wait() inside a goroutine spawned by the same WaitGroup introduces circular deadlock conditions.",
        "Call `wg.Wait()` on the parent coordinating goroutine after all `go func()` worker spawns.",
        "CWE-833",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP375",
        "Go sql.DB connection pool configured with unbounded connections",
        "scale",
        "high",
        "high",
        compile_pattern(r"""db\.SetMaxOpenConns\s*\(\s*0\s*\)"""),
        "SetMaxOpenConns(0) removes the open-connection cap; SetMaxIdleConns(0) merely retains no idle connections.",
        "Set a workload-appropriate open-connection cap; tune idle retention separately.",
        "CWE-400",
        "Capacity",
        frozenset({".go"}),
    ),
    Rule(
        "SP376",
        "Go HTTP client using zero-timeout DefaultClient",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""http\.DefaultClient\.(?:Do|Get|Post)\s*\("""),
        "Go's http.DefaultClient has Timeout = 0 (no timeout), allowing dead network connections to hang goroutines forever.",
        "Construct an explicit `&http.Client{Timeout: 10 * time.Second}`.",
        "CWE-400",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP377",
        "Go http.Server has no effective header-read deadline",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""&http\.Server\s*\{[^\}]*(?!ReadHeaderTimeout\s*:)[^\}]*\}"""),
        "A standard net/http.Server literal has no effective header-read deadline; slow clients can retain connections if this configuration is served without an upstream deadline.",
        "Set `ReadHeaderTimeout: 5 * time.Second` and `WriteTimeout: 10 * time.Second` on http.Server.",
        "CWE-400",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP378",
        "Go cancelable context discards its cancellation function",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""\b\w+\s*,\s*_\s*:?=\s*context\.(?:WithCancel|WithTimeout|WithDeadline)\s*\("""
        ),
        "A standard-library context constructor's CancelFunc is discarded, preventing its owner from explicitly releasing the derived context or timer.",
        "Retain the cancellation function and call it when the work ends, usually with defer cancel().",
        "CWE-400",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP379",
        "Go Mutex lock acquired without immediate defer Unlock",
        "reliability",
        "medium",
        "high",
        compile_pattern(
            r"""([a-zA-Z0-9_]+\.Lock\s*\(\s*\))(?![\s\S]{1,80}defer\s+[a-zA-Z0-9_]+\.Unlock)"""
        ),
        "A sync.Mutex is locked without an immediate defer Unlock, risking permanent deadlock on early return or panic.",
        "Place `defer mu.Unlock()` immediately after `mu.Lock()`.",
        "CWE-833",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP380",
        "Java Executors newCachedThreadPool unbounded thread creation",
        "scale",
        "high",
        "high",
        compile_pattern(r"""Executors\.newCachedThreadPool\s*\(\s*\)"""),
        "newCachedThreadPool() creates an unbounded thread pool that will spawn new threads until OutOfMemoryError under load.",
        "Use `Executors.newFixedThreadPool(n)` or a `ThreadPoolExecutor` with bounded ArrayBlockingQueue.",
        "CWE-400",
        "Capacity",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP381",
        "Java CompletableFuture join called on main thread",
        "scale",
        "high",
        "high",
        compile_pattern(r"""CompletableFuture[^\.]*\.[a-zA-Z0-9_]+\([^\)]*\)\.join\s*\(\s*\)"""),
        "Calling .join() or .get() synchronously on a CompletableFuture blocks the calling thread, causing thread pool starvation.",
        "Chain asynchronous steps with `.thenApply()`, `.thenCompose()`, or use reactive frameworks.",
        "CWE-400",
        "Capacity",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP382",
        "Java SimpleDateFormat shared across multiple threads",
        "correctness",
        "high",
        "high",
        compile_pattern(r"""(?:private\s+static|public\s+static)[^\n]+SimpleDateFormat"""),
        "SimpleDateFormat is not thread-safe and mutates internal calendar state during format() and parse().",
        "Use thread-safe `java.time.format.DateTimeFormatter` (Java 8+) or wrap in ThreadLocal.",
        "CWE-362",
        "Correctness",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP383",
        "Java unclosed JDBC Connection in try block without try-with-resources",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""Connection\s+[a-zA-Z0-9_]+\s*=\s*DriverManager\.getConnection\s*\([^\)]+\)(?![\s\S]*\.close\(\))"""
        ),
        "A JDBC Connection is opened without try-with-resources, leaking database connections on SQL exceptions.",
        "Use try-with-resources: `try (Connection conn = dataSource.getConnection()) { ... }`.",
        "CWE-400",
        "Reliability",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP384",
        "Java HikariCP connection pool missing maximumPoolSize setting",
        "scale",
        "medium",
        "high",
        compile_pattern(r"""new\s+HikariConfig\s*\(\s*\)[^\n]*(?![\s\S]*setMaximumPoolSize)"""),
        "HikariCP configuration does not define maximumPoolSize, relying on default pool sizing that may not match DB capacity.",
        "Configure `config.setMaximumPoolSize(20)` and `config.setMinimumIdle(5)` explicitly.",
        "CWE-400",
        "Capacity",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP385",
        "C# async void method declaration masking unhandled exceptions",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""public\s+async\s+void\s+[a-zA-Z0-9_]+\s*\((?!object\s+sender)"""),
        "Declaring `async void` (outside event handlers) causes unhandled exceptions to crash the entire application process.",
        "Change return type to `async Task` or `async ValueTask`.",
        "CWE-703",
        "Reliability",
        frozenset({".cs"}),
    ),
    Rule(
        "SP386",
        "C# synchronous Task.Result or Task.Wait causing deadlock",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""\.[a-zA-Z0-9_]+Async\s*\([^\)]*\)\.Result|\.[a-zA-Z0-9_]+Async\s*\([^\)]*\)\.Wait\s*\(\s*\)"""
        ),
        "Accessing `.Result` or calling `.Wait()` synchronously on async Tasks blocks thread pool threads and causes synchronization deadlocks.",
        "Use `await` asynchronously throughout the entire call stack.",
        "CWE-833",
        "Capacity",
        frozenset({".cs"}),
    ),
    Rule(
        "SP387",
        "C# HttpClient instantiated directly causing socket exhaustion",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""using\s*\(\s*(?:var|HttpClient)\s+[a-zA-Z0-9_]+\s*=\s*new\s+HttpClient\s*\("""
        ),
        "Instantiating HttpClient in a `using` block leaves TCP sockets in TIME_WAIT state, causing socket exhaustion under load.",
        "Use `IHttpClientFactory` or a static/singleton HttpClient instance.",
        "CWE-400",
        "Capacity",
        frozenset({".cs"}),
    ),
    Rule(
        "SP388",
        "C# Entity Framework DbContext shared across concurrent threads",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""static\s+[a-zA-Z0-9_]*DbContext\s+[a-zA-Z0-9_]+|Task\.Run\s*\([^\)]*dbContext\."""
        ),
        "DbContext is not thread-safe and throwing InvalidOperationException when accessed concurrently across threads.",
        "Use scoped DbContext instances injected per HTTP request via dependency injection.",
        "CWE-362",
        "Reliability",
        frozenset({".cs"}),
    ),
    Rule(
        "SP389",
        "C# async database query ignoring CancellationToken",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""ToListAsync\s*\(\s*\)|FirstOrDefaultAsync\s*\(\s*\)"""),
        "Async database queries that omit CancellationToken continue executing on database servers even after clients disconnect.",
        "Pass `cancellationToken` parameter to all EF Core async LINQ operations (e.g. `ToListAsync(cancellationToken)`).",
        "CWE-400",
        "Capacity",
        frozenset({".cs"}),
    ),
    Rule(
        "SP390",
        "Rust unwrap or expect on fallible network operation",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""(?:reqwest|hyper|tokio::net)[^\n]*\.(?:unwrap|expect)\s*\("""),
        "Calling .unwrap() on network I/O operations will panic the thread on transient connection drops or timeouts.",
        "Propagate errors with the `?` operator or handle failures explicitly with `match`.",
        "CWE-703",
        "Reliability",
        frozenset({".rs"}),
    ),
    Rule(
        "SP391",
        "Rust tokio spawn without error handling or JoinHandle storage",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""\btokio::spawn\s*\("""),
        "tokio::spawn is called without storing the JoinHandle, causing panics in the spawned task to fail silently.",
        "Store the JoinHandle and inspect its output with `handle.await?` or log internal task failures.",
        "CWE-703",
        "Reliability",
        frozenset({".rs"}),
    ),
    Rule(
        "SP392",
        "Rust std Mutex held across await point blocking tokio runtime",
        "scale",
        "high",
        "high",
        compile_pattern(r"""std::sync::Mutex[\s\S]*?\.lock\(\)[\s\S]*?\.await"""),
        "Holding a std::sync::MutexGuard across an `.await` boundary blocks the underlying Tokio worker thread from processing other tasks.",
        "Use `tokio::sync::Mutex` or restructure code so the lock guard is dropped before calling `.await`.",
        "CWE-400",
        "Capacity",
        frozenset({".rs"}),
    ),
    Rule(
        "SP393",
        "Rust unbounded mpsc channel causing memory exhaustion",
        "scale",
        "high",
        "high",
        compile_pattern(r"""tokio::sync::mpsc::unbounded_channel\s*\("""),
        "Unbounded mpsc channels do not exert backpressure on producers, allowing memory to grow unbounded during slow consumer lags.",
        "Use bounded `tokio::sync::mpsc::channel(capacity)` with backpressure.",
        "CWE-400",
        "Capacity",
        frozenset({".rs"}),
    ),
    Rule(
        "SP394",
        "Rust blocking std fs operations inside async context",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""async\s+fn\s+[a-zA-Z0-9_]+[\s\S]*?std::fs::(?:read|write|read_to_string)\s*\("""
        ),
        "Calling synchronous std::fs operations inside async functions stalls Tokio runtime workers.",
        "Use `tokio::fs` asynchronous file APIs or `tokio::task::spawn_blocking`.",
        "CWE-400",
        "Capacity",
        frozenset({".rs"}),
    ),
    Rule(
        "SP395",
        "PHP PDO error mode silent masking database query failures",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""PDO::ATTR_ERRMODE\s*=>\s*PDO::ERRMODE_SILENT"""),
        "PDO configured with ERRMODE_SILENT swallows SQL syntax errors and constraint failures without throwing exceptions.",
        "Configure `PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION`.",
        "CWE-703",
        "Reliability",
        frozenset({".php"}),
    ),
    Rule(
        "SP396",
        "PHP file_get_contents on remote URL without timeout context",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""file_get_contents\s*\(\s*['"]https?:\/\/[^'"]+['"]\s*\)"""),
        "file_get_contents() on remote URLs uses default infinite timeout, hanging PHP-FPM worker processes indefinitely.",
        "Create a stream context with `http => ['timeout' => 5]` and pass to file_get_contents().",
        "CWE-400",
        "Reliability",
        frozenset({".php"}),
    ),
    Rule(
        "SP397",
        "Ruby Net::HTTP request instantiated without read_timeout",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""Net::HTTP\.(?:start|new)\s*\([^\)]+(?!read_timeout)[^\)]*\)"""),
        "Net::HTTP without explicit read_timeout uses default 60-second timeouts, tying up Puma/Unicorn worker threads.",
        "Set `http.read_timeout = 5` and `http.open_timeout = 2` on Net::HTTP objects.",
        "CWE-400",
        "Reliability",
        frozenset({".rb"}),
    ),
    Rule(
        "SP398",
        "Ruby ActiveRecord queries in view templates causing N+1 query storm",
        "scale",
        "high",
        "high",
        compile_pattern(r"""<%[^\n]*\.(?:all|where|find_by|each)[^\n]*%>"""),
        "Executing ActiveRecord database queries directly inside ERB view templates causes severe N+1 query storms.",
        "Pre-load associations in the controller using `.includes()` and pass pre-fetched collections to views.",
        "CWE-400",
        "Capacity",
        frozenset({".erb", ".html.erb"}),
    ),
    Rule(
        "SP399",
        "Redis unbounded KEYS pattern query in production code",
        "scale",
        "critical",
        "high",
        compile_pattern(r"""\.(?:keys|KEYS)\s*\(\s*['"][^'"]*\*"""),
        "Executing Redis KEYS * command scans the entire keyspace synchronously, freezing the single-threaded Redis engine.",
        "Use Redis SCAN cursor-based iteration (`SCAN 0 MATCH ... COUNT 100`) instead of KEYS.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP400",
        "Redis sorted set or hash query without pagination limit",
        "scale",
        "high",
        "high",
        compile_pattern(r"""\.(?:zrange|zrevrange)\s*\([^\)]*,\s*0\s*,\s*-1\s*\)|\.hgetall\s*\("""),
        "Fetching all elements from large Redis hashes or sorted sets (ZRANGE 0 -1, HGETALL) causes high network and memory latency spikes.",
        "Use `HSCAN` / `ZSCAN` or bounded range queries with explicit limit and offset offsets.",
        "CWE-400",
        "Capacity",
    ),
    Rule(
        "SP401",
        "Express app without helmet",
        "security",
        "medium",
        "medium",
        compile_pattern(r"""$^"""),
        "Express app is created without security middleware (helmet).",
        "Add app.use(helmet()) to set security headers (CSP, HSTS, X-Frame-Options, etc.).",
        "CWE-693",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".mjs", ".cjs"}),
    ),
    Rule(
        "SP402",
        "Express auth route without rate limiting",
        "security",
        "medium",
        "low",
        compile_pattern(r"""$^"""),
        "An authentication-sensitive Express route is registered without visible rate-limiting middleware.",
        "Add rate-limiting middleware (e.g. express-rate-limit) or verify the gateway throttles these routes.",
        "CWE-307",
        "OWASP ASVS V2",
        frozenset({".js", ".ts", ".mjs", ".cjs"}),
    ),
    Rule(
        "SP403",
        "Secret in NEXT_PUBLIC_ env var",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""NEXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*[:=]"""
        ),
        "A NEXT_PUBLIC_ environment variable name suggests a secret that will be exposed to all users in the client bundle.",
        "Move secret values to server-only environment variables (without the NEXT_PUBLIC_ prefix).",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset(set()),
    ),
    Rule(
        "SP404",
        "Django SECRET_KEY hardcoded",
        "security",
        "critical",
        "high",
        compile_pattern(r"""SECRET_KEY\s*=\s*["'][^"']{20,}["']"""),
        "Django SECRET_KEY is hardcoded in a settings file.",
        "Load SECRET_KEY from an environment variable or a secrets manager.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset({".py"}),
        redact=True,
    ),
    Rule(
        "SP405",
        "Django ALLOWED_HOSTS accepts all",
        "security",
        "high",
        "high",
        compile_pattern(r"""\b(?-i:ALLOWED_HOSTS)\s*=\s*\[["']\*["']\]"""),
        "Django ALLOWED_HOSTS accepts any hostname, disabling host header validation.",
        "Set ALLOWED_HOSTS to explicit trusted domains.",
        "CWE-20",
        "OWASP ASVS V13",
        frozenset({".py"}),
    ),
    Rule(
        "SP406",
        "Express error sent to client",
        "security",
        "medium",
        "low",
        compile_pattern(r"""res\.(?:json|send)\s*\(\s*(?:err|error)\b"""),
        "An Express error handler appears to send the raw error object to the client.",
        "Return a generic error message and status code. Log the full error server-side.",
        "CWE-209",
        "OWASP ASVS V7",
        frozenset({".js", ".ts", ".mjs", ".cjs"}),
    ),
    Rule(
        "SP407",
        "Cookie session routes without CSRF protection",
        "security",
        "medium",
        "low",
        compile_pattern(r"""$^"""),
        "State-changing routes rely on cookie sessions without visible CSRF middleware.",
        "Add CSRF middleware (e.g. csurf) for cookie-authenticated routes or switch to token authentication.",
        "CWE-352",
        "OWASP ASVS V3",
        frozenset({".js", ".ts", ".mjs", ".cjs"}),
    ),
    Rule(
        "SP408",
        "Meta-framework config without CSP header",
        "security",
        "medium",
        "low",
        compile_pattern(r"""$^"""),
        "A Next.js or Nuxt configuration file does not set a Content-Security-Policy header.",
        "Add a Content-Security-Policy header in the framework config or verify the proxy sets one.",
        "CWE-693",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".mjs", ".cjs"}),
    ),
    Rule(
        "SP409",
        "FastAPI route missing response_model schema",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""@app\.(?:get|post|put|delete|patch)\s*\([^)]*response_model\s*=\s*(?:None|dict|Any|object)\b"""
        ),
        "FastAPI route handler disables output schema filtering via response_model=None/dict/Any, risking internal field leakage.",
        "Define an explicit Pydantic response_model on route decorators to filter output fields.",
        "CWE-200",
        "OWASP ASVS V4",
        frozenset({".py"}),
    ),
    Rule(
        "SP410",
        "Flask secret key set to hardcoded constant",
        "security",
        "critical",
        "high",
        compile_pattern(r"""app\.secret_key\s*=\s*["'][^"'\s]+["']"""),
        "Flask app.secret_key is set to a static hardcoded string in source code.",
        "Load app.secret_key from environment variables (e.g. os.environ['FLASK_SECRET_KEY']).",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset({".py"}),
        redact=True,
    ),
    Rule(
        "SP411",
        "Django debug mode enabled in settings",
        "security",
        "high",
        "high",
        compile_pattern(r"""^\s*DEBUG\s*=\s*True\b"""),
        "Django settings have DEBUG mode enabled directly, risking source code and trace exposure in production.",
        "Set DEBUG = os.getenv('DJANGO_DEBUG', 'False').lower() == 'true'.",
        "CWE-489",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP412",
        "Express body-parser with excessive payload limit",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""bodyParser\.(?:json|urlencoded)\s*\(\s*\{[^}]*limit\s*:\s*["'](?:50|100|500)mb["']"""
        ),
        "Express body parser is configured with excessive JSON payload limits (50mb+), allowing Memory DoS.",
        "Restrict body parser limits to reasonable payload sizes (e.g. limit: '1mb') and stream large file uploads.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP413",
        "Next.js middleware missing static asset exclusion",
        "performance",
        "medium",
        "medium",
        compile_pattern(
            r"""export\s+const\s+config\s*=\s*\{[^}]*matcher:\s*["']/:path\*["'](?!.*_next)"""
        ),
        "Next.js middleware runs on all paths including _next/static, images, and favicon, multiplying serverless invocations.",
        "Add negative matcher patterns to exclude static assets: matcher: ['/((?!_next|favicon.ico).*)'].",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP414",
        "React list rendering using array index as key",
        "correctness",
        "low",
        "medium",
        compile_pattern(
            r"""\.map\s*\(\s*\([^,)]+,\s*(?:index|idx|i)\s*\)\s*=>\s*<[a-zA-Z0-9_]+\s+[^>]*key\s*=\s*\{\s*(?:index|idx|i)\s*\}"""
        ),
        "React list rendering uses array index as key prop, leading to incorrect DOM reconciliation and state bugs on reorder.",
        "Use unique, stable entity IDs (e.g. item.id) as the key prop.",
        "CWE-398",
        "Reliability",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP415",
        "Vue v-html directive with dynamic property",
        "security",
        "high",
        "medium",
        compile_pattern(r"""v-html\s*=\s*["'](?![^"']*sanitize)[a-zA-Z0-9_.]+["']"""),
        "Vue v-html directive renders raw dynamic HTML without visible sanitization, creating XSS vulnerabilities.",
        "Use DOMPurify to sanitize HTML or use standard mustache interpolation.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".html", ".vue"}),
    ),
    Rule(
        "SP416",
        "Spring Boot actuator endpoints exposed publicly",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""management\.endpoints\.web\.exposure\.include\s*=\s*(?:\*|all|env|heapdump)"""
        ),
        "Spring Boot Actuator endpoints (env, heapdump) are exposed without security authentication.",
        "Restrict exposure to health and info, or require administrative credentials: include=health,info.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".yaml", ".properties", ".yml"}),
    ),
    Rule(
        "SP417",
        "Ruby on Rails protect_from_forgery disabled",
        "security",
        "high",
        "high",
        compile_pattern(r"""skip_before_action\s+:verify_authenticity_token\b"""),
        "Rails CSRF protection is globally skipped, making application vulnerable to Cross-Site Request Forgery.",
        "Enable protect_from_forgery with: :exception on ApplicationController.",
        "CWE-352",
        "OWASP ASVS V3",
        frozenset({".rb"}),
    ),
    Rule(
        "SP418",
        "ASP.NET Core UseDeveloperExceptionPage in production",
        "security",
        "high",
        "high",
        compile_pattern(r"""app\.UseDeveloperExceptionPage\s*\(\s*\)\s*;\s*//\s*unconditional"""),
        "UseDeveloperExceptionPage is called unconditionally outside if (app.Environment.IsDevelopment()) blocks.",
        "Wrap UseDeveloperExceptionPage inside if (app.Environment.IsDevelopment()) guard blocks.",
        "CWE-209",
        "OWASP ASVS V7",
        frozenset({".cs"}),
    ),
    Rule(
        "SP419",
        "FastAPI CORS allows wildcard with credentials",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""CORSMiddleware[^)]*allow_origins\s*=\s*\[\s*["']\*["']\s*\][^)]*allow_credentials\s*=\s*True"""
        ),
        "FastAPI CORSMiddleware is configured with wildcard allow_origins and allow_credentials=True.",
        "Specify an explicit list of trusted origin domains when allow_credentials is enabled.",
        "CWE-942",
        "OWASP ASVS V3",
        frozenset({".py"}),
    ),
    Rule(
        "SP420",
        "Next.js Server Action without authorization",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""["']use server["'];\s*\n\s*export\s+async\s+function\s+[a-zA-Z0-9_]+\([^)]*\)\s*\{(?![^}]{0,4000}\b(?:auth|getServerSession|getSession|currentUser|verifySession|requireAuth|requireUser)\s*\()"""
        ),
        "Next.js Server Action is exported without checking user authentication or permissions in the action body.",
        "Verify user session and permissions at the beginning of every Server Action.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP421",
        "Next.js Server Action missing authorization check",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""['"]use\s+server['"][;\s]*\n(?:export\s+)?async\s+function\s+[a-zA-Z0-9_]+\s*\([^\)]*\)\s*\{(?![^}]*(?:auth|session|getServerSession|currentUser|verifySession))"""
        ),
        "A Next.js Server Action ('use server') performs mutations without verifying user session or role permissions.",
        "Verify authentication at the start of every Server Action: `const session = await auth(); if (!session) throw new Error('Unauthorized');`.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP422",
        "Next.js generateStaticParams fetching unbounded external API without limit",
        "scale",
        "medium",
        "high",
        compile_pattern(
            r"""export\s+async\s+function\s+generateStaticParams\s*\(\s*\)\s*\{[\s\S]*?fetch\s*\([^\)]+\)(?!\s*\.slice)"""
        ),
        "generateStaticParams fetches an unbounded collection for static generation, risking build timeouts and memory crashes on large datasets.",
        "Paginate or slice static params generation: `return items.slice(0, 1000).map(...)`.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP424",
        "React state mutated directly bypassing setState",
        "correctness",
        "high",
        "high",
        compile_pattern(
            r"""this\.state\.[a-zA-Z0-9_]+\s*=\s*|[a-zA-Z0-9_]+State\.[a-zA-Z0-9_]+\.push\s*\("""
        ),
        "Mutating React state directly prevents component re-rendering and corrupts component lifecycle.",
        "Use immutable state updates with `setState()` or `setItems(prev => [...prev, newItem])`.",
        "CWE-662",
        "Correctness",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP425",
        "Vue v-html directive rendering untrusted content",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""v-html\s*=\s*["'](?:user|item|comment|post|message)\.[a-zA-Z0-9_]+["']"""
        ),
        "Vue v-html directive renders unescaped HTML, creating XSS vulnerabilities when displaying user data.",
        "Use `v-text` or `{{ text }}` text interpolation, or sanitize HTML with DOMPurify.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".html", ".vue"}),
    ),
    Rule(
        "SP426",
        "Svelte @html tag rendering unescaped content",
        "security",
        "high",
        "high",
        compile_pattern(r"""\{@html\s+(?:user|item|comment|data)\.[a-zA-Z0-9_]+\}"""),
        "Svelte {@html} tag injects unescaped HTML directly into the DOM, risking XSS.",
        "Use standard Svelte `{value}` text bindings or pass through DOMPurify.sanitize().",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".svelte", ".html"}),
    ),
    Rule(
        "SP427",
        "Express helmet middleware explicitly disabling standard protections",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""helmet\s*\(\s*\{[^\}]*(?:contentSecurityPolicy\s*:\s*false|frameguard\s*:\s*false|hidePoweredBy\s*:\s*false)"""
        ),
        "Express helmet() middleware is instantiated with essential security protections disabled.",
        "Keep helmet default protections enabled or configure specific restrictive directives.",
        "CWE-1021",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".mjs"}),
    ),
    Rule(
        "SP428",
        "Express error handling middleware exposing stack traces to client",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""app\.use\s*\(\s*\(\s*err\s*,\s*req\s*,\s*res\s*,\s*next\s*\)\s*=>\s*\{[^}]*res\.(?:send|json)\s*\(\s*err(?:\.stack)?\s*\)"""
        ),
        "Express error handler sends internal Error objects or stack traces directly to the client response.",
        "Log the full error internally and send generic sanitized error messages to clients.",
        "CWE-209",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".mjs"}),
    ),
    Rule(
        "SP430",
        "Express session using default in-memory MemoryStore in production",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""app\.use\s*\(\s*session\s*\(\s*\{[^\}]*(?!store\s*:)[^\}]*\}\s*\)\s*\)"""
        ),
        "express-session without an explicit store uses MemoryStore, which leaks memory and does not scale across instances.",
        "Use Redis (`connect-redis`), PostgreSQL (`connect-pg-simple`), or DynamoDB session stores.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".mjs"}),
    ),
    Rule(
        "SP431",
        "NestJS global ValidationPipe missing whitelist option",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""new\s+ValidationPipe\s*\(\s*\{[^\}]*(?!whitelist\s*:\s*true)[^\}]*\}|new\s+ValidationPipe\s*\(\s*\)"""
        ),
        "NestJS ValidationPipe without `whitelist: true` accepts non-whitelisted properties, enabling mass assignment attacks.",
        "Configure `new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`.",
        "CWE-915",
        "OWASP ASVS V5",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP432",
        "NestJS controller administrative endpoint missing UseGuards decorator",
        "security",
        "high",
        "high",
        compile_pattern(r"""@Controller\s*\(\s*['"]admin[^\n]*\n(?![^@]*@UseGuards)"""),
        "A NestJS admin controller is defined without a class-level `@UseGuards(AuthGuard)` decorator.",
        "Add `@UseGuards(JwtAuthGuard, RolesGuard)` to protect all admin endpoints.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".ts"}),
    ),
    Rule(
        "SP433",
        "Fastify route missing input schema validation definition",
        "security",
        "medium",
        "high",
        compile_pattern(r"""fastify\.(?:post|put|patch)\s*\([^\)]+,\s*async\s*\([^\)]*\)\s*=>"""),
        "A Fastify mutating route is declared without a route `schema` definition (body/params validation).",
        "Define an explicit `schema: { body: Type.Object(...) }` for high performance and input safety.",
        "CWE-20",
        "OWASP ASVS V5",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP434",
        "Fastify server missing connectionTimeout configuration",
        "reliability",
        "medium",
        "high",
        compile_pattern(
            r"""Fastify\s*\(\s*\{[^\}]*(?!connectionTimeout)[^\}]*\}|fastify\s*\(\s*\)"""
        ),
        "Fastify instance is initialized without explicit connectionTimeout, risking slowloris connection saturation.",
        "Configure `connectionTimeout: 10000` (10s) and `keepAliveTimeout: 5000` in Fastify options.",
        "CWE-400",
        "Reliability",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP435",
        "Django DEBUG mode hardcoded in settings file",
        "security",
        "critical",
        "high",
        compile_pattern(r"""^DEBUG\s*=\s*True\s*$"""),
        "DEBUG is hardcoded to True in Django settings, exposing interactive tracebacks and environment secrets in prod.",
        "Load DEBUG from environment: `DEBUG = os.getenv('DJANGO_DEBUG', 'False').lower() == 'true'`.",
        "CWE-489",
        "OWASP ASVS V13",
        frozenset({".py"}),
    ),
    Rule(
        "SP436",
        "Django ALLOWED_HOSTS configured with wildcard in settings",
        "security",
        "high",
        "high",
        compile_pattern(r"""^ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]"""),
        "Setting ALLOWED_HOSTS to wildcard in Django allows Host header poisoning attacks.",
        "Specify exact domain names: `ALLOWED_HOSTS = ['app.example.com', 'api.example.com']`.",
        "CWE-644",
        "OWASP ASVS V13",
        frozenset({".py"}),
    ),
    Rule(
        "SP437",
        "Django SECRET_KEY hardcoded string literal in settings",
        "security",
        "critical",
        "high",
        compile_pattern(r"""^SECRET_KEY\s*=\s*['"][^'"]{10,120}['"]"""),
        "Django SECRET_KEY is hardcoded in settings.py, allowing anyone with source code access to forge sessions.",
        "Load SECRET_KEY from environment variables: `SECRET_KEY = os.environ['DJANGO_SECRET_KEY']`.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP438",
        "Django SESSION_COOKIE_SECURE explicitly disabled",
        "security",
        "high",
        "high",
        compile_pattern(r"""^SESSION_COOKIE_SECURE\s*=\s*False"""),
        "Django SESSION_COOKIE_SECURE is set to False, allowing session cookies to be transmitted over plaintext HTTP.",
        "Set `SESSION_COOKIE_SECURE = True` and `CSRF_COOKIE_SECURE = True` in production settings.",
        "CWE-614",
        "OWASP ASVS V3",
        frozenset({".py"}),
    ),
    Rule(
        "SP439",
        "Django ORM extra() method used with format string",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\.extra\s*\([^\)]*where\s*=\s*\[\s*f['"]"""),
        "Django QuerySet.extra() with formatted where parameter introduces SQL injection vulnerabilities.",
        "Avoid extra() (deprecated); use standard QuerySet methods or RawSQL with parameterized params.",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP440",
        "FastAPI route missing response_model schema definition",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""@(?:app|router)\.(?:get|post)\s*\([^\)]+(?!response_model\s*=)[^\)]*\)\s*\n(?:async\s+)?def\s+[a-zA-Z0-9_]+\s*\([^)]*\)\s*->\s*(?:dict|Any):"""
        ),
        "A FastAPI endpoint returns raw dictionaries without a response_model, risking accidental serialization of internal password hashes.",
        "Specify explicit `response_model=UserResponseDTO` to filter output fields.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP441",
        "Flask app secret_key set to hardcoded string literal",
        "security",
        "critical",
        "high",
        compile_pattern(r"""app\.secret_key\s*=\s*['"][^'"]{6,64}['"]"""),
        "Flask app.secret_key is hardcoded in source code, enabling forged cookie session signatures.",
        "Load secret key from environment: `app.secret_key = os.environ['FLASK_SECRET_KEY']`.",
        "CWE-798",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP442",
        "Flask SESSION_COOKIE_HTTPONLY disabled in configuration",
        "security",
        "high",
        "high",
        compile_pattern(r"""app\.config\[['"]SESSION_COOKIE_HTTPONLY['"]\]\s*=\s*False"""),
        "Disabling SESSION_COOKIE_HTTPONLY allows client-side JavaScript to access session cookies during XSS.",
        "Configure `app.config['SESSION_COOKIE_HTTPONLY'] = True`.",
        "CWE-1004",
        "OWASP ASVS V3",
        frozenset({".py"}),
    ),
    Rule(
        "SP443",
        "Spring Boot Actuator all endpoints exposed over web",
        "security",
        "critical",
        "high",
        compile_pattern(r"""management\.endpoints\.web\.exposure\.include\s*=\s*\*"""),
        "Spring Boot Actuator exposes all operational endpoints including heapdump, env, and shutdown over HTTP.",
        "Expose only health and info: `management.endpoints.web.exposure.include=health,info`.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".yaml", ".properties", ".yml"}),
    ),
    Rule(
        "SP444",
        "Spring Boot H2 in-memory web console enabled in configuration",
        "security",
        "critical",
        "high",
        compile_pattern(r"""spring\.h2\.console\.enabled\s*=\s*true"""),
        "H2 database console is enabled, exposing an unauthenticated web database manager with RCE capabilities.",
        "Disable H2 console in production: `spring.h2.console.enabled=false`.",
        "CWE-284",
        "OWASP ASVS V14",
        frozenset({".yaml", ".properties", ".yml"}),
    ),
    Rule(
        "SP445",
        "Spring Security CSRF protection explicitly disabled",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""\.csrf\(\)\.disable\(\)|\.csrf\([^)]*AbstractHttpConfigurer::disable\)"""
        ),
        "Spring Security CSRF protection is disabled globally, exposing session-authenticated forms to CSRF attacks.",
        "Enable CSRF protection for cookie-authenticated browser endpoints; disable only for stateless token APIs.",
        "CWE-352",
        "OWASP ASVS V3",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP446",
        "Spring Security permitAll on administrative path pattern",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\.requestMatchers\s*\(\s*['"]\/admin\/\*\*['"]\s*\)\.permitAll\(\)"""),
        "Administrative paths matching /admin/** are explicitly permitted to all unauthenticated users in Spring Security.",
        'Require admin role: `.requestMatchers("/admin/**").hasRole("ADMIN")`.',
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP447",
        "Gin framework router missing Recovery panic middleware",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""router\s*:=\s*gin\.New\s*\(\s*\)(?![\s\S]*router\.Use\s*\(\s*gin\.Recovery\s*\(\)\s*\))"""
        ),
        "Gin router initialized with `gin.New()` does not register `gin.Recovery()`, causing panics in route handlers to crash the server.",
        "Use `gin.Default()` or add `router.Use(gin.Recovery())`.",
        "CWE-703",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP448",
        "Fiber framework App initialized without Recover middleware",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""app\s*:=\s*fiber\.New\s*\([^\)]*\)(?![\s\S]*app\.Use\s*\(\s*recover\.New)"""
        ),
        "Fiber web application does not register `recover.New()` middleware, allowing panics to crash the process.",
        "Register `app.Use(recover.New())` immediately after app initialization.",
        "CWE-703",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP449",
        "Ruby on Rails params.permit! blanket mass assignment bypass",
        "security",
        "critical",
        "high",
        compile_pattern(r"""params\.permit!|params\.require\([^\)]+\)\.permit!"""),
        "Using `params.permit!` disables Rails Strong Parameters entirely, enabling mass assignment vulnerabilities.",
        "Explicitly allowlist permitted parameters: `params.require(:user).permit(:name, :email)`.",
        "CWE-915",
        "OWASP ASVS V5",
        frozenset({".rb"}),
    ),
    Rule(
        "SP450",
        "Ruby on Rails config.force_ssl disabled in production",
        "security",
        "high",
        "high",
        compile_pattern(r"""config\.force_ssl\s*=\s*false"""),
        "Rails `config.force_ssl = false` disables HTTPS redirection and HSTS headers in production.",
        "Set `config.force_ssl = true` in `config/environments/production.rb`.",
        "CWE-319",
        "OWASP ASVS V9",
        frozenset({".rb"}),
    ),
    Rule(
        "SP451",
        "Laravel Eloquent model guarded set to empty array",
        "security",
        "high",
        "high",
        compile_pattern(r"""protected\s+\$guarded\s*=\s*\[\s*\];"""),
        "Setting `$guarded = []` in Laravel models completely disables mass assignment protection.",
        "Define an explicit `$fillable` array or specify guarded columns (`$guarded = ['id', 'is_admin']`).",
        "CWE-915",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP452",
        "Laravel DB::raw query constructed with string concatenation",
        "security",
        "critical",
        "high",
        compile_pattern(r"""DB::raw\s*\(\s*['"][^'"]*[\$\.]|\bwhereRaw\s*\(\s*['"][^'"]*[\$\.]"""),
        "Laravel DB::raw() or whereRaw() with string concatenation bypasses PDO parameter binding.",
        "Use parameterized query bindings: `DB::raw('SELECT * WHERE id = ?', [$id])`.",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP453",
        "ASP.NET Core DeveloperExceptionPage enabled in non-development",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""app\.UseDeveloperExceptionPage\s*\(\s*\)(?![\s\S]*if\s*\(\s*app\.Environment\.IsDevelopment)"""
        ),
        "UseDeveloperExceptionPage() is called unconditionally, exposing source code snippets and environment details in production errors.",
        "Wrap in `if (app.Environment.IsDevelopment()) { app.UseDeveloperExceptionPage(); }`.",
        "CWE-209",
        "OWASP ASVS V14",
        frozenset({".cs"}),
    ),
    Rule(
        "SP454",
        "ASP.NET Core AllowAnonymous attribute on administrative controller",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\[AllowAnonymous\]\s*\n\s*public\s+class\s+Admin[a-zA-Z0-9_]*Controller"""
        ),
        "An administrative controller class is decorated with [AllowAnonymous], granting unauthenticated access to admin actions.",
        'Remove [AllowAnonymous] and apply `[Authorize(Roles = "Admin")]`.',
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".cs"}),
    ),
    Rule(
        "SP455",
        "Angular bypassSecurityTrustHtml called with dynamic input",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""this\.sanitizer\.bypassSecurityTrustHtml\s*\(\s*(?:data|user|input|content)"""
        ),
        "bypassSecurityTrustHtml() bypasses Angular's built-in DomSanitizer, creating stored or DOM XSS.",
        "Avoid bypassing security trust or sanitize with DOMPurify before calling bypass methods.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".ts"}),
    ),
    Rule(
        "SP456",
        "Apollo Server GraphQL introspection enabled in production",
        "security",
        "medium",
        "high",
        compile_pattern(r"""new\s+ApolloServer\s*\(\s*\{[^\}]*introspection\s*:\s*true"""),
        "GraphQL introspection is explicitly enabled in production, exposing entire internal schema definitions to attackers.",
        "Set `introspection: process.env.NODE_ENV !== 'production'` in Apollo Server options.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP457",
        "tRPC mutation procedure declared without input validation schema",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""publicProcedure[^\.]*\.mutation\s*\(\s*async\s*\(\s*\{[^\}]*input[^\}]*\}\s*\)"""
        ),
        "A tRPC mutation handles input without defining a `.input(z.object(...))` Zod validation schema.",
        "Add a Zod input validator: `publicProcedure.input(z.object({ id: z.string().uuid() })).mutation(...)`.",
        "CWE-20",
        "OWASP ASVS V5",
        frozenset({".ts"}),
    ),
    Rule(
        "SP458",
        "Prisma schema Float type used for monetary currency fields",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"""(?:price|amount|balance|cost|fee|total)\s+Float\b"""),
        "Using Float in Prisma schema for monetary balances causes floating-point rounding inaccuracies.",
        "Use `Decimal @db.Decimal(10, 2)` or integer cents (`Int`) in Prisma schema.",
        "CWE-682",
        "Correctness",
        frozenset({".prisma"}),
    ),
    Rule(
        "SP459",
        "Drizzle ORM sql.raw query constructed with f-string interpolation",
        "security",
        "critical",
        "high",
        compile_pattern(r"""sql\.raw\s*\(\s*`[^`]*\$\{"""),
        "sql.raw() in Drizzle ORM concatenates raw template strings without parameterization, causing SQL injection.",
        "Use the `sql` template tag directly: `sql`SELECT * FROM users WHERE id = ${userId}``.",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP460",
        "Knex query builder raw query built by string concatenation",
        "security",
        "critical",
        "high",
        compile_pattern(r"""knex\.raw\s*\(\s*`[^`]*\$\{|knex\.raw\s*\(\s*['"][^'"]*\+"""),
        "Knex.raw() receives raw template literals instead of parameterized bindings, causing SQL injection.",
        "Use Knex positional bindings: `knex.raw('SELECT * FROM users WHERE id = ?', [userId])`.",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP461",
        "Remix loader function returning sensitive entity directly",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""export\s+(?:async\s+)?const\s+loader\s*=\s*async\s*\([^\)]*\)\s*=>\s*\{[\s\S]*?return\s+json\s*\(\s*(?:user|account)\s*\)"""
        ),
        "A Remix loader returns entire database models directly to the client bundle, potentially leaking password hashes and tokens.",
        "Select and return only required safe fields: `return json({ id: user.id, name: user.name })`.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP462",
        "Astro API endpoint missing CSRF origin verification on POST handler",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""export\s+const\s+POST\s*:\s*APIRoute\s*=\s*async\s*\([^\)]*\)\s*=>\s*\{(?![^}]*origin)"""
        ),
        "An Astro API POST route handler processes form mutations without validating Origin or Sec-Fetch-Site headers.",
        "Verify `request.headers.get('origin') === expectedOrigin` or use Astro's `security.checkOrigin` option.",
        "CWE-352",
        "OWASP ASVS V3",
        frozenset({".js", ".ts", ".astro"}),
    ),
    Rule(
        "SP463",
        "Next.js Route Handler missing rate limit or authorization in sensitive action",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""export\s+async\s+function\s+DELETE\s*\([^\)]*\)\s*\{(?![^}]*(?:auth|session|token|apiKey))"""
        ),
        "A Next.js DELETE route handler executes without checking caller authentication or role permissions.",
        "Verify session authentication before proceeding with resource deletion.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP464",
        "Express app trust proxy configured insecurely with true",
        "security",
        "medium",
        "high",
        compile_pattern(r"""app\.set\s*\(\s*['"]trust\s+proxy['"]\s*,\s*true\s*\)"""),
        "Setting `trust proxy: true` unconditionally in Express allows clients to spoof their client IP via X-Forwarded-For headers.",
        "Configure trust proxy with specific subnet CIDRs or hop counts (e.g. `app.set('trust proxy', 'loopback')`).",
        "CWE-345",
        "OWASP ASVS V14",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP465",
        "FastAPI background task created without error handling wrapper",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""background_tasks\.add_task\s*\(\s*[a-zA-Z0-9_]+\s*,\s*[^\)]*\)"""),
        "FastAPI BackgroundTasks run after response transmission; unhandled exceptions inside background tasks fail silently.",
        "Wrap background task functions in a top-level try/except block with error alerting.",
        "CWE-703",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP466",
        "Django transaction.atomic missing in multi-table mutation endpoint",
        "reliability",
        "medium",
        "high",
        compile_pattern(
            r"""def\s+[a-zA-Z0-9_]+\s*\([^\)]*request[^\)]*\):\s*\n(?![^@]*@transaction\.atomic)[\s\S]*?\.create\([^\)]*\)[\s\S]*?\.create\([^\)]*\)"""
        ),
        "A Django view executes multiple model create() operations without a transaction.atomic block, risking database inconsistency on partial failure.",
        "Decorate the view with `@transaction.atomic` or wrap mutations in `with transaction.atomic():`.",
        "CWE-662",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP467",
        "Spring Boot multipart file upload without maxFileSize limit",
        "scale",
        "medium",
        "high",
        compile_pattern(
            r"""spring\.servlet\.multipart\.enabled\s*=\s*true(?![\s\S]*max-file-size)"""
        ),
        "Spring Boot multipart upload enabled without explicit max-file-size and max-request-size limits.",
        "Set `spring.servlet.multipart.max-file-size=10MB` and `spring.servlet.multipart.max-request-size=10MB`.",
        "CWE-400",
        "Capacity",
        frozenset({".yaml", ".properties", ".yml"}),
    ),
    Rule(
        "SP468",
        "Ktor HTTP client engine missing timeout configuration",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""HttpClient\s*\([^\)]*\)\s*\{[^\}]*(?!install\s*\(\s*HttpTimeout\s*\))"""
        ),
        "Ktor HttpClient is instantiated without the HttpTimeout plugin installed, allowing calls to hang indefinitely.",
        "Install HttpTimeout: `install(HttpTimeout) { requestTimeoutMillis = 10000; connectTimeoutMillis = 5000 }`.",
        "CWE-400",
        "Reliability",
        frozenset({".kt"}),
    ),
    Rule(
        "SP469",
        "Symfony controller missing IsGranted security attribute",
        "security",
        "high",
        "high",
        compile_pattern(r"""#\[Route\s*\(\s*['"]\/admin[^\n]*\n(?![^#]*#\[IsGranted)"""),
        "A Symfony admin route controller is declared without an `#[IsGranted('ROLE_ADMIN')]` attribute.",
        "Add `#[IsGranted('ROLE_ADMIN')]` attribute above the controller class or action method.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".php"}),
    ),
    Rule(
        "SP470",
        "Phoenix LiveView mount callback missing session token verification",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""def\s+mount\s*\([^\)]*session[^\)]*\)\s*do(?![^e]*Accounts\.get_user_by_session_token)"""
        ),
        "Phoenix LiveView mount/3 callback mounts without verifying the current user session token.",
        "Authenticate live session in on_mount hook: `Accounts.get_user_by_session_token(token)`.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".ex"}),
    ),
    Rule(
        "SP471",
        "FastAPI CORS middleware configured with allow_origins wildcard and allow_credentials",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""add_middleware\s*\(\s*CORSMiddleware[\s\S]*allow_origins\s*=\s*\[\s*['"]\*['"]\s*\][\s\S]*allow_credentials\s*=\s*True"""
        ),
        "FastAPI CORSMiddleware with wildcard origin and allow_credentials permitted enables credential theft.",
        "Specify explicit trusted origins list or set allow_credentials=False for public APIs.",
        "CWE-942",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP472",
        "Flask-CORS configured with origins wildcard and supports_credentials",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""CORS\s*\([^\)]*origins\s*=\s*['"]\*['"][^\)]*supports_credentials\s*=\s*True"""
        ),
        "Flask-CORS with wildcard origin and supports_credentials=True exposes user session cookies to cross-origin attackers.",
        "Specify exact origin domain allowlist in CORS configuration.",
        "CWE-942",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP473",
        "NestJS CORS configuration with origin true reflection",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""app\.enableCors\s*\(\s*\{[^\}]*origin\s*:\s*true[^\}]*credentials\s*:\s*true"""
        ),
        "NestJS enableCors with origin: true reflects any incoming Origin header while allowing credentials.",
        "Configure an explicit array of allowed origin strings: `origin: ['https://app.example.com']`.",
        "CWE-942",
        "OWASP ASVS V14",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP474",
        "Spring Boot WebMvcConfigurer addCorsMappings wildcard credentials",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\.allowedOrigins\s*\(\s*['"]\*['"]\s*\)[\s\S]*\.allowCredentials\s*\(\s*true\s*\)"""
        ),
        "Spring WebMvc CORS with allowedOrigins('*') and allowCredentials(true) causes browser security exceptions or token leaks.",
        'Use `.allowedOriginPatterns("https://*.example.com")` or exact origin list.',
        "CWE-942",
        "OWASP ASVS V14",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP475",
        "Express rate-limit missing keyGenerator using default IP behind reverse proxy",
        "security",
        "medium",
        "high",
        compile_pattern(r"""rateLimit\s*\(\s*\{[^\}]*(?!keyGenerator)[^\}]*\}\s*\)"""),
        "express-rate-limit without keyGenerator uses req.ip; behind a reverse proxy without trust proxy, all clients share one bucket.",
        "Set `app.set('trust proxy', 1)` or configure custom `keyGenerator` based on authenticated user ID or verified IP.",
        "CWE-307",
        "OWASP ASVS V13",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP476",
        "Next.js dangerouslySetInnerHTML used inside component",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!['"]<)[a-zA-Z0-9_.]+\s*\}\s*\}"""
        ),
        "dangerouslySetInnerHTML renders dynamic HTML, exposing client applications to DOM-based XSS attacks.",
        "Sanitize HTML with DOMPurify: `__html: DOMPurify.sanitize(content)`.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP477",
        "Nuxt 3 useFetch missing server: false in client-only mutations",
        "reliability",
        "medium",
        "high",
        compile_pattern(
            r"""useFetch\s*\([^\)]+method\s*:\s*['"]POST['"][^\)]*(?!server\s*:\s*false)"""
        ),
        "Nuxt 3 useFetch with POST method runs on SSR server render unless `server: false` is configured, duplicate-firing mutations.",
        "Use `$fetch` inside event handlers or set `{ server: false }` on useFetch mutations.",
        "CWE-662",
        "Reliability",
        frozenset({".js", ".ts", ".vue"}),
    ),
    Rule(
        "SP478",
        "FastAPI unhandled HTTPException re-thrown losing details",
        "correctness",
        "medium",
        "high",
        compile_pattern(
            r"""except\s+HTTPException:\s*\n\s*raise\s+HTTPException\s*\(\s*status_code\s*=\s*500"""
        ),
        "Catching HTTPException and blindly re-raising 500 masks intentional 400/401/404 business error codes.",
        "Let HTTPException propagate directly or catch specific Database/Network exceptions.",
        "CWE-703",
        "Correctness",
        frozenset({".py"}),
    ),
    Rule(
        "SP479",
        "Django CSRF_TRUSTED_ORIGINS missing https scheme",
        "security",
        "high",
        "high",
        compile_pattern(r"""CSRF_TRUSTED_ORIGINS\s*=\s*\[[^\n]*['"]http:\/\/"""),
        "CSRF_TRUSTED_ORIGINS configured with plain http:// allows CSRF bypass over insecure HTTP connections in production.",
        "Use https:// in all CSRF_TRUSTED_ORIGINS entries: `CSRF_TRUSTED_ORIGINS = ['https://app.example.com']`.",
        "CWE-352",
        "OWASP ASVS V3",
        frozenset({".py"}),
    ),
    Rule(
        "SP480",
        "Laravel route definition without rate limiting middleware",
        "scale",
        "medium",
        "high",
        compile_pattern(
            r"""Route::post\s*\(\s*['"](?:login|register|password\/reset|otp)[\s\S]*?(?!->middleware\s*\(\s*['"]throttle)"""
        ),
        "Sensitive authentication route in Laravel does not attach the `throttle:6,1` rate limiting middleware.",
        "Attach throttle middleware: `Route::post('/login', ...)->middleware('throttle:5,1');`.",
        "CWE-307",
        "OWASP ASVS V13",
        frozenset({".php"}),
    ),
    Rule(
        "SP481",
        "Spring Boot Jackson deserialization default typing enabled",
        "security",
        "critical",
        "high",
        compile_pattern(r"""objectMapper\.enableDefaultTyping\s*\("""),
        "Jackson enableDefaultTyping() permits arbitrary polymorphic class instantiation, causing remote code execution.",
        "Use `@JsonTypeInfo` with explicit subtype allowlists instead of global default typing.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP482",
        "Gin framework c.BindJSON ignoring binding validation error",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""c\.BindJSON\s*\([^\)]+\)(?!\s*==\s*nil|\s*!=\s*nil|\s*;\s*err)"""),
        "Calling c.BindJSON() without inspecting the returned error causes handlers to process uninitialized, zero-value structs.",
        'Check error: `if err := c.ShouldBindJSON(&req); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }`.',
        "CWE-703",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP483",
        "Fiber framework c.BodyParser ignoring returned error",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""c\.BodyParser\s*\([^\)]+\)(?!\s*==\s*nil|\s*!=\s*nil|\s*;\s*err)"""),
        "Fiber c.BodyParser() result is ignored, allowing invalid payloads to execute downstream business logic.",
        "Check error: `if err := c.BodyParser(&req); err != nil { return c.Status(400).SendString(err.Error()) }`.",
        "CWE-703",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP484",
        "Echo framework c.Bind ignoring deserialization error",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""c\.Bind\s*\([^\)]+\)(?!\s*==\s*nil|\s*!=\s*nil|\s*;\s*err)"""),
        "Echo c.Bind() error is discarded, causing corrupted or empty request payloads to pass through.",
        "Handle error: `if err := c.Bind(&req); err != nil { return echo.NewHTTPError(400, err.Error()) }`.",
        "CWE-703",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP485",
        "NestJS microservice transport connection without retry strategy",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""Transport\.(?:REDIS|KAFKA|RMQ)[^\n]*(?!retryAttempts)"""),
        "NestJS Microservice client is configured without retryAttempts, causing startup crashes if message brokers are temporarily unavailable.",
        "Configure `options: { retryAttempts: 5, retryDelay: 3000 }` in MicroserviceOptions.",
        "CWE-703",
        "Reliability",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP486",
        "Prisma client instantiated repeatedly inside function scope",
        "scale",
        "critical",
        "high",
        compile_pattern(
            r"""(?:function|const\s+[a-zA-Z0-9_]+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)\s*\{[\s\S]*?const\s+prisma\s*=\s*new\s+PrismaClient\(\)"""
        ),
        "Creating `new PrismaClient()` inside request handler functions creates a new database connection pool on every invocation.",
        "Instantiate PrismaClient once in a dedicated singleton file (e.g. `lib/prisma.ts`) and export it.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP487",
        "FastAPI streaming response without generator exception handling",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""StreamingResponse\s*\(\s*(?!try)[a-zA-Z0-9_]+\s*\(\s*\)\s*,\s*media_type"""
        ),
        "FastAPI StreamingResponse wrapping a generator without an internal try/finally block leaves upstream connections open on client disconnect.",
        "Wrap the generator iteration in a try/finally block to ensure cleanup on client disconnect.",
        "CWE-400",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP488",
        "Django database connection closed inside thread pool worker",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""ThreadPoolExecutor[\s\S]*?django\.db\.connection\.close\(\)"""),
        "Django database connection is closed inside a thread pool worker while the main request thread is still active.",
        "Use `django.db.connections.close_all()` at worker exit and ensure thread-local database state is isolated.",
        "CWE-662",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP489",
        "Fastify decorated request object mutating shared prototype state",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""fastify\.decorateRequest\s*\(\s*['"][a-zA-Z0-9_]+['"]\s*,\s*\{"""),
        "Fastify decorateRequest with an object reference shares that object across all concurrent HTTP requests.",
        "Pass a primitive default (e.g. `null` or `''`) and populate per-request properties inside an onRequest hook.",
        "CWE-362",
        "Reliability",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP490",
        "Next.js middleware matching all static assets causing performance degradation",
        "scale",
        "medium",
        "high",
        compile_pattern(
            r"""export\s+const\s+config\s*=\s*\{\s*\n\s*matcher:\s*\[\s*['"]\/:\s*path\*['"]\s*\]"""
        ),
        "Next.js middleware matcher matches all requests without excluding _next/static, public images, and favicon.",
        "Add negative lookahead matcher: `matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']`.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP501",
        "Unmetered AI/LLM API route",
        "scale",
        "high",
        "medium",
        compile_pattern(
            r"""(?:openai\.(?:chat\.completions|completions|images)\.create|anthropic\.messages\.create|genai\.generate_content|google\.generativeai)\b"""
        ),
        "An AI/LLM API call is executed in application code; ensure it is protected by authentication and rate limiting.",
        "Add user authentication, rate limits (e.g. 5 req/min), and per-user credit quotas before calling LLM endpoints.",
        "CWE-400",
        "Cost & Capacity",
        frozenset(set()),
    ),
    Rule(
        "SP502",
        "Insecure payment webhook handler",
        "security",
        "critical",
        "high",
        compile_pattern(r"""stripe\.webhooks\.constructEvent\s*\(\s*req\.body\b"""),
        "Stripe webhook handler passes parsed JSON body instead of raw buffer, causing verification failure.",
        "Pass the raw request buffer to stripe.webhooks.constructEvent using express.raw({ type: 'application/json' }).",
        "CWE-345",
        "OWASP ASVS V13",
        frozenset(set()),
    ),
    Rule(
        "SP503",
        "Leaked Supabase service role key",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:NEXT_PUBLIC_[A-Z0-9_]*SUPABASE_SERVICE_ROLE_KEY|NEXT_PUBLIC_[A-Z0-9_]*SERVICE_ROLE|createClient\s*\([^)]*NEXT_PUBLIC_[^)]*SERVICE)"""
        ),
        "A Supabase service_role key is exposed to client-side code, completely bypassing Row Level Security (RLS).",
        "Move the service_role key to a server-only environment variable without any client-side prefix.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset(set()),
        redact=True,
    ),
    Rule(
        "SP504",
        "Missing payment gateway idempotency key",
        "cost & scale",
        "high",
        "medium",
        compile_pattern(
            r"""stripe\.(?:charges|paymentIntents|refunds|transfers)\.create\s*\((?![^)\n]*idempotency_key)(?![^)\n]*idempotencyKey)[^)\n]*\)"""
        ),
        "Mutating payment gateway API call is executed without providing an explicit idempotency key.",
        "Pass a unique idempotency_key (e.g. order ID or UUID) on payment and refund creation requests.",
        "CWE-352",
        "Capacity",
        frozenset({".js", ".ts", ".rb", ".py"}),
    ),
    Rule(
        "SP505",
        "LLM prompt direct string interpolation",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:messages\s*=\s*\[[^\]]*f["'][^"']*\{user_input\}|prompt\s*=\s*f["'][^"']*\{[a-zA-Z0-9_]+\})"""
        ),
        "LLM prompt is constructed using direct string interpolation with untrusted user input, enabling Prompt Injection.",
        "Separate user input into distinct message roles (e.g. role: 'user') and sanitize delimiters.",
        "CWE-74",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP506",
        "LLM function call execution without schema validation",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""def\s+execute_tool\s*\([^)]*\):[^\n]*\n\s*(?:eval|exec|os\.system|subprocess)\s*\("""
        ),
        "AI model function/tool call arguments are executed directly in system interpreters without strict schema validation.",
        "Validate all tool arguments with strict schemas (Pydantic / Zod) and restrict available functions to an allowlist.",
        "CWE-20",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP507",
        "Vector database query with unfiltered embedding",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""(?:index\.query|collection\.query|vector_store\.similarity_search)\s*\([^)]*(?!filter\s*=)(?!where\s*=)\)"""
        ),
        "Vector similarity search is performed without tenant or user metadata filtering, enabling cross-tenant data leakage.",
        "Include explicit metadata filters (e.g. filter={'tenant_id': user.tenant_id}) in all vector queries.",
        "CWE-20",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP508",
        "AI agent autonomous tool execution without constraints",
        "security",
        "high",
        "medium",
        compile_pattern(r"""AgentExecutor\s*\([^)]*tools\s*=\s*(?:all_tools|get_all_tools\(\))"""),
        "AI Agent executor is granted unconstrained access to all tools without allowlist restrictions or approval gates.",
        "Provide an explicit, minimal allowlist of safe tools and require human approval for destructive operations.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP509",
        "Vector database API key committed",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:PINECONE_API_KEY|QDRANT_API_KEY|WEAVIATE_API_KEY|CHROMA_API_KEY)\s*[:=]\s*["'][a-zA-Z0-9_-]{32,}["']"""
        ),
        "A vector database API key (Pinecone, Qdrant, Weaviate) is hardcoded in source files.",
        "Revoke the vector database API key and inject it at runtime via environment variables.",
        "CWE-798",
        "OWASP ASVS V14",
        redact=True,
    ),
    Rule(
        "SP510",
        "Stripe payment webhook missing timestamp verification",
        "security",
        "high",
        "high",
        compile_pattern(r"""stripe\.Webhook\.construct_event\s*\([^)]*tolerance\s*=\s*None"""),
        "Stripe webhook construct_event called with tolerance=None, disabling timestamp verification against replay attacks.",
        "Enforce default timestamp tolerance (e.g. 300 seconds) to reject replayed webhook requests.",
        "CWE-294",
        "OWASP ASVS V13",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP511",
        "PayPal webhook signature verification omitted",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""app\.post\s*\(\s*["'][^"']*paypal-webhook["'],\s*async\s*\([^)]*\)\s*=>\s*\{(?!.*verifyWebhookSignature)"""
        ),
        "PayPal webhook handler processes events without verifying webhook signature headers with PayPal API.",
        "Verify PayPal webhook events using the PayPal SDK verifyWebhookSignature method before processing.",
        "CWE-345",
        "OWASP ASVS V13",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP512",
        "Supabase client without service role isolation",
        "security",
        "high",
        "medium",
        compile_pattern(
            r"""createClient\s*\([^,]+,\s*(?:process\.env\.)?SUPABASE_SERVICE_ROLE_KEY"""
        ),
        "Supabase client is instantiated with the service_role key in client-accessible code.",
        "Use createClient with NEXT_PUBLIC_SUPABASE_ANON_KEY on the client and restrict service_role to server APIs.",
        "CWE-284",
        "OWASP ASVS V4",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP513",
        "Clerk or Auth0 webhook without raw signature verification",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""app\.post\s*\(\s*["'][^"']*(?:clerk|auth0)-webhook["'],\s*(?!.*Webhook\()[^)]*\)"""
        ),
        "Clerk or Auth0 webhook endpoint is registered without Svix / raw webhook signature verification.",
        "Use the Svix Webhook class with svix-id, svix-timestamp, and svix-signature headers.",
        "CWE-345",
        "OWASP ASVS V13",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP514",
        "LangChain unsafe code execution tool enabled",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""from\s+langchain_experimental\.tools\s+import\s+(?:PythonREPLTool|PythonAstREPLTool)\b"""
        ),
        "LangChain PythonREPLTool is imported and enabled, allowing LLM prompt injections to execute arbitrary code.",
        "Avoid PythonREPLTool in production or isolate code execution in secure gVisor / Firecracker microVMs.",
        "CWE-95",
        "OWASP ASVS V1",
        frozenset({".py"}),
    ),
    Rule(
        "SP515",
        "AI streaming response without rate limiting or quota",
        "cost & scale",
        "high",
        "medium",
        compile_pattern(
            r"""(?:openai\.(?:chat\.completions|responses)\.create|anthropic\.messages\.create)\s*\([^)]*stream\s*=\s*True(?!\s*,\s*max_tokens)"""
        ),
        "Streaming LLM response is initiated without specifying max_tokens budget cap or rate limiting.",
        "Specify explicit max_tokens on streaming completions and enforce token quota limits per user.",
        "CWE-400",
        "Cost & Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP516",
        "AI LLM prompt injection via direct f-string concatenation of user input",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:prompt|messages)\s*=\s*(?:f['"][^'"]*\{user_input\}|f['"][^'"]*\{req\.body|\.format\(user_input\))"""
        ),
        "User input is concatenated directly into an LLM system or user prompt without boundary delimiters or role separation.",
        "Use structured role-based message arrays `[{'role': 'user', 'content': user_input}]` instead of raw prompt string interpolation.",
        "CWE-94",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP517",
        "AI LLM streaming API call without timeout or client disconnect cancellation",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""(?:openai|anthropic)\.chat\.completions\.create\s*\([^\)]*stream\s*:\s*True[^\)]*(?!timeout\s*=)"""
        ),
        "Streaming LLM completions without a timeout or AbortController leave backend worker threads hanging if clients drop connection.",
        "Pass an explicit timeout (e.g. `timeout=60.0`) and listen to request abort signals.",
        "CWE-400",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP518",
        "AI agent tool executing shell commands without human-in-the-loop gate",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""@tool[^\n]*\ndef\s+(?:execute_bash|run_shell|execute_command)\s*\([^)]*\):\s*\n[\s\S]*?subprocess\.(?:run|Popen|call)"""
        ),
        "An AI agent tool executes arbitrary terminal commands without a human approval confirmation gate or container sandbox.",
        "Run agent code inside an ephemeral isolated sandbox (Docker/gVisor/e2b) and require explicit human-in-the-loop authorization.",
        "CWE-78",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP519",
        "Vector database query requesting unbounded top_k results",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:index|client)\.query\s*\([^\)]*top_k\s*:\s*(?:[1-9]\d{3,}|1000)\b"""
        ),
        "Querying a vector index with top_k >= 1000 causes severe vector search latency spikes and large memory allocations.",
        "Limit top_k to the minimum required for context (e.g. `top_k: 10` to `50`) and apply reranking.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP520",
        "LangChain load_tools including dangerous shell or python execution",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""load_tools\s*\(\s*\[[^\]]*(?:['"]terminal['"]|['"]python_repl['"]|['"]bash['"])"""
        ),
        "LangChain loads unrestricted terminal or Python REPL tools, allowing LLM output to achieve Remote Code Execution.",
        "Remove terminal/python_repl from toolkits; use strictly scoped API tools with argument validation.",
        "CWE-95",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP521",
        "LangChain SQLDatabaseChain instantiated without query checker verification",
        "security",
        "high",
        "high",
        compile_pattern(r"""SQLDatabaseChain\s*\([^\)]*(?!use_query_checker\s*=\s*True)[^\)]*\)"""),
        "SQLDatabaseChain without query validation may execute destructive DDL/DML statements generated by hallucinations.",
        "Configure `use_query_checker=True` and connect using a read-only database user account.",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".py"}),
    ),
    Rule(
        "SP522",
        "OpenAI client initialized without request timeout",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""OpenAI\s*\(\s*\)[^\n]*(?!timeout)|new\s+OpenAI\s*\(\s*\{[^\}]*(?!timeout\s*:)[^\}]*\}"""
        ),
        "OpenAI SDK client is created with default infinite timeout, risking connection starvation during OpenAI outages.",
        "Set explicit timeout duration in OpenAI client configuration options.",
        "CWE-400",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP523",
        "LLM generated SQL query executed directly against production database without read-only mode",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:llm_sql|generated_query|ai_query)\s*=\s*[\s\S]*?cursor\.execute\s*\(\s*(?:llm_sql|generated_query|ai_query)"""
        ),
        "An AI-generated SQL query is executed directly against the database without AST validation or read-only connection limits.",
        "Execute AI queries exclusively against read-only replicas with query execution timeouts and transaction rollback.",
        "CWE-89",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP524",
        "LLM generated code evaluated directly using eval or exec",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:eval|exec)\s*\(\s*(?:response|completion|llm_output)\.choices\[0\]"""
        ),
        "Evaluating dynamic LLM output strings creates Remote Code Execution vulnerabilities from prompt injection.",
        "Never execute LLM code strings directly; parse structured data using JSON schemas or isolated WASM runtimes.",
        "CWE-95",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP525",
        "RAG embedding generation called inside single-item loop instead of batch",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""for\s+[a-zA-Z0-9_]+\s+in\s+[a-zA-Z0-9_]+:\s*\n[\s\S]*?(?:openai|client)\.embeddings\.create\s*\([^\)]*input\s*=\s*[a-zA-Z0-9_]+\b"""
        ),
        "Generating embeddings in a single-item loop makes separate HTTP calls per item, causing severe latency and rate limiting.",
        "Batch inputs: `client.embeddings.create(input=batch_of_texts, model='text-embedding-3-small')`.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP526",
        "AI chat history stored in unbounded memory array causing context overflow",
        "scale",
        "medium",
        "high",
        compile_pattern(
            r"""messages\.append\s*\(\s*\{['"]role['"]\s*:\s*['"]user['"][\s\S]*?(?!messages\s*=\s*messages\[-)"""
        ),
        "Appending chat messages without a sliding window or token count pruner causes memory exhaustion and token limit errors.",
        "Implement a sliding context window: keep only the last N messages or summarize older history.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP527",
        "AI agent tool calling recursion loop without max_iterations limit",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""(?:while\s+response\.tool_calls\s*:|(?:tool_call|agent\s+loop|llm)[^\n]{0,160}\n[^\n]{0,120}while\s+True\s*:|while\s+True\s*:[^\n]{0,120}\n[^\n]{0,160}(?:tool_call|llm\b|agent\b|chat\())(?![^\n]{0,200}max_iterations)"""
        ),
        "An agent tool calling execution loop runs without a max_iterations counter, risking infinite API billing loops on hallucinated tools.",
        "Set an explicit loop counter: `max_iterations = 10` and break with an error if exceeded.",
        "CWE-835",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP528",
        "Stripe Checkout session created without client_reference_id or order metadata",
        "correctness",
        "high",
        "high",
        compile_pattern(
            r"""stripe\.checkout\.Session\.create\s*\([^\)]+(?!client_reference_id\s*=)[^\)]*(?!metadata\s*=)"""
        ),
        "Creating a Stripe Checkout session without client_reference_id or metadata makes correlating completed payments to user accounts unreliable.",
        "Pass `client_reference_id=user_id` and `metadata={'order_id': order_id}`.",
        "CWE-703",
        "Correctness",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP529",
        "Stripe webhook handler parsing JSON without raw body buffer verification",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""stripe\.Webhook\.constructEvent\s*\(\s*(?:req\.body|JSON\.stringify\(req\.body\))\s*,"""
        ),
        "Passing parsed JSON to Stripe constructEvent fails signature verification or enables webhook forging.",
        "Pass the raw unmodified Buffer: `express.raw({ type: 'application/json' })`.",
        "CWE-345",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP530",
        "Stripe refund initiated without administrative permission verification",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:app|router)\.post\s*\([^\)]*refund[^\)]*\)\s*=>\s*\{(?![^}]*(?:isAdmin|hasRole|requireRole|adminAuth))[\s\S]*?stripe\.refunds\.create"""
        ),
        "A refund endpoint executes Stripe refunds without verifying that the authenticated user possesses administrative refund permissions.",
        "Verify administrative role permissions before invoking stripe refund operations.",
        "CWE-862",
        "OWASP ASVS V4",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP531",
        "Stripe customer created inside request loop without checking existing customer ID",
        "scale",
        "medium",
        "high",
        compile_pattern(
            r"""stripe\.Customer\.create\s*\([^\)]*email\s*=\s*[^\)]+\)(?![^;]*user\.stripe_customer_id)"""
        ),
        "Creating Stripe customers on every checkout without checking user.stripe_customer_id spawns duplicate customer objects.",
        "Check and reuse existing `user.stripe_customer_id` before creating new Stripe customers.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP532",
        "Payment charge created without idempotency_key parameter",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""stripe\.(?:charges|paymentIntents)\.create\s*\((?![^\)]*idempotency)[^\)]+\)"""
        ),
        "Creating payment charges without an idempotency key can cause double-charging customers during network retries.",
        "Pass an idempotency key: `stripe.PaymentIntent.create(..., idempotency_key=f'order_{order_id}')`.",
        "CWE-662",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP533",
        "Webhook handler responding 200 before persisting event to queue or database",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""(?:res\.status\(200\)\.send|return\s+Response\(status=200\))[\s\S]*?(?:await\s+db\.|db\.session\.add)"""
        ),
        "Sending HTTP 200 to webhook providers before persisting the payload risks permanent event loss if the server crashes mid-process.",
        "Persist the webhook event payload to a durable database table or queue before sending HTTP 200.",
        "CWE-703",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP534",
        "Webhook timestamp tolerance verification omitted enabling replay attacks",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:verifyWebhook|validateWebhookSignature)\s*\([^\)]*(?!tolerance|timestamp)[^\)]*\)"""
        ),
        "Webhook signature validation without timestamp tolerance allows captured webhooks to be replayed indefinitely.",
        "Verify `Math.abs(Date.now() - timestamp) <= 300_000` (5-minute tolerance window).",
        "CWE-294",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP535",
        "AWS S3 presigned URL generated with excessive expiration duration",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""generate_presigned_url\s*\([^\)]*ExpiresIn\s*=\s*(?:60480[1-9]|6048[1-9]\d|60[5-9]\d{3}|[7-9]\d{5,}|\d{7,})"""
        ),
        "Generating S3 presigned URLs with expiration > 7 days violates AWS limits and leaves resources exposed for excessive windows.",
        "Set `ExpiresIn=3600` (1 hour) or maximum 86400 (24 hours).",
        "CWE-613",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP536",
        "AWS SQS message receiver without visibility timeout extension in long task",
        "reliability",
        "medium",
        "high",
        compile_pattern(
            r"""sqs\.receive_message\s*\([^\)]+\)[\s\S]*?time\.sleep\s*\(\s*(?:[6-9]\d|\d{3,})\s*\)"""
        ),
        "Processing long-running SQS messages without heartbeat visibility timeout extensions causes duplicate concurrent processing.",
        "Call `change_message_visibility` periodically during processing or increase queue default visibility timeout.",
        "CWE-662",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP537",
        "AWS Lambda handler missing connection caching outside handler function",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""def\s+lambda_handler\s*\([^\)]*\):\s*\n[\s\S]*?(?:boto3\.client|psycopg2\.connect|pymongo\.MongoClient)\s*\("""
        ),
        "Instantiating database or AWS SDK clients inside the Lambda handler function prevents connection reuse across warm invocations.",
        "Initialize database connections and AWS SDK clients outside the lambda_handler function.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP538",
        "AWS DynamoDB scan operation used in user-facing query path",
        "scale",
        "high",
        "high",
        compile_pattern(r"""(?:dynamodb|table)\.scan\s*\("""),
        "DynamoDB scan() reads every item in the entire table, causing high latency and consuming read capacity units rapidly.",
        "Use `table.query()` with partition key condition and Global Secondary Indexes (GSI).",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP539",
        "GCP Cloud Storage signed URL generated without expiration cap",
        "security",
        "medium",
        "high",
        compile_pattern(r"""generate_signed_url\s*\([^\)]*(?!expiration\s*=)"""),
        "Cloud Storage signed URL generated without an explicit expiration timestamp defaults to overly permissive lifetimes.",
        "Specify `expiration=datetime.timedelta(minutes=15)`.",
        "CWE-613",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP540",
        "Azure Blob Storage SAS token generated with full write and delete permissions",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""BlobSasPermissions\s*\(\s*read\s*=\s*True\s*,\s*write\s*=\s*True\s*,\s*delete\s*=\s*True\s*\)"""
        ),
        "Generating Azure Blob SAS tokens with delete permissions exposes storage containers to malicious data destruction.",
        "Grant only required permissions (e.g. `BlobSasPermissions(read=True)` for downloads).",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".cs", ".py"}),
    ),
    Rule(
        "SP541",
        "Cloudflare Turnstile or reCAPTCHA verification skipped on backend",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:turnstile|recaptcha)[^\n]*\n(?:async\s+)?def\s+[a-zA-Z0-9_]+\s*\([^\)]*\):\s*\n(?![^}]*https:\/\/(?:challenges\.cloudflare\.com|www\.google\.com\/recaptcha\/api\/siteverify))"""
        ),
        "A form endpoint includes CAPTCHA tokens in request body but skips backend verification with the CAPTCHA provider API.",
        "Verify the token server-side: `await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { body: ... })`.",
        "CWE-602",
        "OWASP ASVS V13",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP542",
        "Twilio SMS sending called inside loop without rate limiter",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""for\s+[a-zA-Z0-9_]+\s+in\s+[a-zA-Z0-9_]+:\s*\n[\s\S]*?twilio_client\.messages\.create\s*\("""
        ),
        "Sending Twilio SMS messages inside a loop without rate limiting exceeds carrier MPS (Messages Per Second) limits and triggers 429s.",
        "Use Twilio Messaging Services with rate queuing or throttle queue dispatchers.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP543",
        "ChromaDB persistent client instantiated per request without singleton",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:async\s+def|function)\s+[a-zA-Z0-9_]+[\s\S]*?chromadb\.PersistentClient\s*\("""
        ),
        "Instantiating ChromaDB PersistentClient inside request handlers locks DuckDB/SQLite storage and causes disk contention.",
        "Initialize `chromadb.PersistentClient()` as an application singleton.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP544",
        "Weaviate vector search query missing limit parameter",
        "scale",
        "medium",
        "high",
        compile_pattern(r"""client\.query\.get\s*\([^\)]+\)(?!\s*\.with_limit\()"""),
        "Querying Weaviate without `.with_limit(n)` returns large default payloads, consuming high memory.",
        "Append `.with_limit(10)` to Weaviate query chains.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP545",
        "AI system prompt containing hardcoded API keys or secret instructions",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""system_prompt\s*=\s*['"][^'"]*(?:api_key|password|secret_token|PRIVATE KEY)[^'"]*['"]"""
        ),
        "Hardcoding internal secrets inside AI system prompts exposes credentials to users via Prompt Extraction attacks.",
        "Keep credentials in secure backend vaults and execute authenticated tools server-side.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP546",
        "Payment line item price taken directly from untrusted client payload",
        "security",
        "critical",
        "high",
        compile_pattern(r"""(?:amount|unit_amount|price)\s*:\s*req\.body\.(?:price|amount)"""),
        "The checkout endpoint trusts the payment amount from req.body, allowing attackers to modify product prices to $0.01.",
        "Lookup product prices securely from database catalogs using product IDs: `const price = await db.getPrice(productId)`.",
        "CWE-602",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP547",
        "Kafka producer publishing financial events without all ACKs guarantee",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""acks\s*=\s*(?:0|1)\b|acks\s*:\s*['"]?(?:0|1)['"]?"""),
        "Publishing critical financial events without full broker acknowledgments risks permanent message loss on failovers.",
        "Configure `acks='all'` (or `acks=-1`) with `min.insync.replicas=2` in Kafka producer settings.",
        "CWE-400",
        "Reliability",
        frozenset({".java", ".js", ".ts", ".py"}),
    ),
    Rule(
        "SP548",
        "Kafka consumer auto-committing offsets before message processing completes",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""enable\.auto\.commit\s*:\s*true|enable_auto_commit\s*=\s*True"""),
        "Auto-committing offsets on interval before message handlers finish risks dropping messages if consumer crashes during processing.",
        "Set `enable.auto.commit = false` and commit offsets manually after successful database processing.",
        "CWE-703",
        "Reliability",
        frozenset({".java", ".js", ".ts", ".py"}),
    ),
    Rule(
        "SP549",
        "RabbitMQ channel created per message without connection pooling",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""for\s+[a-zA-Z0-9_]+\s+in\s+[a-zA-Z0-9_]+:\s*\n[\s\S]*?connection\.channel\s*\("""
        ),
        "Opening a new AMQP channel for every published message creates massive Erlang process churn on RabbitMQ nodes.",
        "Reuse long-lived publisher channels across requests.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP550",
        "OpenTelemetry tracer span started without ending in finally block",
        "reliability",
        "medium",
        "high",
        compile_pattern(
            r"""span\s*=\s*tracer\.start_span\s*\([^\)]+\)(?![\s\S]*try:\s*\n[\s\S]*finally:\s*\n\s*span\.end\(\))"""
        ),
        "Starting an OpenTelemetry span without ending it in a finally block leaves traces open and leaks memory on exceptions.",
        "Use `with tracer.start_as_current_span('name'):` context manager or `finally: span.end()`.",
        "CWE-400",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP551",
        "AWS SNS topic subscriber without subscription filter policy",
        "scale",
        "medium",
        "high",
        compile_pattern(
            r"""resource\s+["']aws_sns_topic_subscription["'][^\{]+\{(?![\s\S]*filter_policy)"""
        ),
        "SNS subscription omits filter_policy, causing every subscriber to receive all topic traffic and wasting compute.",
        "Add a `filter_policy` to match only relevant event types at the SNS layer.",
        "CWE-400",
        "Capacity",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP552",
        "AWS EventBridge rule target missing Dead Letter Queue (DLQ)",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""resource\s+["']aws_cloudwatch_event_target["'][^\{]+\{(?![\s\S]*dead_letter_config)"""
        ),
        "An EventBridge target does not configure a Dead Letter Queue (DLQ), dropping events permanently on invocation failures.",
        "Add `dead_letter_config { arn = aws_sqs_queue.dlq.arn }` to event target definitions.",
        "CWE-703",
        "Reliability",
        frozenset({".hcl", ".tf"}),
    ),
    Rule(
        "SP553",
        "AWS Secrets Manager get_secret_value called inside Lambda handler",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""def\s+lambda_handler\s*\([^\)]*\):\s*\n[\s\S]*?secretsmanager[^\n]*get_secret_value"""
        ),
        "Fetching secrets inside the Lambda handler function adds 100-300ms latency to every request and hits API rate limits.",
        "Fetch and cache secrets outside the handler in global scope with a background TTL refresh.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP554",
        "AWS CloudWatch put_metric_data called synchronously in API path",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:async\s+def|def)\s+[a-zA-Z0-9_]+\s*\([^\)]*request[^\)]*\):[\s\S]*?cloudwatch\.put_metric_data"""
        ),
        "Calling put_metric_data synchronously adds 50-150ms HTTP latency per request to CloudWatch API endpoints.",
        "Use CloudWatch Embedded Metric Format (EMF) logs or background batch metric dispatchers.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP555",
        "GCP Secret Manager client instantiated inside Cloud Function handler",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""def\s+[a-zA-Z0-9_]+\s*\((?:request|event)[^\)]*\):[\s\S]*?secretmanager\.SecretManagerServiceClient"""
        ),
        "Creating SecretManagerServiceClient inside handler functions forces TCP handshake on every invocation.",
        "Instantiate SecretManagerServiceClient in module scope outside the request handler.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP556",
        "GCP Cloud Pub/Sub subscriber without automatic ack deadline extension",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""subscriber\.subscribe\s*\([^\)]+(?!flow_control)"""),
        "Pub/Sub subscriber without flow control or auto-lease extension drops long-running message leases, causing duplicate delivery.",
        "Configure `FlowControl(max_messages=100)` and `auto_ack=False` with explicit ack upon completion.",
        "CWE-703",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP557",
        "Azure Key Vault secret retrieval inside HTTP request handler without cache",
        "scale",
        "high",
        "high",
        compile_pattern(r"""(?:app|router)\.(?:get|post)[\s\S]*?secret_client\.get_secret\s*\("""),
        "Calling Azure Key Vault synchronously inside request routes introduces 100ms+ roundtrip latencies and rate limits.",
        "Cache secrets in memory with a 15-minute TTL or inject as environment variables at deploy time.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".cs", ".py"}),
    ),
    Rule(
        "SP558",
        "Azure Cosmos DB query without partition key filter",
        "scale",
        "high",
        "high",
        compile_pattern(r"""container\.items\.query\s*\([^\)]*(?!partitionKey)[^\)]*\)"""),
        "Querying Cosmos DB without a partition key forces an expensive cross-partition fan-out query across all shards.",
        "Specify `partition_key=user_id` in Cosmos DB read/query operations.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".cs", ".py"}),
    ),
    Rule(
        "SP559",
        "PayPal webhook verification skipped in production endpoint",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:paypal|paypal_webhook)[^\n]*\n(?:async\s+)?def\s+[a-zA-Z0-9_]+\s*\([^\)]*\):\s*\n(?![^}]*verify-webhook-signature)"""
        ),
        "A PayPal webhook handler processes payment notifications without verifying the signature against PayPal's verification API.",
        "Verify signature via PayPal `v1/notifications/verify-webhook-signature` before fulfilling orders.",
        "CWE-345",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP560",
        "Razorpay webhook missing HMAC-SHA256 signature verification",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:razorpay_webhook|razorpay)[^\n]*\n(?:async\s+)?def\s+[a-zA-Z0-9_]+\s*\([^\)]*\):\s*\n(?![^}]*(?:validate_webhook_signature|crypto\.createHmac))"""
        ),
        "A Razorpay webhook endpoint does not verify the `x-razorpay-signature` header using HMAC-SHA256.",
        "Verify signature: `razorpay.Utility.verify_webhook_signature(body, signature, secret)`.",
        "CWE-345",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP561",
        "Adyen webhook missing HMAC signature calculation check",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:adyen_webhook|adyen)[^\n]*\n(?:async\s+)?def\s+[a-zA-Z0-9_]+\s*\([^\)]*\):\s*\n(?![^}]*hmacValidator\.validateHMAC)"""
        ),
        "Adyen webhook notification is processed without validating the HMAC signature with the merchant HMAC key.",
        "Validate HMAC: `hmacValidator.validateHMAC(notificationRequestItem, hmacKey)`.",
        "CWE-345",
        "OWASP ASVS V14",
        frozenset({".java", ".js", ".ts", ".py"}),
    ),
    Rule(
        "SP562",
        "Square payment create call missing idempotency_key",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""payments_api\.create_payment\s*\([^\)]*(?!idempotency_key)[^\)]*\)"""),
        "Square create_payment call omits the idempotency_key parameter, risking duplicate charges on network retries.",
        "Pass a unique `idempotency_key: crypto.randomUUID()` with every payment creation request.",
        "CWE-662",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP563",
        "Stripe subscription upgrade missing proration_behavior specification",
        "correctness",
        "medium",
        "high",
        compile_pattern(
            r"""stripe\.Subscription\.modify\s*\([^\)]*items\s*=\s*\[[^\)]*(?!proration_behavior)"""
        ),
        "Modifying a Stripe subscription without specifying proration_behavior risks unintended customer overcharges or undercharges.",
        "Specify `proration_behavior='create_prorations'` or `'none'` explicitly.",
        "CWE-682",
        "Correctness",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP564",
        "Stripe invoice payment failed webhook event unhandled",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""switch\s*\(\s*event\.type\s*\)\s*\{[\s\S]*?case\s+['"]payment_intent\.succeeded['"]:(?![^}]*case\s+['"]invoice\.payment_failed['"])"""
        ),
        "Stripe webhook switch statement handles successful payments but omits `invoice.payment_failed` and `customer.subscription.deleted`.",
        "Handle failure events: downgrade user tier, revoke access, and notify customer on `invoice.payment_failed`.",
        "CWE-703",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP565",
        "Payment webhook processing without distributed idempotency lock",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""case\s+['"]payment_intent\.succeeded['"]:\s*\n(?![^;]*(?:redis\.setnx|redisLock|redlock|SELECT.*FOR UPDATE))"""
        ),
        "Processing payment fulfillment webhooks concurrently across multiple instances without a distributed lock can cause double fulfillment.",
        "Acquire an atomic lock with `SET event_id NX EX 300` in Redis before fulfilling purchases.",
        "CWE-362",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP566",
        "Currency conversion calculation performed with float division instead of integer cents",
        "correctness",
        "high",
        "high",
        compile_pattern(
            r"""(?:amount|price|balance)\s*\/\s*100\.\d+|float\s*\(\s*(?:cents|amount)\s*\)\s*\/"""
        ),
        "Converting currency cents to major units with floating point division introduces IEEE 754 precision drift.",
        "Store and calculate all currency in integer minor units (cents) or use Decimal math.",
        "CWE-682",
        "Correctness",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP567",
        "Billing balance decremented without non-negative check",
        "correctness",
        "critical",
        "high",
        compile_pattern(
            r"""user\.credits\s*-\s*=\s*[a-zA-Z0-9_]+(?![^;\n]*if\s*user\.credits\s*>=)"""
        ),
        "Credits or user account balances are decremented without verifying `credits >= required_amount`, allowing negative balances.",
        "Enforce database constraints (`CHECK (credits >= 0)`) and check balance before deducting.",
        "CWE-682",
        "Correctness",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP568",
        "AI prompt template without delimiter boundary escaping",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""PromptTemplate\s*\(\s*template\s*=\s*['"][^'"]*\{user_input\}['"](?![\s\S]*input_variables)"""
        ),
        "LangChain / LlamaIndex PromptTemplate embeds user input without clear XML or Markdown boundary delimiters.",
        "Wrap user input in XML tags (e.g. `<user_query>{input}</user_query>`) and instruct model to treat contents as raw data.",
        "CWE-94",
        "OWASP ASVS V5",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP569",
        "AI assistant tool executing destructive file deletion",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""@tool[^\n]*\ndef\s+(?:delete_file|remove_directory|drop_table)\s*\([^)]*\):\s*\n[\s\S]*?(?:os\.remove|shutil\.rmtree|cursor\.execute\s*\(\s*['"]DROP)"""
        ),
        "An AI tool gives models unrestricted permission to delete files or drop database tables without confirmation.",
        "Require user confirmation tokens or soft-delete with recycle bin retention.",
        "CWE-250",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP570",
        "AI model output rendered directly as unescaped markdown with HTML enabled",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""<ReactMarkdown\s+rehypePlugins=\s*\{\s*\[\s*rehypeRaw\s*\]\s*\}\s*>\s*\{(?:message|aiOutput|response)\.content\}"""
        ),
        "Rendering AI model output with `rehypeRaw` enabled in ReactMarkdown enables indirect prompt injection XSS.",
        "Disable `rehypeRaw` or sanitize output with DOMPurify before markdown rendering.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".jsx", ".tsx"}),
    ),
    Rule(
        "SP571",
        "Vector collection created without explicit distance metric",
        "correctness",
        "medium",
        "high",
        compile_pattern(
            r"""(?:create_collection|createIndex)\s*\([^\)]*(?!distance|metric)[^\)]*\)"""
        ),
        "Vector collection is created without an explicit distance metric (Cosine, DotProduct, Euclidean), risking mismatched similarity rankings.",
        "Specify `distance=Distance.COSINE` explicitly during collection creation.",
        "CWE-682",
        "Correctness",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP572",
        "Milvus vector search called without prior index loading",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""\bcollection\.search\s*\("""),
        "Milvus collection search() requires loading index into memory with `collection.load()` first, failing otherwise.",
        "Call `collection.load()` before executing search queries.",
        "CWE-703",
        "Reliability",
        frozenset({".py"}),
    ),
    Rule(
        "SP573",
        "SendGrid mail sending in single-item loop without batching",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""for\s+[a-zA-Z0-9_]+\s+in\s+[a-zA-Z0-9_]+:\s*\n[\s\S]*?sg\.send\s*\(\s*message\s*\)"""
        ),
        "Sending SendGrid emails in a synchronous loop makes a separate API request per recipient, triggering 429 rate limits.",
        "Use SendGrid Personalizations to send up to 1,000 personalized emails in a single batch API call.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP574",
        "RabbitMQ message consumed with auto_ack=True in durable queue",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""channel\.basic_consume\s*\([^\)]*auto_ack\s*=\s*True"""),
        "Consuming RabbitMQ messages with `auto_ack=True` acknowledges messages before processing finishes, losing messages on worker crashes.",
        "Set `auto_ack=False` and call `ch.basic_ack(delivery_tag)` after successful processing.",
        "CWE-703",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP575",
        "AI prompt caching key constructed without hashing long content",
        "scale",
        "medium",
        "high",
        compile_pattern(r"""cache\.get\s*\(\s*(?:prompt|system_prompt\s*\+\s*user_input)\s*\)"""),
        "Using long prompt strings (>4KB) directly as cache keys causes massive Redis memory consumption and key truncation.",
        "Hash long prompts: `key = f'llm_cache:{hashlib.sha256(prompt.encode()).hexdigest()}'`.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP576",
        "AI structured output JSON parsing missing validation error handler",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""(?:response_format|output_parser)\s*=\s*[\s\S]*?JSON\.parse\s*\([^\)]+\)(?![^;]*catch)"""
        ),
        "Parsing LLM JSON output without a try/catch or ValidationError handler crashes endpoints when models output invalid JSON.",
        "Use instructor/zod parser with retry loops: `try { Schema.parse(json) } catch { retryWithFeedback() }`.",
        "CWE-703",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP577",
        "Prometheus metric counter registered inside request handler scope",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:async\s+def|function)\s+[a-zA-Z0-9_]+[\s\S]{0,2000}?new\s+(?:Counter|Gauge|Histogram)\s*\("""
        ),
        "Registering Prometheus metrics inside request handlers throws duplicate registration errors or leaks memory on every hit.",
        "Declare Prometheus metrics globally once in module scope.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP578",
        "Feature flag evaluation without fallback default value on SDK timeout",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""client\.variation\s*\([^\)]*,\s*(?:null|undefined)\s*\)|ldClient\.variation\s*\([^\)]*,\s*None\s*\)"""
        ),
        "Evaluating feature flags without a safe fallback boolean/value defaults to unexpected behavior when flag services timeout.",
        "Pass an explicit safe fallback: `ldClient.variation('new-billing', user, False)`.",
        "CWE-703",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP579",
        "Feature flag client instantiated per request without background polling",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:async\s+def|function)\s+[a-zA-Z0-9_]+[\s\S]{0,2000}?new\s+(?:LaunchDarkly|UnleashClient|PostHog)\s*\("""
        ),
        "Initializing feature flag SDK clients inside request handlers forces network calls and certificate handshakes on every request.",
        "Instantiate feature flag clients once at application startup.",
        "CWE-400",
        "Capacity",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP580",
        "OpenTelemetry trace baggage headers forwarded without sanitization",
        "security",
        "medium",
        "high",
        compile_pattern(r"""W3CBaggagePropagator\.inject\s*\([^\)]*req\.headers\['baggage'\]"""),
        "Forwarding untrusted client baggage headers into downstream internal services can leak internal metadata or inject arbitrary attributes.",
        "Filter and allowlist baggage keys before propagating to internal microservices.",
        "CWE-20",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP581",
        "Redis distributed lock released without verifying lock token ownership",
        "reliability",
        "critical",
        "high",
        compile_pattern(r"""redis\.delete\s*\(\s*lock_key\s*\)"""),
        "Deleting a Redis lock directly without checking if current worker still owns the token allows slow workers to release other workers' locks.",
        "Release locks using Lua scripts that verify matching token: `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`.",
        "CWE-362",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP582",
        "Redis distributed lock acquired without TTL expiration timeout",
        "reliability",
        "critical",
        "high",
        compile_pattern(r"""redis\.setnx\s*\(\s*lock_key\s*,\s*token\s*\)(?![\s\S]*expire)"""),
        "Acquiring a Redis lock using SETNX without a TTL expiration causes permanent deadlocks if the lock holder crashes before release.",
        "Use atomic `SET lock_key token NX PX 30000` (set if not exists with 30s expiration).",
        "CWE-833",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP583",
        "BullMQ worker explicitly disables stalled checks",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""\bskipStalledCheck\s*:\s*true\b"""),
        "A BullMQ Worker explicitly disables its stalled checker; verify whether another worker owns recovery.",
        "Remove skipStalledCheck: true to retain BullMQ's default checks, or document and test a dedicated recovery worker.",
        "CWE-703",
        "Reliability",
        frozenset({".js", ".ts"}),
    ),
    Rule(
        "SP584",
        "Temporal workflow activity called without start_to_close_timeout",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""workflow\.execute_activity\s*\([^\)]*(?!start_to_close_timeout)"""),
        "Executing a Temporal activity without start_to_close_timeout allows hung activities to block workflow execution indefinitely.",
        "Configure `start_to_close_timeout=timedelta(minutes=5)` on all activity executions.",
        "CWE-400",
        "Reliability",
        frozenset({".ts", ".go", ".py"}),
    ),
    Rule(
        "SP585",
        "Temporal workflow mutating static or global variables",
        "correctness",
        "critical",
        "high",
        compile_pattern(
            # shipproof-ignore SP585 -- detector fixture literal, not a workflow declaration.
            r"""@workflow\.defn(?:(?!@workflow\.defn)[\s\S]){0,6000}?global\s+(?P<sp585_name>[a-zA-Z_]\w*)(?:(?!@workflow\.defn)[\s\S]){0,2000}?(?P=sp585_name)\s*(?:\+=|-=|\*=|/=|//=|%=|=(?!=))"""
        ),
        "Mutating static or global variables inside Temporal workflow definitions causes non-deterministic history replay bugs.",
        "Keep workflow state strictly encapsulated within workflow instance state fields.",
        "CWE-362",
        "Correctness",
        frozenset({".java", ".ts", ".go", ".py"}),
    ),
    Rule(
        "SP586",
        "Temporal workflow calling non-deterministic sleep or system clock",
        "correctness",
        "critical",
        "high",
        compile_pattern(
            r"""@workflow\.defn[\s\S]*?(?:time\.sleep|datetime\.now|Date\.now|System\.currentTimeMillis)\s*\("""
        ),
        "Calling standard time.sleep() or Date.now() directly inside Temporal workflows breaks deterministic workflow replaying.",
        "Use `workflow.sleep()` and `workflow.now()`.",
        "CWE-840",
        "Correctness",
        frozenset({".java", ".ts", ".go", ".py"}),
    ),
    Rule(
        "SP587",
        "Temporal activity retrying on non-retryable validation error",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""RetryPolicy\s*\([^\)]*(?!non_retryable_error_types)"""),
        "Retrying business logic validation errors in Temporal activities wastes retry budgets and delays error reporting.",
        "Configure `non_retryable_error_types=['ValidationError', 'InvalidInputError']` in RetryPolicy.",
        "CWE-703",
        "Reliability",
        frozenset({".ts", ".go", ".py"}),
    ),
    Rule(
        "SP588",
        "Supabase client initialized on client side with service_role key",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""createClient\s*\([^\)]*process\.env\.NEXT_PUBLIC_SUPABASE_URL[^\)]*SUPABASE_SERVICE_ROLE_KEY"""
        ),
        "Passing the Supabase service_role key to client-side createClient bypasses all Row Level Security (RLS) policies.",
        "Use `NEXT_PUBLIC_SUPABASE_ANON_KEY` on client side and restrict `service_role` exclusively to secure server runtimes.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".jsx", ".tsx"}),
    ),
    Rule(
        "SP589",
        "Vector index created with Euclidean metric on un-normalized vectors",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"""metric_type\s*=\s*['"]L2['"][^;]*(?!normalize)"""),
        "Using L2 Euclidean distance without vector normalization causes vector magnitudes to distort semantic ranking.",
        "Normalize embeddings before insertion (`vector / np.linalg.norm(vector)`) or use Cosine distance.",
        "CWE-682",
        "Correctness",
        frozenset({".ts", ".py"}),
    ),
    Rule(
        "SP590",
        "Unbounded in-memory queue without maxsize parameter",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:asyncio\.Queue|queue\.Queue)\s*\(\s*\)|asyncio\.Queue\s*\(\s*maxsize\s*=\s*0\s*\)"""
        ),
        "Creating an in-memory queue with default unbounded maxsize allows producer spikes to consume memory.",
        "Set an explicit bounded queue size: `asyncio.Queue(maxsize=1000)`.",
        "CWE-400",
        "Capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP591",
        "Client module imports a server-only runtime dependency",
        "correctness",
        "medium",
        "high",
        compile_pattern(
            r"""(?:from|import)\s+['"](?:@prisma/client|drizzle-orm/node-postgres|server-only|pg|mysql2)['"]"""
        ),
        "An explicit client module imports a runtime server dependency; framework enforcement may reject the build. Type-only imports are excluded.",
        "Isolate database logic in Server Components or Server Actions, or use import 'server-only'.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs"}),
    ),
    Rule(
        "SP592",
        "Next.js mutating route handler or action casting request body directly to any",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:\bas\s+any\b|\b:\s*any\b).*?(?:req\.json|request\.json)|(?:req\.json|request\.json|await\s+req\.json\(\)).*?\bas\s+any\b"""
        ),
        "Casting request body to 'as any' disables TypeScript type safety and runtime validation, inviting injection and state corruption.",
        "Validate request payloads with Zod (e.g. const body = schema.parse(await req.json())).",
        "CWE-20",
        "OWASP ASVS V5",
        frozenset({".ts", ".tsx"}),
    ),
    Rule(
        "SP593",
        "Next.js 15 route segment params accessed without await Promise resolution",
        "correctness",
        "high",
        "high",
        compile_pattern(
            r"""(?:const|let|var)\s+[a-zA-Z0-9_]+\s*=\s*(?:params|searchParams)\.[a-zA-Z0-9_]+"""
        ),
        "In Next.js 15, route segment params and searchParams are asynchronous Promises; accessing them synchronously throws runtime errors.",
        "Type params as Promise<{ id: string }> and resolve with const { id } = await params.",
        "CWE-840",
        "Correctness",
        frozenset({".ts", ".tsx", ".js", ".jsx"}),
    ),
    Rule(
        "SP594",
        "Authenticated user-specific API call configured with static force-cache",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""fetch\s*\([^)]*(?:/api/user|/api/me|/api/account|/api/profile|/api/billing)[^)]*cache\s*:\s*['"]force-cache['"]|cache\s*:\s*['"]force-cache['"]"""
        ),
        "Configuring force-cache on user-specific or authenticated endpoints caches private responses in Next.js Data Cache, leaking user data.",
        "Use cache: 'no-store' or dynamic tag-based cache revalidation for authenticated data.",
        "CWE-524",
        "OWASP ASVS V8",
        frozenset({".ts", ".tsx", ".js", ".jsx"}),
    ),
    Rule(
        "SP595",
        "Next.js Server Action database mutation without cache revalidation",
        "reliability",
        "medium",
        "high",
        compile_pattern(
            r"""(?:prisma\.[a-zA-Z0-9_]+\.(?:create|update|delete|upsert)|db\.(?:insert|update|delete)\()"""
        ),
        "Mutating database records in Server Actions without calling revalidatePath or revalidateTag leaves client Router Cache stale.",
        "Call revalidatePath('/resource') or revalidateTag('tag') after successful mutations.",
        "CWE-664",
        "Reliability",
        frozenset({".ts", ".tsx", ".js", ".jsx"}),
    ),
    Rule(
        "SP596",
        "Client-only React hook used inside Server Component without use client",
        "correctness",
        "high",
        "high",
        compile_pattern(r"""\b(?:useState|useEffect|useLayoutEffect|useReducer)\s*\("""),
        "Calling client hooks (useState, useEffect) in Server Components without 'use client' causes React SSR compilation failures.",
        "Add 'use client' at the top of the file or extract stateful logic into a separate Client Component.",
        "CWE-758",
        "Correctness",
        frozenset({".tsx", ".jsx"}),
    ),
    Rule(
        "SP597",
        "Next.js Server Component has adjacent sequential independent fetches",
        "scale",
        "high",
        "high",
        compile_pattern(r"""\bawait\s+fetch\s*\("""),
        "Adjacent awaits on distinct literal default-GET URLs serialize this component's uncached fetch work; cache and rendering mode determine user impact.",
        "Parallelize independent fetches using Promise.all([fetch1, fetch2]) or wrap in <Suspense> boundaries.",
        "CWE-400",
        "Performance",
        frozenset({".ts", ".tsx", ".js", ".jsx"}),
    ),
    Rule(
        "SP598",
        "Next.js mutating route handler using cookie auth without CSRF origin verification",
        "security",
        "critical",
        "high",
        compile_pattern(r"""export\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE)"""),
        "Next.js mutating Route Handlers using cookie authentication without checking Origin or Sec-Fetch-Site headers are vulnerable to CSRF.",
        "Verify request.headers.get('origin') matches host or enforce SameSite=Strict cookies with CSRF tokens.",
        "CWE-352",
        "OWASP ASVS V4",
        frozenset({".ts", ".tsx", ".js", ".jsx"}),
    ),
    Rule(
        "SP599",
        "Unchecked JSON field is dereferenced through a TypeScript non-null assertion",
        "reliability",
        "high",
        "high",
        compile_pattern(
            r"""\b(?:res|response|data|json|payload)\.[a-zA-Z0-9_]+!|\.[a-zA-Z0-9_]+!\s*(?:;|\n|$)"""
        ),
        "A field from a local json() result is immediately dereferenced through a non-null assertion without a visible validation step; missing fields may throw.",
        "Use Zod validation or optional chaining (?.) with nullish coalescing defaults (??).",
        "CWE-476",
        "Reliability",
        frozenset({".ts", ".tsx"}),
    ),
    Rule(
        "SP600",
        "Next.js Server Action accepting unverified userId argument for database mutation",
        "security",
        "critical",
        "high",
        compile_pattern(r"""function\s+[a-zA-Z0-9_]+\s*\([^)]*(?:userId|accountId|tenantId)"""),
        "Accepting userId from client arguments in Server Actions creates an IDOR vulnerability allowing users to mutate other accounts.",
        "Obtain the userId directly from authenticated session: const session = await auth(); const userId = session.user.id.",
        "CWE-639",
        "OWASP ASVS V4",
        frozenset({".ts", ".tsx", ".js", ".jsx"}),
    ),
    Rule(
        "SP601",
        "LLM output dynamically evaluated in code or shell interpreter",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:\beval|\bexec|\bos\.system|\bsubprocess\.run|\bchild_process\.exec)\s*\([^)]*(?:response|completion|llm_output|message\.content|choices\[0\])"""
        ),
        "Direct execution of LLM output in dynamic evaluation or system shells allows prompt injection to achieve arbitrary code execution.",
        "Parse LLM output into structured JSON with strict schema validation before any processing.",
        "CWE-94",
        "OWASP LLM01",
        frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".mjs"}),
    ),
    Rule(
        "SP602",
        "Direct rendering of raw LLM completion string into raw HTML",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*(?:completion|message\.content|response\.text)|v-html\s*=\s*['"][^'"]*(?:completion|message\.content|response\.text))"""
        ),
        "Rendering untrusted LLM output into raw HTML (dangerouslySetInnerHTML / v-html) causes Cross-Site Scripting (XSS).",
        "Sanitize markdown using DOMPurify or render plain text children.",
        "CWE-79",
        "OWASP LLM02",
        frozenset({".jsx", ".tsx", ".vue", ".js", ".ts"}),
    ),
    Rule(
        "SP603",
        "Unbounded prompt input ingestion passed to LLM API without truncation",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""(?:openai|anthropic|bedrock|gemini|cohere)\.[a-zA-Z0-9_.]+\.create\([^)]*prompt:\s*(?:req\.body|request\.body|request\.json|params)"""
        ),
        "Ingesting unbounded user input into LLM API calls enables Model Denial of Service (DoS) and massive API billing spikes.",
        "Enforce strict character/token truncation limits before passing prompts to model APIs.",
        "CWE-400",
        "OWASP LLM04",
        frozenset({".py", ".ts", ".js", ".mjs"}),
    ),
    Rule(
        "SP604",
        "Unsanitized user inputs concatenated directly into system prompt",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:role\s*:\s*['"]system['"]|system\s*=\s*)[^}]*(?:\$\{req|\$\{user_input|\+\s*user_input|\+\s*req\.body|\+\s*request\.args)"""
        ),
        "Concatenating unescaped user inputs directly into system prompts allows System Prompt Injection and jailbreaks.",
        "Separate system instructions from user inputs using structured message roles { role: 'user', content: ... }.",
        "CWE-74",
        "OWASP LLM07",
        frozenset({".py", ".ts", ".js", ".mjs"}),
    ),
    Rule(
        "SP605",
        "AI Agent tool definition with unbounded file write or shell execution capability",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:name:\s*['"](?:execute_shell|run_terminal_command|write_file_root)['"]|tool_definition\([^)]*(?:shell_exec|system_command|write_arbitrary_file))"""
        ),
        "Exposing unrestricted shell execution or filesystem write tools to AI agents without confirmation gates leads to catastrophic actions.",
        "Require explicit user confirmation for destructive agent tool invocations.",
        "CWE-250",
        "OWASP LLM08",
        frozenset({".py", ".ts", ".js", ".json", ".yaml", ".yml"}),
    ),
    Rule(
        "SP606",
        "Kubernetes container definition without CPU or memory resource limits",
        "scale",
        "high",
        "high",
        compile_pattern(r"""resources\s*:\s*\{\s*\}"""),
        "Kubernetes containers without resource limits can monopolize cluster resources and crash neighboring pods (noisy neighbor DoS).",
        "Configure explicit resources.limits.cpu and resources.limits.memory in container specs.",
        "CWE-400",
        "Kubernetes Hardening",
        frozenset({".yaml", ".yml", ".json"}),
    ),
    Rule(
        "SP607",
        "Kubernetes container configured with privileged securityContext",
        "security",
        "critical",
        "high",
        compile_pattern(r"""privileged\s*:\s*true\b"""),
        "Running Kubernetes containers in privileged mode grants full host root access, bypassing container boundary isolation.",
        "Set securityContext.privileged: false and drop all unnecessary Linux capabilities.",
        "CWE-250",
        "Kubernetes Hardening",
        frozenset({".yaml", ".yml", ".json"}),
    ),
    Rule(
        "SP608",
        "Kubernetes container root filesystem configured as writable",
        "security",
        "high",
        "high",
        compile_pattern(r"""readOnlyRootFilesystem\s*:\s*false\b"""),
        "Writable container root filesystems allow attackers to persist malware or modify binaries during runtime.",
        "Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for scratch directories.",
        "CWE-732",
        "Kubernetes Hardening",
        frozenset({".yaml", ".yml", ".json"}),
    ),
    Rule(
        "SP609",
        "Kubernetes container spec missing liveness or readiness probe",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""missing_k8s_probe_placeholder"""),
        "Kubernetes deployments without health probes cannot detect deadlocks or route traffic away from unready instances.",
        "Configure both livenessProbe and readinessProbe with appropriate initial delays.",
        "CWE-664",
        "Kubernetes Hardening",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP610",
        "Kubernetes pod volume configured with direct host filesystem mount",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\bhostPath\s*:"""),
        "Mounting host filesystem paths (hostPath) into Kubernetes pods exposes underlying host OS data and credentials.",
        "Use persistent volume claims (PVC) or configMaps/secrets instead of hostPath.",
        "CWE-59",
        "Kubernetes Hardening",
        frozenset({".yaml", ".yml", ".json"}),
    ),
    Rule(
        "SP611",
        "GraphQL server initialized with introspection enabled in production",
        "security",
        "high",
        "high",
        compile_pattern(r"""\bintrospection\s*:\s*true\b"""),
        "Enabling GraphQL introspection in production allows attackers to discover hidden schemas, admin queries, and unreleased mutations.",
        "Disable introspection in production: introspection: process.env.NODE_ENV !== 'production'.",
        "CWE-200",
        "OWASP ASVS V14",
        frozenset({".js", ".ts", ".py", ".mjs"}),
    ),
    Rule(
        "SP612",
        "GraphQL server configured without query depth or complexity limits",
        "scale",
        "high",
        "high",
        compile_pattern(r"""graphql_missing_depth_placeholder"""),
        "GraphQL endpoints without query depth or complexity limits are vulnerable to deeply nested query denial of service.",
        "Add graphql-depth-limit plugin (e.g. max depth 5-8) to GraphQL server configuration.",
        "CWE-400",
        "OWASP ASVS V11",
        frozenset({".js", ".ts", ".py", ".mjs"}),
    ),
    Rule(
        "SP613",
        "Outbound gRPC client invoke called without deadline or timeout",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""(?:\.Invoke|\.NewClient)\([^)]*context\.(?:Background|TODO)\(\)"""),
        "Outbound gRPC calls without explicit deadlines or context timeouts can hang indefinitely when downstreams stall.",
        "Pass a context with deadline: ctx, cancel := context.WithTimeout(ctx, 5*time.Second).",
        "CWE-400",
        "Reliability",
        frozenset({".go", ".py", ".ts", ".js"}),
    ),
    Rule(
        "SP614",
        "gRPC server initialized with insecure credentials or unencrypted channel",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:grpc\.insecure_server_credentials\(\)|grpc\.insecure_channel\b|insecure\.NewCredentials\(\))"""
        ),
        "Starting gRPC servers or channels with insecure credentials transmits unencrypted data across networks.",
        "Use TLS/mTLS credentials via grpc.ssl_server_credentials() or credentials.NewServerTLSFromFile().",
        "CWE-319",
        "OWASP ASVS V9",
        frozenset({".py", ".go", ".ts", ".js"}),
    ),
    Rule(
        "SP615",
        "OAuth2 authorization URL generated without random state parameter",
        "security",
        "high",
        "high",
        compile_pattern(r"""https://[a-zA-Z0-9_.-]+/oauth/authorize\?(?!.*state=)[^"'\s]+"""),
        "Initiating OAuth2 authorization flows without a cryptographically random state parameter enables Cross-Site Request Forgery (CSRF).",
        "Generate a secure random state token, store in user session, and verify on callback.",
        "CWE-352",
        "OWASP ASVS V3",
        frozenset({".py", ".ts", ".js", ".go", ".java", ".php", ".cs"}),
    ),
    Rule(
        "SP616",
        "OAuth callback matching redirect_uri against wildcard or unanchored regex",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:redirect_uri|redirectUri)\s*(?:==~|\.match\(|\.test\(|~=)\s*['"][^'"]*\*"""
        ),
        "Matching OAuth redirect_uri against wildcards or unanchored regular expressions enables open redirect and token theft.",
        "Use exact URI match comparison against registered redirect URIs.",
        "CWE-601",
        "OWASP ASVS V3",
        frozenset({".py", ".ts", ".js", ".go", ".java", ".php"}),
    ),
    Rule(
        "SP617",
        "Public client OAuth2 authorization flow initiating without PKCE code_challenge",
        "security",
        "critical",
        "high",
        compile_pattern(r"""/oauth/authorize\?[^"'\s]*response_type=code(?!.*code_challenge=)"""),
        "Initiating OAuth2 authorization flows from public clients (SPAs, mobile apps) without PKCE allows authorization code interception.",
        "Include code_challenge (S256) in auth request and code_verifier in token exchange.",
        "CWE-306",
        "RFC 7636 PKCE",
        frozenset({".py", ".ts", ".js", ".dart", ".kt", ".swift"}),
    ),
    Rule(
        "SP618",
        "Redis cache key set without expiration TTL parameter",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""\b(?:redis|redisClient)\.set\(\s*['"][^'"]+['"]\s*,\s*[^,)]+\s*\)"""),
        "Setting Redis cache keys without expiration TTL leads to unbounded memory growth and OOM eviction crashes.",
        "Always specify a TTL: redis.set(key, value, ex=3600).",
        "CWE-400",
        "Reliability",
        frozenset({".py", ".ts", ".js", ".go", ".php"}),
    ),
    Rule(
        "SP619",
        "Kafka consumer configured with enable.auto.commit risking message loss",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""['"]?enable\.auto\.commit['"]?\s*[:=]\s*(?:true|True)\b"""),
        "Kafka consumers configured with auto-commit commit offsets before message processing finishes, causing message loss during crashes.",
        "Set enable.auto.commit: false and commit offsets manually after successful processing.",
        "CWE-664",
        "Reliability",
        frozenset({".py", ".ts", ".js", ".java", ".go", ".properties", ".yaml", ".yml"}),
    ),
    Rule(
        "SP620",
        "PostgreSQL migration adding non-null column with volatile default acquiring table lock",
        "scale",
        "high",
        "high",
        compile_pattern(
            r"""ALTER\s+TABLE\s+[a-zA-Z0-9_.]+\s+ADD\s+COLUMN\s+[a-zA-Z0-9_]+\s+[a-zA-Z0-9_()]+\s+NOT\s+NULL\s+DEFAULT\s+(?:now\(\)|uuid_generate_v4\(\)|gen_random_uuid\(\))"""
        ),
        "Adding a column with a non-null volatile default (ADD COLUMN NOT NULL DEFAULT now()) on large PostgreSQL tables acquires an exclusive table lock.",
        "Add column as nullable, backfill values in batches, then add NOT NULL constraint with VALIDATE CONSTRAINT.",
        "CWE-400",
        "Database Safety",
        frozenset({".sql", ".py", ".ts", ".js"}),
    ),
    Rule(
        "SP621",
        "Rust unwrap or expect invoked in HTTP route handler risking thread panic",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""\.(?:unwrap|expect)\(\)"""),
        "Calling .unwrap() or .expect() in Rust HTTP handlers causes worker threads to panic upon encountering unexpected inputs.",
        "Handle errors gracefully with ? operator or match returning appropriate HTTP error responses.",
        "CWE-754",
        "Reliability",
        frozenset({".rs"}),
    ),
    Rule(
        "SP622",
        "Go deferred file or response Close in write operation without error check",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""defer\s+(?:file|f|writer|out)\.Close\(\)"""),
        "Using defer file.Close() on write operations in Go ignores potential write errors during buffer flushing.",
        "Check the error of file.Close() or file.Sync() before returning from write functions.",
        "CWE-755",
        "Reliability",
        frozenset({".go"}),
    ),
    Rule(
        "SP623",
        "Java dynamic JNDI lookup via InitialContext allowing remote code execution",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:InitialContext|ctx)\.lookup\([^)]*(?:request\.getParameter|req\.getParameter|params|headers)"""
        ),
        "Passing dynamic strings to Java InitialContext.lookup() allows remote code execution via JNDI injection (Log4Shell class).",
        "Restrict JNDI lookups to safe local constants and disable remote codebase loading.",
        "CWE-502",
        "OWASP ASVS V5",
        frozenset({".java", ".kt", ".scala", ".groovy"}),
    ),
    Rule(
        "SP624",
        "Non-cryptographic PRNG used to generate security token or key",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:token|secret|password|key|reset[_-]?code|otp)\s*[:=]\s*(?:Math\.random\(\)|random\.random\(\)|rand\.Intn\(|Random\(\)\.(?:nextInt|nextDouble)\s*\()"""
        ),
        "Using non-cryptographic PRNGs (Math.random(), random.random()) for security tokens makes them predictable and forgeable.",
        "Use cryptographically secure random generators: crypto.randomBytes() or secrets.token_hex().",
        "CWE-327",
        "OWASP ASVS V6",
        frozenset({".js", ".ts", ".py", ".go", ".java", ".cs", ".php", ".dart"}),
    ),
    Rule(
        "SP625",
        "Unawaited async task invoked in ASP.NET request handler swallowing exceptions",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""_\s*=\s*Task\.Run\("""),
        "Fire-and-forget async task invocations in C# ASP.NET request handlers swallow unhandled exceptions and starve thread pools.",
        "Always await async tasks or schedule background work with IBackgroundTaskQueue / BackgroundService.",
        "CWE-664",
        "Reliability",
        frozenset({".cs"}),
    ),
    Rule(
        "SP626",
        "AWS S3 bucket policy allowing public wildcard principal",
        "security",
        "critical",
        "high",
        compile_pattern(r"""(?:"Principal"|Principal|"principal"|principal)\s*[:=]\s*["']\*["']"""),
        "AWS S3 bucket policy configured with public wildcard Principal grants unrestricted internet access to sensitive cloud storage.",
        "Restrict S3 bucket access with block_public_policy and specify explicit IAM role ARNs in Principal.",
        "CWE-284",
        "Cloud Security",
        frozenset({".json", ".tf", ".yaml", ".yml"}),
    ),
    Rule(
        "SP627",
        "AWS storage resource created without encryption at rest",
        "security",
        "high",
        "high",
        compile_pattern(r"""\b(?:encrypted|storage_encrypted)\s*=\s*false\b"""),
        "AWS EBS volumes or RDS databases created without encryption at rest expose raw disk data in case of physical compromise or snapshot leakage.",
        "Enable encryption at rest: encrypted = true and kms_key_id = aws_kms_key.main.arn.",
        "CWE-311",
        "Cloud Security",
        frozenset({".tf", ".json", ".yaml", ".yml"}),
    ),
    Rule(
        "SP628",
        "Security group ingress rule allowing 0.0.0.0/0 on administrative ports",
        "security",
        "critical",
        "high",
        compile_pattern(r"""cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0/0["']\s*\]"""),
        "Security group ingress rules allowing 0.0.0.0/0 on administrative ports (SSH 22 / RDP 3389) invite brute-force and exploit scanning.",
        "Restrict ingress to internal VPN CIDR blocks or use AWS Systems Manager Session Manager.",
        "CWE-284",
        "Cloud Security",
        frozenset({".tf", ".json", ".yaml", ".yml"}),
    ),
    Rule(
        "SP629",
        "IAM policy granting wildcard actions or resources",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:"Action"|Action|"Resource"|Resource)\s*[:=]\s*\[?\s*["']\*["']\s*\]?"""
        ),
        "IAM policies granting wildcard actions (Action: '*') or resources (Resource: '*') violate the principle of least privilege.",
        "Specify explicit granular actions and resources: Action = ['s3:GetObject'], Resource = [aws_s3_bucket.main.arn].",
        "CWE-732",
        "Cloud Security",
        frozenset({".tf", ".json", ".yaml", ".yml"}),
    ),
    Rule(
        "SP630",
        "CloudFront distribution or ALB listener allowing unencrypted HTTP",
        "security",
        "high",
        "high",
        compile_pattern(r"""viewer_protocol_policy\s*=\s*["']allow-all["']"""),
        "CloudFront or ALB listeners allowing unencrypted HTTP (allow-all) expose network traffic to eavesdropping and man-in-the-middle attacks.",
        "Enforce HTTPS redirection: viewer_protocol_policy = 'redirect-to-https'.",
        "CWE-319",
        "Cloud Security",
        frozenset({".tf", ".json", ".yaml", ".yml"}),
    ),
    Rule(
        "SP631",
        "Node.js native module imported with explicit Edge runtime",
        "reliability",
        "critical",
        "high",
        compile_pattern(
            r"""import\s+.*?from\s+["'](?:node:)?(?:fs|child_process|cluster|dgram|v8)["']"""
        ),
        "An explicit Edge runtime declaration imports a native Node.js module that is unavailable in Next.js Edge.",
        "Use Edge-compatible Web Standard APIs (Fetch, Streams, Web Crypto) instead of node:fs / node:child_process.",
        "CWE-664",
        "Reliability",
        frozenset({".js", ".ts", ".tsx", ".jsx", ".mjs"}),
    ),
    Rule(
        "SP632",
        "Unbounded edge fetch loop against Cloudflare KV or database",
        "scale",
        "high",
        "high",
        compile_pattern(r"""(?:env\.KV|env\.DB|env\.D1)\.(?:get|list|prepare)\("""),
        "Executing unbounded fetch loops against Cloudflare KV or D1 databases exhausts edge CPU time limits and degrades edge performance.",
        "Use cursor-based pagination and batching with max limit parameters (e.g. limit: 100).",
        "CWE-400",
        "Scale",
        frozenset({".js", ".ts", ".mjs"}),
    ),
    Rule(
        "SP633",
        "Edge Worker accumulating full response payload in memory instead of streaming",
        "scale",
        "medium",
        "high",
        compile_pattern(r"""await\s+response\.(?:arrayBuffer|blob)\(\)"""),
        "Accumulating full response payloads in memory before returning from Edge Workers causes worker OOM kills.",
        "Stream large responses using TransformStream or pipeThrough directly to client.",
        "CWE-400",
        "Scale",
        frozenset({".js", ".ts", ".mjs"}),
    ),
    Rule(
        "SP634",
        "Dynamic authenticated API response cached on edge CDN",
        "security",
        "high",
        "high",
        compile_pattern(r"""headers\.set\(\s*["']Cache-Control["'],\s*["']public,\s*max-age="""),
        "Caching dynamic authenticated API responses on edge CDN stores private user data in public cache nodes.",
        "Set Cache-Control: private, no-store on authenticated endpoints.",
        "CWE-664",
        "OWASP ASVS V8",
        frozenset({".js", ".ts", ".mjs", ".py"}),
    ),
    Rule(
        "SP635",
        "WebSocket connection initialized without heartbeat ping-pong interval timeout",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""new\s+WebSocketServer\("""),
        "WebSocket connections without heartbeat ping/pong interval monitoring leak zombie connections and exhaust server file descriptors.",
        "Implement periodic ping/pong heartbeats: setInterval(() => ws.ping(), 30000) and terminate dead sockets.",
        "CWE-400",
        "Reliability",
        frozenset({".js", ".ts", ".mjs"}),
    ),
    Rule(
        "SP636",
        "Server-Sent Events stream missing client disconnect event listener",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""["']text/event-stream["']"""),
        "Server-Sent Events (SSE) streams without client disconnect cleanup listeners continue pushing events to closed sockets, leaking memory.",
        "Listen for client disconnect: req.on('close', () => clearInterval(interval)) to clean up resources.",
        "CWE-664",
        "Reliability",
        frozenset({".js", ".ts", ".py", ".go"}),
    ),
    Rule(
        "SP637",
        "WebSocket upgrade handler accepting connection without authentication verification",
        "security",
        "critical",
        "high",
        compile_pattern(r"""wss\.handleUpgrade\("""),
        "Accepting WebSocket upgrade requests without prior authentication token verification exposes internal real-time events to unauthorized clients.",
        "Validate authentication token in upgrade handler before accepting connection: if (!auth(req)) socket.destroy().",
        "CWE-306",
        "OWASP ASVS V3",
        frozenset({".js", ".ts", ".mjs"}),
    ),
    Rule(
        "SP638",
        "BroadcastChannel or event subscription without unmount cleanup listener",
        "reliability",
        "high",
        "high",
        compile_pattern(r"""new\s+BroadcastChannel\("""),
        "Adding event listeners or BroadcastChannel subscribers without removing them on component unmount causes memory leaks.",
        "Always clean up listeners: return () => channel.close() or removeEventListener().",
        "CWE-400",
        "Reliability",
        frozenset({".js", ".ts", ".tsx", ".jsx"}),
    ),
    Rule(
        "SP639",
        "Symmetric cipher initialized in insecure ECB mode",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\b(?:crypto\.createCipheriv\(\s*["'](?:des|blowfish|rc4)|Cipher\.getInstance\(\s*["'](?:DES|Blowfish|RC4))"""
        ),
        "Using legacy broken ciphers like DES or Blowfish lacks security guarantees against modern attacks.",
        "Use AES-GCM or ChaCha20-Poly1305 with a secure random IV.",
        "CWE-327",
        "OWASP ASVS V6",
        frozenset({".py", ".js", ".ts", ".java", ".go", ".cs", ".php"}),
    ),
    Rule(
        "SP640",
        "RSA key pair generated with insufficient key length below 2048 bits",
        "security",
        "high",
        "high",
        compile_pattern(r"""(?:modulusLength|key_size|keysize|bits)\s*[:=]\s*(?:512|768|1024)\b"""),
        "RSA keys shorter than 2048 bits (e.g. 512 or 1024 bits) are vulnerable to factorization attacks using modern compute resources.",
        "Generate RSA keys with at least 2048 or 4096 bits: generateKeyPairSync('rsa', { modulusLength: 2048 }).",
        "CWE-326",
        "OWASP ASVS V6",
        frozenset({".py", ".js", ".ts", ".java", ".go", ".cs", ".php"}),
    ),
    Rule(
        "SP641",
        "Static hardcoded Initialization Vector or salt reused in cipher operation",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""(?:const|let|var|byte\[\])\s+(?:iv|salt)\s*=\s*(?:Buffer\.from\(['"][0-9a-fA-F]{16,}['"]|b?['"][0-9a-fA-F]{16,}['"])"""
        ),
        "Using a hardcoded static Initialization Vector (IV) in symmetric encryption breaks semantic security across multiple encryptions.",
        "Generate a fresh cryptographically random IV for every encryption: crypto.randomBytes(16).",
        "CWE-329",
        "OWASP ASVS V6",
        frozenset({".py", ".js", ".ts", ".java", ".go", ".cs"}),
    ),
    Rule(
        "SP642",
        "Broken hash algorithm MD5 or SHA1 used in security signature or password context",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:crypto\.createHash|hashlib\.(?:md5|sha1)|MessageDigest\.getInstance)\(\s*["'](?:md5|sha1|MD5|SHA1)["']\)"""
        ),
        "MD5 and SHA1 hash algorithms suffer from practical collision attacks and are broken for digital signatures and password hashing.",
        "Use SHA-256 / SHA-512 for signatures and Argon2id / bcrypt for password hashing.",
        "CWE-328",
        "OWASP ASVS V6",
        frozenset({".py", ".js", ".ts", ".java", ".go", ".cs", ".php"}),
    ),
    Rule(
        "SP643",
        "Secret HMAC signature or token compared with non-constant-time equality operator",
        "security",
        "high",
        "high",
        compile_pattern(r"""\b(?:signature|clientSig|hmacToken|expectedSig)\s*===\s*"""),
        "Comparing HMAC signatures or secrets with standard equality operators (==, ===) leaks timing information (timing attack).",
        "Use constant-time comparison: crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)).",
        "CWE-208",
        "OWASP ASVS V6",
        frozenset({".js", ".ts", ".py", ".go"}),
    ),
    Rule(
        "SP644",
        "Svelte raw HTML rendered with unescaped tag without sanitization",
        "security",
        "critical",
        "high",
        compile_pattern(r"""\{@html\s+"""),
        "Rendering dynamic user input using Svelte {@html ...} without sanitization leads to stored or reflected Cross-Site Scripting (XSS).",
        "Sanitize raw HTML with DOMPurify.sanitize(userInput) before rendering in {@html}.",
        "CWE-79",
        "OWASP ASVS V5",
        frozenset({".svelte"}),
    ),
    Rule(
        "SP645",
        "Android WebView configured with JavaScript and file URL access enabled",
        "security",
        "high",
        "high",
        compile_pattern(r"""setAllowFileAccessFromFileURLs\(\s*true\s*\)"""),
        "Enabling JavaScript and file URL access in Android WebView allows malicious web pages to read local private app files.",
        "Disable file access from file URLs: webSettings.setAllowFileAccessFromFileURLs(false).",
        "CWE-200",
        "OWASP Mobile M1",
        frozenset({".java", ".kt"}),
    ),
    Rule(
        "SP646",
        "iOS URLSession configured to unconditionally trust all SSL certificates",
        "security",
        "high",
        "high",
        compile_pattern(r"""URLCredential\(\s*trust:\s*serverTrust\s*\)"""),
        "Overriding URLSessionDelegate to unconditionally accept all SSL certificates disables TLS certificate verification in iOS apps.",
        "Use default URLSession certificate validation or implement strict public key pinning.",
        "CWE-295",
        "OWASP Mobile M3",
        frozenset({".swift", ".m"}),
    ),
    Rule(
        "SP647",
        "Frontend proxy API endpoint accepting arbitrary full target URL parameter",
        "security",
        "high",
        "high",
        compile_pattern(
            r"""(?:fetch|axios\.(?:get|post))\(\s*(?:body\.url|req\.query\.url|params\.url)"""
        ),
        "Accepting a full destination URL parameter in backend API proxy endpoints enables Server-Side Request Forgery (SSRF).",
        "Validate URL target against strict allowlist of domains and reject private IP ranges.",
        "CWE-918",
        "OWASP ASVS V12",
        frozenset({".ts", ".js", ".py"}),
    ),
    Rule(
        "SP648",
        "React or Vue WebSocket connection opened inside effect without teardown return",
        "reliability",
        "medium",
        "high",
        compile_pattern(r"""new\s+WebSocket\(\s*["']wss?://"""),
        "Instantiating WebSockets or EventSource instances inside React useEffect without a return cleanup function creates multiple leaking sockets.",
        "Return a cleanup function from useEffect: return () => ws.close().",
        "CWE-664",
        "Reliability",
        frozenset({".jsx", ".tsx"}),
    ),
    Rule(
        "SP649",
        "Multitenant database query missing tenant scope filter",
        "security",
        "critical",
        "high",
        compile_pattern(
            r"""\bFROM\s+[a-zA-Z0-9_]+\s+WHERE\s+id\s*=\s*(?::id|\?|\$1)(?!\s+AND\s+tenant_id)"""
        ),
        "Executing multitenant database queries without an explicit tenant_id filter allows cross-tenant data leakage (IDOR / BOLA).",
        "Always include tenant scope in queries: WHERE id = :id AND tenant_id = :tenant_id.",
        "CWE-863",
        "OWASP ASVS V4",
        frozenset({".sql"}),
    ),
    Rule(
        "SP650",
        "Unbounded recursive JSON parse or schema evaluation without nesting depth limits",
        "scale",
        "high",
        "high",
        compile_pattern(r"""function\s+parseRecursive[a-zA-Z0-9_]*\("""),
        "Parsing deeply nested JSON payloads or unbounded recursive structures leads to call stack overflow or exponential CPU denial of service.",
        "Enforce payload size and nesting depth limits before deserializing nested structures.",
        "CWE-400",
        "Reliability",
        frozenset({".js", ".ts", ".py"}),
    ),
    Rule(
        "SP651",
        "Kubernetes container adds ALL or SYS_ADMIN Linux capabilities",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""(?<![A-Za-z0-9_])capabilities\s*:\s*\n(?:[ \t]+[^\n]*\n){0,8}?[ \t]+add\s*:\s*(?:\[[^\]\n]*(?:["']?(?:ALL|SYS_ADMIN)["']?)[^\]\n]*\]|(?:\n[ \t]+-\s*["']?(?:ALL|SYS_ADMIN)["']?\s*)+)"""
        ),
        "A Kubernetes container explicitly adds the ALL or SYS_ADMIN capability set.",
        "Drop ALL capabilities and add back only individually reviewed capabilities required by the workload.",
        "CWE-250",
        "Kubernetes PSS Restricted",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP652",
        "Kubernetes seccomp profile explicitly set to Unconfined",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""seccompProfile\s*:\s*\n[ \t]+type\s*:\s*["']?Unconfined["']?[ \t]*(?:#.*)?(?:\r?\n|$)"""
        ),
        "A Kubernetes securityContext explicitly disables seccomp syscall filtering.",
        "Set seccompProfile.type to RuntimeDefault or a reviewed Localhost profile.",
        "CWE-693",
        "Kubernetes PSS Restricted",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP653",
        "Kubernetes procMount explicitly set to Unmasked",
        "security",
        "medium",
        "high",
        compile_pattern(r"""^\s*procMount\s*:\s*["']?Unmasked["']?\s*(?:#.*)?$"""),
        "A Kubernetes container explicitly requests an unmasked proc filesystem.",
        "Remove procMount: Unmasked and use the runtime's default procfs masking.",
        "CWE-250",
        "Kubernetes PSS Restricted",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP654",
        "Kubernetes Windows container enables HostProcess",
        "security",
        "medium",
        "high",
        compile_pattern(r"""^\s*hostProcess\s*:\s*true\s*(?:#.*)?$"""),
        "A Kubernetes Windows container explicitly enables host-level process isolation.",
        "Set windowsOptions.hostProcess to false for application workloads and isolate any reviewed node agent exception.",
        "CWE-250",
        "Kubernetes PSS Restricted",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP655",
        "Kubernetes AppArmor profile explicitly set to Unconfined",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""(?:appArmorProfile\s*:\s*\n[ \t]+type\s*:\s*["']?Unconfined["']?|container\.apparmor\.security\.beta\.kubernetes\.io/[A-Za-z0-9_.-]+\s*:\s*["']?unconfined["']?)"""
        ),
        "A Kubernetes workload explicitly disables its AppArmor confinement profile.",
        "Use RuntimeDefault or a reviewed Localhost AppArmor profile and remove legacy unconfined annotations.",
        "CWE-693",
        "Kubernetes PSS Restricted",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP656",
        "Kubernetes RBAC role grants wildcard API groups, resources, or verbs",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""(?:\A|(?<=\n))[ \t]*apiVersion[ \t]*:[ \t]*rbac\.authorization\.k8s\.io/v1[^\n]*(?:(?!\n[ \t]*---[ \t]*(?:\n|$))[\s\S]){0,2000}?\n[ \t]*kind[ \t]*:[ \t]*(?:Role|ClusterRole)[^\n]*(?:(?!\n[ \t]*---[ \t]*(?:\n|$))[\s\S]){0,5000}?\n[ \t]*(?:-\s*)?(?:apiGroups|resources|verbs)[ \t]*:[ \t]*(?:\[[^\]\n]*["']?\*["']?[^\]\n]*\]|\n(?:[ \t]+-\s*[^\n]+\n){0,8}?[ \t]+-\s*["']?\*["']?[ \t]*(?:#.*)?(?:\n|$))"""
        ),
        "A Kubernetes Role or ClusterRole grants a wildcard API group, resource, or verb.",
        "Enumerate only the API groups, resources, and verbs the workload demonstrably needs.",
        "CWE-250",
        "Kubernetes RBAC least privilege",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP657",
        "Kubernetes binding grants the built-in cluster-admin role",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""(?:\A|(?<=\n))[ \t]*apiVersion[ \t]*:[ \t]*rbac\.authorization\.k8s\.io/v1[^\n]*(?:(?!\n[ \t]*---[ \t]*(?:\n|$))[\s\S]){0,2000}?\n[ \t]*kind[ \t]*:[ \t]*(?:RoleBinding|ClusterRoleBinding)[^\n]*(?:(?!\n[ \t]*---[ \t]*(?:\n|$))[\s\S]){0,5000}?\n[ \t]*roleRef[ \t]*:[ \t]*(?:\{[^\n}]*\bname[ \t]*:[ \t]*["']?cluster-admin["']?[^\n}]*\}|(?:\n[ \t]+[^\n]*){0,8}?\n[ \t]+name[ \t]*:[ \t]*["']?cluster-admin["']?[ \t]*(?:#.*)?(?:\n|$))"""
        ),
        "A RoleBinding or ClusterRoleBinding grants the built-in cluster-admin ClusterRole.",
        "Bind application subjects to a purpose-built role containing only required permissions.",
        "CWE-250",
        "Kubernetes RBAC least privilege",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP658",
        "GitHub Actions security scanner failure explicitly forced to success",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""^\s*(?:-\s*)?(?:run\s*:\s*)?["']?(?:(?:npm|pnpm|yarn)\s+audit\b|cargo\s+audit\b|govulncheck\b|gosec\b|pip-audit\b|bandit\b|trivy\b|shipproof\s+(?:check|scan)\b|dotnet\s+(?:(?:list\s+package)|(?:package\s+list))\b.*--vulnerable\b).*?(?:\|\|\s*(?:true|:)\s*|;\s*exit\s+0\s*)["']?\s*$"""
        ),
        "A GitHub Actions security scanner command masks its failure with a forced zero exit.",
        "Remove the forced-success branch and let the scanner's nonzero exit fail the required job.",
        "CWE-390",
        "CI/CD integrity",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP659",
        "GitHub Actions security scan step configured to continue on error",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""(?:\A|(?<=\n))[ \t]*-\s+(?=(?:(?!\n[ \t]*-\s+)[\s\S]){0,1200}?continue-on-error\s*:\s*true)(?:(?!\n[ \t]*-\s+)[\s\S]){0,1200}?(?:run\s*:\s*[^\n]*(?:(?:npm|pnpm|yarn)\s+audit\b|cargo\s+audit\b|govulncheck\b|gosec\b|pip-audit\b|bandit\b|trivy\b|shipproof\s+(?:check|scan)\b)|uses\s*:\s*(?:github/codeql-action|aquasecurity/trivy-action|actions/dependency-review-action|gitleaks/gitleaks-action)(?:/[^@\s]+)?@)"""
        ),
        "A GitHub Actions security scan step is allowed to fail without failing its job.",
        "Remove continue-on-error from enforcement scans; isolate informational scans in a clearly non-required job.",
        "CWE-390",
        "CI/CD integrity",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP660",
        "GitHub reusable workflow inherits every caller secret",
        "security",
        "medium",
        "high",
        compile_pattern(r"""^\s*secrets\s*:\s*["']?inherit["']?\s*(?:#.*)?$"""),
        "A reusable workflow call implicitly receives every secret available to the caller.",
        "Pass only explicitly named secrets required by the called workflow.",
        "CWE-200",
        "CI/CD least privilege",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP661",
        "Kubernetes API server enables AlwaysAllow authorization",
        "security",
        "medium",
        "high",
        compile_pattern(
            r"""(?:--authorization-mode(?:=|\s+)[^\n"']*\bAlwaysAllow\b|authorization-mode\s*:\s*["']?[^\n"']*\bAlwaysAllow\b)"""
        ),
        "The Kubernetes API server authorization chain includes AlwaysAllow.",
        "Remove AlwaysAllow and configure an explicit production authorization chain such as Node,RBAC.",
        "CWE-862",
        "Kubernetes authorization",
        frozenset({".yaml", ".yml"}),
    ),
    Rule(
        "SP662",
        "Django CORS policy allows all origins",
        "security",
        "medium",
        "high",
        compile_pattern(r"""(?<![A-Za-z0-9_])CORS_ALLOW_ALL_ORIGINS\s*[:=]\s*True"""),
        "django-cors-headers is configured to reflect any origin, defeating origin-based browser isolation.",
        "Set CORS_ALLOW_ALL_ORIGINS to False and enumerate the trusted origins in CORS_ALLOWED_ORIGINS.",
        "CWE-942",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP663",
        "Django session cookie sent without the Secure flag",
        "security",
        "medium",
        "high",
        compile_pattern(r"""(?<![A-Za-z0-9_])SESSION_COOKIE_SECURE\s*[:=]\s*False"""),
        "Session cookies explicitly marked non-secure can be captured from plain-HTTP traffic or a shared network.",
        "Remove the override (Django defaults SESSION_COOKIE_SECURE to True) or set it explicitly and serve the site over HTTPS only.",
        "CWE-614",
        "OWASP ASVS V3",
        frozenset({".py"}),
    ),
    Rule(
        "SP664",
        "FastAPI app routes without visible rate limiting",
        "security",
        "medium",
        "low",
        compile_pattern(r"""$^"""),
        "FastAPI routes are registered without visible rate-limiting middleware or dependencies.",
        "Add rate limiting (for example slowapi or gateway throttling) and cover authentication-sensitive routes with tests asserting 429 responses.",
        "CWE-307",
        "OWASP ASVS V2",
        frozenset({".py"}),
    ),
    Rule(
        "SP665",
        "Django settings enable DEBUG in a production settings module",
        "security",
        "medium",
        "medium",
        compile_pattern(r"""$^"""),
        "A Django settings module turns DEBUG on, exposing detailed error pages, settings, and stack traces.",
        "Set DEBUG = False for deployable settings and keep debug behavior in local-only settings modules.",
        "CWE-489",
        "OWASP ASVS V14",
        frozenset({".py"}),
    ),
    Rule(
        "SP666",
        "PHP upload allowlist trusts browser MIME metadata",
        "security",
        "medium",
        "low",
        compile_pattern(
            r"""(?:if\s*\([^\n]*\$_FILES\[[^\]]+\]\[['\"]type['\"]\]|in_array\s*\(\s*\$_FILES\[[^\]]+\]\[['\"]type['\"]\])"""
        ),
        "A PHP upload decision uses the browser-supplied MIME metadata instead of validating file content.",
        "Use finfo or content-based validation on the temporary file, then enforce a safe destination and extension policy.",
        "CWE-434",
        "OWASP ASVS V5",
        frozenset({".php"}),
    ),
    Rule(
        "SP667",
        "Go sensitive cookie without explicit HttpOnly",
        "security",
        "medium",
        "low",
        re.compile(
            r"""(?:http\.)?SetCookie\s*\([^,]+,\s*&(?:http\.)?Cookie\s*\{(?=[^}]*Name\s*:\s*[\"'](?:session|auth|token|jwt|refresh)[\"'])(?:(?!HttpOnly\s*:\s*true)[^}])*\}\s*\)""",
            re.IGNORECASE | re.DOTALL,
        ),
        "A sensitive Go cookie literal omits an explicit HttpOnly flag, leaving the session value readable by script.",
        "Set HttpOnly: true together with Secure and an appropriate SameSite policy, or document a deliberate non-sensitive cookie.",
        "CWE-1004",
        "OWASP ASVS V3",
        frozenset({".go"}),
    ),
    Rule(
        "SP668",
        "C/C++ format string taken directly from argv",
        "security",
        "medium",
        "medium",
        compile_pattern(
            r"""(?<![\w.:])(?:(?:std::)?printf\s*\(\s*argv\s*\[[^\]\r\n]{1,128}\]|syslog\s*\(\s*[^,()\n]{1,128},\s*argv\s*\[[^\]\r\n]{1,128}\]|(?:std::)?(?:fprintf|sprintf)\s*\(\s*[^,()\n]{1,256},\s*argv\s*\[[^\]\r\n]{1,128}\]|(?:std::)?snprintf\s*\(\s*[^,()\n]{1,256},\s*[^,()\n]{1,256},\s*argv\s*\[[^\]\r\n]{1,128}\])"""
        ),
        "A C/C++ formatted-output call receives an attacker-controlled argv value as its format string.",
        'Use a constant format string such as "%s" and pass argv as data; validate command-line inputs before use.',
        "CWE-134",
        "CERT C FIO30-C",
        frozenset({".c", ".cc", ".cpp", ".h", ".hpp"}),
    ),
    Rule(
        "SP669",
        "Dart credential stored in SharedPreferences",
        "security",
        "medium",
        "low",
        compile_pattern(
            r"""(?:SharedPreferences|\bprefs\b)\s*\.\s*setString\s*\(\s*["'](?:token|access[_-]?token|refresh[_-]?token|password|secret|api[_-]?key)["']"""
        ),
        "A Dart preference write stores a credential-like value in SharedPreferences, which is not a secure secret store.",
        "Use platform secure storage or an approved encrypted vault for credentials and tokens; keep preferences for non-sensitive settings.",
        "CWE-922",
        "OWASP ASVS V6",
        frozenset({".dart"}),
    ),
    Rule(
        "SP670",
        "C# XmlReader combines DTD parsing and external resolution",
        "security",
        "medium",
        "low",
        compile_pattern(r"$^"),
        "A directly consumed XmlReaderSettings initializer combines DtdProcessing.Parse and XmlUrlResolver; external input and deployment still require review.",
        "Use a null/throwing resolver and separately bound XML/entity expansion. DTD parsing with a null resolver is not by itself external entity resolution.",
        "CWE-611",
        "OWASP ASVS V5",
        frozenset({".cs"}),
    ),
    Rule(
        "SP671",
        "Roblox executes an HTTP response as Luau source",
        "security",
        "medium",
        "medium",
        compile_pattern(r"$^"),
        "A direct HttpService response is compiled and immediately executed with loadstring.",
        "Vendor reviewed modules and parse HTTP responses as data; disable LoadStringEnabled unless explicitly required.",
        "CWE-494",
        "Roblox server script integrity",
        frozenset({".lua", ".luau"}),
    ),
    Rule(
        "SP672",
        "Roblox remote callback executes client-supplied source",
        "security",
        "medium",
        "medium",
        compile_pattern(r"$^"),
        "A server remote callback immediately compiles and executes a client data argument.",
        "Use server-owned action handlers and validate client arguments; do not execute client-supplied code.",
        "CWE-94",
        "Roblox client-server boundary",
        frozenset({".lua", ".luau"}),
    ),
    Rule(
        "SP673",
        "Rust constructs an invalid reference",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An explicit std/core zeroed or uninitialized call constructs an invalid reference.",
        "Create the reference from a live value, or keep storage as MaybeUninit until a valid value is written.",
        "CWE-665",
        "Rust reference validity",
        frozenset({".rs"}),
    ),
    Rule(
        "SP674",
        "Next.js image optimizer permits private IP targets",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "Exported image options explicitly set dangerouslyAllowLocalIP to true.",
        "Keep private IP image targets blocked unless origins and network isolation are reviewed.",
        "CWE-918",
        "Next.js image request boundary",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP675",
        "JWT verification skips time-claim validation",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported jsonwebtoken verify call ignores expiration or not-before claims.",
        "Restore exp/nbf validation on authentication paths and test token lifetime boundaries.",
        "CWE-613",
        "JWT lifetime validation",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP676",
        "JWT permits incompatible asymmetric key types",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported jsonwebtoken verify/sign call enables allowInvalidAsymmetricKeyTypes.",
        "Use compatible algorithm/key pairs and remove this legacy compatibility opt-out.",
        "CWE-347",
        "JWT algorithm/key compatibility",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP677",
        "Node AES-GCM uses a short authentication tag",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported Node crypto AES-GCM call selects a 4- or 8-byte authentication tag.",
        "Prefer the default 16-byte tag; review protocol limits before retaining shorter legacy tags.",
        "CWE-326",
        "Authenticated encryption strength",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP678",
        "Node unsafe Buffer is immediately read as a string",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A positive-size imported unsafe Buffer is converted to a string before an overwrite.",
        "Use Buffer.alloc or overwrite every byte before converting unsafe storage to a string.",
        "CWE-908",
        "Initialized memory confidentiality",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP679",
        "Node HTTP explicitly enables a lenient parser",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported HTTP(S) call explicitly selects insecure HTTP parsing/validation.",
        "Keep strict parsing enabled and reject malformed HTTP consistently across intermediaries.",
        "CWE-444",
        "HTTP parser agreement",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP680",
        "Electron BrowserWindow disables web security",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported BrowserWindow constructor sets webPreferences.webSecurity to false.",
        "Retain browser security and use narrow reviewed IPC or protocol APIs for cross-origin needs.",
        "CWE-693",
        "Electron origin boundary",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP681",
        "Electron renderer enables Node without context isolation",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A BrowserWindow combines nodeIntegration true and contextIsolation false.",
        "Disable Node integration, enable isolation and sandboxing, and expose validated contextBridge APIs.",
        "CWE-749",
        "Electron privilege boundary",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP682",
        "Puppeteer launches Chromium without its sandbox",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported Puppeteer launch passes an explicit --no-sandbox argument.",
        "Configure a supported Chromium sandbox or independently reviewed host containment.",
        "CWE-693",
        "Browser process containment",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP683",
        "Declared PHP version predates PHP2Shell fixes",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "This declared upstream PHP version predates CVE-2026-109618/CVE-2026-109619 fixes. Review web-runtime deployment and vendor backports; this is not proof of an exploitable host.",
        "Upgrade to PHP 8.2.35/8.3.36/8.4.27/8.5.12 or a verified vendor-fixed build, restart web workers and verify the running binary. Reviewed 2026-10-22; no online lookup is performed.",
        "CWE-1395",
        "PHP runtime supply-chain advisories",
    ),
    Rule(
        "SP684",
        "Declared Node.js version predates October 2026 security baseline",
        "security",
        "high",
        "high",
        compile_pattern(r"$^"),
        "The declared Node.js pin predates its branch's 2026-10-21 security release; deployment, affected APIs and vendor backports remain unverified.",
        "Verify Node 22.23.4/24.22.1/26.12.1 or a vendor-fixed build and restart affected processes. Offline snapshot reviewed 2026-10-22.",
        "CWE-1395",
        "Node.js runtime security advisories",
    ),
    Rule(
        "SP685",
        "Declared Node.js branch is past upstream support",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "The declared Node.js branch is upstream EOL in the October 2026 schedule; separate vendor security support is not established by this pin.",
        "Move deployment to a maintained patched branch or verify ongoing vendor security support. Offline snapshot reviewed 2026-10-22.",
        "CWE-1104",
        "Runtime support lifecycle",
    ),
    Rule(
        "SP686",
        "Node TLS configuration selects a legacy protocol",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported TLS/HTTPS call explicitly selects a TLS 1.0/1.1 protocol floor or method.",
        "Prefer TLS 1.2 or newer and verify negotiated protocols against deployment policy.",
        "CWE-327",
        "RFC 8996 deprecated transport protocols",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP687",
        "WebSocket server payload limit is disabled or overflows",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported ws server's maxPayload becomes nonpositive after signed-32-bit conversion.",
        "Set a workload-appropriate positive message cap below 2^31 bytes and test rejection.",
        "CWE-400",
        "WebSocket message resource bound",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP688",
        "Next.js SVG image delivery explicitly removes browser safeguards",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "Exported image options enable SVG, inline disposition and an explicitly empty CSP.",
        "Use attachment delivery and a restrictive image CSP; verify final response headers and trusted image origins.",
        "CWE-79",
        "Next.js image response boundary",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP689",
        "Kestrel request-body size limit explicitly disabled",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A typed Kestrel configuration explicitly assigns Limits.MaxRequestBodySize = null.",
        "Set a finite body limit or verify an independent per-request/proxy cap and bounded streaming behavior.",
        "CWE-400",
        "ASP.NET request resource bounds",
        frozenset({".cs"}),
    ),
    Rule(
        "SP690",
        "Roblox remote directly requires a client-selected module",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A locally constructed remote passes client data directly to require.",
        "Select reviewed modules server-side using validated action IDs.",
        "CWE-829",
        "Roblox module trust boundary",
        frozenset({".lua", ".luau"}),
    ),
    Rule(
        "SP691",
        "Roblox remote directly removes a client-selected object",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A locally constructed remote calls Destroy or Kick on its client-selected target without a local guard.",
        "Select targets on the server and validate ownership and permission before removing an instance or Player.",
        "CWE-862",
        "Roblox instance authorization",
        frozenset({".lua", ".luau"}),
    ),
    Rule(
        "SP692",
        "JWT RSA signing key-size safeguard explicitly disabled",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "Imported JWT sign options explicitly enable undersized RSA keys.",
        "Remove allowInsecureKeySizes and use a sufficiently strong RSA signing key.",
        "CWE-326",
        "JWT signing key strength",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP693",
        "Node HTTP receive deadlines explicitly disabled",
        "scale",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "Imported server options set both requestTimeout and headersTimeout to zero.",
        "Retain finite request/header receive deadlines or verify independent ingress bounds.",
        "CWE-400",
        "HTTP receive resource bounds",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP694",
        "Direct await of an empty asynchronous race",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An empty native Promise.race or imported Dart Future.any is directly awaited.",
        "Handle the empty-input branch explicitly before awaiting a race.",
        "CWE-754",
        "Asynchronous completion",
        JS_CONFIG_SUFFIXES | frozenset({".dart"}),
    ),
    Rule(
        "SP695",
        "Native array sort comparator returns a boolean",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A literal array sort uses a two-parameter comparator that returns only a comparison boolean.",
        "Return a negative number, zero or a positive number; test ascending and descending inputs.",
        "CWE-682",
        "Comparison contract",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP696",
        "XML entity expansion limit explicitly removed",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "XmlReader.Create receives inline settings enabling DTD parsing with a zero entity-character limit.",
        "Use finite entity/document limits or prohibit DTDs; a null resolver alone does not bound internal entities.",
        "CWE-776",
        "XML expansion resource bounds",
        frozenset({".cs"}),
    ),
    Rule(
        "SP697",
        "Unverified logging configuration listener explicitly started",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A directly imported logging.config.listen with verify=None is immediately started.",
        "Authenticate configuration bytes with a verified callback, or omit the listener.",
        "CWE-94",
        "Local configuration trust boundary",
        frozenset({".py"}),
    ),
    Rule(
        "SP698",
        "Awaited synchronous compression still blocks the caller",
        "performance",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported Node zlib synchronous operation is directly awaited.",
        "Use asynchronous compression/streams or a bounded worker for expensive data; await does not offload synchronous work.",
        "CWE-400",
        "Event-loop CPU budget",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP699",
        "Rust unchecked NonZero construction receives zero",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A qualified std/core NonZero integer constructor explicitly receives zero without validation.",
        "Use NonZero::new and handle None, or establish a nonzero value before unsafe construction.",
        "CWE-665",
        "Rust value validity",
        frozenset({".rs"}),
    ),
    Rule(
        "SP700",
        "Node timer delay exceeds its supported range",
        "performance",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported timer receives a delay above 2147483647 ms, which Node clamps to 1 ms.",
        "Use bounded delay chunks or a scheduler; validate timer inputs before registration.",
        "CWE-681",
        "Timer range and scheduling",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP701",
        "SQLAlchemy QueuePool capacity explicitly unlimited",
        "scale",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported native QueuePool is constructed with pool_size=0 or max_overflow=-1.",
        "Set finite pool size and overflow bounds suitable for total application concurrency.",
        "CWE-400",
        "Database connection capacity",
        frozenset({".py"}),
    ),
    Rule(
        "SP702",
        "React effect setup is an async function",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported React effect receives an async setup function, which returns a Promise rather than cleanup or undefined.",
        "Keep setup synchronous; start async work inside it and return synchronous cleanup with cancellation as needed.",
        "CWE-664",
        "React effect lifecycle",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP703",
        "Await uses a callback Node I/O API",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported callback pipeline/readFile/writeFile overload is awaited as if it returned a completion Promise.",
        "Use the corresponding node:stream/promises or node:fs/promises API, or keep callback completion explicit.",
        "CWE-664",
        "I/O completion ownership",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP704",
        "PostgreSQL URL overrides an explicit custom-CA TLS object",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An imported pg Client/Pool receives a literal SSL URL parameter and an SSL object with a custom CA; URL parsing replaces that object.",
        "Choose one TLS configuration source; keep custom CA settings in the SSL object and remove SSL parameters from the connection URL.",
        "CWE-436",
        "Database TLS configuration precedence",
        JS_CONFIG_SUFFIXES,
    ),
    Rule(
        "SP705",
        "PostgreSQL concurrent index operation is inside a transaction",
        "correctness",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A supported concurrent CREATE/DROP/REINDEX operation occurs inside an explicit transaction.",
        "Run concurrent index operations outside a transaction; configure the migration runner accordingly.",
        "CWE-664",
        "PostgreSQL transactional DDL contract",
        frozenset({".sql"}),
    ),
    Rule(
        "SP706",
        "PostgreSQL definer SELECT searches temporary relations first",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "An SQL SECURITY DEFINER function explicitly puts pg_temp first in search_path and selects from an unqualified relation.",
        "Schema-qualify protected relations and place only trusted schemas before pg_temp, which should be last.",
        "CWE-426",
        "Privileged SQL name resolution",
        frozenset({".sql"}),
    ),
    Rule(
        "SP707",
        "Roblox remote writes client-selected DataStore keys and values",
        "security",
        "medium",
        "high",
        compile_pattern(r"$^"),
        "A native remote callback directly passes client-selected key/value arguments to native DataStore SetAsync.",
        "Choose authorized keys on the server, validate values and bound requests before persisting client input.",
        "CWE-862",
        "Roblox persistent-data authorization",
        frozenset({".lua", ".luau"}),
    ),
)

# Secret rules are exactly the rules that redact credential material in evidence.
# Derived from metadata (not a hand-maintained ID list) so new provider-token
# rules inherit placeholder filtering, comment scanning, and document scanning.
SECRET_RULE_IDS = frozenset(rule.rule_id for rule in RULES if rule.redact)
MINIMIZED_EVIDENCE_RULE_IDS = frozenset(
    {
        "SP212",
        "SP336",
        "SP346",
        "SP377",
        "SP378",
        "SP591",
        "SP621",
        *(f"SP{number}" for number in range(666, 708)),
    }
)
RULE_INDEX = {rule.rule_id: rule for rule in RULES}

# Rules whose evidence is the CONTENT of a string literal (URL query shapes,
# URI schemes) rather than code position; the inside-string filter must not
# suppress them.
STRING_CONTENT_RULE_IDS = frozenset({"SP063", "SP148", "SP615", "SP616", "SP617"})


# --- Literal gate prefilter ---
# A regex can only match text that contains every literal the pattern requires
# (and, for alternations such as `Counter|Gauge|Histogram`, at least one literal
# from each group). Checking those literals with substring/mini-regex probes
# first skips most rule executions entirely without changing any result.

_HAS_CASED = re.compile(r"[^\W\d_]", re.UNICODE)
_SRE_ATOMIC_GROUP_OP = getattr(_sre_constants, "ATOMIC_GROUP", None)


class LiteralGate:
    """Sound prefilter: `allows(text)` is False only when the rule cannot match.

    Constraints: every `required` literal must appear, and for each DNF group at
    least one branch conjunction must be fully present.
    """

    __slots__ = ("_ci", "_group_branches", "_plain")

    def __init__(
        self,
        required: Iterable[str],
        groups: Iterable[Iterable[Iterable[str]]],
    ) -> None:
        self._plain = tuple(
            lit for lit in required if _HAS_CASED.search(lit) is None and len(lit) >= 2
        )
        self._ci = tuple(
            re.compile(re.escape(lit), re.IGNORECASE)
            for lit in required
            if _HAS_CASED.search(lit) is not None and len(lit) >= 2
        )
        self._group_branches = tuple(
            tuple(
                (
                    frozenset(lit for lit in branch if _HAS_CASED.search(lit) is None),
                    tuple(
                        re.compile(re.escape(lit), re.IGNORECASE)
                        for lit in branch
                        if _HAS_CASED.search(lit) is not None
                    ),
                )
                for branch in group
            )
            for group in groups
        )

    def allows(self, text: str) -> bool:
        for literal in self._plain:
            if literal not in text:
                return False
        for pattern in self._ci:
            if pattern.search(text) is None:
                return False
        for group in self._group_branches:
            if not any(
                all(literal in text for literal in plain)
                and all(pattern.search(text) is not None for pattern in ci)
                for plain, ci in group
            ):
                return False
        return True


def _required_literals(
    node: Iterable,
) -> tuple[frozenset[str], tuple[tuple[frozenset[str], ...], ...]]:
    """Walk a parsed regex tree collecting literals every match must contain.

    Returns (and_literals, dnf_groups): each `and` literal must appear in any
    match, and for each DNF group at least one branch's full literal set must be
    present. When the tree cannot prove anything, both collections are empty.
    """
    required: set[str] = set()
    groups: list[tuple[frozenset[str], ...]] = []
    buffer: list[str] = []

    def flush() -> None:
        if buffer:
            required.add("".join(buffer))
            buffer.clear()

    for op, arg in node:
        if op is _sre_constants.LITERAL:
            buffer.append(chr(arg))
            continue
        flush()
        if op is _sre_constants.SUBPATTERN:
            sub_required, sub_groups = _required_literals(arg[-1])
            required |= sub_required
            groups.extend(sub_groups)
        elif _SRE_ATOMIC_GROUP_OP is not None and op is _SRE_ATOMIC_GROUP_OP:
            sub_required, sub_groups = _required_literals(arg)
            required |= sub_required
            groups.extend(sub_groups)
        elif op is _sre_constants.BRANCH:
            branches = [_required_literals(branch) for branch in arg[1]]
            if all(
                branch_required and not branch_groups for branch_required, branch_groups in branches
            ):
                groups.append(tuple(branch_required for branch_required, _ in branches))
                continue
            common: set[str] | None = None
            for branch_required, _branch_groups in branches:
                common = set(branch_required) if common is None else common & set(branch_required)
            if common:
                required |= common
        elif op in (_sre_constants.MAX_REPEAT, _sre_constants.MIN_REPEAT):
            if arg[0] >= 1:
                sub_required, sub_groups = _required_literals(arg[2])
                required |= sub_required
                groups.extend(sub_groups)
        elif op is _sre_constants.ASSERT:
            sub_required, sub_groups = _required_literals(arg[1])
            required |= sub_required
            groups.extend(sub_groups)
        # IN, ANY, CATEGORY, AT, ASSERT_NOT, GROUPREF, GROUPREF_EXISTS and
        # friends impose no provable literal requirement.

    flush()
    return frozenset(required), tuple(groups)


def build_rule_gates(rules: Sequence[Rule]) -> dict[str, LiteralGate]:
    gates: dict[str, LiteralGate] = {}
    for rule in rules:
        try:
            parsed = _sre_parser.parse(rule.pattern.pattern, rule.pattern.flags)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError, re.error):
            continue
        required, groups = _required_literals(parsed)
        if required or groups:
            gates[rule.rule_id] = LiteralGate(required, groups)
    return gates


def rule_gates() -> dict[str, LiteralGate]:
    """Build the literal prefilter lazily to keep --explain/MCP startup fast."""
    gates = getattr(rule_gates, "cache", None)
    if gates is None:
        gates = build_rule_gates(RULES)
        rule_gates.cache = gates
    return gates


DATABASE_SUFFIXES = {".sqlite", ".sqlite3", ".db"}
REPARSE_POINT_ATTRIBUTE = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    """Include Windows junctions even on Python versions without Path.is_junction."""
    return stat_module.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT_ATTRIBUTE
    )


# Content-bearing container formats. Members stay omitted unless
# --inspect-archives is set, and even then only ZIP-based suffixes are opened
# in memory with hard member/byte/ratio bounds (see archive_inspect).
CONTAINER_SUFFIXES = frozenset(
    {
        ".zip",
        ".docx",
        ".xlsx",
        ".pptx",
        ".jar",
        ".war",
        ".apk",
        ".ipa",
        ".aab",
        ".whl",
        ".egg",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".zst",
        ".7z",
        ".rar",
    }
)

# Known static assets, compiled artifacts, and generated reports: deliberately
# out of scope for a source scanner, counted for visibility but never treated
# as omitted content.
ASSET_SUFFIXES = frozenset(
    {
        ".sarif",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",
        ".ico",
        ".bmp",
        ".tif",
        ".tiff",
        ".avif",
        ".heic",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".mkv",
        ".webm",
        ".wav",
        ".flac",
        ".ogg",
        ".pdf",
        ".psd",
        ".ai",
        ".sketch",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".pyc",
        ".pyo",
        ".class",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".wasm",
        ".coverage",
    }
)


def is_text_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    return (
        suffix in TEXT_SUFFIXES
        or suffix in DATABASE_SUFFIXES
        or path.name.lower() in TEXT_NAMES
        or _is_sensitive_env_path(path.name)
    )


def classify_unscannable(path: Path) -> str:
    """Return why a non-text file is outside the scanner's scope."""
    suffix = path.suffix.lower()
    if suffix in DATABASE_SUFFIXES:
        return "database"
    if suffix in CONTAINER_SUFFIXES:
        return "container"
    if suffix in ASSET_SUFFIXES:
        return "asset"
    if path.name.lower() in {".coverage"}:
        return "asset"
    return "binary"


def scanner_file_kind(path: Path) -> str:
    """Return the selector used by suffix-scoped rules, including suffixless manifests."""
    name = path.name.lower()
    if name in {"dockerfile", "containerfile"}:
        return name
    return path.suffix.lower()


def normalize_exclude_patterns(patterns: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in patterns:
        pattern = value.replace("\\", "/").removeprefix("./")
        if (
            not pattern
            or pattern.startswith("/")
            or "\x00" in pattern
            or ".." in pattern.split("/")
            or len(pattern) > 512
        ):
            raise ValueError(f"unsafe exclude pattern: {value!r}")
        normalized.append(pattern)
    return tuple(dict.fromkeys(normalized))


def is_excluded(relative_path: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatchcase(relative_path, pattern):
            return True
        if pattern.endswith("/**") and relative_path == pattern.removesuffix("/**"):
            return True
    return False


def iter_scannable_files(
    root: Path,
    max_file_bytes: int,
    exclude_patterns: Sequence[str] = (),
    include_paths: frozenset[str] | None = None,
    tracked_paths: frozenset[str] | None = None,
) -> Iterable[tuple[Path, str, str | None]]:
    """Walk deterministically while pruning unselected ignored trees.

    Yields ``(path, relative_path, skip_reason)``. A ``None`` skip reason means
    the file is in scope for content scanning; otherwise the reason is one of
    the coverage-ledger categories (``symlink``, ``unreadable``, ``excluded``,
    ``size``, ``database``, ``container``, ``asset``, ``binary``).

    Dependency/build trees remain cheap by default, but repository scans can
    pass Git-index paths (and/or an explicit changed-file selection) so a
    tracked file inside one of those trees is not silently skipped. ``None``
    preserves the historical pruning behavior for callers without Git
    evidence.
    """
    walk_errors = 0
    selected_paths = set(tracked_paths or ())
    selected_paths.update(include_paths or ())
    ignored_file_selection = (
        set(include_paths) if include_paths is not None else set(tracked_paths or ())
    )
    selected_directories: set[str] = set()
    for selected_path in selected_paths:
        normalized = selected_path.replace("\\", "/").strip("/")
        if not normalized or normalized == ".":
            continue
        parts = normalized.split("/")
        selected_directories.add(normalized)
        selected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))

    def record_walk_error(error: OSError) -> None:
        nonlocal walk_errors
        try:
            relative = Path(error.filename).relative_to(root).as_posix()
        except (TypeError, ValueError):
            relative = "."
        if not is_excluded(relative, exclude_patterns) and _coverage_path_selected(
            relative, include_paths, directory=True
        ):
            walk_errors += 1

    for directory, subdirectories, filenames in os.walk(
        root, topdown=True, onerror=record_walk_error, followlinks=False
    ):
        relative_directory = Path(directory).relative_to(root)
        inside_ignored_tree = any(part in SKIP_DIRS for part in relative_directory.parts)
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if (
                (not inside_ignored_tree and name not in SKIP_DIRS)
                or (
                    (tracked_paths is not None or include_paths is not None)
                    and (relative_directory / name).as_posix() in selected_directories
                )
            )
            and not is_excluded(
                (relative_directory / name).as_posix().removeprefix("./"),
                exclude_patterns,
            )
        )
        for name in tuple(subdirectories):
            child = Path(directory, name)
            try:
                child_stat = os.lstat(child)
            except OSError as exc:
                subdirectories.remove(name)
                record_walk_error(exc)
                continue
            if is_link_or_reparse(child_stat):
                subdirectories.remove(name)
                if _coverage_path_selected(
                    child.relative_to(root).as_posix(), include_paths, directory=True
                ):
                    yield child, child.relative_to(root).as_posix(), "symlink"
        for filename in sorted(filenames):
            path = Path(directory, filename)
            relative_path = path.relative_to(root).as_posix()
            # Once a conventionally ignored tree is retained for a tracked or
            # explicitly selected path, do not fan back out into its entire
            # untracked dependency/build output. This keeps the Git-index
            # escape hatch bounded to the files that justified descending.
            if (
                inside_ignored_tree
                and (tracked_paths is not None or include_paths is not None)
                and relative_path not in ignored_file_selection
            ):
                continue
            if is_excluded(relative_path, exclude_patterns):
                yield path, relative_path, "excluded"
                continue
            try:
                file_stat = os.lstat(path)
            except OSError:
                yield path, path.relative_to(root).as_posix(), "unreadable"
                continue
            if is_link_or_reparse(file_stat):
                yield path, path.relative_to(root).as_posix(), "symlink"
                continue
            if not stat_module.S_ISREG(file_stat.st_mode):
                yield path, relative_path, "unreadable"
                continue
            # Artifact detection needs only the fixed SQLite header, regardless
            # of the database size; database contents are never analyzed.
            if path.suffix.lower() in DATABASE_SUFFIXES:
                yield path, relative_path, None
                continue
            if not is_text_file(path):
                yield path, relative_path, classify_unscannable(path)
                continue
            if file_stat.st_size <= max_file_bytes:
                yield path, relative_path, None
            elif inside_ignored_tree:
                # Git-index/include hatches re-enter skip trees for tracked
                # source. Oversized catalogs in those trees stay omitted without
                # failing the completeness gate of the selected application.
                yield path, relative_path, "excluded"
            else:
                yield path, relative_path, "size"
    # Keep only a count: a tree full of denied directories must not allocate an
    # unbounded diagnostic/path list. Errors are already scoped by the callback.
    for _ in range(walk_errors):
        yield root, "", "walk_error"


def _coverage_path_selected(
    relative_path: str, include_paths: frozenset[str] | None, *, directory: bool = False
) -> bool:
    if include_paths is None:
        return True
    if not directory:
        return relative_path in include_paths
    prefix = "" if relative_path in {"", "."} else relative_path.rstrip("/") + "/"
    return relative_path in include_paths or any(path.startswith(prefix) for path in include_paths)


def terminal_safe_text(value: object) -> str:
    """Neutralize C0/C1 and escape bytes before putting untrusted text on stdout."""
    text = str(value)
    safe: list[str] = []
    for character in text:
        codepoint = ord(character)
        if codepoint < 0x20 or codepoint == 0x7F or 0x80 <= codepoint <= 0x9F:
            if character in {"\n", "\t"}:
                safe.append(" ")
            else:
                safe.append(f"\\x{codepoint:02x}")
        else:
            safe.append(character)
    return "".join(safe)


def clean_evidence(line: str, redact: bool) -> str:
    compact = terminal_safe_text(line.strip().replace("\t", " "))[:240]
    return "[REDACTED: credential-like material]" if redact else compact


HASH_COMMENT_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".sh",
        ".bash",
        ".ps1",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".env",
        ".rb",
        ".erb",
        ".ex",
        ".exs",
        ".graphql",
        ".gql",
        ".prisma",
        ".service",
    }
)
HASH_COMMENT_NAMES = frozenset(
    {
        "dockerfile",
        "containerfile",
        "makefile",
        "procfile",
        ".env",
        ".nvmrc",
        ".node-version",
        ".php-version",
        ".tool-versions",
    }
)
SLASH_COMMENT_SUFFIXES = frozenset(
    {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".java",
        ".kt",
        ".kts",
        ".go",
        ".rs",
        ".cs",
        ".php",
        ".vue",
        ".svelte",
        ".astro",
        ".html",
        ".swift",
        ".dart",
        ".scala",
        ".groovy",
        ".m",
        ".mm",
    }
)


def comment_line_prefixes(path: Path) -> tuple[str, ...]:
    """Resolve the comment markers used to open a comment line for this file type."""
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in HASH_COMMENT_SUFFIXES or name in HASH_COMMENT_NAMES:
        return ("#",)
    if suffix in SLASH_COMMENT_SUFFIXES:
        return ("//", "/*")
    if suffix == ".sql":
        return ("--", "/*")
    if suffix in {".lua", ".luau"}:
        return ("--",)
    if suffix in {".tf", ".hcl"}:
        return ("#", "//")
    return ()


def is_pure_comment(line: str, path: Path, prefixes: Sequence[str] | None = None) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    markers = prefixes if prefixes is not None else comment_line_prefixes(path)
    if markers == ("#",):
        return stripped.startswith("#")
    if markers == ("--",):
        return stripped.startswith("--")
    if markers == ("//", "/*"):
        return stripped.startswith(("//", "/*", "*", "<!--"))
    if markers == ("--", "/*"):
        return stripped.startswith(("--", "/*", "*"))
    if markers == ("#", "//"):
        return stripped.startswith(("#", "//"))
    return False


def index_outside_strings(line: str, marker: str) -> int:
    """Return the first index of marker that is not inside a quoted string segment."""
    quote = ""
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in {"'", '"', "`"}:
            quote = char
        elif line.startswith(marker, index):
            return index
        index += 1
    return -1


def extract_inline_ignore_ids(line: str, prefixes: Sequence[str]) -> tuple[str, ...]:
    """Collect suppressed rule IDs, but only from markers inside comments (not string data).

    Files without comment markers (JSON, Markdown) still honor a marker that
    starts the line, which keeps documentation suppressions explicit.
    """
    marker_index = line.find(INLINE_IGNORE_MARKER)
    if marker_index < 0:
        return ()
    rest = line[marker_index + len(INLINE_IGNORE_MARKER) :]
    if rest and rest[0] not in " \t:,":
        return ()
    if prefixes:
        comment_index = -1
        for marker in prefixes:
            position = index_outside_strings(line, marker)
            if position >= 0 and (comment_index < 0 or position < comment_index):
                comment_index = position
        if comment_index < 0 or marker_index < comment_index:
            return ()
    elif not line.lstrip().startswith(INLINE_IGNORE_MARKER):
        return ()
    return tuple(dict.fromkeys(INLINE_IGNORE_IDS.findall(line, marker_index)))


TEST_PATH_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "spec",
        "specs",
        "__tests__",
        "docs",
        "doc",
        "documentation",
        "examples",
        "example",
        "samples",
        "sample",
        "benchmarks",
        "benchmark",
        "fixtures",
    }
)

DOWNRANK_CONFIDENCE = {
    "high": "medium",
    "medium": "low",
    "low": "low",
}

# Structural rules whose framework must be declared in a repository manifest to
# keep full confidence. Absent manifests keep confidence; present-but-absent
# framework declarations downgrade it (see find_regex_issues).
RULE_FRAMEWORK_HINTS = {
    "SP108": frozenset(
        {"fastapi", "django", "flask", "express", "fastify", "nestjs", "koa", "hono"}
    ),
    "SP593": frozenset({"nextjs"}),
    "SP401": frozenset({"express"}),
    "SP402": frozenset({"express"}),
    "SP407": frozenset({"express"}),
    "SP408": frozenset({"express"}),
    "SP404": frozenset({"django"}),
    "SP410": frozenset({"flask"}),
    "SP591": frozenset({"nextjs", "react"}),
    "SP595": frozenset({"nextjs", "react"}),
    "SP596": frozenset({"nextjs"}),
    "SP597": frozenset({"nextjs", "react"}),
    "SP598": frozenset({"nextjs", "react"}),
    "SP600": frozenset({"nextjs", "react"}),
    "SP664": frozenset({"fastapi"}),
    "SP665": frozenset({"django"}),
}

# Pattern-detection rules whose look-alike risk also depends on the declared
# framework; without this they would never participate in the downgrade above.
FRAMEWORK_HINT_PATTERN_RULES = frozenset({"SP593"})

# Bundled vendor artifacts: minified bundles and content-hashed filenames.
MINIFIED_FILE_NAME = re.compile(
    r"(?:\.min\.(?:js|mjs|cjs|css)|-[0-9a-f]{8,}\.(?:js|mjs|cjs|css))$",
    re.IGNORECASE,
)


EVAL_DATASET_FILENAMES = frozenset(
    {
        "evals.json",
        "evals.jsonl",
        "evals.yaml",
        "evals.yml",
        "dataset.json",
        "dataset.jsonl",
        "dataset.yaml",
        "dataset.yml",
    }
)


@lru_cache(maxsize=8192)
def determine_scope(relative_path: str) -> str:
    normalized = relative_path.replace("\\", "/").removeprefix("./").lower()
    parts = normalized.split("/")
    if any(part in TEST_PATH_SEGMENTS for part in parts[:-1]):
        return "test"
    filename = parts[-1]
    # Authored eval datasets hold prompts, expected outputs, and ground-truth
    # strings; they are test data, not executable skill logic.
    if filename in EVAL_DATASET_FILENAMES and any(part in {"evals", "eval"} for part in parts[:-1]):
        return "test"
    stem = Path(filename).stem
    suffixes = "".join(Path(filename).suffixes).lower()
    if (
        filename.startswith("test_")
        or stem.startswith("test_")
        or stem.endswith(("_test", "_tests", ".test", ".spec", "_spec"))
        or filename in {"conftest.py", "conftest.js", "conftest.ts", "conftest.jsx", "conftest.tsx"}
        or suffixes.endswith(
            (
                ".test.js",
                ".test.ts",
                ".test.jsx",
                ".test.tsx",
                ".spec.js",
                ".spec.ts",
                ".spec.jsx",
                ".spec.tsx",
            )
        )
    ):
        return "test"
    return "app"


def offset_to_position(source_text: str, offset: int) -> tuple[int, int]:
    """Map a 0-based string offset to a 1-based (line, column) pair."""
    line = source_text.count("\n", 0, offset) + 1
    column = offset - source_text.rfind("\n", 0, offset)
    return line, column


def make_finding(
    rule: Rule,
    relative_path: str,
    line_number: int,
    evidence: str,
    detection: str = "pattern",
    scope: str | None = None,
    confidence: str | None = None,
    verification_status: str = "unverified",
    column: int | None = None,
    end_line: int | None = None,
    end_column: int | None = None,
    history_commit: str | None = None,
    minimal_evidence: str | None = None,
) -> Finding:
    safe_evidence = clean_evidence(evidence, rule.redact)
    minimized = rule.rule_id in MINIMIZED_EVIDENCE_RULE_IDS or minimal_evidence is not None
    if minimized and not rule.redact:
        safe_evidence = clean_evidence(minimal_evidence or rule.message, False)
    if rule.redact or minimized:
        content_hash = hashlib.sha256(evidence.strip().encode("utf-8", "replace")).hexdigest()[:12]
        identity = f"{rule.rule_id}:{relative_path}:{content_hash}"
    else:
        identity = f"{rule.rule_id}:{relative_path}:{safe_evidence}"
    fingerprint = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:24]
    finding_scope = scope if scope is not None else determine_scope(relative_path)
    base_confidence = confidence if confidence is not None else rule.confidence
    finding_confidence = (
        DOWNRANK_CONFIDENCE.get(base_confidence, base_confidence)
        if finding_scope == "test" and confidence is None
        else base_confidence
    )
    return Finding(
        rule.rule_id,
        rule.title,
        rule.category,
        rule.severity,
        finding_confidence,
        relative_path,
        line_number,
        safe_evidence,
        rule.message,
        rule.remediation,
        rule.cwe,
        rule.owasp,
        fingerprint,
        detection,
        PROOF_LEVELS.get(detection, "L0"),
        finding_scope,
        verification_status,
        column,
        end_line,
        end_column,
        history_commit,
        match_confidence=base_confidence,
        tier="advisory" if rule.rule_id in precision_policy.ADVISORY_RULE_IDS else "gate",
    )


SKILL_RULE_IDS = frozenset(
    {
        "SP096",
        "SP097",
        "SP098",
        "SP099",
        "SP100",
    }
)

# Documents are normally excluded from executable-code rules. Skill rules are
# the narrow exception, but only after the caller has established that the
# document belongs to a declared Agent Skill package.
DOCUMENT_SCAN_RULE_IDS = SKILL_RULE_IDS


def has_skill_path_context(relative_path: str) -> bool:
    """Infer explicit Skill ownership for in-memory/direct scanner callers."""

    normalized = relative_path.replace("\\", "/").strip("/")
    parts = tuple(part.casefold() for part in normalized.split("/") if part)
    if not parts:
        return False
    if parts[-1] == "skill.md":
        return True
    return "skills" in parts[:-1]


def is_within_skill_root(relative_path: str, skill_roots: frozenset[str]) -> bool:
    """Return whether a repository path belongs to a discovered Skill package."""

    normalized = relative_path.replace("\\", "/").strip("/").casefold()
    for root in skill_roots:
        if not root or normalized == root or normalized.startswith(root + "/"):
            return True
    return False


def discover_skill_roots(root: Path, exclude_patterns: Sequence[str]) -> frozenset[str]:
    """Discover Skill descriptors independently of file-size and file-only excludes."""

    roots: set[str] = set()
    for directory, subdirectories, filenames in os.walk(root, topdown=True, onerror=lambda _: None):
        relative_directory = Path(directory).relative_to(root)
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name not in SKIP_DIRS
            and not is_excluded(
                (relative_directory / name).as_posix().removeprefix("./"),
                exclude_patterns,
            )
        )
        for name in tuple(subdirectories):
            try:
                linked = is_link_or_reparse(os.lstat(Path(directory, name)))
            except OSError:
                linked = True
            if linked:
                subdirectories.remove(name)
        descriptor_name = next(
            (name for name in filenames if name.casefold() == "skill.md"),
            None,
        )
        if descriptor_name is None:
            continue
        descriptor = Path(directory, descriptor_name)
        try:
            descriptor_stat = os.lstat(descriptor)
        except OSError:
            continue
        if not stat_module.S_ISREG(descriptor_stat.st_mode) or is_link_or_reparse(descriptor_stat):
            continue
        parent = relative_directory.as_posix().casefold()
        roots.add("" if parent == "." else parent)
    return frozenset(roots)


MCP_RULE_IDS = frozenset({"SP271", "SP272", "SP273", "SP274", "SP275"})
MCP_SOURCE_SIGNAL = re.compile(
    r"@modelcontextprotocol/sdk|\bMcpServer\b|\bFastMCP\b|"
    r"\bregisterTool\s*\(|\b(?:server|mcp)\.tool\s*\(",
    re.IGNORECASE,
)


def has_mcp_context(relative_path: str, source_text: str) -> bool:
    """Require visible MCP ownership before applying MCP-specific rules."""

    normalized = relative_path.replace("\\", "/").lower()
    path_has_mcp_segment = re.search(r"(?:^|[/_.-])mcp(?:$|[/_.-])", normalized) is not None
    return path_has_mcp_segment or MCP_SOURCE_SIGNAL.search(source_text) is not None


FILE_LEVEL_RULE_IDS = frozenset(
    {
        "SP210",
        "SP212",
        "SP220",
        "SP583",
        "SP599",
        "SP107",
        "SP131",
        "SP108",
        "SP115",
        "SP120",
        "SP303",
        "SP304",
        "SP305",
        "SP307",
        "SP314",
        "SP316",
        "SP317",
        "SP318",
        "SP401",
        "SP402",
        "SP407",
        "SP408",
        "SP591",
        "SP595",
        "SP596",
        "SP597",
        "SP598",
        "SP600",
        "SP609",
        "SP612",
        "SP631",
        "SP664",
        "SP665",
        "SP670",
        "SP671",
        "SP672",
        "SP673",
        "SP674",
        "SP675",
        "SP676",
        "SP677",
        "SP678",
        "SP679",
        "SP680",
        "SP681",
        "SP682",
        "SP683",
        "SP684",
        "SP685",
        "SP686",
        "SP687",
        "SP688",
        "SP689",
        "SP690",
        "SP691",
        "SP692",
        "SP693",
        "SP694",
        "SP695",
        "SP696",
        "SP697",
        "SP698",
        "SP699",
        "SP700",
        "SP701",
        "SP702",
        "SP703",
        "SP704",
        "SP705",
        "SP706",
        "SP707",
        "SP336",
        "SP346",
        "SP377",
        "SP378",
        "SP621",
    }
)

APPLICABLE_RULES_CACHE: dict[tuple[str, bool, bool], tuple[Rule, ...]] = {}


def applicable_line_rules(
    suffix: str, is_document: bool, is_manifest_name: bool
) -> tuple[Rule, ...]:
    """Resolve the line-scanned rules once per file class instead of per file."""
    cache_key = (suffix, is_document, is_manifest_name)
    cached = APPLICABLE_RULES_CACHE.get(cache_key)
    if cached is not None:
        return cached
    selected = [
        rule
        for rule in RULES
        if rule.rule_id not in FILE_LEVEL_RULE_IDS
        and not (suffix == ".cs" and rule.rule_id in {"SP056", "SP084"})
        and not (rule.rule_id == "SP202" and not is_manifest_name)
        and not (is_document and not rule.redact and rule.rule_id not in DOCUMENT_SCAN_RULE_IDS)
        and not (
            rule.suffixes
            and suffix not in rule.suffixes
            and not (rule.rule_id == "SP094" and is_manifest_name)
        )
    ]
    if suffix == ".dart":
        selected = [
            replace(
                rule,
                pattern=compile_pattern(
                    r"\b(?:ftp://[a-zA-Z0-9_.-]+:[^@\s/]+@|telnet://[a-zA-Z0-9_.-]+)"
                ),
            )
            if rule.rule_id == "SP170"
            else rule
            for rule in selected
        ]
    resolved = tuple(selected)
    APPLICABLE_RULES_CACHE[cache_key] = resolved
    return resolved


def github_run_expression_lines(source_text: str, rule_id: str = "SP210") -> list[int]:
    """Recognize ordinary workflow step run scalars, not env/with/prose.

    This is intentionally a narrow YAML reader: block mappings, sequence steps,
    quoted keys, and literal/folded/quoted run scalars. Flow maps and aliases are
    not resolved. Block/quoted scalar contents cannot create new YAML keys.
    """
    stack: list[tuple[int, str]] = []
    scalar_indent: int | None = None
    scalar_run = False
    quote: str | None = None
    result: list[int] = []
    pattern = find_rule(rule_id).pattern
    pending: list[tuple[int, str]] = []
    folded = False

    def matches_command(value: str) -> bool:
        if rule_id != "SP212":
            return pattern.search(value) is not None
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        try:
            lexer = shlex.shlex(value, posix=True, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            words = list(lexer)
        except ValueError:
            return False
        command: list[str] = []
        for word in [*words, ";"]:
            if word in {";", "&&", "||", "|", "&"}:
                if command in (["env"], ["printenv"], ["set"]):
                    return True
                command = []
            else:
                command.append(word)
        return False

    def scalar_text(value: str, active_quote: str | None = None) -> tuple[str, str | None]:
        index = 0
        while index < len(value):
            char = value[index]
            if active_quote:
                if char == "\\" and active_quote == '"':
                    index += 2
                    continue
                if char == active_quote:
                    if active_quote == "'" and value[index : index + 2] == "''":
                        index += 2
                        continue
                    active_quote = None
            elif char in {'"', "'"}:
                active_quote = char
            elif char == "#" and (index == 0 or value[index - 1].isspace()):
                return value[:index], active_quote
            index += 1
        return value, active_quote

    def flush_environment_scalar() -> None:
        if not pending:
            return
        if folded:
            if matches_command(" ".join(value.strip() for _, value in pending)):
                result.append(pending[0][0])
        elif not any("<<" in value for _, value in pending):
            # Heredoc bodies and multi-line shell quotes are data, not commands.
            # Heredocs are deliberately unresolved rather than partially parsed.
            shell_quote: str | None = None
            for number, value in pending:
                previous = shell_quote
                _, shell_quote = scalar_text(value, shell_quote)
                if previous is None and shell_quote is None and matches_command(value):
                    result.append(number)
        pending.clear()

    for line_number, line in enumerate(source_text.splitlines(), 1):
        if quote is not None:
            value, quote = scalar_text(line, quote)
            if scalar_run and rule_id == "SP212":
                pending.append((line_number, value))
                if quote is None:
                    # YAML quoted scalars fold physical newlines into spaces.
                    flush_environment_scalar()
            elif scalar_run and matches_command(value):
                result.append(line_number)
            continue
        indent = len(line) - len(line.lstrip(" "))
        if scalar_indent is not None:
            if not line.strip() or indent > scalar_indent:
                if scalar_run and rule_id == "SP212":
                    pending.append((line_number, line))
                elif scalar_run and matches_command(line):
                    result.append(line_number)
                continue
            flush_environment_scalar()
            scalar_indent = None
        match = re.match(r"""^( *)(?:- +)?(?:([\w-]+)|"([\w-]+)"|'([\w-]+)')\s*:\s*(.*)$""", line)
        if match is None:
            continue
        key = next(value for value in match.group(2, 3, 4) if value is not None)
        key_indent = line.index(key)
        while stack and stack[-1][0] >= key_indent:
            stack.pop()
        ancestors = [item[1] for item in stack]
        scalar_run = (
            key == "run"
            and len(ancestors) == 3
            and ancestors[0] == "jobs"
            and ancestors[2] == "steps"
        )
        raw_value = match.group(5)
        value, end_quote = scalar_text(raw_value)
        if re.fullmatch(r"[|>][1-9+-]{0,2}\s*", value):
            scalar_indent = key_indent
            folded = value.startswith(">")
        else:
            if scalar_run and rule_id == "SP212" and end_quote and raw_value.startswith(('"', "'")):
                folded = True
                pending.append((line_number, value))
            elif scalar_run and matches_command(value):
                result.append(line_number)
            # Only a quote at the start creates a YAML quoted scalar. Shell
            # quotes in a plain run command do not consume subsequent YAML.
            quote = end_quote if raw_value.startswith(('"', "'")) else None
        if not value.strip():
            stack.append((key_indent, key))
    flush_environment_scalar()
    return result


def js_context_tokens(source: str) -> list[tuple[str, int]]:
    return js_config_checks.js_context_tokens(source)


def js_context_structure(values: Sequence[str]) -> tuple[dict[int, int], list[int]]:
    return js_config_checks.js_context_structure(values)


def js_shadowed_bindings(
    values: Sequence[str], pairs: dict[int, int], bindings: dict[str, int]
) -> set[str]:
    """Collect rebinding/parameter evidence once, not once per imported name."""
    shadowed: set[str] = set()
    parameter_ranges = [0] * (len(values) + 1)
    for opening, closing in pairs.items():
        if (
            values[opening] == "("
            and closing + 1 < len(values)
            and values[closing + 1] in {"{", "=>"}
        ):
            parameter_ranges[opening + 1] += 1
            parameter_ranges[closing] -= 1
    for index, value in enumerate(values):
        if value != "import":
            continue
        end = index + 1
        while end < len(values) and end - index < 256 and values[end] not in {"from", ";"}:
            end += 1
        for cursor in range(index + 1, end):
            name = values[cursor]
            if name in bindings and not index < bindings[name] < end:
                shadowed.add(name)
    in_parameters = 0
    for index, value in enumerate(values):
        in_parameters += parameter_ranges[index]
        if value not in bindings:
            continue
        if in_parameters or (
            index != bindings[value]
            and (
                (index and values[index - 1] in {"const", "let", "var", "class", "function", "as"})
                or (index + 1 < len(values) and values[index + 1] in {"=", "=>"})
            )
        ):
            shadowed.add(value)
    return shadowed


def js_precision_lines(
    path: Path,
    source: str,
    frameworks: frozenset[str] | None,
    minimal_evidence: dict[tuple[str, int], str] | None = None,
) -> list[tuple[str, int]]:
    """Require local identity, scope and literal evidence for bounded JS/TS checks."""
    tokens = js_context_tokens(source)
    values = [token[0] for token in tokens]
    pairs, depths = js_context_structure(values)
    if not depths:
        return []
    hits: list[tuple[str, int]] = []
    excerpts: dict[tuple[str, int], str] = {}
    for rule_id, start, _end in js_config_checks.signature_spans(
        path, tokens, pairs, depths, excerpts
    ):
        line_number = source.count("\n", 0, start) + 1
        hits.append((rule_id, line_number))
        if minimal_evidence is not None:
            minimal_evidence[(rule_id, line_number)] = excerpts[(rule_id, start)]

    # Only literal top-level BullMQ imports/require bindings establish identity.
    bindings: dict[str, tuple[str, int]] = {}
    for index, value in enumerate(values):
        if depths[index] != 0:
            continue
        if value == "import" and values[index + 1 : index + 2] != ["type"]:
            if values[index + 1 : index + 3] == ["*", "as"] and values[index + 4 : index + 6] in (
                ["from", "'bullmq'"],
                ["from", '"bullmq"'],
            ):
                bindings[values[index + 3]] = ("namespace", index + 3)
            opening = index + 1
            closing = pairs.get(opening)
            if (
                closing is not None
                and values[opening] == "{"
                and values[closing + 1 : closing + 3]
                in (["from", "'bullmq'"], ["from", '"bullmq"'])
            ):
                for cursor in range(opening + 1, closing):
                    if values[cursor] == "Worker" and values[cursor - 1] in {"{", ","}:
                        binding = cursor + 2 if values[cursor + 1] == "as" else cursor
                        bindings[values[binding]] = ("named", binding)
        if value == "const" and values[index + 1 : index + 2] == ["{"]:
            closing = pairs.get(index + 1)
            if (
                closing is not None
                and values[closing + 1 : closing + 4] == ["=", "require", "("]
                and values[closing + 4 : closing + 6] in (["'bullmq'", ")"], ['"bullmq"', ")"])
            ):
                for cursor in range(index + 2, closing):
                    if values[cursor] == "Worker" and values[cursor - 1] in {"{", ","}:
                        binding = cursor + 2 if values[cursor + 1] == ":" else cursor
                        bindings[values[binding]] = ("named", binding)
    binding_positions = {name: binding for name, (_, binding) in bindings.items()}
    binding_positions.setdefault("fetch", -1)
    shadowed = js_shadowed_bindings(values, pairs, binding_positions)
    for index, value in enumerate(values[:-1]):
        name = values[index + 1]
        if value != "new" or name not in bindings or name in shadowed:
            continue
        kind, _ = bindings[name]
        constructor = ["new", name] + ([".", "Worker"] if kind == "namespace" else [])
        if values[index : index + len(constructor)] != constructor:
            continue
        opening = index + len(constructor)
        closing = pairs.get(opening)
        if closing is None or values[opening] != "(" or closing - opening > 512:
            continue
        commas = [
            i
            for i in range(opening + 1, closing)
            if values[i] == "," and depths[i] == depths[opening] + 1
        ]
        if len(commas) != 2:
            continue
        options = commas[-1] + 1
        if values[options] != "{" or pairs.get(options) != closing - 1:
            continue
        option_depth = depths[options] + 1
        segments: list[list[str]] = [[]]
        for cursor in range(options + 1, closing - 1):
            if values[cursor] == "," and depths[cursor] == option_depth:
                segments.append([])
            else:
                segments[-1].append(values[cursor])
        if any(segment and segment[0] in {"...", "["} for segment in segments):
            continue
        configured = [
            segment[1:]
            for segment in segments
            if segment and segment[0].strip("\"'") == "skipStalledCheck"
        ]
        if configured and configured[-1] == [":", "true"]:
            hits.append(("SP583", source.count("\n", 0, tokens[index][1]) + 1))

    # A client directive can follow another directive (for example use strict),
    # but not an import or an ordinary executable statement.
    directives: set[str] = set()
    cursor = 0
    while cursor < len(values) and values[cursor].startswith(("'", '"')):
        next_cursor = cursor + 1
        if next_cursor < len(values) and values[next_cursor] != ";":
            gap = source[tokens[cursor][1] + len(values[cursor]) : tokens[next_cursor][1]]
            if "\n" not in gap or values[next_cursor] in {
                "(",
                "[",
                ".",
                "?.",
                "+",
                "-",
                "*",
                "/",
                "?",
                "&&",
                "||",
            }:
                break
        directives.add(values[cursor])
        cursor = next_cursor + (values[next_cursor : next_cursor + 1] == [";"])

    if path.suffix.lower() in find_rule("SP591").suffixes and directives.intersection(
        {'"use client"', "'use client'"}
    ):
        for index in js_config_checks.client_runtime_imports(values, pairs, depths):
            hits.append(("SP591", source.count("\n", 0, tokens[index][1]) + 1))

    for index in js_config_checks.next_server_hook_indices(
        path, values, pairs, depths, frameworks, directives
    ):
        hits.append(("SP596", source.count("\n", 0, tokens[index][1]) + 1))

    # Adjacent default-GET literal requests in one exported async Page/Layout.
    if (
        path.name.lower()
        in {
            "page.tsx",
            "page.jsx",
            "page.ts",
            "page.js",
            "layout.tsx",
            "layout.jsx",
            "layout.ts",
            "layout.js",
        }
        and (frameworks is None or "nextjs" in frameworks)
        and not directives.intersection({'"use client"', "'use client'"})
        and "fetch" not in bindings
        and "fetch" not in shadowed
    ):
        for index in range(len(values) - 5):
            if depths[index] != 0 or values[index : index + 4] != [
                "export",
                "default",
                "async",
                "function",
            ]:
                continue
            opening = index + 4 if values[index + 4] == "(" else index + 5
            params_end = pairs.get(opening)
            body = params_end + 1 if params_end is not None else -1
            if body not in pairs or values[body] != "{":
                continue
            previous: tuple[int, str, int] | None = None
            for cursor in range(body + 1, pairs[body]):
                if depths[cursor] != depths[body] + 1 or values[cursor] != "const":
                    continue
                chunk = values[cursor : cursor + 8]
                if (
                    len(chunk) != 8
                    or chunk[2:6] != ["=", "await", "fetch", "("]
                    or chunk[7] != ")"
                    or not re.fullmatch(r"""["']https?://[^"'\\]+["']""", chunk[6])
                ):
                    previous = None
                    continue
                end = cursor + 8
                if values[end : end + 1] == [";"]:
                    end += 1
                url = chunk[6][1:-1]
                if previous is not None and previous[2] == cursor and previous[1] != url:
                    hits.append(("SP597", source.count("\n", 0, tokens[previous[0]][1]) + 1))
                    break
                previous = (cursor, url, end)

    # A JSON parse followed immediately by an unchecked field dereference.
    # Non-null assertions alone have no runtime operation; names alone are not sources.
    if path.suffix.lower() in {".ts", ".tsx"}:
        for index in range(len(values) - 9):
            if (
                values[index] not in {"const", "let"}
                or values[index + 2 : index + 4] != ["=", "await"]
                or values[index + 5 : index + 9] != [".", "json", "(", ")"]
            ):
                continue
            name = values[index + 1]
            cursor = index + 9
            if values[cursor : cursor + 1] == [";"]:
                cursor += 1
            if values[cursor : cursor + 1] == ["return"]:
                use = cursor + 1
            elif values[cursor : cursor + 1] == ["const"] and values[cursor + 2 : cursor + 3] == [
                "="
            ]:
                use = cursor + 3
            else:
                continue
            if (
                use + 4 < len(values)
                and depths[cursor] == depths[index]
                and values[use : use + 2] == [name, "."]
                and re.fullmatch(r"[A-Za-z_$][\w$]*", values[use + 2])
                and values[use + 3] == "!"
                and values[use + 4] in {".", "[", "("}
            ):
                hits.append(("SP599", source.count("\n", 0, tokens[use][1]) + 1))
    return list(dict.fromkeys(hits))


def dotnet_xml_precision_lines(source: str) -> list[int]:
    return dotnet_cookie_checks.xml_precision_lines(source, js_context_tokens, js_context_structure)


def find_regex_issues(
    path: Path,
    relative_path: str,
    source_text: str,
    lines: Sequence[str] | None = None,
    python_string_lines: frozenset[int] | None = None,
    detected_frameworks: frozenset[str] | None = None,
    skill_context: bool | None = None,
    docstring_lines: frozenset[int] | None = None,
) -> list[Finding]:
    findings: list[Finding] = BoundedFindings()
    suffix = path.suffix.lower()
    file_kind = scanner_file_kind(path)
    normalized_relative_path = relative_path.replace("\\", "/").lower().removeprefix("./")
    is_github_workflow = normalized_relative_path.startswith(".github/workflows/") or (
        "/.github/workflows/" in f"/{normalized_relative_path}"
    )
    source_lines = source_text.splitlines()
    if any(len(line) > MAX_SCAN_LINE_CHARS for line in source_lines):
        raise ScanCoverageError("line_limit")
    lines = source_lines if lines is None else lines
    if suffix == ".sql" and any(
        marker in source_text.upper() for marker in ("CONCURRENTLY", "DEFINER")
    ):
        try:
            sql_spans = sql_checks.signature_spans(source_text)
        except sql_checks.LexicalLimitError as exc:
            raise ScanCoverageError("parser_limit") from exc
        for rule_id, offset, _end, excerpt in sql_spans:
            append_file_level_finding(
                findings,
                rule_id,
                relative_path,
                lines,
                source_text.count("\n", 0, offset) + 1,
                minimal_evidence=excerpt,
            )
    if (
        suffix == ".cs"
        and any(
            marker in source_text
            for marker in (
                "CookieOptions",
                "CookieAuthenticationOptions",
                "KestrelServerOptions",
                "MaxCharactersFromEntities",
                "SslClientAuthenticationOptions",
            )
        )
        and not any(marker in source_text for marker in ('@"', '$"', '"""'))
    ):
        tokens = js_context_tokens(source_text)
        pairs, depths = js_context_structure([value for value, _ in tokens])
        if depths:
            for rule_id, offset in [
                *dotnet_cookie_checks.signature_offsets(tokens, pairs),
                *dotnet_cookie_checks.xml_entity_offsets(tokens, pairs),
            ]:
                line_number = source_text.count("\n", 0, offset) + 1
                previous = len(findings)
                excerpt = {
                    "SP104": "Typed SslStream client options explicitly accept all remote certificate validation results",
                    "SP056": "ASP.NET Core cookie configuration explicitly sets HttpOnly=false",
                    "SP084": "ASP.NET Core cookie configuration explicitly weakens Secure protection",
                    "SP689": "Kestrel options explicitly assign Limits.MaxRequestBodySize=null",
                    "SP696": "XML settings enable DTD parsing and explicitly remove the entity-character limit",
                }[rule_id]
                append_file_level_finding(
                    findings,
                    rule_id,
                    relative_path,
                    lines,
                    line_number,
                    minimal_evidence=excerpt,
                )
                if len(findings) > previous:
                    findings[-1] = replace(findings[-1], tier="advisory")
    if suffix == ".dart" and (
        ("package:http/http.dart" in source_text and "http:" in source_text.lower())
        or "dart:async" in source_text
    ):
        try:
            spans = dart_transport_checks.signature_offsets(source_text)
        except polyglot_checks.LexicalLimitError as exc:
            raise ScanCoverageError("parser_limit") from exc
        for rule_id, offset in spans:
            line_number = source_text.count("\n", 0, offset) + 1
            previous = len(findings)
            append_file_level_finding(findings, rule_id, relative_path, lines, line_number)
            if len(findings) > previous:
                findings[-1] = replace(findings[-1], tier="advisory")
    if suffix == ".cs" and "XmlReaderSettings" in source_text and "XmlResolver" in source_text:
        for line_number in dotnet_xml_precision_lines(source_text):
            append_file_level_finding(findings, "SP670", relative_path, lines, line_number)
    if path.name.lower() in {"dockerfile", "containerfile", ".php-version", ".tool-versions"}:
        for version, line_number in php_advisories.advisory_declarations(path, source_text):
            append_file_level_finding(
                findings,
                "SP683",
                relative_path,
                lines,
                line_number,
                minimal_evidence=f"Declared upstream PHP version: {version}",
            )
    if path.name.lower() in node_advisories.DECLARATION_NAMES:
        for rule_id, version, line_number in node_advisories.advisory_declarations(
            path, source_text
        ):
            append_file_level_finding(
                findings,
                rule_id,
                relative_path,
                lines,
                line_number,
                minimal_evidence=f"Declared upstream Node.js version: {version}",
            )
    # Keep this public helper safe for direct callers too. File/snippet scans
    # already enforce the line budget, but rule-contract builders and tests can
    # invoke the regex engine directly with attacker-controlled text.
    if any(len(line) > MAX_SCAN_LINE_CHARS for line in lines):
        raise ScanCoverageError("line_limit")
    format_token_starts = None
    if suffix in find_rule("SP668").suffixes and "argv" in source_text:
        # Code-shaped printf text in C strings/comments is not a call. C++ raw
        # strings need a different lexer; leave that ambiguous context unresolved.
        format_token_starts = (
            set()
            if 'R"' in source_text
            else {
                offset
                for value, offset in js_context_tokens(source_text)
                if value in {"printf", "fprintf", "sprintf", "snprintf", "syslog", "std"}
            }
        )
    if suffix in {".lua", ".luau", ".rs", ".go"}:
        language = "go" if suffix == ".go" else "rust" if suffix == ".rs" else "lua"
        try:
            spans = polyglot_checks.signature_spans(source_text, language)
        except polyglot_checks.LexicalLimitError as exc:
            raise ScanCoverageError("parser_limit") from exc
        for rule_id, start, end in spans:
            line_number, column = offset_to_position(source_text, start)
            prefixes = comment_line_prefixes(path)
            adjacent = lines[max(0, line_number - 2) : line_number]
            if any(rule_id in extract_inline_ignore_ids(line, prefixes) for line in adjacent):
                continue
            end_line, end_column = offset_to_position(source_text, end)
            finding = make_finding(
                find_rule(rule_id),
                relative_path,
                line_number,
                lines[line_number - 1],
                detection="structural",
                column=column,
                end_line=end_line,
                end_column=end_column,
                minimal_evidence="reqwest Client builder explicitly enables an invalid-certificate/hostname TLS switch"
                if rule_id == "SP104"
                else {
                    "SP377": "net/http.Server literal has no effective header-read deadline",
                    "SP378": "context constructor explicitly discards its CancelFunc",
                    "SP621": "panic-prone unwrap/expect in a locally bound HTTP route handler",
                    "SP707": "Native remote passes client-selected key and value directly to DataStore SetAsync",
                }.get(rule_id),
            )
            # New Rust TLS variants are advisory until representative review.
            findings.append(replace(finding, tier="advisory") if rule_id == "SP104" else finding)
    if is_github_workflow and suffix in {".yml", ".yaml"}:
        for line_number in github_run_expression_lines(source_text):
            append_file_level_finding(findings, "SP210", relative_path, lines, line_number)
        for line_number in github_run_expression_lines(source_text, "SP212"):
            append_file_level_finding(
                findings,
                "SP212",
                relative_path,
                lines,
                line_number,
                minimal_evidence="workflow run command dumps the complete environment",
            )
    if suffix in JS_CONFIG_SUFFIXES and any(
        marker in source_text
        for marker in (
            "bullmq",
            "fetch",
            ".json",
            "use client",
            "dangerouslyAllowLocalIP",
            "dangerouslyAllowSVG",
            "jsonwebtoken",
            "authTagLength",
            "allocUnsafe",
            "insecureHTTPParser",
            "httpValidation",
            "headersTimeout",
            "Promise",
            "sort",
            "toSorted",
            "zlib",
            "timers",
            "webPreferences",
            "puppeteer",
            "minVersion",
            "secureProtocol",
            "maxPayload",
            "react",
            "pipeline",
            "connectionString",
            "createReadStream",
            "readFile",
            "writeFile",
        )
    ):
        excerpts: dict[tuple[str, int], str] = {}
        for rule_id, line_number in js_precision_lines(
            Path(relative_path.replace("\\", "/")), source_text, detected_frameworks, excerpts
        ):
            append_file_level_finding(
                findings,
                rule_id,
                relative_path,
                lines,
                line_number,
                minimal_evidence=excerpts.get((rule_id, line_number)),
            )
    package_dependency_names: set[str] = set()
    package_lifecycle_names: set[str] = set()
    if path.name.lower() == "package.json":
        try:
            package_payload = json.loads(source_text)
        except (json.JSONDecodeError, TypeError, RecursionError, MemoryError):
            package_payload = None
        if isinstance(package_payload, dict):
            for section_name in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
                "bundledDependencies",
            ):
                section = package_payload.get(section_name)
                if isinstance(section, dict):
                    package_dependency_names.update(
                        name
                        for name, value in section.items()
                        if isinstance(name, str)
                        and isinstance(value, str)
                        and value.lower() in {"*", "latest"}
                    )
            scripts = package_payload.get("scripts")
            if isinstance(scripts, dict):
                package_lifecycle_names.update(
                    name
                    for name, value in scripts.items()
                    if name in {"install", "preinstall", "postinstall"}
                    and isinstance(value, str)
                    and re.search(r"(?:curl\s|wget\s|node\s+-e|python\s+-c)", value)
                )
    comment_prefixes = comment_line_prefixes(path)
    comment_flags = [is_pure_comment(line, path, comment_prefixes) for line in lines]
    if python_string_lines:
        comment_flags = [
            flag or (index + 1) in python_string_lines for index, flag in enumerate(comment_flags)
        ]
    elif suffix in SLASH_COMMENT_SUFFIXES and ("`" in source_text or "/*" in source_text):
        js_prose = js_template_prose_lines(source_text)
        if js_prose:
            comment_flags = [flag or index in js_prose for index, flag in enumerate(comment_flags)]
    ignore_rule_ids = [extract_inline_ignore_ids(line, comment_prefixes) for line in lines]
    applicable_rules = applicable_line_rules(
        file_kind,
        suffix in DOCUMENT_SUFFIXES,
        path.name.lower() in {"dockerfile", "containerfile"},
    )
    mcp_context = has_mcp_context(relative_path, source_text)
    effective_skill_context = (
        has_skill_path_context(relative_path) if skill_context is None else skill_context
    )
    docstring_lines = docstring_lines or frozenset()
    gates = rule_gates()
    for rule in applicable_rules:
        rule_is_secret = rule.redact
        rule_id = rule.rule_id
        # Lua/Luau support starts with its own lexical checks and secret rules.
        # Generic foreign-language regexes have no validated Luau semantics.
        if suffix in {".lua", ".luau"} and not rule_is_secret:
            continue
        if rule_id in SKILL_RULE_IDS and not effective_skill_context:
            continue
        if rule_id in MCP_RULE_IDS and not mcp_context:
            continue
        if rule_id in {"SP092", "SP095"} and path.name.lower() != "package.json":
            continue
        if rule_id == "SP093" and path.name.lower() != "pom.xml":
            continue
        if rule_id in {"SP658", "SP659", "SP660"} and not is_github_workflow:
            continue
        gate = gates.get(rule_id)
        # File-level prefilter: a literal the pattern requires is absent from
        # the whole file, so the rule cannot match any line or span in it.
        # Tiny files skip the gate — scanning a handful of lines directly is
        # cheaper than the gate probe itself (measured on the 1,000-file
        # generated benchmark).
        if gate is not None and len(lines) > 4 and not gate.allows(source_text):
            continue
        pattern_search = rule.pattern.search
        if rule_id in {"SP092", "SP095"}:
            allowed_names = (
                package_dependency_names if rule_id == "SP092" else package_lifecycle_names
            )
            if not allowed_names:
                continue
            for index, line in enumerate(lines):
                for match in rule.pattern.finditer(line):
                    key_match = re.match(r"""["']([^"']+)["']""", match.group(0))
                    if key_match is None or key_match.group(1) not in allowed_names:
                        continue
                    findings.append(
                        make_finding(
                            rule,
                            relative_path,
                            index + 1,
                            line,
                            column=match.start() + 1,
                            end_column=match.end() + 1,
                        )
                    )
            continue
        if rule_id == "SP093":
            for dependency in re.finditer(
                r"<dependency\b[^>]*>[\s\S]*?</dependency\s*>",
                source_text,
                re.IGNORECASE,
            ):
                for match in rule.pattern.finditer(dependency.group(0)):
                    absolute_start = dependency.start() + match.start()
                    prefix = source_text[:absolute_start]
                    if prefix.rfind("<!--") > prefix.rfind("-->"):
                        continue
                    line_number, column = offset_to_position(source_text, absolute_start)
                    evidence = lines[line_number - 1] if line_number <= len(lines) else ""
                    findings.append(
                        make_finding(
                            rule,
                            relative_path,
                            line_number,
                            evidence,
                            column=column,
                            end_column=column + len(match.group(0)),
                        )
                    )
            continue
        if r"[\s\S]" in rule.pattern.pattern or r"\n" in rule.pattern.pattern:
            for match in rule.pattern.finditer(source_text):
                if (
                    rule_id == "SP668"
                    and format_token_starts is not None
                    and match.start() not in format_token_starts
                ):
                    continue
                matched_text = match.group(0)
                # Structural rules operate within one nearby declaration or block. A match
                # spanning most of a file is cross-block correlation, not evidence.
                if (
                    len(matched_text) > MAX_MULTILINE_MATCH_CHARS
                    or matched_text.count("\n") > MAX_MULTILINE_MATCH_LINES
                ):
                    continue
                line_number = source_text.count("\n", 0, match.start()) + 1
                index = line_number - 1
                if index >= len(lines):
                    continue
                if not rule_is_secret and (comment_flags[index] or line_number in docstring_lines):
                    continue
                if rule_id == "SP019" and line_number in docstring_lines:
                    continue
                if rule_id in ignore_rule_ids[index]:
                    continue
                if index >= 1 and rule_id in ignore_rule_ids[index - 1]:
                    continue
                if rule_is_secret and is_placeholder_secret(matched_text):
                    continue
                if rule_id == "SP518" and re.search(
                    r"\b(?:require|request|verify|await)_?(?:human_)?approval\b|"
                    r"\b(?:human_)?approval_(?:required|confirmed)\b|"
                    r"\bconfirm_shell_command\b",
                    matched_text,
                    re.IGNORECASE,
                ):
                    continue
                confidence_override = (
                    secret_confidence(rule, matched_text) if rule_is_secret else None
                )
                start_column = offset_to_position(source_text, match.start())[1]
                end_line_no, end_column = offset_to_position(source_text, match.end())
                findings.append(
                    make_finding(
                        rule,
                        relative_path,
                        line_number,
                        lines[index],
                        confidence=confidence_override,
                        column=start_column,
                        end_line=end_line_no if end_line_no != line_number else None,
                        end_column=end_column if end_line_no != line_number else None,
                    )
                )
            continue
        for index, line in enumerate(lines):
            if not rule_is_secret and (comment_flags[index] or (index + 1) in docstring_lines):
                continue
            if rule_id == "SP019" and (index + 1) in docstring_lines:
                continue
            if rule_id in ignore_rule_ids[index]:
                continue
            if index >= 1 and rule_id in ignore_rule_ids[index - 1]:
                continue
            match = pattern_search(line)
            if not match:
                continue
            matched_text = match.group(0)
            if rule_is_secret and is_placeholder_secret(matched_text):
                continue
            # A match entirely inside a quoted literal is data (an example,
            # log message, or documented snippet), not executable code.
            # Exception: rules whose evidence IS the string content (OAuth
            # URL parameters, javascript: schemes) and secret values.
            if (
                not rule_is_secret
                and rule_id not in STRING_CONTENT_RULE_IDS
                and _match_inside_string_literal(line, match.start())
            ):
                continue
            confidence_override = secret_confidence(rule, matched_text) if rule_is_secret else None
            findings.append(
                make_finding(
                    rule,
                    relative_path,
                    index + 1,
                    line,
                    confidence=confidence_override,
                    column=match.start() + 1,
                    end_column=match.end() + 1,
                )
            )

    # Kubernetes: Deployment without liveness/readiness probe
    if (
        suffix in {".yaml", ".yml"}
        and re.search(r"kind:\s*Deployment", source_text)
        and "containers:" in source_text
        and not re.search(r"(?:livenessProbe|readinessProbe)", source_text)
    ):
        deploy_line = next(
            (i for i, v in enumerate(lines, 1) if re.search(r"kind:\s*Deployment", v)),
            1,
        )
        append_file_level_finding(findings, "SP609", relative_path, lines, deploy_line)

    # GraphQL: Server initialized without depthLimit or validationRules
    if (
        suffix in {".js", ".ts", ".mjs"}
        and "ApolloServer" in source_text
        and not any(k in source_text for k in ("depthLimit", "validationRules", "queryComplexity"))
    ):
        apollo_line = next(
            (i for i, v in enumerate(lines, 1) if "ApolloServer" in v),
            1,
        )
        append_file_level_finding(findings, "SP612", relative_path, lines, apollo_line)

    # Next.js / React Server Components checks
    if (
        suffix in {".ts", ".tsx", ".js", ".jsx"}
        and "use server" in source_text
        and re.search(
            r"(?:prisma|db)\.[a-zA-Z0-9_]+\.(?:create|update|delete|upsert|insert)", source_text
        )
        and not any(r in source_text for r in ("revalidatePath", "revalidateTag", "redirect"))
    ):
        mut_line = next(
            (
                i
                for i, v in enumerate(lines, 1)
                if re.search(
                    r"(?:prisma|db)\.[a-zA-Z0-9_]+\.(?:create|update|delete|upsert|insert)", v
                )
            ),
            None,
        )
        if mut_line:
            append_file_level_finding(findings, "SP595", relative_path, lines, mut_line)

    if (
        suffix in {".ts", ".js"}
        and re.search(r"export\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE)", source_text)
        and "cookies()" in source_text
        and not any(
            h in source_text.lower() for h in ("origin", "referer", "csrf", "sec-fetch-site")
        )
    ):
        post_line = next(
            (
                i
                for i, v in enumerate(lines, 1)
                if re.search(r"export\s+async\s+function\s+(?:POST|PUT|PATCH|DELETE)", v)
            ),
            None,
        )
        if post_line:
            append_file_level_finding(findings, "SP598", relative_path, lines, post_line)

    if (
        suffix in {".ts", ".tsx", ".js"}
        and "use server" in source_text
        and re.search(
            r"function\s+[a-zA-Z0-9_]+\s*\([^)]*(?:userId|accountId|tenantId)",
            source_text,
            re.IGNORECASE,
        )
        and re.search(r"(?:prisma|db)\.[a-zA-Z0-9_]+\.(?:update|delete|upsert)", source_text)
    ):
        action_line = next(
            (
                i
                for i, v in enumerate(lines, 1)
                if re.search(
                    r"function\s+[a-zA-Z0-9_]+\s*\([^)]*(?:userId|accountId|tenantId)",
                    v,
                    re.IGNORECASE,
                )
            ),
            None,
        )
        if action_line:
            append_file_level_finding(findings, "SP600", relative_path, lines, action_line)

    if (
        suffix == ".py"
        and re.search(r"allow_origins\s*=\s*\[[\"']\*[\"']\]", source_text)
        and re.search(r"allow_credentials\s*=\s*True", source_text)
    ):
        line = next((i for i, value in enumerate(lines, 1) if "allow_origins" in value), 1)
        rule = Rule(
            "SP107",
            "Credentialed wildcard CORS",
            "security",
            "high",
            "high",
            compile_pattern(r"$^"),
            "Wildcard origins and credentials create an unsafe cross-origin policy.",
            "Allowlist exact trusted origins and test preflight behavior.",
            "CWE-942",
            "OWASP ASVS V3",
        )
        findings.append(
            make_finding(rule, relative_path, line, lines[line - 1] if lines else "", "structural")
        )

    if (
        suffix in {".js", ".mjs", ".cjs", ".ts"}
        and re.search(r"origin\s*:\s*(?:true|[\"']\*[\"'])", source_text)
        and re.search(r"credentials\s*:\s*true", source_text)
    ):
        line = next((i for i, value in enumerate(lines, 1) if "origin" in value), 1)
        rule = Rule(
            "SP107",
            "Credentialed wildcard CORS",
            "security",
            "high",
            "high",
            compile_pattern(r"$^"),
            "Wildcard origins and credentials create an unsafe cross-origin policy.",
            "Allowlist exact trusted origins and test preflight behavior.",
            "CWE-942",
            "OWASP ASVS V3",
        )
        findings.append(
            make_finding(rule, relative_path, line, lines[line - 1] if lines else "", "structural")
        )

    # Framework-specific: Express checks key on a real (non-comment) express()
    # call — framework repositories quote `app = express()` in documentation
    # comments across dozens of files (measured: 95 false hits in express/).
    has_express_call = suffix in {".js", ".mjs", ".cjs", ".ts"} and any(
        re.search(r"express\s*\(\s*\)", line, re.IGNORECASE) and not comment_flags[index]
        for index, line in enumerate(lines)
    )

    # Framework-specific: Express without helmet
    if has_express_call and "helmet" not in source_text.lower():
        express_line = next(
            (
                index + 1
                for index, line in enumerate(lines)
                if not comment_flags[index] and re.search(r"express\s*\(\s*\)", line, re.IGNORECASE)
            ),
            None,
        )
        if express_line:
            line_str = lines[express_line - 1]
            prev_line_str = lines[express_line - 2] if express_line >= 2 else ""
            ignore_curr = extract_inline_ignore_ids(line_str, comment_prefixes)
            ignore_prev = extract_inline_ignore_ids(prev_line_str, comment_prefixes)
            if not ("SP401" in ignore_curr or "SP401" in ignore_prev):
                rule = find_rule("SP401")
                findings.append(
                    make_finding(rule, relative_path, express_line, line_str, "structural")
                )

    # Framework-specific: Express auth route without rate limiting
    if has_express_call and not RATE_LIMIT_MARKERS.search(source_text):
        route_line = next(
            (i for i, value in enumerate(lines, 1) if AUTH_SENSITIVE_ROUTE.search(value)),
            None,
        )
        if route_line:
            append_file_level_finding(findings, "SP402", relative_path, lines, route_line)

    # Framework-specific: Express admin/internal route without visible
    # authorization (SP108 on JavaScript). Report only when the route's own
    # chain shows no auth hint AND the file registers no global auth middleware
    # AND its non-comment code carries no broad authorization signal; routes
    # whose guard lives in another module stay unreported (documented FP
    # boundary). Comment lines cannot grant or revoke coverage.
    if has_express_call and suffix in {".js", ".mjs", ".cjs", ".ts"}:
        js_admin_lines = express_admin_route_lines_without_auth(lines, comment_flags)
        code_only_text = "\n".join(
            line for index, line in enumerate(lines) if not comment_flags[index]
        )
        if (
            js_admin_lines
            and not has_global_express_auth(code_only_text)
            and not BROAD_JS_AUTH_SIGNAL.search(code_only_text)
        ):
            for admin_line in js_admin_lines[:5]:
                append_file_level_finding(findings, "SP108", relative_path, lines, admin_line)

    # Framework-specific: cookie-session routes without CSRF protection
    if (
        has_express_call
        and COOKIE_SESSION_MARKERS.search(source_text)
        and not CSRF_MARKERS.search(source_text)
    ):
        route_line = next(
            (i for i, value in enumerate(lines, 1) if STATE_CHANGING_ROUTE.search(value)),
            None,
        )
        if route_line:
            append_file_level_finding(findings, "SP407", relative_path, lines, route_line)

    # Framework-specific: Next.js/Nuxt config without a CSP header
    if META_FRAMEWORK_CONFIG_NAME.match(path.name.lower()) and not CSP_MARKERS.search(source_text):
        append_file_level_finding(findings, "SP408", relative_path, lines, 1)

    # XXE: lxml parsing without entity hardening
    if suffix == ".py" and "lxml" in source_text and "resolve_entities" not in source_text:
        lxml_line = next(
            (i for i, value in enumerate(lines, 1) if LXML_PARSE_CALL.search(value)),
            None,
        )
        if lxml_line:
            append_file_level_finding(findings, "SP115", relative_path, lines, lxml_line)

    # Unsafe JS deserialization: node-serialize
    if NODE_SERIALIZE_REQUIRE.search(source_text) and UNSERIALIZE_CALL.search(source_text):
        unserialize_line = next(
            (i for i, value in enumerate(lines, 1) if UNSERIALIZE_CALL.search(value)),
            None,
        )
        if unserialize_line:
            append_file_level_finding(findings, "SP120", relative_path, lines, unserialize_line)

    # Reliability: retry policy without a stop condition
    if (
        suffix == ".py"
        and TENACITY_RETRY.search(source_text)
        and not STOP_CONDITION_HINT.search(source_text)
    ):
        retry_line = next(
            (i for i, value in enumerate(lines, 1) if TENACITY_RETRY.search(value)),
            None,
        )
        if retry_line:
            append_file_level_finding(findings, "SP318", relative_path, lines, retry_line)
    if UNBOUNDED_JS_RETRIES.search(source_text):
        retry_line = next(
            (i for i, value in enumerate(lines, 1) if UNBOUNDED_JS_RETRIES.search(value)),
            None,
        )
        if retry_line:
            append_file_level_finding(findings, "SP318", relative_path, lines, retry_line)

    # Reliability: Go http.Server without timeouts
    if (
        suffix == ".go"
        and GO_HTTP_SERVER_INIT.search(source_text)
        and not any(t in source_text for t in ("ReadTimeout", "ReadHeaderTimeout"))
    ):
        server_line = next(
            (i for i, value in enumerate(lines, 1) if GO_HTTP_SERVER_INIT.search(value)),
            None,
        )
        if server_line:
            append_file_level_finding(findings, "SP131", relative_path, lines, server_line)

    if (
        suffix in {".yaml", ".yml"}
        and "kind: Deployment" in source_text
        and "containers:" in source_text
        and not any(p in source_text for p in ("livenessProbe", "readinessProbe", "startupProbe"))
    ):
        dep_line = next(
            (i for i, value in enumerate(lines, 1) if "kind: Deployment" in value),
            None,
        )
        if dep_line:
            append_file_level_finding(findings, "SP609", relative_path, lines, dep_line)

    if (
        suffix in {".js", ".ts", ".mjs", ".cjs"}
        and (
            "ApolloServer" in source_text
            or "createYoga" in source_text
            or "graphqlHTTP" in source_text
        )
        and not any(
            d in source_text for d in ("depthLimit", "costAnalysis", "queryComplexity", "maxDepth")
        )
    ):
        gql_line = next(
            (
                i
                for i, value in enumerate(lines, 1)
                if "ApolloServer" in value or "createYoga" in value or "graphqlHTTP" in value
            ),
            None,
        )
        if gql_line:
            append_file_level_finding(findings, "SP612", relative_path, lines, gql_line)

    if (
        suffix in {".ts", ".tsx", ".js", ".jsx", ".mjs"}
        and "runtime" in source_text
        and "edge" in source_text
    ):
        declaration_lines = js_static_declaration_lines(lines)
        if any(EDGE_RUNTIME_DECLARATION.fullmatch(lines[index]) for index in declaration_lines):
            edge_line = next(
                (
                    index + 1
                    for index in declaration_lines
                    if EDGE_NATIVE_IMPORT.match(lines[index])
                ),
                None,
            )
            if edge_line:
                append_file_level_finding(findings, "SP631", relative_path, lines, edge_line)

    # Framework-specific: FastAPI routes without visible rate limiting
    if (
        suffix == ".py"
        and (re.search(r"\bFastAPI\s*\(", source_text) or "APIRouter(" in source_text)
        and any(
            re.search(r"@(?:app|router)\.[a-z]+(?:\.[a-z]+)?\s*\(", line)
            for index, line in enumerate(lines)
            if not comment_flags[index]
        )
        and not any(
            marker in source_text.lower()
            for marker in ("limiter", "slowapi", "rate_limit", "ratelimit", "throttle")
        )
    ):
        rate_limit_line = next(
            (
                index + 1
                for index, line in enumerate(lines)
                if not comment_flags[index]
                and re.search(r"@(?:app|router)\.[a-z]+(?:\.[a-z]+)?\s*\(", line)
            ),
            1,
        )
        append_file_level_finding(findings, "SP664", relative_path, lines, rate_limit_line)

    # Framework-specific: Django deployable settings module with DEBUG enabled
    if (
        suffix == ".py"
        and any(
            re.search(r"\bDEBUG\s*=\s*True\b", line) and not comment_flags[index]
            for index, line in enumerate(lines)
        )
        and any(
            marker in source_text
            for marker in ("ALLOWED_HOSTS", "INSTALLED_APPS", "MIDDLEWARE", "STATICFILES_DIRS")
        )
    ):
        debug_line = next(
            (
                index + 1
                for index, line in enumerate(lines)
                if not comment_flags[index] and re.search(r"\bDEBUG\s*=\s*True\b", line)
            ),
            1,
        )
        append_file_level_finding(findings, "SP665", relative_path, lines, debug_line)

    # Framework-aware confidence: structural framework rules keep their default
    # confidence only when the manifest declares that framework. A rule firing
    # in a repo whose manifests do not mention the framework is more likely a
    # look-alike, so downgrade confidence (never suppress) — unless framework
    # state is unknown (single-file snippets have no manifests to inspect).
    if detected_frameworks is not None:
        findings = [
            (
                replace(finding, confidence=DOWNRANK_CONFIDENCE.get(finding.confidence, "low"))
                if finding.rule_id in RULE_FRAMEWORK_HINTS
                and not RULE_FRAMEWORK_HINTS[finding.rule_id] & detected_frameworks
                and (
                    finding.detection == "structural"
                    or finding.rule_id in FRAMEWORK_HINT_PATTERN_RULES
                )
                else finding
            )
            for finding in findings
        ]
    # Generated/minified lines: a finding on a thousand-plus-character line is
    # usually machine-produced bundle text, so keep it for review but at a
    # lower confidence. Bundled vendor filenames (.min.js and hashed bundles)
    # get the same treatment for every line. Secrets stay at full confidence —
    # a key inside a bundle is still a leaked key.
    findings = [
        (
            replace(finding, confidence=DOWNRANK_CONFIDENCE.get(finding.confidence, "low"))
            if finding.rule_id not in SECRET_RULE_IDS
            and (
                (0 < finding.line <= len(lines) and len(lines[finding.line - 1]) > 1000)
                or MINIFIED_FILE_NAME.search(relative_path.replace("\\", "/")) is not None
            )
            else finding
        )
        for finding in findings
    ]
    return findings


def resolve_dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


ROUTE_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
SENSITIVE_ROUTE_SEGMENTS = frozenset({"admin", "internal", "management"})
AUTHORIZATION_DEPENDENCY_HINTS = ("auth", "admin", "permission", "policy", "role", "scope")
PAGE_SIZE_PARAMETERS = frozenset({"limit", "page_size", "per_page"})
RATE_LIMIT_MARKERS = re.compile(r"rate[-_]?limit|limiter|throttle", re.IGNORECASE)
AUTH_SENSITIVE_ROUTE = re.compile(
    r"\.\s*(?:post|use|all)\s*\(\s*[\"'][^\"']*(?:login|sign-?in|auth|session|token|password)",
    re.IGNORECASE,
)
COOKIE_SESSION_MARKERS = re.compile(
    r"cookie[-_]?parser|express-session|req\.cookies|req\.session", re.IGNORECASE
)
CSRF_MARKERS = re.compile(r"csurf|csrf", re.IGNORECASE)
STATE_CHANGING_ROUTE = re.compile(r"\.\s*(?:post|put|patch|delete)\s*\(", re.IGNORECASE)
CSP_MARKERS = re.compile(r"content[-_]?security[-_]?policy|\bcsp\b", re.IGNORECASE)
META_FRAMEWORK_CONFIG_NAME = re.compile(r"(?:next|nuxt)\.config\.(?:js|mjs|cjs|ts)$")
LXML_PARSE_CALL = re.compile(r"\betree\s*\.\s*(?:parse|fromstring|XML|frombuffer)\s*\(")
NODE_SERIALIZE_REQUIRE = re.compile(r"require\s*\(\s*[\"']node-serialize[\"']\s*\)")
UNSERIALIZE_CALL = re.compile(r"\.\s*unserialize\s*\(")
TENACITY_RETRY = re.compile(r"@retry\s*\(")
STOP_CONDITION_HINT = re.compile(r"\bstop")
UNBOUNDED_JS_RETRIES = re.compile(r"retries\s*:\s*Infinity\b", re.IGNORECASE)
GO_HTTP_SERVER_INIT = re.compile(r"http\.Server\s*\{")

# Express authorization evidence (SP108 on JavaScript). A route counts as
# covered when its own middleware chain names an auth-like identifier or when
# the file registers a global app.use(<auth middleware>). Files that carry no
# broad auth signal at all are the reviewable gap; routes whose authorization
# lives in another module stay unreported by design.
JS_ADMIN_ROUTE_CALL = re.compile(
    r"""\.\s*(?:all|get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]*)["'`]""",
    re.IGNORECASE,
)
GLOBAL_AUTH_USE = re.compile(r"""\.\s*use\s*\(""")
GLOBAL_AUTH_HINTS = ("auth", "jwt", "passport", "login", "permission", "policy", "scope")
ROUTE_CHAIN_AUTH_HINTS = (*GLOBAL_AUTH_HINTS, "admin", "role", "session")
BROAD_JS_AUTH_SIGNAL = re.compile(
    r"""passport|jsonwebtoken|\bjwt\b|express-session|\bclerk\b|\bauth0\b"""
    r"""|next-auth|authmiddleware|requireauth|checkauth|isauthenticated"""
    r"""|ensureauthenticated|ensureadmin|verifytoken|authoriz""",
    re.IGNORECASE,
)


def _js_balanced_paren_span(
    source_text: str, open_index: int, limit_chars: int = 4000
) -> int | None:
    """Index of the ')' matching source_text[open_index].

    Skips string literals (including template interpolations) and comments so
    nested calls and quoted paths cannot desynchronize the depth count. The
    scan is bounded by limit_chars and returns None when no close is found.
    """
    limit = min(len(source_text), open_index + limit_chars)
    depth = 0
    index = open_index
    while index < limit:
        char = source_text[index]
        if char == "/" and index + 1 < limit and source_text[index + 1] == "/":
            newline = source_text.find("\n", index, limit)
            index = newline if newline != -1 else limit
            continue
        if char == "/" and index + 1 < limit and source_text[index + 1] == "*":
            closing = source_text.find("*/", index + 2, limit)
            index = closing + 2 if closing != -1 else limit
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            while index < limit:
                inner = source_text[index]
                if inner == "\\":
                    index += 2
                    continue
                if (
                    quote == "`"
                    and inner == "$"
                    and index + 1 < limit
                    and source_text[index + 1] == "{"
                ):
                    brace_depth = 1
                    index += 2
                    while index < limit and brace_depth:
                        nested = source_text[index]
                        if nested == "{":
                            brace_depth += 1
                        elif nested == "}":
                            brace_depth -= 1
                            if brace_depth == 0:
                                break
                        elif nested in {"'", '"'}:
                            nested_quote = nested
                            index += 1
                            while index < limit:
                                if source_text[index] == "\\":
                                    index += 2
                                    continue
                                if source_text[index] == nested_quote:
                                    break
                                index += 1
                        index += 1
                    continue
                if inner == quote:
                    break
                index += 1
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def has_global_express_auth(code_text: str) -> bool:
    """True when some .use(...) registration passes an auth-like middleware.

    Only bare identifiers count as coverage: app.use(express.json()) is
    configuration, not authorization evidence. ``code_text`` must have pure
    comment lines removed so documentation prose cannot grant coverage.
    """
    checked = 0
    for match in GLOBAL_AUTH_USE.finditer(code_text):
        close_index = _js_balanced_paren_span(code_text, match.end() - 1)
        if close_index is None:
            continue
        arguments = code_text[match.end() : close_index]
        for token in re.findall(r"[A-Za-z_$][\w$.]*", arguments):
            lowered = token.rsplit(".", 1)[-1].lower()
            if any(hint in lowered for hint in GLOBAL_AUTH_HINTS):
                return True
        checked += 1
        if checked >= 64:
            break
    return False


def express_admin_route_lines_without_auth(
    lines: Sequence[str], comment_flags: Sequence[bool]
) -> list[int]:
    """Return 1-based lines of admin/internal/management route registrations
    whose own middleware chain shows no authorization hint."""
    results: list[int] = []
    for index, line in enumerate(lines):
        if comment_flags[index]:
            continue
        match = JS_ADMIN_ROUTE_CALL.search(line)
        if match is None:
            continue
        segments = [segment.strip(":").lower() for segment in match.group(1).split("/")]
        if not SENSITIVE_ROUTE_SEGMENTS.intersection(segments):
            continue
        chain_text = line[match.end() :].lower()
        if any(hint in chain_text for hint in ROUTE_CHAIN_AUTH_HINTS):
            continue
        results.append(index + 1)
    return results


def find_rule(rule_id: str) -> Rule:
    rule = RULE_INDEX.get(rule_id)
    if rule is None:
        raise ValueError(f"unknown rule id: {rule_id}")
    return rule


EDGE_RUNTIME_DECLARATION = re.compile(
    r"""[ \t]*export[ \t]+const[ \t]+runtime[ \t]*=[ \t]*(["'])edge\1[ \t]*;?[ \t]*(?://[^\r\n]*)?"""
)
EDGE_NATIVE_IMPORT = re.compile(
    r"""^[ \t]*import[ \t]+(?!type\b)[^;\r\n]*?\bfrom[ \t]+["'](?:node:)?(?:fs|child_process|cluster|dgram|v8)["']"""
)


def js_static_declaration_lines(lines: Sequence[str]) -> list[int]:
    """Conservative module-level candidates, excluding comments and quoted data.

    This is not a JS parser. Stop at ambiguous JSX or template interpolation;
    do not manufacture declaration evidence from unhandled syntax.
    """
    candidates: list[int] = []
    quote: str | None = None
    block_comment = False
    depth = 0
    for line_index, line in enumerate(lines):
        if quote is None and not block_comment and depth == 0:
            candidates.append(line_index)
        index = 0
        while index < len(line):
            char = line[index]
            pair = line[index : index + 2]
            if block_comment:
                if pair == "*/":
                    block_comment = False
                    index += 1
            elif quote is not None:
                if char == "\\":
                    index += 1
                elif char == quote:
                    quote = None
                elif quote == "`" and pair == "${":
                    return candidates
            elif pair == "//":
                break
            elif pair == "/*":
                block_comment = True
                index += 1
            elif char in {"'", '"', "`"}:
                quote = char
            elif char == "<" and depth == 0:
                return candidates
            elif char in "({[":
                depth += 1
            elif char in ")}]":
                depth = max(0, depth - 1)
            index += 1
    return candidates


def _match_inside_string_literal(line: str, column: int) -> bool:
    """True when ``column`` lies inside an unclosed quoted literal of ``line``.

    Single-line heuristic across ', ", and ` with escape handling; multi-line
    prose is already covered by the dedicated multiline-string filters.
    """
    quote = None
    index = 0
    while index < column:
        char = line[index]
        if quote is not None:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = None
        elif char in {"'", '"', "`"}:
            quote = char
        index += 1
    return quote is not None


def append_file_level_finding(
    findings: list[Finding],
    rule_id: str,
    relative_path: str,
    lines: Sequence[str],
    line_number: int,
    *,
    minimal_evidence: str | None = None,
) -> None:
    line_str = lines[line_number - 1] if 1 <= line_number <= len(lines) else ""
    prev_line_str = lines[line_number - 2] if line_number >= 2 else ""
    prefixes = comment_line_prefixes(Path(relative_path))
    ignore_curr = extract_inline_ignore_ids(line_str, prefixes)
    ignore_prev = extract_inline_ignore_ids(prev_line_str, prefixes)
    if rule_id in ignore_curr or rule_id in ignore_prev:
        return
    findings.append(
        make_finding(
            find_rule(rule_id),
            relative_path,
            line_number,
            line_str,
            "structural",
            minimal_evidence=minimal_evidence,
        )
    )


def route_decorator_calls(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Call]:
    route_calls: list[ast.Call] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        method = resolve_dotted_name(decorator.func).rsplit(".", 1)[-1].lower()
        if method in ROUTE_METHODS:
            route_calls.append(decorator)
    return route_calls


def route_path(route_call: ast.Call) -> str | None:
    if not route_call.args:
        return None
    value = route_call.args[0]
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def find_authorized_routers(tree: ast.AST) -> set[str]:
    authorized_routers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func_name = resolve_dotted_name(node.value.func).rsplit(".", 1)[-1]
            if func_name in {"APIRouter", "FastAPI"}:
                for kw in node.value.keywords:
                    if kw.arg == "dependencies":
                        for child in ast.walk(kw.value):
                            if (
                                isinstance(child, ast.Call)
                                and resolve_dotted_name(child.func).rsplit(".", 1)[-1] == "Depends"
                                and child.args
                                and any(
                                    hint in resolve_dotted_name(child.args[0]).lower()
                                    for hint in AUTHORIZATION_DEPENDENCY_HINTS
                                )
                            ):
                                for target in node.targets:
                                    if isinstance(target, ast.Name):
                                        authorized_routers.add(target.id)
    return authorized_routers


def has_visible_authorization_dependency(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    route_calls: Sequence[ast.Call],
) -> bool:
    candidates: list[ast.AST] = [
        *node.args.defaults,
        *(value for value in node.args.kw_defaults if value is not None),
        *(
            argument.annotation
            for argument in [*node.args.args, *node.args.kwonlyargs]
            if argument.annotation
        ),
    ]
    for route_call in route_calls:
        candidates.extend(
            keyword.value for keyword in route_call.keywords if keyword.arg == "dependencies"
        )
    for candidate in candidates:
        for child in ast.walk(candidate):
            if not isinstance(child, ast.Call):
                continue
            if resolve_dotted_name(child.func).rsplit(".", 1)[-1] != "Depends" or not child.args:
                continue
            dependency_name = resolve_dotted_name(child.args[0]).lower()
            if any(hint in dependency_name for hint in AUTHORIZATION_DEPENDENCY_HINTS):
                return True
    return False


def parameter_defaults(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[ast.arg, ast.AST | None]]:
    positional = [*node.args.posonlyargs, *node.args.args]
    positional_defaults: list[ast.AST | None] = [None] * (
        len(positional) - len(node.args.defaults)
    ) + list(node.args.defaults)
    return [
        *zip(positional, positional_defaults, strict=True),
        *zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True),
    ]


def has_page_size_bound(argument: ast.arg, default: ast.AST | None) -> bool:
    candidates = [value for value in (argument.annotation, default) if value is not None]
    for candidate in candidates:
        for child in ast.walk(candidate):
            if not isinstance(child, ast.Call):
                continue
            validator = resolve_dotted_name(child.func).rsplit(".", 1)[-1]
            if validator not in {"Query", "Field"}:
                continue
            if any(
                keyword.arg == "le" and isinstance(keyword.value, ast.Constant)
                for keyword in child.keywords
            ):
                return True
    return False


def is_interpolated_sql_value(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return any(
            isinstance(child, ast.Constant) and isinstance(child.value, str)
            for child in ast.walk(node)
        )
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
    )


# --- Taint tracking constants ---
CREDENTIAL_NAME_HINTS = ("key", "token", "secret", "password", "passwd", "credential")
BASE64_DECODE_NAMES = frozenset({"b64decode", "a2b_base64"})
TAINT_SOURCES = frozenset(
    {
        "request.args",
        "request.form",
        "request.json",
        "request.data",
        "request.values",
        "request.files",
        "request.headers",
        "request.cookies",
        "request.query_params",
        "request.path_params",
        "request.body",
        "request.get_json",
        "request.url",
        "input",
        "sys.stdin",
        "sys.argv",
        "os.environ",
        "os.getenv",
    }
)
TAINT_SANITIZERS = frozenset(
    {
        "int",
        "float",
        "bool",
        "abs",
        "len",
        "round",
        "escape",
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
        "shlex.quote",
        "quote",
        "quote_plus",
        "re.escape",
        "validator",
        "validate",
        "sanitize",
        "is_uuid",
        "uuid.uuid4",
        "uuid.UUID",
        "secure_filename",
    }
)
TAINT_SINKS = {
    "execute": "SP103",
    "executemany": "SP103",
    "raw": "SP103",
    "eval": "SP101",
    "exec": "SP101",
    "compile": "SP101",
    "system": "SP102",
    "popen": "SP102",
    "check_output": "SP102",
    "check_call": "SP102",
}


class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(
        self,
        relative_path: str,
        source_lines: Sequence[str],
        authorized_routers: set[str] | None = None,
        ignore_ids: Sequence[tuple[str, ...]] | None = None,
    ) -> None:
        self.relative_path = relative_path
        self.source_lines = source_lines
        self.authorized_routers = authorized_routers or set()
        self.ignore_ids = ignore_ids or ()
        self.findings: list[Finding] = BoundedFindings()
        self.async_function_depth = 0
        self.loop_depth = 0
        self.transaction_depth = 0
        self.local_assignments: dict[str, ast.AST] = {}
        self.import_aliases: dict[str, str] = {}
        self.tainted_vars: set[str] = set()

    def line_is_ignored(self, rule_id: str, line_number: int) -> bool:
        if not self.ignore_ids:
            return False
        if 0 < line_number <= len(self.ignore_ids) and rule_id in self.ignore_ids[line_number - 1]:
            return True
        return (
            line_number >= 2
            and line_number - 2 < len(self.ignore_ids)
            and rule_id in self.ignore_ids[line_number - 2]
        )

    def add_finding(
        self,
        rule: Rule,
        node: ast.AST,
        detection: str = "ast",
        confidence: str | None = None,
    ) -> None:
        line_number = getattr(node, "lineno", 1)
        if self.line_is_ignored(rule.rule_id, line_number):
            return
        evidence = (
            self.source_lines[line_number - 1] if 0 < line_number <= len(self.source_lines) else ""
        )
        column = getattr(node, "col_offset", None)
        end_line = getattr(node, "end_lineno", None)
        end_column = getattr(node, "end_col_offset", None)
        self.findings.append(
            make_finding(
                rule,
                self.relative_path,
                line_number,
                evidence,
                detection=detection,
                confidence=confidence,
                column=column + 1 if column is not None else None,
                end_line=end_line if end_line is not None and end_line != line_number else None,
                end_column=(
                    end_column + 1
                    if end_column is not None and end_line is not None and end_line != line_number
                    else None
                ),
            )
        )

    def inspect_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        route_calls = route_decorator_calls(node)
        if not route_calls:
            return
        sensitive_route = next(
            (
                route_call
                for route_call in route_calls
                if (path := route_path(route_call))
                and SENSITIVE_ROUTE_SEGMENTS.intersection(path.lower().split("/"))
            ),
            None,
        )
        if sensitive_route:
            caller_name = resolve_dotted_name(sensitive_route.func).split(".", 1)[0]
            is_router_authorized = caller_name in self.authorized_routers
            if not is_router_authorized and not has_visible_authorization_dependency(
                node, route_calls
            ):
                self.add_finding(find_rule("SP108"), sensitive_route)
        for argument, default in parameter_defaults(node):
            if argument.arg in PAGE_SIZE_PARAMETERS and not has_page_size_bound(argument, default):
                self.add_finding(find_rule("SP305"), argument)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.import_aliases[alias.asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            qualified = f"{module}.{alias.name}" if module else alias.name
            target_name = alias.asname if alias.asname else alias.name
            self.import_aliases[target_name] = qualified
        self.generic_visit(node)

    def _resolve_name(self, name: str) -> str:
        """Resolve a call name through import aliases."""
        parts = name.split(".", 1)
        resolved_head = self.import_aliases.get(parts[0], parts[0])
        return f"{resolved_head}.{parts[1]}" if len(parts) > 1 else resolved_head

    def _is_taint_source(self, node: ast.AST) -> bool:
        """Check if an AST node represents a taint source (user input)."""
        if isinstance(node, ast.Subscript):
            base = resolve_dotted_name(node.value)
            return self._resolve_name(base) in TAINT_SOURCES
        if isinstance(node, ast.Call):
            name = self._resolve_name(resolve_dotted_name(node.func))
            return name in TAINT_SOURCES or (
                name.rsplit(".", 1)[-1]
                in {
                    "get_json",
                    "get",
                }
                and any(src in name for src in ("request", "args", "form", "params"))
            )
        if isinstance(node, ast.Attribute):
            full = self._resolve_name(resolve_dotted_name(node))
            return full in TAINT_SOURCES
        return False

    def _is_sanitized(self, node: ast.AST) -> bool:
        """Check if an expression is wrapped in a known sanitizer call."""
        if isinstance(node, ast.Call):
            name = self._resolve_name(resolve_dotted_name(node.func)).rsplit(".", 1)[-1].lower()
            return name in TAINT_SANITIZERS or any(
                s in name for s in ("sanitize", "validate", "escape", "clean")
            )
        return False

    def _propagate_taint(self, target: ast.AST, value: ast.AST) -> None:
        """Track taint through simple assignments."""
        if not isinstance(target, ast.Name):
            return
        if self._is_sanitized(value):
            self.tainted_vars.discard(target.id)
            return
        if self._is_taint_source(value):
            self.tainted_vars.add(target.id)
            return
        if isinstance(value, ast.Name) and value.id in self.tainted_vars:
            self.tainted_vars.add(target.id)
            return
        if isinstance(value, (ast.BinOp, ast.JoinedStr)):
            for child in ast.walk(value):
                if isinstance(child, ast.Name) and child.id in self.tainted_vars:
                    self.tainted_vars.add(target.id)
                    return
        if isinstance(value, ast.Call):
            for arg in [*value.args, *(kw.value for kw in value.keywords)]:
                if (
                    isinstance(arg, ast.Name)
                    and arg.id in self.tainted_vars
                    and not self._is_sanitized(value)
                ):
                    self.tainted_vars.add(target.id)
                    return

    def _inspect_hardcoded_credential(self, target: ast.Name, value: ast.AST) -> None:
        """Flag credential variables assembled from string literals or base64 data.

        The regex engine only sees single quoted literals, so concatenated or
        encoded credentials would otherwise slip past SP003.
        """
        if not any(hint in target.id.lower() for hint in CREDENTIAL_NAME_HINTS):
            return
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            parts = [
                child.value
                for child in ast.walk(value)
                if isinstance(child, ast.Constant) and isinstance(child.value, str)
            ]
            if len(parts) >= 2 and sum(len(part) for part in parts) >= 16:
                self.add_finding(find_rule("SP003"), value, detection="ast")
        elif isinstance(value, ast.Call) and value.args:
            call_name = self._resolve_name(resolve_dotted_name(value.func))
            argument = value.args[0]
            if (
                call_name.rsplit(".", 1)[-1] in BASE64_DECODE_NAMES
                and isinstance(argument, ast.Constant)
                and isinstance(argument.value, str)
                and len(argument.value) >= 16
            ):
                self.add_finding(find_rule("SP003"), value, detection="ast", confidence="low")

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.local_assignments[target.id] = node.value
                # Track simple function rebinding: unsafe = eval
                if isinstance(node.value, ast.Name) and node.value.id in {
                    "eval",
                    "exec",
                    "compile",
                    "getattr",
                }:
                    self.import_aliases[target.id] = node.value.id
                self._propagate_taint(target, node.value)
                self._inspect_hardcoded_credential(target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.loop_depth += 1
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.loop_depth += 1
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_With(self, node: ast.With) -> None:
        is_tx = any(
            (
                resolve_dotted_name(item.context_expr)
                .lower()
                .endswith((".transaction", ".begin", ".atomic"))
                or (
                    isinstance(item.context_expr, ast.Call)
                    and resolve_dotted_name(item.context_expr.func)
                    .lower()
                    .endswith((".transaction", ".begin", ".atomic"))
                )
            )
            for item in node.items
        )
        if is_tx:
            self.transaction_depth += 1
        self.generic_visit(node)
        if is_tx:
            self.transaction_depth -= 1

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        is_tx = any(
            (
                resolve_dotted_name(item.context_expr)
                .lower()
                .endswith((".transaction", ".begin", ".atomic"))
                or (
                    isinstance(item.context_expr, ast.Call)
                    and resolve_dotted_name(item.context_expr.func)
                    .lower()
                    .endswith((".transaction", ".begin", ".atomic"))
                )
            )
            for item in node.items
        )
        if is_tx:
            self.transaction_depth += 1
        self.generic_visit(node)
        if is_tx:
            self.transaction_depth -= 1

    def _taint_function_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Mark function parameters that have taint-source annotations or defaults."""
        for arg in [*node.args.args, *node.args.kwonlyargs]:
            if arg.annotation:
                ann_name = resolve_dotted_name(arg.annotation).lower()
                if any(hint in ann_name for hint in ("request", "form", "body", "query")):
                    self.tainted_vars.add(arg.arg)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.inspect_route(node)
        prev_assignments = self.local_assignments.copy()
        prev_tainted = self.tainted_vars.copy()
        self.local_assignments.clear()
        self.tainted_vars.clear()
        self._taint_function_params(node)
        self.async_function_depth += 1
        self.generic_visit(node)
        self.async_function_depth -= 1
        self.local_assignments = prev_assignments
        self.tainted_vars = prev_tainted

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.inspect_route(node)
        prev_assignments = self.local_assignments.copy()
        prev_tainted = self.tainted_vars.copy()
        self.local_assignments.clear()
        self.tainted_vars.clear()
        self._taint_function_params(node)
        previous_depth = self.async_function_depth
        self.async_function_depth = 0
        self.generic_visit(node)
        self.async_function_depth = previous_depth
        self.local_assignments = prev_assignments
        self.tainted_vars = prev_tainted

    def visit_Call(self, node: ast.Call) -> None:
        raw_name = resolve_dotted_name(node.func)
        name = self._resolve_name(raw_name)
        method = name.rsplit(".", 1)[-1]

        # --- Taint sink analysis ---
        sink_rule_id = TAINT_SINKS.get(method)
        if sink_rule_id and node.args:
            first_arg = node.args[0]
            if (
                isinstance(first_arg, ast.Name)
                and first_arg.id in self.tainted_vars
                and not self._is_sanitized(node)
            ):
                self.add_finding(find_rule(sink_rule_id), first_arg, detection="taint")
        if method in {"execute", "query", "raw"} and node.args:
            first_arg = node.args[0]
            if is_interpolated_sql_value(first_arg):
                self.add_finding(find_rule("SP103"), first_arg)
            elif isinstance(first_arg, ast.Name) and first_arg.id in self.local_assignments:
                assigned_val = self.local_assignments[first_arg.id]
                if is_interpolated_sql_value(assigned_val):
                    self.add_finding(find_rule("SP103"), first_arg, detection="taint")
        if name in {"eval", "exec"} and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id in self.local_assignments:
                assigned_val = self.local_assignments[first_arg.id]
                if not (
                    isinstance(assigned_val, ast.Constant)
                    and isinstance(assigned_val.value, (int, float, bool))
                ):
                    self.add_finding(find_rule("SP101"), node, detection="ast")
            elif not (
                isinstance(first_arg, ast.Constant)
                and isinstance(first_arg.value, (int, float, bool))
            ):
                self.add_finding(find_rule("SP101"), node, detection="ast")
        if self.loop_depth > 0:
            receiver = name.split(".", 1)[0].lower() if "." in name else ""
            db_methods = {"query", "execute", "filter_by", "find_one", "fetch_one"}
            db_receivers = {"db", "session", "cursor", "repo", "conn", "orm"}
            if method in db_methods or (
                receiver in db_receivers and method in {"get", "find", "select", "filter"}
            ):
                self.add_finding(find_rule("SP307"), node)

        def _is_http_client_binding(var_name: str) -> bool:
            # A bare receiver only counts as an HTTP client when it was
            # assigned from a known client constructor. Untracked names such
            # as Flask's dict-like `session` or a test `client` are not
            # outbound requests (measured against the flask and requests
            # corpora).
            assigned = self.local_assignments.get(var_name)
            if not isinstance(assigned, ast.Call):
                return False
            return resolve_dotted_name(assigned.func).lower() in {
                "requests.session",
                "session",
                "httpx.client",
                "client",
                "httpx.asyncclient",
                "asyncclient",
                "aiohttp.clientsession",
                "clientsession",
            }

        is_http_request = name in {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            "httpx.get",
            "httpx.post",
            "httpx.put",
            "httpx.patch",
            "httpx.delete",
            "http_client.get",
            "http_client.post",
        } or (
            method in {"get", "post", "put", "patch", "delete"}
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and (
                node.func.value.id.lower() in {"http", "http_client"}
                or _is_http_client_binding(node.func.value.id)
            )
        )
        if is_http_request and not any(keyword.arg == "timeout" for keyword in node.keywords):
            self.add_finding(find_rule("SP304"), node)
        if self.transaction_depth > 0 and is_http_request:
            self.add_finding(find_rule("SP316"), node)
        if (
            name in {"render_template_string", "jinja2.Template", "Template"}
            and node.args
            and is_interpolated_sql_value(node.args[0])
        ):
            self.add_finding(find_rule("SP137"), node.args[0])
        if name in {"tempfile.mktemp", "mktemp"}:
            self.add_finding(find_rule("SP139"), node)
        if method == "extractall" and isinstance(node.func, ast.Attribute):
            self.add_finding(find_rule("SP111"), node)
        if self.async_function_depth > 0:
            if name == "time.sleep":
                self.add_finding(find_rule("SP303"), node)
            elif name in {
                "requests.get",
                "requests.post",
                "requests.put",
                "requests.patch",
                "requests.delete",
                "urllib.request.urlopen",
            }:
                self.add_finding(find_rule("SP317"), node)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        is_infinite = isinstance(node.test, ast.Constant) and bool(node.test.value)
        if is_infinite and node.body:
            has_backoff = False
            for child in ast.walk(node):
                if isinstance(child, (ast.Break, ast.Return, ast.Yield, ast.YieldFrom, ast.Await)):
                    has_backoff = True
                    break
                if isinstance(child, ast.Call):
                    call_name = resolve_dotted_name(child.func).lower()
                    if any(
                        token in call_name
                        for token in ("sleep", "wait", "select", "recv", "poll", "backoff")
                    ):
                        has_backoff = True
                        break
            if not has_backoff:
                self.add_finding(find_rule("SP310"), node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.body:
            for stmt in node.body:
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    name = resolve_dotted_name(stmt.value.func).lower()
                    if name in {"time.sleep", "sleep"} and stmt.value.args:
                        arg0 = stmt.value.args[0]
                        if isinstance(arg0, ast.Constant) and arg0.value == 0:
                            self.add_finding(find_rule("SP312"), node)
                            break
        self.generic_visit(node)


def parse_python_source(source_text: str, *, strict: bool = False) -> ast.Module | None:
    """Parse Python source, treating parser failures as unavailable evidence in strict mode."""
    try:
        return ast.parse(source_text)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        if strict:
            raise ScanCoverageError("parser_limit") from exc
        return None


def js_template_prose_lines(source_text: str) -> frozenset[int]:
    """0-based indices of JS/TS lines that sit entirely in template or comment prose.

    One conservative pass tracks quotes, escapes, backtick templates (with
    interpolation depth), line comments, and block comments. A line counts as
    prose only when it starts inside a template or block comment and never
    shows code-ish characters; any line touching a backtick, interpolation
    marker, brace, or semicolon stays scannable, so real code inside
    interpolations cannot be suppressed. Nested templates inside
    interpolations give up tracking for the rest of the file (never marks
    prose again) rather than risk suppressing real code.
    """
    prose: set[int] = set()
    state = "code"  # code | single | double | template | block | untracked
    interpolation_depth = 0
    escaped = False
    for line_index, line in enumerate(source_text.splitlines()):
        started_in_prose = state in {"template", "block"}
        saw_code = False
        index = 0
        while index < len(line):
            char = line[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if state == "code":
                if char == "'":
                    state = "single"
                elif char == '"':
                    state = "double"
                elif char == "`":
                    state = "template"
                    interpolation_depth = 0
                elif char == "/" and line[index : index + 2] == "//":
                    break
                elif char == "/" and line[index : index + 2] == "/*":
                    state = "block"
                    index += 1
                elif not char.isspace():
                    saw_code = True
            elif state == "single":
                if char == "\\":
                    escaped = True
                elif char == "'":
                    state = "code"
            elif state == "double":
                if char == "\\":
                    escaped = True
                elif char == '"':
                    state = "code"
            elif state == "template":
                if char == "\\":
                    escaped = True
                elif interpolation_depth == 0 and char == "`":
                    state = "code"
                elif interpolation_depth == 0 and line[index : index + 2] == "${":
                    interpolation_depth = 1
                    saw_code = True
                    index += 1
                elif interpolation_depth > 0:
                    saw_code = True
                    if char == "{":
                        interpolation_depth += 1
                    elif char == "}":
                        interpolation_depth -= 1
                    elif char == "`":
                        # Nested template inside an interpolation: stop
                        # marking prose for the rest of the file.
                        state = "untracked"
                        break
            elif state == "block" and line[index : index + 2] == "*/":
                state = "code"
                index += 1
            index += 1
        if started_in_prose and state in {"template", "block"} and not saw_code:
            prose.add(line_index)
    return frozenset(prose)


def multiline_string_lines(tree: ast.Module | None) -> frozenset[int]:
    """Interior lines of multi-line string constants (docstrings and prose blocks).

    Those lines contain only literal text, so non-secret rules may skip them the
    same way they skip comments. f-string components are excluded because their
    embedded expressions can hold real code.
    """
    if tree is None:
        return frozenset()
    joined_parts: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for child in ast.walk(node):
                if isinstance(child, ast.Constant):
                    joined_parts.add(id(child))
    lines: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in joined_parts
        ):
            end = getattr(node, "end_lineno", None)
            if end is not None and end > node.lineno:
                lines.update(range(node.lineno + 1, end))
    return frozenset(lines)


def find_python_ast_issues(
    relative_path: str,
    source_text: str,
    lines: Sequence[str] | None = None,
    tree: ast.Module | None = None,
    ignore_ids: Sequence[tuple[str, ...]] | None = None,
) -> list[Finding]:
    if tree is None:
        tree = parse_python_source(source_text)
        if tree is None:
            return []
    try:
        authorized_routers = find_authorized_routers(tree)
        visitor = PythonSecurityVisitor(
            relative_path,
            source_lines=lines if lines is not None else source_text.splitlines(),
            authorized_routers=authorized_routers,
            ignore_ids=ignore_ids,
        )
        visitor.visit(tree)
        if "create_task" in source_text or "logging" in source_text or "QueuePool" in source_text:
            for rule_id, node in python_runtime_checks.observations(tree):
                visitor.add_finding(find_rule(rule_id), node)
    except (RecursionError, MemoryError, python_runtime_checks.AnalysisLimitError) as exc:
        # A pathological AST is unavailable evidence, never a clean scan and
        # never a process crash. The worker transports this typed omission.
        raise ScanCoverageError("parser_limit") from exc
    return visitor.findings


def lint_source_snippet(source_text: str, filename: str = "snippet.py") -> list[Finding]:
    """Lint an in-memory code snippet without reading from disk."""
    if any(len(line) > MAX_SCAN_LINE_CHARS for line in source_text.splitlines()):
        raise ScanCoverageError("line_limit")
    path = Path(filename)
    lines = source_text.splitlines()
    # Snippet linting is consumed as validation evidence by the CLI/MCP. A
    # parser failure must therefore be visible as unavailable evidence rather
    # than silently dropping every AST-layer rule from an otherwise clean
    # result. Repository scans use the same strict path in scan_single_file.
    # Preserve the historical convenience of linting a deliberately truncated
    # snippet such as ``def f():\n``: this is an incomplete editor buffer, not
    # parser-version skew. Every other syntax/parser failure remains invalid
    # evidence (exit 2), including malformed code that merely contains a
    # security-sensitive token.
    python_tree = None
    if path.suffix.lower() == ".py":
        try:
            python_tree = parse_python_source(source_text, strict=True)
        except ScanCoverageError as exc:
            cause = exc.__cause__
            if not (isinstance(cause, IndentationError) and source_text.rstrip().endswith(":")):
                raise
    python_string_lines = multiline_string_lines(python_tree) if python_tree is not None else None
    doc_lines = (
        precision_policy.docstring_lines(python_tree) if python_tree is not None else frozenset()
    )
    findings = find_regex_issues(
        path, filename, source_text, lines, python_string_lines, docstring_lines=doc_lines
    )
    if python_tree is not None:
        prefixes = comment_line_prefixes(path)
        ignore_ids = [extract_inline_ignore_ids(line, prefixes) for line in lines]
        findings.extend(
            find_python_ast_issues(filename, source_text, lines, python_tree, ignore_ids)
        )
    active, _ = deduplicate_and_suppress_findings(findings)
    return precision_policy.apply_file_precision(
        active,
        relative_path=filename,
        source_text=source_text,
        secret_rule_ids=SECRET_RULE_IDS,
        source_path=filename,
    )


@dataclass(frozen=True)
class SuppressionRule:
    """Human-authored glob suppression; the reason field is mandatory."""

    rule_id: str = ""
    path: str = ""
    evidence: str = ""
    reason: str = ""


@dataclass(frozen=True)
class SuppressionBaseline:
    """Version-2 baseline: exact fingerprints plus auditable glob rules."""

    fingerprints: dict[str, str]
    rules: tuple[SuppressionRule, ...] = ()
    scanner_version: str | None = None


_BASELINE_MATCHER_LIMIT = 512
MAX_BASELINE_BYTES = 2_000_000
MAX_BASELINE_FINGERPRINTS = 10_000
MAX_BASELINE_RULES = 256


def _baseline_matcher(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _BASELINE_MATCHER_LIMIT:
        raise ValueError(f"baseline {label} must be a non-empty string of at most 512 characters")
    if not value.isprintable():
        raise ValueError(f"baseline {label} must not contain control characters")
    return value


def _baseline_reason(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("every baseline rule or fingerprint needs a non-empty reason")
    return _baseline_matcher(value, "reason")


def _baseline_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("baseline contains duplicate JSON keys")
        payload[key] = value
    return payload


def _baseline_keys(payload: dict[str, object], allowed: set[str]) -> None:
    if set(payload) - allowed:
        raise ValueError("baseline contains unknown fields; check the suppression scope")


def _path_inside_root(root: Path, candidate: Path | None) -> str | None:
    """Repository-relative path of candidate when it lives inside root."""
    if candidate is None:
        return None
    try:
        return candidate.resolve().relative_to(root).as_posix()
    except (ValueError, OSError):
        return None


def load_baseline_fingerprints(path: Path | None) -> SuppressionBaseline:
    """Load a version-1 (string array) or version-2 baseline; invalid input raises."""
    if path is None:
        return SuppressionBaseline(fingerprints={})
    try:
        source = read_scannable_bytes(path, MAX_BASELINE_BYTES).decode("utf-8")
    except ScanCoverageError as exc:
        raise ValueError("baseline is unreadable or exceeds the input byte limit") from exc
    try:
        payload = json.loads(source, object_pairs_hook=_baseline_object_pairs)
    except (RecursionError, MemoryError) as exc:
        raise ValueError("baseline JSON exceeds parser/resource limits") from exc
    if not isinstance(payload, dict):
        raise ValueError("baseline must contain a JSON object")
    _baseline_keys(payload, {"version", "scanner_version", "fingerprints", "rules"})
    version = payload.get("version", 1)
    if type(version) is not int or version not in (1, 2):
        raise ValueError("unsupported baseline version; expected integer 1 or 2")
    if version == 1 and ("rules" in payload or "fingerprints" not in payload):
        raise ValueError("version-1 baseline requires fingerprints and cannot contain glob rules")
    scanner_version = payload.get("scanner_version")
    if scanner_version is not None:
        _baseline_matcher(scanner_version, "scanner_version")
    raw_fingerprints = payload.get("fingerprints", [])
    if not isinstance(raw_fingerprints, list):
        raise ValueError("baseline must contain an array named 'fingerprints'")
    if len(raw_fingerprints) > MAX_BASELINE_FINGERPRINTS:
        raise ValueError("baseline fingerprint count exceeds the limit of 10000")
    fingerprints: dict[str, str] = {}
    for entry in raw_fingerprints:
        if isinstance(entry, str):
            _baseline_matcher(entry, "fingerprint")
            fingerprints[entry] = ""
            continue
        if isinstance(entry, dict):
            if version != 2:
                raise ValueError("version-1 baseline fingerprints must be strings")
            _baseline_keys(entry, {"hash", "reason", "rule_id", "path"})
            raw_hash = entry.get("hash")
            if not isinstance(raw_hash, str) or not raw_hash:
                raise ValueError("baseline fingerprint objects need a non-empty 'hash'")
            _baseline_matcher(raw_hash, "fingerprint")
            reason = _baseline_reason(entry.get("reason"))
            for label in ("rule_id", "path"):
                if label in entry:
                    _baseline_matcher(entry[label], label)
            fingerprints[raw_hash] = reason
            continue
        raise ValueError("baseline fingerprints must be strings or objects with a 'hash'")
    raw_rules = payload.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError("baseline must contain an array named 'rules'")
    if len(raw_rules) > MAX_BASELINE_RULES:
        raise ValueError("baseline rule count exceeds the limit of 256")
    rules: list[SuppressionRule] = []
    for entry in raw_rules:
        if not isinstance(entry, dict):
            raise ValueError("baseline rules must be objects")
        _baseline_keys(entry, {"id", "path", "evidence", "reason"})
        reason = _baseline_reason(entry.get("reason"))
        rule_id = _baseline_matcher(entry["id"], "rule id") if "id" in entry else ""
        rule_path = _baseline_matcher(entry["path"], "rule path") if "path" in entry else ""
        rule_evidence = (
            _baseline_matcher(entry["evidence"], "rule evidence") if "evidence" in entry else ""
        )
        if not (rule_id or rule_path or rule_evidence):
            raise ValueError("baseline rules need at least one matcher: id, path, or evidence")
        rules.append(
            SuppressionRule(rule_id=rule_id, path=rule_path, evidence=rule_evidence, reason=reason)
        )
    return SuppressionBaseline(
        fingerprints=fingerprints, rules=tuple(rules), scanner_version=scanner_version
    )


def _rule_suppresses(rule: SuppressionRule, finding: Finding) -> bool:
    if rule.rule_id and not fnmatch.fnmatchcase(finding.rule_id, rule.rule_id):
        return False
    if rule.path and not fnmatch.fnmatchcase(finding.path, rule.path):
        return False
    return not (rule.evidence and not fnmatch.fnmatchcase(finding.evidence, rule.evidence))


def deduplicate_and_suppress_findings(
    findings: Iterable[Finding],
    baseline: SuppressionBaseline | set[str] | None = None,
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    unique: dict[tuple[str, str, int], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line)
        existing = unique.get(key)
        if existing is None:
            unique[key] = finding
        elif PROOF_RANK.get(finding.proof_level, 0) > PROOF_RANK.get(existing.proof_level, 0):
            # Same rule and line: keep the finding from the stronger engine so a
            # pattern hit never shadows richer AST/taint evidence.
            unique[key] = finding
    active: list[Finding] = []
    suppressed: list[tuple[Finding, str]] = []
    if isinstance(baseline, SuppressionBaseline):
        fingerprint_reasons = baseline.fingerprints
        rules = baseline.rules
    else:
        fingerprint_reasons = {value: "" for value in (baseline or set())}
        rules = ()
    for finding in unique.values():
        if finding.fingerprint in fingerprint_reasons:
            suppressed.append((finding, fingerprint_reasons[finding.fingerprint]))
        else:
            matched = next((rule for rule in rules if _rule_suppresses(rule, finding)), None)
            if matched is not None:
                suppressed.append((finding, matched.reason))
            else:
                active.append(finding)
    active.sort(
        key=lambda item: (
            SEVERITY[item.severity],
            CONFIDENCE[item.confidence],
            item.path,
            item.line,
        )
    )
    return active, suppressed


MANIFEST_FILE_NAMES = (
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "Pipfile",
    "poetry.lock",
    "go.mod",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "global.json",
    "Directory.Packages.props",
)


def repository_manifest_present(root: Path) -> bool:
    if any((root / name).is_file() for name in MANIFEST_FILE_NAMES):
        return True
    return bool(list(root.glob("*.csproj")) or list(root.glob("*.sln")))


def detect_frameworks(root: Path, max_file_bytes: int = 1_000_000) -> set[str]:
    """Detect frameworks and runtimes from manifest files in the repository root."""
    frameworks: set[str] = set()

    # 1. Node.js / TypeScript (package.json)
    pkg_path = root / "package.json"
    if pkg_path.is_file():
        try:
            pkg = json.loads(read_scannable_bytes(pkg_path, max_file_bytes).decode("utf-8"))
            if not isinstance(pkg, dict):
                raise ValueError("package manifest must contain an object")
            all_deps: dict[str, str] = {}
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                val = pkg.get(key)
                if isinstance(val, dict):
                    all_deps.update(val)
            # Fullstack & Frontend
            if "next" in all_deps:
                frameworks.add("nextjs")
            if "nuxt" in all_deps or "nuxt3" in all_deps:
                frameworks.add("nuxt")
            if "@sveltejs/kit" in all_deps:
                frameworks.add("sveltekit")
            if "@remix-run/react" in all_deps or "@remix-run/node" in all_deps:
                frameworks.add("remix")
            if "astro" in all_deps:
                frameworks.add("astro")
            if "vue" in all_deps:
                frameworks.add("vue")
            if "@angular/core" in all_deps:
                frameworks.add("angular")
            if "react" in all_deps and "next" not in all_deps:
                frameworks.add("react")
            if "solid-js" in all_deps:
                frameworks.add("solid")
            # Backend
            if "express" in all_deps:
                frameworks.add("express")
            if "fastify" in all_deps:
                frameworks.add("fastify")
            if "@nestjs/core" in all_deps:
                frameworks.add("nestjs")
            if "koa" in all_deps:
                frameworks.add("koa")
            if "hono" in all_deps:
                frameworks.add("hono")
            if "elysia" in all_deps:
                frameworks.add("elysia")
            # ORMs & DBs
            if "@prisma/client" in all_deps or "prisma" in all_deps:
                frameworks.add("prisma")
            if "drizzle-orm" in all_deps:
                frameworks.add("drizzle")
            if "typeorm" in all_deps:
                frameworks.add("typeorm")
            if "mongoose" in all_deps:
                frameworks.add("mongoose")
            if "@supabase/supabase-js" in all_deps:
                frameworks.add("supabase")
        except (OSError, ValueError, RecursionError, MemoryError):
            pass

    # 2. Python (pyproject.toml, requirements.txt, setup.py, Pipfile, poetry.lock)
    for manifest in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile", "poetry.lock"):
        manifest_path = root / manifest
        if manifest_path.is_file():
            try:
                text = read_scannable_bytes(manifest_path, max_file_bytes).decode("utf-8").lower()
                if "django" in text:
                    frameworks.add("django")
                if "fastapi" in text:
                    frameworks.add("fastapi")
                if "flask" in text:
                    frameworks.add("flask")
                if "starlette" in text and "fastapi" not in text:
                    frameworks.add("starlette")
                if "tornado" in text:
                    frameworks.add("tornado")
                if "litestar" in text:
                    frameworks.add("litestar")
                if "sanic" in text:
                    frameworks.add("sanic")
                if "sqlalchemy" in text:
                    frameworks.add("sqlalchemy")
                if "supabase" in text:
                    frameworks.add("supabase")
            except (OSError, ValueError):
                pass

    # 3. Go (go.mod)
    go_mod = root / "go.mod"
    if go_mod.is_file():
        try:
            text = read_scannable_bytes(go_mod, max_file_bytes).decode("utf-8").lower()
            if "gin-gonic/gin" in text:
                frameworks.add("gin")
            if "labstack/echo" in text:
                frameworks.add("echo")
            if "gofiber/fiber" in text:
                frameworks.add("fiber")
            if "go-chi/chi" in text:
                frameworks.add("chi")
        except (OSError, ValueError):
            pass

    # 4. Rust (Cargo.toml)
    cargo_toml = root / "Cargo.toml"
    if cargo_toml.is_file():
        try:
            text = read_scannable_bytes(cargo_toml, max_file_bytes).decode("utf-8").lower()
            if "actix-web" in text:
                frameworks.add("actix")
            if "axum" in text:
                frameworks.add("axum")
            if "rocket" in text:
                frameworks.add("rocket")
        except (OSError, ValueError):
            pass

    # 5. PHP (composer.json)
    composer_json = root / "composer.json"
    if composer_json.is_file():
        try:
            text = read_scannable_bytes(composer_json, max_file_bytes).decode("utf-8").lower()
            if "laravel" in text:
                frameworks.add("laravel")
            if "symfony" in text:
                frameworks.add("symfony")
        except (OSError, ValueError):
            pass

    # 6. Ruby (Gemfile)
    gemfile = root / "Gemfile"
    if gemfile.is_file():
        try:
            text = read_scannable_bytes(gemfile, max_file_bytes).decode("utf-8").lower()
            if "rails" in text:
                frameworks.add("rails")
            if "sinatra" in text:
                frameworks.add("sinatra")
        except (OSError, ValueError):
            pass

    # 7. Java / Kotlin / JVM (pom.xml, build.gradle, build.gradle.kts)
    for jvm_file in ("pom.xml", "build.gradle", "build.gradle.kts"):
        jvm_path = root / jvm_file
        if jvm_path.is_file():
            try:
                text = read_scannable_bytes(jvm_path, max_file_bytes).decode("utf-8").lower()
                if "spring-boot" in text or "springframework" in text:
                    frameworks.add("springboot")
                if "quarkus" in text:
                    frameworks.add("quarkus")
                if "micronaut" in text:
                    frameworks.add("micronaut")
            except (OSError, ValueError):
                pass

    # 8. C# / .NET (*.csproj, global.json, *.sln)
    try:
        if (
            list(root.glob("*.csproj"))
            or (root / "global.json").is_file()
            or list(root.glob("*.sln"))
        ):
            frameworks.add("dotnet")
            for csproj in root.glob("*.csproj"):
                text = read_scannable_bytes(csproj, max_file_bytes).decode("utf-8").lower()
                if "microsoft.aspnetcore" in text:
                    frameworks.add("aspnetcore")
                if "microsoft.entityframeworkcore" in text:
                    frameworks.add("entityframework")
    except (OSError, ValueError):
        pass

    # 9. C / C++ (CMakeLists.txt, Makefile)
    if (root / "CMakeLists.txt").is_file():
        frameworks.add("cmake")
    if (root / "Makefile").is_file() or (root / "makefile").is_file():
        frameworks.add("make")

    # 10. Containers & Infra
    if (
        (root / "Dockerfile").is_file()
        or (root / "docker-compose.yml").is_file()
        or (root / "compose.yaml").is_file()
        or (root / "compose.yml").is_file()
    ):
        frameworks.add("docker")
    if (root / ".github" / "workflows").is_dir():
        frameworks.add("github-actions")
    if (root / "serverless.yml").is_file() or (root / "serverless.ts").is_file():
        frameworks.add("serverless")

    return frameworks


GIT_REF_PATTERN = re.compile(r"^[A-Za-z0-9._/@][A-Za-z0-9._/@~-]*$")


def _trusted_git_binary(root: Path) -> Path:
    """Resolve Git without accepting a repository-controlled PATH shadow."""
    git_location = shutil.which("git")
    if not git_location:
        raise ValueError("git-history evidence is unavailable: git was not found")
    lexical = Path(git_location)
    if not lexical.is_absolute():
        raise ValueError("git-history evidence refused a relative Git PATH entry")
    repository_path = Path(os.path.abspath(os.fspath(root)))
    repository_root = root.resolve()
    # Check both lexical and canonical spellings. The lexical check catches a
    # repo symlink directory pointing outside; the canonical check catches a
    # host PATH symlink resolving back into the repository. Keeping both roots
    # handles Windows long/8.3 spellings without following the candidate link.
    canonical = lexical.resolve()
    for candidate in (lexical, canonical):
        for boundary in (repository_path, repository_root):
            try:
                candidate.relative_to(boundary)
            except ValueError:
                continue
            raise ValueError("git-history evidence refused a Git executable inside the scan root")
    return canonical


def changed_files(root: Path, git_ref: str) -> frozenset[str]:
    """Resolve repository-relative paths changed relative to a git ref, failing closed."""
    if not GIT_REF_PATTERN.match(git_ref):
        raise ValueError(f"invalid git ref: {git_ref!r}")
    repository_root = root.resolve()
    commands = (
        [
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            "--find-renames",
            "--find-copies-harder",
            "--relative",
            git_ref,
            "--",
            ".",
        ],
        [
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            ".",
        ],
    )
    changed: set[str] = set()
    try:
        git_binary = _trusted_git_binary(repository_root)
    except ValueError as exc:
        message = str(exc).replace("git-history evidence", "changed-file evidence")
        raise ValueError(message) from exc
    environment = os.environ.copy()
    for name in tuple(environment):
        if name in {
            "GIT_DIR",
            "GIT_COMMON_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
        } or name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            environment.pop(name)
    environment.update(
        {
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    for command in commands:
        try:
            completed = subprocess.run(  # noqa: S603 (validated absolute git path and ref)
                [
                    str(git_binary),
                    "--no-pager",
                    "-c",
                    "core.fsmonitor=false",
                    "-C",
                    str(repository_root),
                    *command,
                ],
                capture_output=True,
                check=False,
                env=environment,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"cannot resolve changed files: {exc}") from exc
        if len(completed.stdout) + len(completed.stderr) > 2_000_000:
            raise ValueError("changed-file evidence exceeded the 2000000-byte output limit")
        if completed.returncode != 0:
            error_text = (completed.stderr or completed.stdout).decode("utf-8", "replace")
            details = error_text.strip().splitlines()
            hint = details[0] if details else "git failed"
            raise ValueError(f"cannot resolve git ref {git_ref!r}: {hint}")
        stdout = completed.stdout.decode("utf-8", "replace")
        changed.update(raw_path for raw_path in stdout.split("\0") if raw_path)
    return frozenset(path.removeprefix("./") for path in changed)


def load_impact_graph_module():
    companion = Path(__file__).resolve().parent / "impact_graph.py"
    if not companion.is_file():
        raise ValueError("--cross-file requires the impact_graph.py companion script")
    spec = importlib.util.spec_from_file_location("shipproof_impact_graph", companion)
    if spec is None or spec.loader is None:
        raise ValueError("could not load the impact graph analyzer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def collect_cross_file_taint(
    root: Path,
    *,
    allowed_paths: frozenset[str] | None = None,
    max_file_bytes: int = 1_000_000,
) -> tuple[list[Finding], int, int]:
    """Promote unsanitized interprocedural taint flows into L2 findings.

    Uses the offline impact-graph analyzer (route entrypoints -> helpers ->
    dangerous sinks across files). Each flow lands on the sink line; when a
    lower-proof finding for the same rule and line already exists, dedup keeps
    this richer taint evidence instead. Returns (findings, total_flows,
    unsanitized_flows).
    """
    module = load_impact_graph_module()
    graph = module.ImpactGraph(
        root,
        allowed_paths=allowed_paths,
        max_file_bytes=max_file_bytes,
    )
    graph.build()
    flows = graph.propagate_interprocedural_taint()
    findings: list[Finding] = BoundedFindings()
    unsanitized = 0
    for flow in sorted(
        flows,
        key=lambda item: (item.sink_file, item.sink_line, item.sink_rule_id, item.source_file),
    ):
        if flow.is_sanitized:
            continue
        unsanitized += 1
        rule = find_rule(flow.sink_rule_id)
        chain = " -> ".join([*flow.call_chain[-4:], f"sink:{flow.sink_function}"])
        evidence = (
            f"Tainted '{flow.source_param}' from {flow.source_file} reaches a "
            f"{flow.sink_type.replace('_', ' ')} sink via {chain}"
        )
        findings.append(make_finding(rule, flow.sink_file, flow.sink_line, evidence, "taint"))
    return findings, len(flows), unsanitized


PARALLEL_MIN_FILES = 24
MAX_SCAN_JOBS = 32


def _worker_initializer() -> None:
    """Make this module importable inside spawned workers on every platform."""
    scripts_directory = str(Path(__file__).resolve().parent)
    if scripts_directory not in sys.path:
        sys.path.insert(0, scripts_directory)


class ScanCoverageError(ValueError):
    """An expected content omission, distinct from a finding or analyzer crash."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def read_scannable_bytes(path: Path, limit: int, *, header_only: bool = False) -> bytes:
    """Read a bounded regular file without following a final symlink.

    The descriptor checks cover replacement between discovery and open. This is
    not a filesystem snapshot; callers must scan a quiescent checkout.
    """
    try:
        before = path.lstat()
        if not stat_module.S_ISREG(before.st_mode) or is_link_or_reparse(before):
            raise ScanCoverageError("unreadable")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat_module.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise ScanCoverageError("unreadable")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(limit if header_only else limit + 1)
            after = os.fstat(descriptor)
            if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ScanCoverageError("unreadable")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ScanCoverageError("unreadable") from exc
    if not header_only and len(content) > limit:
        raise ScanCoverageError("oversized")
    return content


def safe_write_text(path: Path, content: str, *, label: str = "output") -> Path:
    """Atomically write a report without following a final symlink.

    A report path can be supplied by an untrusted workflow input. ``Path.write_text``
    follows a replaced/dangling symlink, so write a temporary sibling and replace
    the directory entry instead. Parent symlinks are rejected too: resolving one
    would let a repository-controlled link redirect an apparently local report
    outside the intended workspace.
    """
    requested = Path(path)
    absolute = Path(os.path.abspath(os.fspath(requested)))
    parent = absolute.parent
    try:
        current = Path(parent.anchor) if parent.anchor else Path()
        for component in parent.parts:
            if component == parent.anchor:
                continue
            current /= component
            metadata = current.lstat()
            if is_link_or_reparse(metadata):
                raise ValueError(
                    f"{label} directory contains a symlink or reparse point: {current}"
                )
            if not stat_module.S_ISDIR(metadata.st_mode):
                raise ValueError(f"{label} parent is not a directory: {current}")
    except FileNotFoundError as exc:
        raise ValueError(f"{label} directory is unavailable: {parent}") from exc
    except OSError as exc:
        raise ValueError(f"{label} directory is unavailable: {parent}") from exc
    destination = parent / absolute.name
    try:
        metadata = destination.lstat()
    except FileNotFoundError:
        metadata = None
    except OSError as exc:
        raise ValueError(f"{label} path is unavailable: {destination}") from exc
    if metadata is not None and (
        stat_module.S_ISLNK(metadata.st_mode) or not stat_module.S_ISREG(metadata.st_mode)
    ):
        raise ValueError(f"{label} path must be a regular file, not a symlink or directory")
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=str(parent)
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    except OSError as exc:
        raise ValueError(f"could not write {label}: {destination}") from exc
    finally:
        if temporary_name:
            with contextlib.suppress(OSError):
                os.unlink(temporary_name)
    return destination


def scan_single_file(
    path: Path,
    relative_path: str,
    max_file_bytes: int,
    detected_frameworks: frozenset[str] | None,
    skill_context: bool = False,
) -> list[Finding]:
    """Scan one file with both engines; shared by sequential and parallel paths.

    Expected omissions raise ScanCoverageError; the worker transports a typed
    outcome separately from findings so no sentinel can masquerade as evidence.
    """
    if path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
        header = read_scannable_bytes(path, 16, header_only=True)
        if header.startswith(b"SQLite format 3") or path.suffix.lower() in {".sqlite", ".sqlite3"}:
            return [
                make_finding(
                    find_rule("SP314"),
                    relative_path,
                    1,
                    f"Tracked database file: {relative_path}",
                    "artifact",
                )
            ]
        return []
    try:
        text = read_scannable_bytes(path, max_file_bytes).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanCoverageError("unreadable") from exc
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.splitlines()
    # Python's backtracking ``re`` engine is intentionally dependency-free, so
    # a hostile single-line source file could otherwise make one pattern spend
    # quadratic time searching an unbounded line. Do not truncate the line and
    # claim coverage: transport the omission to the ledger and let production
    # gates fail closed.
    if any(len(line) > MAX_SCAN_LINE_CHARS for line in lines):
        raise ScanCoverageError("line_limit")
    python_tree = parse_python_source(text, strict=True) if path.suffix.lower() == ".py" else None
    python_string_lines = multiline_string_lines(python_tree) if python_tree is not None else None
    doc_lines = (
        precision_policy.docstring_lines(python_tree) if python_tree is not None else frozenset()
    )
    file_findings = find_regex_issues(
        path,
        relative_path,
        text,
        lines,
        python_string_lines,
        detected_frameworks,
        skill_context,
        docstring_lines=doc_lines,
    )
    if python_tree is not None:
        prefixes = comment_line_prefixes(path)
        ignore_ids = [extract_inline_ignore_ids(line, prefixes) for line in lines]
        file_findings.extend(
            find_python_ast_issues(relative_path, text, lines, python_tree, ignore_ids)
        )
    return precision_policy.apply_file_precision(
        file_findings,
        relative_path=relative_path,
        source_text=text,
        secret_rule_ids=SECRET_RULE_IDS,
        source_path=str(path),
    )


def _scan_file_task(
    task: tuple[str, str, int, tuple[str, ...] | None, bool],
) -> tuple[list[Finding], str | None]:
    """Pool worker entry point: unpack one scan task and return its findings."""
    path_text, relative_path, max_file_bytes, frameworks, skill_context = task
    detected = frozenset(frameworks) if frameworks is not None else None
    try:
        return scan_single_file(
            Path(path_text), relative_path, max_file_bytes, detected, skill_context
        ), None
    except ScanCoverageError as exc:
        return [], exc.reason


def _tracked_paths_for_scan(root: Path) -> frozenset[str]:
    """Return Git-index paths so committed ignored-tree files stay visible.

    The normal walker prunes dependency/build trees for bounded performance.
    A committed file in one of those trees is part of the review surface,
    however, and must not disappear merely because its parent directory is
    conventionally ignored. Git's NUL-delimited output keeps unusual names
    unambiguous; the shared bounded runner also strips repository-level Git
    overrides and refuses a repository-local Git executable.
    """
    status, output, _ = _run_git_bounded(
        root,
        ["ls-files", "--cached", "-z", "--"],
        timeout_seconds=10,
        max_output_bytes=8_000_000,
    )
    if status != 0:
        raise ValueError("git index listing failed")
    paths: set[str] = set()
    for raw_path in output.split("\0"):
        if not raw_path:
            continue
        relative = raw_path.replace("\\", "/")
        if (
            relative.startswith("/")
            or "\x00" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise ValueError("git index returned an unsafe relative path")
        paths.add(relative)
    return frozenset(paths)


def _has_prunable_tree(root: Path) -> bool:
    """Cheaply determine whether Git-index discovery is needed.

    Avoid a Git subprocess for ordinary repositories with no dependency/build
    trees (and for callers that only select normal source files). The walk is
    bounded by returning as soon as a prunable directory is observed; Git's
    own metadata is ignored because it never contains tracked worktree paths.
    """
    try:
        for _directory, subdirectories, _filenames in os.walk(
            root, topdown=True, followlinks=False
        ):
            if any(name in SKIP_DIRS - {".git"} for name in subdirectories):
                return True
            subdirectories[:] = [name for name in subdirectories if name != ".git"]
    except OSError:
        # A walk failure is already incomplete evidence; ask for the index so
        # a tracked ignored file cannot be silently hidden by the same failure.
        return True
    return False


def scan_repository(
    root: Path,
    max_file_bytes: int = 1_000_000,
    baseline: SuppressionBaseline | set[str] | None = None,
    exclude_patterns: Sequence[str] = (),
    include_paths: frozenset[str] | None = None,
    cross_file: bool = False,
    jobs: int = 1,
    excluded_paths: frozenset[str] | None = None,
    scan_profile: str | None = None,
    inspect_archives: bool = False,
) -> tuple[list[Finding], dict[str, object]]:
    repository_root = root.resolve()
    if not repository_root.is_dir():
        raise ValueError(f"not a directory: {repository_root}")
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    if max_file_bytes < 1:
        raise ValueError("max-file-bytes must be positive")
    findings: list[Finding] = BoundedFindings(MAX_FINDINGS_TOTAL)
    frameworks = detect_frameworks(repository_root, max_file_bytes)
    # Without any manifest at all, framework state is unknown (do not downgrade
    # structural framework findings); with manifests present, an undeclared
    # framework is real evidence the rule may be a look-alike.
    detected_frameworks = (
        frozenset(frameworks) if repository_manifest_present(repository_root) else None
    )
    framework_tuple = tuple(sorted(frameworks)) if detected_frameworks is not None else None
    normalized_excludes = normalize_exclude_patterns(exclude_patterns)
    baseline_exclusions = excluded_paths or frozenset()
    task_candidates: list[tuple[str, str, int, tuple[str, ...] | None]] = []
    skill_roots = discover_skill_roots(repository_root, normalized_excludes)
    git_index_unavailable = False
    tracked_paths: frozenset[str] | None = frozenset()
    # A nested scan root may not contain its worktree's .git marker. In that
    # case there is no safe index to consult and the historical pruning remains
    # the only bounded option. For a real worktree, inability to read the
    # index is itself incomplete evidence rather than a reason to claim green.
    if (repository_root / ".git").exists() and _has_prunable_tree(repository_root):
        try:
            tracked_paths = _tracked_paths_for_scan(repository_root)
        except ValueError:
            tracked_paths = None
            git_index_unavailable = True
    coverage = {
        "unreadable": 0,
        "parser_limit": 0,
        "line_limit": 0,
        "oversized": 0,
        "containers": 0,
        "assets": 0,
        "binary": 0,
        "symlinks": 0,
        "excluded": 0,
        "databases": 0,
        "baseline_excluded": 0,
    }
    files_scanned = 0
    pending_containers: list[tuple[Path, str]] = []
    for path, relative_path, skip_reason in iter_scannable_files(
        repository_root,
        max_file_bytes,
        normalized_excludes,
        include_paths,
        tracked_paths,
    ):
        if skip_reason == "walk_error":
            coverage["unreadable"] += 1
            continue
        if not _coverage_path_selected(
            relative_path, include_paths, directory=skip_reason == "symlink"
        ):
            continue
        if relative_path in baseline_exclusions:
            coverage["baseline_excluded"] += 1
            continue
        if skip_reason is None:
            if path.suffix.lower() in DATABASE_SUFFIXES:
                coverage["databases"] += 1
            task_candidates.append((str(path), relative_path, max_file_bytes, framework_tuple))
        elif skip_reason == "excluded":
            coverage["excluded"] += 1
        elif skip_reason == "container":
            pending_containers.append((path, relative_path))
        elif skip_reason == "asset":
            coverage["assets"] += 1
        elif skip_reason == "binary":
            coverage["binary"] += 1
        elif skip_reason == "symlink":
            coverage["symlinks"] += 1
        elif skip_reason == "size":
            coverage["oversized"] += 1
        elif skip_reason == "unreadable":
            coverage["unreadable"] += 1

    tasks = [(*task, is_within_skill_root(task[1], skill_roots)) for task in task_candidates]
    scanned_paths: set[str] = set()
    discovered_coverage = coverage.copy()

    def record_result(task, outcome):
        nonlocal files_scanned
        file_findings, omission = outcome
        if omission is not None:
            coverage[omission] += 1
        else:
            files_scanned += 1
            scanned_paths.add(task[1])
            findings.extend(file_findings)

    if jobs > 1 and len(tasks) >= PARALLEL_MIN_FILES:
        # Parallel scanning keeps byte-identical output: tasks run in walk
        # order, each file's findings stay grouped, and dedup/sort run in the
        # parent exactly as in the sequential path.
        from concurrent.futures import ProcessPoolExecutor

        worker_jobs = min(jobs, MAX_SCAN_JOBS, len(tasks))
        try:
            with ProcessPoolExecutor(
                max_workers=worker_jobs, initializer=_worker_initializer
            ) as executor:
                for task, outcome in zip(
                    tasks, executor.map(_scan_file_task, tasks, chunksize=4), strict=True
                ):
                    record_result(task, outcome)
        except (OSError, ImportError, RuntimeError) as exc:
            # RuntimeError covers BrokenProcessPool: when this module was
            # imported under a non-canonical name (embedding tools, notebooks),
            # workers cannot unpickle task functions. Output stays correct via
            # the sequential path.
            print(
                f"shipproof: parallel scan unavailable ({type(exc).__name__}: {exc}); "
                "continuing sequentially",
                file=sys.stderr,
            )
            # Preserve the same total cap after a worker-pool fallback. A
            # plain list here would re-open the OOM path the bound is meant to
            # close when many files each approach the per-file limit.
            findings = BoundedFindings(MAX_FINDINGS_TOTAL)
            files_scanned = 0
            scanned_paths.clear()
            coverage = discovered_coverage.copy()
            for task in tasks:
                record_result(task, _scan_file_task(task))
    else:
        for task in tasks:
            record_result(task, _scan_file_task(task))

    remaining_containers: list[tuple[Path, str]] = []
    for path, relative_path in pending_containers:
        if (
            not inspect_archives
            or path.suffix.lower() not in archive_inspect.ZIP_INSPECTABLE_SUFFIXES
        ):
            remaining_containers.append((path, relative_path))
            continue
        inspection = archive_inspect.inspect_zip_archive(
            path, relative_path, text_suffixes=TEXT_SUFFIXES
        )
        member_omission = False
        for member in inspection.members:
            try:
                extra = lint_source_snippet(member.source_text, member.virtual_path)
            except ScanCoverageError as exc:
                coverage[exc.reason] = coverage.get(exc.reason, 0) + 1
                member_omission = True
                continue
            findings.extend(extra)
            files_scanned += 1
            scanned_paths.add(member.virtual_path)
        if not inspection.complete or member_omission:
            remaining_containers.append((path, relative_path))
    coverage["containers"] += len(remaining_containers)

    environment_paths = {path for path in scanned_paths if _is_sensitive_env_path(path)}
    if environment_paths:
        try:
            status, index_output, _ = _run_git_bounded(
                repository_root,
                ["ls-files", "--cached", "-z", "--"],
                timeout_seconds=10,
                max_output_bytes=2_000_000,
            )
            if status != 0:
                git_index_unavailable = True
            else:
                findings.extend(
                    find_tracked_env_issues(environment_paths, set(index_output.split("\0")))
                )
        except ValueError:
            git_index_unavailable = True

    if cross_file:
        try:
            cross_findings, flow_count, unsanitized_count = collect_cross_file_taint(
                repository_root,
                allowed_paths=frozenset(scanned_paths),
                max_file_bytes=max_file_bytes,
            )
        except (OSError, ValueError, RecursionError, MemoryError) as exc:
            raise ValueError(f"cross-file analysis failed: {exc}") from exc
        findings.extend(cross_findings)

    active, suppressed = deduplicate_and_suppress_findings(findings, baseline)
    profile = (
        scan_profile
        if scan_profile in {"application", "library"}
        else (precision_policy.detect_scan_profile(scanned_paths, active))
    )
    active = precision_policy.apply_library_mode(active, profile, SECRET_RULE_IDS)
    # Omitted or uninspected content must remain visible in the evidence
    # ledger. Parser failures are especially important: syntax-invalid or
    # pathological Python can otherwise hide every AST finding.
    reasons = [
        name
        for name, counter in (
            ("unreadable", coverage["unreadable"]),
            ("parser_limit", coverage["parser_limit"]),
            ("line_limit", coverage["line_limit"]),
            ("oversized", coverage["oversized"]),
            ("containers", coverage["containers"]),
            ("symlinks", coverage["symlinks"]),
            ("binary", coverage["binary"]),
        )
        if counter
    ]
    if git_index_unavailable:
        reasons.append("git_index_unavailable")
    completeness = {
        "is_complete": not reasons,
        "reasons": reasons,
        **coverage,
    }
    stats = {
        "files_scanned": files_scanned,
        "suppressed": len(suppressed),
        "completeness": completeness,
        "scan_profile": profile,
        "_suppressed": suppressed,
    }
    if cross_file:
        stats["cross_file_flows"] = flow_count
        stats["cross_file_flows_unsanitized"] = unsanitized_count
    if frameworks:
        stats["frameworks"] = sorted(frameworks)
    return active, stats


def determine_verdict(
    findings: Sequence[Finding],
    include_tests: bool = False,
    completeness: dict[str, object] | None = None,
    *,
    block_min_proof: str = "L1",
) -> str:
    evaluated = findings if include_tests else [item for item in findings if item.scope == "app"]
    reportable = [item for item in evaluated if not precision_policy.is_advisory(item)]
    gate_items = [
        item
        for item in reportable
        if precision_policy.is_gate_finding(
            item, block_min_proof=block_min_proof, secret_rule_ids=SECRET_RULE_IDS
        )
    ]
    gate_severities = {item.severity for item in gate_items}
    reportable_severities = {item.severity for item in reportable}
    if gate_severities & {"critical", "high"}:
        return "BLOCK"
    if reportable_severities & {"critical", "high"}:
        return "REVIEW"
    if reportable_severities & {"medium", "low"}:
        return "CONDITIONAL"
    if completeness is not None and not completeness.get("is_complete", True):
        # Omitted content must never be reported as a complete pass.
        return "CONDITIONAL"
    return "PASS_WITH_EVIDENCE"


def gate_failed(
    findings: Sequence[Finding],
    fail_on: str,
    include_tests: bool = False,
    *,
    completeness: object = None,
    fail_on_incomplete: bool = False,
    block_min_proof: str = "L1",
) -> bool:
    """Evaluate the documented severity gate for a set of findings."""
    if (
        fail_on_incomplete
        and isinstance(completeness, dict)
        and not completeness.get("is_complete", True)
    ):
        return True
    if fail_on == "none":
        return False
    evaluated = findings if include_tests else [item for item in findings if item.scope == "app"]
    return any(
        SEVERITY[item.severity] <= SEVERITY[fail_on]
        and precision_policy.is_gate_finding(
            item, block_min_proof=block_min_proof, secret_rule_ids=SECRET_RULE_IDS
        )
        for item in evaluated
    )


def build_decision_trace(
    findings: Sequence[Finding],
    stats: dict[str, object],
    *,
    fail_on: str,
    include_tests: bool,
    max_file_bytes: int,
    min_confidence: str | None,
    exclude_patterns: Sequence[str],
    baseline_fingerprints: int,
    changed_candidates: int | None,
    findings_before_confidence_filter: int,
    fail_on_incomplete: bool = False,
    block_min_proof: str = "L1",
) -> dict[str, object]:
    """Explain a gate decision with bounded, content-free, deterministic counts."""
    evaluated = (
        list(findings) if include_tests else [item for item in findings if item.scope == "app"]
    )
    blocking = (
        0
        if fail_on == "none"
        else sum(
            SEVERITY[item.severity] <= SEVERITY[fail_on]
            and precision_policy.is_gate_finding(
                item, block_min_proof=block_min_proof, secret_rule_ids=SECRET_RULE_IDS
            )
            for item in evaluated
        )
    )
    selection: dict[str, object] = {
        "mode": "changed" if changed_candidates is not None else "repository",
        "files_scanned": int(stats["files_scanned"]),
        "max_file_bytes": max_file_bytes,
        "exclude_patterns": len(tuple(dict.fromkeys(exclude_patterns))),
        "baseline_fingerprints": baseline_fingerprints,
        "minimum_confidence": min_confidence,
    }
    if changed_candidates is not None:
        selection["changed_candidates"] = changed_candidates
    result = {
        "rule_selection": {
            "catalog_rules": len(RULES),
            "detected_frameworks": list(stats.get("frameworks", [])),
        },
        "selection": selection,
        "finding_flow": {
            "before_confidence_filter": findings_before_confidence_filter,
            "active": len(findings),
            "suppressed_by_baseline": int(stats["suppressed"]),
            "evaluated_by_gate": len(evaluated),
            "blocking": blocking,
        },
        "gate": {
            "threshold": fail_on,
            "include_tests": include_tests,
            "failed": gate_failed(
                findings,
                fail_on,
                include_tests,
                completeness=stats.get("completeness"),
                fail_on_incomplete=fail_on_incomplete,
                block_min_proof=block_min_proof,
            ),
            "verdict": determine_verdict(
                findings,
                include_tests,
                stats.get("completeness"),
                block_min_proof=block_min_proof,
            ),
            "block_min_proof": block_min_proof,
        },
    }
    profile = stats.get("scan_profile")
    if profile in {"application", "library"}:
        result["gate"]["scan_profile"] = profile
    return result


MAX_HISTORY_OUTPUT_BYTES = 16_000_000
MAX_HISTORY_FINDINGS = 5_000


def _run_git_bounded(
    root: Path,
    arguments: Sequence[str],
    *,
    timeout_seconds: int = 120,
    max_output_bytes: int = MAX_HISTORY_OUTPUT_BYTES,
) -> tuple[int, str, str]:
    """Run trusted Git with bounded stdout+stderr and no project code execution."""
    git_binary = _trusted_git_binary(root)
    repository_root = root.resolve()

    environment = os.environ.copy()
    # Caller/project Git overrides must not redirect evidence to a different
    # repository/index or inject config that executes a filesystem monitor.
    for name in tuple(environment):
        if name in {
            "GIT_DIR",
            "GIT_COMMON_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
        } or name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            environment.pop(name)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        process = subprocess.Popen(  # noqa: S603
            [
                str(git_binary),
                "--no-pager",
                "-c",
                "core.quotePath=false",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(repository_root),
                *arguments,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=environment,
        )
    except OSError as exc:
        raise ValueError(f"git-history evidence is unavailable: {exc}") from exc

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    total_bytes = [0]
    lock = threading.Lock()
    exceeded = threading.Event()

    def drain(name: str, stream: object) -> None:
        read = stream.read
        while True:
            chunk = read(65_536)
            if not chunk:
                return
            with lock:
                total_bytes[0] += len(chunk)
                if total_bytes[0] > max_output_bytes:
                    exceeded.set()
                    process.kill()
                    return
                buffers[name].extend(chunk)

    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise ValueError(
            f"git-history evidence exceeded the {timeout_seconds}-second timeout"
        ) from exc
    finally:
        for thread in threads:
            thread.join(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    if exceeded.is_set():
        raise ValueError(f"git-history evidence exceeded the {max_output_bytes}-byte output limit")
    return (
        process.returncode,
        buffers["stdout"].decode("utf-8", "replace"),
        buffers["stderr"].decode("utf-8", "replace"),
    )


def _is_sensitive_env_path(relative_path: str) -> bool:
    return (
        re.fullmatch(
            r"\.env(?:\.(?:local|production|secret|staging))?",
            Path(relative_path).name,
            re.IGNORECASE,
        )
        is not None
    )


def find_tracked_env_issues(selected_paths: set[str], tracked_paths: set[str]) -> list[Finding]:
    """Filename risk backed by Git-index membership, never text mentioning .env."""
    return [
        make_finding(
            find_rule("SP220"),
            relative_path,
            1,
            "Git index contains a sensitive environment filename; contents are not verified.",
            "artifact",
        )
        for relative_path in sorted(selected_paths & tracked_paths)
        if _is_sensitive_env_path(relative_path)
    ]


def _scan_history_secrets(root: Path, max_commits: int = 500) -> tuple[list[Finding], int]:
    """Scan bounded Git patches for secrets introduced on added lines."""
    if max_commits < 1 or max_commits > 500:
        raise ValueError("history max_commits must be from 1 through 500")
    probe_status, probe_stdout, probe_stderr = _run_git_bounded(
        root,
        ["rev-parse", "--is-inside-work-tree"],
        timeout_seconds=10,
        max_output_bytes=65_536,
    )
    if probe_status != 0 or probe_stdout.strip() != "true":
        detail = probe_stderr.strip().splitlines()[:1]
        suffix = f": {detail[0]}" if detail else ""
        raise ValueError(f"git-history evidence requires a Git worktree{suffix}")

    status, raw_output, stderr = _run_git_bounded(
        root,
        [
            "log",
            "--all",
            "--patch",
            "--no-color",
            "--no-renames",
            "--no-textconv",
            "--no-ext-diff",
            "--unified=0",
            f"--max-count={max_commits}",
            "--format=%x00%H",
        ],
    )
    if status != 0:
        detail = stderr.strip().splitlines()[:1]
        suffix = f": {detail[0]}" if detail else ""
        raise ValueError(f"git-history evidence failed{suffix}")

    findings: list[Finding] = []
    commits_scanned = 0
    hunk_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    for commit_block in raw_output.split("\x00"):
        if not commit_block.strip():
            continue
        lines = commit_block.splitlines()
        sha = lines[0].strip()
        if re.fullmatch(r"[0-9a-f]{40,64}", sha) is None:
            continue
        commits_scanned += 1
        current_file = ""
        current_line: int | None = None
        env_paths_reported: set[str] = set()
        for diff_line in lines[1:]:
            if diff_line.startswith("diff --git "):
                current_file = ""
                current_line = None
                continue
            if diff_line.startswith("+++ b/"):
                current_file = diff_line[6:]
                current_line = None
                if current_file not in env_paths_reported and _is_sensitive_env_path(current_file):
                    env_paths_reported.add(current_file)
                    findings.append(
                        make_finding(
                            find_rule("SP220"),
                            current_file,
                            1,
                            current_file,
                            detection="history",
                            history_commit=sha,
                        )
                    )
                continue
            hunk_match = hunk_pattern.match(diff_line)
            if hunk_match:
                current_line = int(hunk_match.group(1))
                continue
            if not current_file or current_line is None:
                continue
            if diff_line.startswith("+") and not diff_line.startswith("+++"):
                added_line = diff_line[1:]
                line_findings = find_regex_issues(
                    Path(current_file),
                    current_file,
                    added_line,
                    [added_line],
                )
                for candidate in line_findings:
                    rule = RULE_INDEX[candidate.rule_id]
                    if not rule.redact or rule.rule_id == "SP220":
                        continue
                    findings.append(
                        make_finding(
                            rule,
                            current_file,
                            current_line,
                            added_line,
                            detection="history",
                            confidence=candidate.confidence,
                            column=candidate.column,
                            end_column=candidate.end_column,
                            history_commit=sha,
                        )
                    )
                    if len(findings) > MAX_HISTORY_FINDINGS:
                        raise ValueError(
                            f"git-history evidence exceeded {MAX_HISTORY_FINDINGS} findings"
                        )
                current_line += 1
            elif diff_line.startswith("-") and not diff_line.startswith("---"):
                continue
            else:
                current_line += 1
    return findings, commits_scanned


def build_json_report(
    root: Path,
    findings: Sequence[Finding],
    stats: dict[str, object],
    include_tests: bool = False,
    decision_trace: dict[str, object] | None = None,
    *,
    block_min_proof: str = "L1",
) -> dict[str, object]:
    if len(findings) > MAX_FINDINGS_TOTAL:
        raise FindingLimitError(f"finding output exceeded the total limit of {MAX_FINDINGS_TOTAL}")
    # Keys prefixed with "_" are internal transports (e.g. the suppressed
    # finding list) and must never leak into the public summary.
    public_stats = {key: value for key, value in stats.items() if not key.startswith("_")}
    completeness = public_stats.get("completeness")
    app_findings = [f for f in findings if f.scope == "app"]
    test_findings = [f for f in findings if f.scope == "test"]
    limitations = [
        "Fast heuristic scan; confirm every finding.",
        "No runtime reachability or general dependency CVE feed; dated version advisories do not verify deployed vendor patches.",
    ]
    if isinstance(completeness, dict) and not completeness.get("is_complete", True):
        reasons = ", ".join(str(reason) for reason in completeness.get("reasons", []))
        limitations.append(
            f"Scan coverage is incomplete ({reasons}); a zero-finding result is not a complete pass."
        )
    if "history_commits_scanned" in stats:
        limitations.append(
            "Git-history evidence covers bounded added patch lines; rotate confirmed credentials."
        )
    else:
        limitations.append("No git-history scan was requested.")
    report: dict[str, object] = {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "version": VERSION, "command": "scan"},
        "root": str(root.resolve()),
        "verdict": determine_verdict(
            findings,
            include_tests,
            completeness if isinstance(completeness, dict) else None,
            block_min_proof=block_min_proof,
        ),
        "summary": {
            "findings": len(findings),
            "app_findings": len(app_findings),
            "test_findings": len(test_findings),
            **public_stats,
            "by_severity": dict(Counter(item.severity for item in findings)),
        },
        "findings": [_finding_payload(item) for item in findings],
        "limitations": limitations,
    }
    if decision_trace is not None:
        report["decision_trace"] = decision_trace
    return report


def render_decision_trace(decision_trace: dict[str, object], *, markdown: bool) -> list[str]:
    rule_selection = decision_trace["rule_selection"]
    selection = decision_trace["selection"]
    finding_flow = decision_trace["finding_flow"]
    gate = decision_trace["gate"]
    confidence = selection["minimum_confidence"] or "all"
    changed = (
        f"; {selection['changed_candidates']} changed candidates"
        if "changed_candidates" in selection
        else ""
    )
    values = [
        f"Scope: {selection['mode']}{changed}; {selection['files_scanned']} files scanned",
        f"Rules: {rule_selection['catalog_rules']} catalog rules; {len(rule_selection['detected_frameworks'])} detected frameworks",
        f"Filters: confidence={confidence}; {selection['exclude_patterns']} excludes; {selection['baseline_fingerprints']} baseline fingerprints",
        f"Findings: {finding_flow['before_confidence_filter']} before confidence filter; {finding_flow['active']} active; {finding_flow['suppressed_by_baseline']} suppressed",
        f"Gate: threshold={gate['threshold']}; {finding_flow['evaluated_by_gate']} evaluated; {finding_flow['blocking']} blocking; failed={str(gate['failed']).lower()}",
    ]
    if markdown:
        return ["## Decision trace", "", *[f"- {value}" for value in values], ""]
    return ["  Decision trace:", *[f"    {value}" for value in values], ""]


def render_suppressed_section(
    suppressed: Sequence[tuple[Finding, str]], *, markdown: bool
) -> list[str]:
    """Auditable listing of suppressed findings with their baseline reasons."""
    if not suppressed:
        return []
    lines = (
        ["## Suppressed findings", ""] if markdown else ["  Suppressed findings (baseline):", ""]
    )
    for item, reason in suppressed[:200]:
        safe_path = terminal_safe_text(item.path).replace("`", "\\`")
        location = f"`{safe_path}:{item.line}`" if markdown else f"{safe_path}:{item.line}"
        shown_reason = terminal_safe_text(reason or "(no reason recorded)")
        if markdown:
            lines.append(f"- {item.severity.upper()} {item.rule_id} at {location} — {shown_reason}")
        else:
            lines.append(f"  - {item.severity.upper()} {item.rule_id} at {location}")
            lines.append(f"    reason: {shown_reason}")
    if len(suppressed) > 200:
        lines.append(
            f"- …and {len(suppressed) - 200} more suppressed findings."
            if markdown
            else f"  - …and {len(suppressed) - 200} more."
        )
    lines.append("")
    return lines


def render_markdown_report(
    root: Path,
    findings: Sequence[Finding],
    stats: dict[str, object],
    suppressed: Sequence[tuple[Finding, str]] = (),
    decision_trace: dict[str, object] | None = None,
    *,
    include_tests: bool = False,
    block_min_proof: str = "L1",
) -> str:
    completeness = stats.get("completeness")
    counts = Counter(item.severity for item in findings)
    display, collapsed_notes = precision_policy.collapse_for_display(findings)
    lines = [
        "# ShipProof report",
        "",
        f"**Verdict:** {determine_verdict(findings, include_tests=include_tests, completeness=completeness if isinstance(completeness, dict) else None, block_min_proof=block_min_proof)}",
        "",
        f"Scanned `{stats['files_scanned']}` files; found `{len(findings)}` active issues; suppressed `{stats['suppressed']}`.",
        "",
    ]
    if isinstance(completeness, dict) and not completeness.get("is_complete", True):
        reasons = ", ".join(str(reason) for reason in completeness.get("reasons", []))
        lines.extend(
            [
                f"**Coverage:** incomplete ({reasons}); a zero-finding result is not a complete pass.",
                "",
            ]
        )
    lines.extend(
        [
            "| Critical | High | Medium | Low |",
            "| ---: | ---: | ---: | ---: |",
            f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |",
            "",
        ]
    )
    for item in display:
        safe_path = terminal_safe_text(item.path).replace("`", "\\`")
        lines.extend(
            [
                f"## {item.severity.upper()} · {terminal_safe_text(item.rule_id)} · {terminal_safe_text(item.title)}",
                "",
                f"`{safe_path}:{item.line}` · confidence: `{terminal_safe_text(item.confidence)}` · scope: `{terminal_safe_text(item.scope)}` · {terminal_safe_text(item.category)}",
                "",
                f"> {terminal_safe_text(item.evidence)}",
                "",
                terminal_safe_text(item.message),
                "",
                f"**Fix:** {terminal_safe_text(item.remediation)}",
                "",
                f"Mapping: `{terminal_safe_text(item.cwe)}` · `{terminal_safe_text(item.owasp)}` · fingerprint `{terminal_safe_text(item.fingerprint)}`",
                "",
            ]
        )
    if collapsed_notes:
        lines.extend(["## Collapsed findings", "", *[f"- {note}" for note in collapsed_notes], ""])
    lines.extend(render_suppressed_section(suppressed, markdown=True))
    if decision_trace is not None:
        lines.extend(render_decision_trace(decision_trace, markdown=True))
    lines.extend(
        [
            "## Limitations",
            "",
            "This is a fast heuristic scan. Confirm every finding with complete data-flow and runtime context; use dedicated SAST, secret-history, dependency, IaC, and load-testing tools for release evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def read_source_context(
    root: Path,
    relative_path: str,
    target_line: int,
    context: int = 2,
) -> list[tuple[int, str]]:
    """Read surrounding lines from source for terminal display."""
    try:
        source_path = root / relative_path
        text = read_scannable_bytes(source_path, MAX_SNIPPET_BYTES).decode(
            "utf-8", errors="replace"
        )
        source_lines = text.splitlines()
        start = max(0, target_line - 1 - context)
        end = min(len(source_lines), target_line + context)
        return [(i + 1, terminal_safe_text(source_lines[i])) for i in range(start, end)]
    except (OSError, ScanCoverageError, UnicodeError):
        return []


def read_finding_context(
    root: Path,
    finding: Finding,
    context: int = 2,
) -> list[tuple[int, str]]:
    """Return context without re-reading credential material hidden by a finding."""
    if (
        finding.rule_id in SECRET_RULE_IDS
        or finding.rule_id in MINIMIZED_EVIDENCE_RULE_IDS
        or (finding.rule_id == "SP104" and finding.tier == "advisory")
        or (finding.rule_id in {"SP056", "SP084"} and finding.tier == "advisory")
    ):
        return [(finding.line, terminal_safe_text(finding.evidence))]
    return read_source_context(root, finding.path, finding.line, context=context)


def render_terminal_report(
    root: Path,
    findings: Sequence[Finding],
    stats: dict[str, object],
    decision_trace: dict[str, object] | None = None,
    suppressed: Sequence[tuple[Finding, str]] = (),
    *,
    include_tests: bool = False,
    block_min_proof: str = "L1",
) -> str:
    """Render a code-review style terminal report with emoji, context, and evidence."""
    completeness = stats.get("completeness")
    verdict = determine_verdict(
        findings,
        include_tests=include_tests,
        completeness=completeness if isinstance(completeness, dict) else None,
        block_min_proof=block_min_proof,
    )
    counts = Counter(item.severity for item in findings)
    lines: list[str] = []

    # Header
    icon = (
        "\u2705"
        if verdict == "PASS_WITH_EVIDENCE"
        else "\u26a0"
        if verdict == "REVIEW"
        else "\u274c"
    )
    lines.append(f"\n  {icon} ShipProof: {verdict}")
    lines.append(
        f"  Scanned {stats['files_scanned']} files \u2022 {len(findings)} findings \u2022 {stats['suppressed']} suppressed"
    )
    if isinstance(completeness, dict) and not completeness.get("is_complete", True):
        reasons = ", ".join(str(reason) for reason in completeness.get("reasons", []))
        lines.append(
            f"  \u26a0 Coverage incomplete ({reasons}); zero findings is not a complete pass."
        )
    if counts:
        parts = []
        for sev in ("critical", "high", "medium", "low"):
            if counts.get(sev, 0) > 0:
                parts.append(f"{SEVERITY_ICON.get(sev, '')} {counts[sev]} {sev}")
        bullet = " \u2022 "
        lines.append(f"  {bullet.join(parts)}")
    lines.append("")

    display, collapsed_notes = precision_policy.collapse_for_display(findings)
    # Findings
    for item in display:
        icon = SEVERITY_ICON.get(item.severity, "")
        safe_title = terminal_safe_text(item.title)
        safe_rule_id = terminal_safe_text(item.rule_id)
        safe_path = terminal_safe_text(item.path)
        safe_confidence = terminal_safe_text(item.confidence)
        safe_scope = terminal_safe_text(item.scope)
        conf_label = terminal_safe_text(CONFIDENCE_LABEL.get(item.confidence, safe_confidence))
        scope_suffix = f" \u2022 scope: {safe_scope}" if item.scope != "app" else ""
        lines.append(f"  {icon} {item.severity.upper()} \u2014 {safe_title} ({safe_rule_id})")
        lines.append(
            f"     {safe_path}:{item.line}  \u2022  confidence: {conf_label}{scope_suffix}"
        )
        lines.append("")

        # Source context
        context_lines = read_finding_context(root, item)
        if context_lines:
            lines.append("     Evidence:")
            for line_num, line_text in context_lines:
                marker = " >" if line_num == item.line else "  "
                lines.append(f"     {line_num:4d}{marker} {line_text}")
            lines.append("")

        # Why + Fix
        lines.append(f"     Why: {terminal_safe_text(item.message)}")
        lines.append(f"     Fix: {terminal_safe_text(item.remediation)}")
        lines.append(
            f"     Ref: {terminal_safe_text(item.cwe)} \u2022 {terminal_safe_text(item.owasp)}"
        )
        lines.append("")
        lines.append("  " + "\u2500" * 70)
        lines.append("")

    for note in collapsed_notes:
        lines.append(f"  {note}")
        lines.append("")

    if findings:
        lines.append(
            "  \u2192 Run `shipproof scan --fix-prompt` to generate AI-ready fix instructions"
        )
        lines.append("  \u2192 Run `shipproof scan --format json` for machine-readable output")
        lines.append("")

    lines.extend(render_suppressed_section(suppressed, markdown=False))

    if decision_trace is not None:
        lines.extend(render_decision_trace(decision_trace, markdown=False))

    return "\n".join(lines)


def render_github_annotations(findings: Sequence[Finding]) -> str:
    """Render GitHub Actions workflow annotations for inline PR notices."""
    lines: list[str] = []
    for item in findings:
        level = "error" if item.severity in ("critical", "high") else "warning"
        safe_path = terminal_safe_text(item.path).replace("%", "%25").replace(",", "%2C")
        position = f"file={safe_path},line={item.line}"
        title = (
            terminal_safe_text(f"{item.rule_id} {item.title}")
            .replace("%", "%25")
            .replace(",", "%2C")
        )
        column_suffix = f",col={item.column}" if item.column is not None else ""
        message = (
            terminal_safe_text(f"{item.message} Fix: {item.remediation}")
            .replace("%", "%25")
            .replace("\r", " ")
            .replace("\n", " ")
            .replace("::", "")
        )
        lines.append(f"::{level} {position},title={title}{column_suffix}::{message}")
    return "\n".join(lines)


def get_engineering_contract(rule_id: str, category: str, message: str) -> dict[str, list[str]]:
    """Derive dynamic SWE reasoning dimensions, implicit requirements, and failure scenarios."""
    explanation = RULE_EXPLANATIONS.get(rule_id, {})

    # 1. Engineering Dimensions
    if (
        rule_id in {"SP304", "SP318", "SP306", "SP315"}
        or "timeout" in message.lower()
        or "retry" in message.lower()
    ):
        dimensions = [
            "Timeout Budgets & Deadline Propagation",
            "Retry Amplification & Cascading Failures",
            "Circuit Breakers & Graceful Fallbacks",
            "Observable Error Classification",
        ]
    elif (
        rule_id in {"SP103", "SP301", "SP305"}
        or "sql" in message.lower()
        or "query" in message.lower()
        or "page" in message.lower()
    ):
        dimensions = [
            "Transaction Isolation & Partial Failure Recovery",
            "Lost Updates & Row-Level Concurrency",
            "Bounded Result Sets & Query Pagination",
            "Index Traversal & Connection Pool Hygiene",
        ]
    elif (
        rule_id in {"SP108", "SP109", "SP201", "SP203"}
        or "auth" in message.lower()
        or "permission" in message.lower()
    ):
        dimensions = [
            "Object-Level Authorization & IDOR Protection",
            "Tenant Boundary Isolation",
            "Least Privilege & Default-Deny Policy",
            "Token Lifecycle & Invalidation",
        ]
    elif (
        rule_id in {"SP312", "SP313", "SP308"}
        or "cache" in message.lower()
        or "memory" in message.lower()
        or "queue" in message.lower()
    ):
        dimensions = [
            "Cache Invalidation & Stampede Mitigation",
            "Bounded In-Memory Structures & Eviction",
            "Backpressure & Poison-Message Handling",
        ]
    elif rule_id in SECRET_RULE_IDS or "secret" in message.lower() or "key" in message.lower():
        dimensions = [
            "Secret Non-Persistence & Environment Injection",
            "Credential Rotation & Zero-Downtime Rollover",
            "Audit Trail & Least-Privilege IAM Scope",
        ]
    else:
        dimensions = [
            "API Contract & Backward Compatibility",
            "Defensive Input Sanitization & Type Boundaries",
            "Deterministic State Transitions",
        ]

    # 2. Implicit Requirements
    if rule_id in {"SP304", "SP318"}:
        implicit_reqs = [
            "Preserve existing caller exception hierarchy; map timeout errors to domain errors.",
            "Ensure total latency (timeout * max_retries) strictly conforms to service SLO budget.",
            "Do not block async event loop or caller thread during connection negotiation.",
        ]
    elif rule_id in {"SP301", "SP305"}:
        implicit_reqs = [
            "Enforce strict upper bound on limit/page_size even if client supplies larger value.",
            "Handle offset beyond total row count gracefully with empty list (HTTP 200).",
            "Ensure queries use index-backed sort keys to prevent full table scans.",
        ]
    elif rule_id in {"SP108", "SP109"}:
        implicit_reqs = [
            "Enforce authorization before executing any business logic or state modification.",
            "Return 403 Forbidden for authenticated non-authorized users, 401 for unauthenticated.",
            "Preserve legitimate user access paths while closing escalation routes.",
        ]
    elif rule_id in {"SP103"}:
        implicit_reqs = [
            "Use parameterized SQL bindings; never concatenate untrusted inputs.",
            "Verify all dynamic identifiers (e.g. column names) are checked against a strict allowlist.",
        ]
    else:
        implicit_reqs = [
            "Preserve public API contract and response payload schema.",
            "Ensure failure states return appropriate error codes rather than unhandled crashes.",
        ]

    # 3. Failure Scenarios (Counterfactuals)
    failure_scenarios: list[str] = []
    if explanation.get("attack"):
        failure_scenarios.append(explanation["attack"])
    if rule_id in {"SP304", "SP318"}:
        failure_scenarios.extend(
            [
                "Upstream dependency accepts TCP connection but stalls indefinitely during body transfer.",
                "Simultaneous upstream latency spike causes all caller worker threads to hang, exhausting server threadpool.",
            ]
        )
    elif rule_id in {"SP301", "SP305"}:
        failure_scenarios.extend(
            [
                "Client requests page_size=1000000 causing database buffer pool thrashing and memory spike.",
                "Concurrent inserts cause pagination drift resulting in duplicate or skipped records.",
            ]
        )
    elif rule_id in {"SP108", "SP109"}:
        failure_scenarios.extend(
            [
                "Regular authenticated user submits payload to target endpoint and modifies elevated resource.",
                "Missing tenant scoping allows user in Organization A to access records belonging to Organization B.",
            ]
        )
    elif not failure_scenarios:
        failure_scenarios = [
            "Unexpected input type or null value causes unhandled runtime exception.",
            "Network partition or timeout during processing causes inconsistent state.",
        ]

    return {
        "engineering_dimensions": dimensions,
        "implicit_requirements": implicit_reqs,
        "failure_scenarios": failure_scenarios,
    }


def render_fix_prompts(
    root: Path,
    findings: Sequence[Finding],
    as_json: bool = False,
    context_level: str = "full",
) -> str:
    """Generate progressively disclosed AI-ready fix prompts."""
    if context_level not in CONTEXT_LEVELS:
        raise ValueError(f"context-level must be one of: {', '.join(CONTEXT_LEVELS)}")
    if not findings:
        if as_json:
            return json.dumps([], indent=2)
        return "No findings to fix.\n"

    if as_json:
        prompts: list[dict[str, object]] = []
        for item in findings:
            context_lines = read_finding_context(root, item)
            code_context = [
                {"line": num, "text": text, "is_target": num == item.line}
                for num, text in context_lines
            ]
            contract = get_engineering_contract(item.rule_id, item.category, item.message)
            core_prompt = (
                f"Fix {item.rule_id} in {item.path} (line {item.line}).\n\n"
                f"Problem:\n{item.message}\n\n"
                f"Required fix:\n{item.remediation}"
            )
            constraints = (
                "Constraints:\n"
                "- Do not change the public API contract\n"
                "- Add a regression test that verifies the fix\n"
                f"- Reference: {item.cwe}, {item.owasp}"
            )
            full_contract = (
                "Engineering Dimensions:\n"
                + "\n".join(f"- [x] {d}" for d in contract["engineering_dimensions"])
                + "\n\n"
                "Implicit Requirements:\n"
                + "\n".join(f"- {r}" for r in contract["implicit_requirements"])
                + "\n\n"
                "Failure Scenarios to Guard Against:\n"
                + "\n".join(f"- {s}" for s in contract["failure_scenarios"])
            )
            overview_contract = "Implicit Requirements:\n" + "\n".join(
                f"- {requirement}" for requirement in contract["implicit_requirements"]
            )
            prompt_sections = [core_prompt]
            if context_level == "overview":
                prompt_sections.append(overview_contract)
            elif context_level == "full":
                prompt_sections.append(full_contract)
            prompt_sections.append(constraints)
            prompt: dict[str, object] = {
                "context_level": context_level,
                "rule_id": item.rule_id,
                "title": item.title,
                "path": item.path,
                "line": item.line,
                "severity": item.severity,
                "confidence": item.confidence,
                "scope": item.scope,
                "problem": item.message,
                "remediation": item.remediation,
                "cwe": item.cwe,
                "owasp": item.owasp,
                "prompt": "\n\n".join(prompt_sections),
            }
            if context_level in {"overview", "full"}:
                prompt.update(
                    {
                        "evidence": item.evidence,
                        "context": code_context,
                        "implicit_requirements": contract["implicit_requirements"],
                    }
                )
            if context_level == "full":
                prompt.update(
                    {
                        "engineering_dimensions": contract["engineering_dimensions"],
                        "failure_scenarios": contract["failure_scenarios"],
                    }
                )
            prompts.append(prompt)
        return json.dumps(prompts, indent=2)

    lines: list[str] = [
        "# ShipProof Fix Prompts",
        "",
        "Copy any prompt below into your AI coding assistant (Codex, Claude Code, Cursor, etc.)",
        "",
    ]
    for i, item in enumerate(findings, 1):
        contract = get_engineering_contract(item.rule_id, item.category, item.message)
        lines.append(f"## [{i}] {item.rule_id}: {item.title}")
        lines.append("")
        lines.append("```")
        lines.append(f"Fix {item.rule_id} in {item.path} (line {item.line}).")
        lines.append("")
        lines.append(f"Problem: {item.message}")
        lines.append("")

        # Include source context
        context_lines = read_finding_context(root, item)
        if context_level in {"overview", "full"} and context_lines:
            lines.append("Current code:")
            for line_num, line_text in context_lines:
                marker = ">>>" if line_num == item.line else "   "
                lines.append(f"  {line_num}: {marker} {line_text}")
            lines.append("")

        lines.append(f"Required fix: {item.remediation}")
        lines.append("")
        if context_level == "full":
            lines.append("Engineering Dimensions:")
            for dim in contract["engineering_dimensions"]:
                lines.append(f"- [x] {dim}")
            lines.append("")
        if context_level in {"overview", "full"}:
            lines.append("Implicit Requirements:")
            for req in contract["implicit_requirements"]:
                lines.append(f"- {req}")
            lines.append("")
        if context_level == "full":
            lines.append("Failure Scenarios to Guard Against:")
            for scenario in contract["failure_scenarios"]:
                lines.append(f"- {scenario}")
            lines.append("")
        lines.append("Constraints:")
        lines.append("- Do not change the public API contract")
        lines.append("- Add a regression test that verifies the fix")
        lines.append(f"- Reference: {item.cwe}, {item.owasp}")
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def apply_autofix_to_line(rule_id: str, line: str) -> str | None:
    """Attempt deterministic remediation for a single line based on rule_id."""
    if rule_id == "SP104":
        v_false = "verify=" + "False"
        v_space_false = "verify = " + "False"
        if v_false in line:
            return line.replace(v_false, "verify=True")
        if v_space_false in line:
            return line.replace(v_space_false, "verify = True")
    elif rule_id == "SP201":
        dbg_true = "debug=" + "True"
        dbg_space_true = "debug = " + "True"
        dbg_upper_true = "DEBUG = " + "True"
        if dbg_true in line:
            return line.replace(dbg_true, "debug=False")
        if dbg_space_true in line:
            return line.replace(dbg_space_true, "debug = False")
        if dbg_upper_true in line:
            return line.replace(dbg_upper_true, "DEBUG = False")
    return None


def run_autofix(
    root: Path,
    findings: Sequence[Finding],
    dry_run: bool = False,
    max_file_bytes: int = 1_000_000,
) -> tuple[int, list[str]]:
    """Apply deterministic autofixes and verify them with a re-scan loop."""
    fixed_count = 0
    messages: list[str] = []
    files_to_fix: dict[str, list[Finding]] = {}
    for item in findings:
        files_to_fix.setdefault(item.path, []).append(item)

    modified_files: set[Path] = set()

    for rel_path, file_findings in files_to_fix.items():
        file_path = root / rel_path
        try:
            content = read_scannable_bytes(file_path, max_file_bytes).decode(
                "utf-8", errors="replace"
            )
            lines = content.splitlines()
            file_modified = False

            file_fixed_count = 0
            file_messages: list[str] = []
            for item in sorted(file_findings, key=lambda x: x.line, reverse=True):
                if 1 <= item.line <= len(lines):
                    orig_line = lines[item.line - 1]
                    fixed_line = apply_autofix_to_line(item.rule_id, orig_line)
                    if fixed_line is not None and fixed_line != orig_line:
                        lines[item.line - 1] = fixed_line
                        file_modified = True
                        file_fixed_count += 1
                        prefix = "DRY-RUN" if dry_run else "FIXED"
                        file_messages.append(
                            f"[{prefix}] {item.rule_id} at {item.path}:{item.line}\n"
                            f"  - {orig_line.strip()}\n"
                            f"  + {fixed_line.strip()}"
                        )

            if file_modified:
                if not dry_run:
                    new_content = "\n".join(lines) + ("\n" if content.endswith("\n") else "")
                    safe_write_text(file_path, new_content, label="autofix output")
                    modified_files.add(file_path)
                fixed_count += file_fixed_count
                messages.extend(file_messages)
        except (OSError, ValueError) as exc:
            messages.append(f"[ERROR] Failed to fix {rel_path}: {exc}")

    if modified_files and not dry_run:
        messages.append("\n-- Autofix Verification Loop --")
        for m_path in sorted(modified_files):
            rel_str = str(m_path.relative_to(root))
            m_text = read_scannable_bytes(m_path, max_file_bytes).decode("utf-8", errors="replace")
            re_findings = find_regex_issues(m_path, rel_str, m_text)
            if m_path.suffix.lower() == ".py":
                re_findings.extend(find_python_ast_issues(rel_str, m_text))
            active, _ = deduplicate_and_suppress_findings(re_findings)
            if not active:
                messages.append(f"  \u2705 {rel_str}: Verified (0 findings remain)")
            else:
                messages.append(
                    f"  \u26a0\ufe0f {rel_str}: {len(active)} findings remain after fix"
                )

    return fixed_count, messages


def render_explain(
    rule_id: str,
    as_json: bool = False,
    context_level: str = "full",
) -> str:
    """Render a progressively disclosed explanation for a single rule."""
    if context_level not in CONTEXT_LEVELS:
        raise ValueError(f"context-level must be one of: {', '.join(CONTEXT_LEVELS)}")
    rule = None
    for r in RULES:
        if r.rule_id == rule_id:
            rule = r
            break
    if rule is None:
        if as_json:
            return json.dumps(
                {
                    "context_level": context_level,
                    "error": f"Unknown rule: {rule_id}",
                    "valid_rules": [r.rule_id for r in RULES],
                },
                indent=2,
            )
        return f"Unknown rule: {rule_id}. Valid rules: {', '.join(r.rule_id for r in RULES)}\n"

    explanation = RULE_EXPLANATIONS.get(rule_id, {})
    conf_label = CONFIDENCE_LABEL.get(rule.confidence, rule.confidence)
    contract = get_engineering_contract(rule.rule_id, rule.category, rule.message)

    if as_json:
        details: dict[str, object] = {
            "context_level": context_level,
            "rule_id": rule.rule_id,
            "title": rule.title,
            "category": rule.category,
            "severity": rule.severity,
            "confidence": conf_label,
            "message": rule.message,
            "remediation": rule.remediation,
        }
        if context_level in {"overview", "full"}:
            details.update(
                {
                    "cwe": rule.cwe,
                    "owasp": rule.owasp,
                    "why": explanation.get("why", ""),
                    "false_positive": explanation.get("false_positive", ""),
                    "test": explanation.get("test", ""),
                }
            )
        if context_level == "full":
            details.update(
                {
                    "attack": explanation.get("attack", ""),
                    "engineering_dimensions": contract["engineering_dimensions"],
                    "implicit_requirements": contract["implicit_requirements"],
                    "failure_scenarios": contract["failure_scenarios"],
                }
            )
        return json.dumps(details, indent=2)

    lines = [
        "",
        f"  {SEVERITY_ICON.get(rule.severity, '')} {rule.rule_id}: {rule.title}",
        f"  Severity: {rule.severity.upper()} \u2022 Confidence: {conf_label} \u2022 Category: {rule.category}",
    ]
    if context_level in {"overview", "full"}:
        lines.extend([f"  {rule.cwe} \u2022 {rule.owasp}", ""])
    else:
        lines.append("")
    lines.extend(["  What it detects:", f"    {rule.message}", ""])
    if context_level in {"overview", "full"} and explanation.get("why"):
        lines.extend(["  Why this matters:", f"    {explanation['why']}", ""])
    if context_level == "full" and explanation.get("attack"):
        lines.extend(["  Attack scenario:", f"    {explanation['attack']}", ""])
    if context_level in {"overview", "full"} and explanation.get("false_positive"):
        lines.extend(
            ["  False-positive possibilities:", f"    {explanation['false_positive']}", ""]
        )
    lines.extend(["  Recommended fix:", f"    {rule.remediation}", ""])
    if context_level in {"overview", "full"} and explanation.get("test"):
        lines.extend(["  Regression test:", f"    {explanation['test']}", ""])
    if context_level == "full" and contract.get("engineering_dimensions"):
        lines.extend(
            ["  Engineering dimensions:"]
            + [f"    - {d}" for d in contract["engineering_dimensions"]]
            + [""]
        )
    if context_level == "full" and contract.get("implicit_requirements"):
        lines.extend(
            ["  Implicit requirements:"]
            + [f"    - {r}" for r in contract["implicit_requirements"]]
            + [""]
        )
    return "\n".join(lines)


# --- Mechanical fix scaffolds -------------------------------------------
# Curated, deterministic line transforms for rules whose safe correction is
# purely mechanical (flag flips). Every scaffold is a *suggestion requiring
# human review* — never applied automatically, and never generated for
# redacted secret rules where before/after text would leak credential
# material into reports.
_FIX_LINE_TRANSFORMS: dict[str, tuple[re.Pattern[str], object, str, str]] = {
    "SP102": (
        re.compile(r"(shell\s*[=:]\s*)(true|True|1)(?![\w])"),
        lambda m: (
            m.group(1)
            + ("0" if m.group(2) == "1" else ("False" if m.group(2)[0].isupper() else "false"))
        ),
        "Disable shell interpretation so metacharacters cannot chain commands.",
        "Confirm no argument depends on shell syntax (pipes, globs, $VAR); prefer argument arrays.",
    ),
    "SP104": (
        re.compile(r"((?:verify|rejectUnauthorized)\s*[:=]\s*)(false|False)"),
        lambda m: m.group(1) + ("True" if m.group(2)[0].isupper() else "true"),
        "Restore TLS peer verification.",
        "Ensure the runtime trusts the correct CA bundle; pin certificates for fixed internal endpoints.",
    ),
    "SP201": (
        re.compile(r"(debug\s*[:=]\s*)(true|True|1)(?![\w])"),
        lambda m: m.group(1) + ("0" if m.group(2) == "1" else "False"),
        "Turn off debug mode in application code.",
        "Drive debug from environment configuration instead of a constant.",
    ),
    "SP133": (
        re.compile(r'(debug\s*=\s*)("true")'),
        lambda m: m.group(1) + '"false"',
        "Disable ASP.NET debug compilation in deployed configuration.",
        "Keep retail/debug overrides per-environment rather than committed literals.",
    ),
}


def build_fix_scaffold(finding: Finding) -> dict[str, str] | None:
    """Return a review-required mechanical fix suggestion, or None.

    Scaffolds exist only for curated flag-flip rules; the transform runs on
    the finding's evidence line and must change it to produce a scaffold.
    Redacted rules never scaffold because their evidence carries no usable,
    leak-safe source text.
    """
    rule = RULE_INDEX.get(finding.rule_id)
    if rule is None or rule.redact:
        return None
    spec = _FIX_LINE_TRANSFORMS.get(finding.rule_id)
    if spec is None:
        return None
    pattern, replacement, summary, note = spec
    before = finding.evidence.strip()
    if not before:
        return None
    after = pattern.sub(replacement, before)
    if after == before:
        return None
    return {
        "summary": summary,
        "before": before,
        "after": after,
        "review_note": note,
    }


def _finding_payload(item: Finding) -> dict[str, object]:
    payload: dict[str, object] = asdict(item)
    if payload.get("history_commit") is None:
        payload.pop("history_commit", None)
    if payload.get("scan_profile") is None:
        payload.pop("scan_profile", None)
    scaffold = build_fix_scaffold(item)
    if scaffold is not None:
        payload["fix_scaffold"] = scaffold
    return payload


# --- SARIF enrichment ---------------------------------------------------
# GitHub code-scanning ranks alerts by rule.properties["security-severity"]
# (a 0.0-10.0 string). We derive it deterministically from the severity label.
_SEVERITY_TO_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "none": "1.0",
}

# CWE -> STRIDE legs (dominant leg first) so Security-tab consumers can group
# findings by threat-model class. Unmapped CWE roots fall back to the default
# pair, so every rule carries at least one leg.
_CWE_TO_STRIDE: dict[str, tuple[str, ...]] = {
    "59": ("T", "E"),
    "74": ("T",),
    "78": ("T", "E"),
    "79": ("T", "I"),
    "88": ("T",),
    "89": ("T", "I"),
    "90": ("T",),
    "94": ("T", "E"),
    "95": ("T", "E"),
    "98": ("T", "E"),
    "102": ("E",),
    "113": ("T", "I"),
    "120": ("T", "E"),
    "200": ("I",),
    "208": ("S",),
    "209": ("I",),
    "22": ("I", "T"),
    "250": ("E",),
    "256": ("I",),
    "284": ("E", "T"),
    "294": ("S",),
    "295": ("S", "I"),
    "306": ("S", "E"),
    "307": ("D", "S"),
    "311": ("I",),
    "319": ("I",),
    "321": ("I", "S"),
    "326": ("I",),
    "327": ("I",),
    "328": ("I",),
    "329": ("I",),
    "330": ("S", "I"),
    "337": ("S", "I"),
    "338": ("S", "I"),
    "345": ("S", "T"),
    "346": ("S",),
    "347": ("S", "T"),
    "352": ("T", "S"),
    "353": ("T",),
    "362": ("T", "E"),
    "377": ("T",),
    "390": ("R",),
    "396": ("R",),
    "398": ("R", "T"),
    "400": ("D",),
    "430": ("E",),
    "453": ("T",),
    "470": ("E",),
    "476": ("D",),
    "489": ("I",),
    "502": ("T", "E"),
    "524": ("I",),
    "532": ("I",),
    "598": ("I",),
    "601": ("S",),
    "602": ("E",),
    "611": ("I", "T"),
    "613": ("S",),
    "614": ("I",),
    "621": ("T", "E"),
    "624": ("T", "E"),
    "639": ("E",),
    "643": ("T",),
    "644": ("T",),
    "650": ("E",),
    "662": ("D",),
    "667": ("T",),
    "674": ("D",),
    "693": ("E",),
    "732": ("E",),
    "748": ("E",),
    "754": ("D",),
    "755": ("D",),
    "758": ("S",),
    "770": ("D",),
    "772": ("D",),
    "798": ("I",),
    "829": ("T", "E"),
    "833": ("D",),
    "834": ("D",),
    "835": ("D",),
    "862": ("S", "E"),
    "863": ("E", "S"),
    "915": ("T", "E"),
    "916": ("I",),
    "917": ("T", "E"),
    "918": ("I", "E"),
    "922": ("I",),
    "942": ("S",),
    "943": ("T", "E"),
    "1004": ("I",),
    "1021": ("S",),
    "1022": ("S",),
    "1088": ("T",),
    "1104": ("T",),
    "1275": ("S",),
    "1321": ("T", "E"),
    "1333": ("D",),
    "1336": ("T", "E"),
    "1385": ("S",),
}
_DEFAULT_STRIDE_LEGS: tuple[str, ...] = ("T", "I")


def _stride_legs_for_cwe(cwe: str | None) -> tuple[str, ...]:
    if not cwe:
        return _DEFAULT_STRIDE_LEGS
    digits = "".join(char for char in cwe if char.isdigit())
    return _CWE_TO_STRIDE.get(digits, _DEFAULT_STRIDE_LEGS)


def _git_provenance(root: Path | None) -> list[dict[str, str]] | None:
    """Local read-only git context for versionControlProvenance.

    Reads HEAD, branch, and origin URL straight from repository metadata — no
    network, no worktree writes. Returns None outside git repositories so the
    SARIF key is simply omitted rather than fabricated.
    """
    if root is None:
        return None

    def git(*args: str) -> str:
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell disabled
            ["git", "-C", str(root), *args],  # noqa: S607
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
        return completed.stdout.strip()

    try:
        revision = git("rev-parse", "HEAD")
        if not revision:
            return None
        entry: dict[str, str] = {"revisionId": revision}
        branch = git("rev-parse", "--abbrev-ref", "HEAD")
        if branch and branch != "HEAD":
            entry["branch"] = branch
        remote = git("config", "--get", "remote.origin.url")
        if remote:
            entry["repositoryUri"] = remote
        return [entry]
    except OSError:
        return None


def build_sarif_report(
    findings: Sequence[Finding],
    root: Path | None = None,
    suppressed: Sequence[tuple[Finding, str]] = (),
    completeness: dict[str, object] | None = None,
) -> dict[str, object]:
    if len(findings) + len(suppressed) > MAX_FINDINGS_TOTAL:
        raise FindingLimitError(f"SARIF output exceeded the total limit of {MAX_FINDINGS_TOTAL}")
    rules: dict[str, Finding] = {item.rule_id: item for item in findings}
    for item, _reason in suppressed:
        rules.setdefault(item.rule_id, item)
    level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "none": "note",
    }
    results = []
    for item in findings:
        region: dict[str, int] = {"startLine": item.line}
        if item.column is not None:
            region["startColumn"] = item.column
        if item.end_line is not None:
            region["endLine"] = item.end_line
        if item.end_column is not None:
            region["endColumn"] = item.end_column
        result_entry: dict[str, object] = {
            "ruleId": item.rule_id,
            "level": level.get(item.severity, "note"),
            "message": {"text": item.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": item.path},
                        "region": region,
                    }
                }
            ],
            "partialFingerprints": {"shipproof/v1": item.fingerprint},
            "properties": {
                "severity": item.severity,
                "confidence": item.confidence,
                "detection": item.detection,
                "proof_level": item.proof_level,
                "scope": item.scope,
                "verification_status": item.verification_status,
                "cwe": item.cwe,
            },
        }
        scaffold = build_fix_scaffold(item)
        if scaffold is not None:
            # Suggestions replace the finding's full first line with its
            # corrected form; transforms are line-scoped by design.
            result_entry["fixes"] = [
                {
                    "description": {"text": f"{scaffold['summary']} {scaffold['review_note']}"},
                    "artifactChanges": [
                        {
                            "artifactLocation": {"uri": item.path},
                            "replacements": [
                                {
                                    "deletedRegion": {
                                        "startLine": item.line,
                                        "startColumn": 1,
                                        "endLine": item.line,
                                        "endColumn": len(scaffold["before"]) + 1,
                                    },
                                    "insertedContent": {"text": scaffold["after"]},
                                }
                            ],
                        }
                    ],
                }
            ]
        results.append(result_entry)
    for item, reason in suppressed:
        results.append(
            {
                "ruleId": item.rule_id,
                "level": level.get(item.severity, "note"),
                "message": {"text": item.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item.path},
                            "region": {"startLine": item.line},
                        }
                    }
                ],
                "partialFingerprints": {"shipproof/v1": item.fingerprint},
                # Suppressed findings stay in the report as auditable external
                # suppressions instead of vanishing from the evidence trail.
                "suppressions": [
                    {
                        "kind": "external",
                        "status": "accepted",
                        "justification": reason
                        or "suppressed by legacy baseline (no reason recorded)",
                    }
                ],
                "properties": {
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "detection": item.detection,
                    "proof_level": item.proof_level,
                    "scope": item.scope,
                    "verification_status": item.verification_status,
                    "cwe": item.cwe,
                },
            }
        )
    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "ShipProof",
                "version": VERSION,
                "informationUri": "https://github.com/kingggg5/shipproof",
                "rules": [
                    {
                        "id": item.rule_id,
                        "name": item.title.replace(" ", "_"),
                        "shortDescription": {"text": item.title},
                        "fullDescription": {"text": item.message},
                        "help": {"text": item.remediation},
                        "properties": {
                            "tags": [
                                item.category,
                                item.cwe,
                                item.owasp,
                                *(f"stride:{leg}" for leg in _stride_legs_for_cwe(item.cwe)),
                            ],
                            "security-severity": _SEVERITY_TO_SECURITY_SEVERITY.get(
                                item.severity, "5.0"
                            ),
                        },
                    }
                    for item in rules.values()
                ],
            }
        },
        "results": results,
        "automationDetails": {"id": f"shipproof/{VERSION}"},
    }
    if completeness is not None:
        complete = bool(completeness.get("is_complete", False))
        run["properties"] = {"completeness": completeness}
        invocation: dict[str, object] = {"executionSuccessful": complete}
        if not complete:
            invocation["toolExecutionNotifications"] = [
                {
                    "level": "warning",
                    "message": {
                        "text": "Scan coverage is incomplete; zero results do not establish a clean scan."
                    },
                }
            ]
        run["invocations"] = [invocation]
    provenance = _git_provenance(root)
    if provenance is not None:
        run["versionControlProvenance"] = provenance
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
    }


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument(
        "--format",
        choices=("json", "markdown", "sarif", "terminal", "github"),
        default=None,
    )
    parser.add_argument("--output", type=Path, help="Write report to a file instead of stdout")
    parser.add_argument(
        "--baseline", type=Path, help="Suppress reviewed fingerprints from this JSON baseline"
    )
    parser.add_argument(
        "--baseline-out", type=Path, help="Write active fingerprints as a reviewable baseline"
    )
    parser.add_argument(
        "--baseline-reason",
        default="Generated baseline; review required",
        help="Reason recorded by --baseline-out (default: Generated baseline; review required)",
    )
    parser.add_argument(
        "--show-suppressed",
        action="store_true",
        default=False,
        help="List suppressed findings with their baseline reasons in the report",
    )
    coverage_group = parser.add_mutually_exclusive_group()
    coverage_group.add_argument(
        "--fail-on-incomplete",
        dest="fail_on_incomplete",
        action="store_true",
        default=None,
        help="Fail when repository scan coverage is incomplete (default)",
    )
    coverage_group.add_argument(
        "--allow-incomplete",
        dest="allow_incomplete",
        action="store_true",
        default=False,
        help="Explicit exploratory override: keep exit 0 when coverage is incomplete",
    )
    parser.add_argument("--fail-on", choices=tuple(SEVERITY), default="high")
    parser.add_argument(
        "--block-min-proof",
        choices=("L0", "L1", "L2"),
        default="L1",
        help="Minimum proof level for a finding to fail the gate (default: L1)",
    )
    parser.add_argument(
        "--scan-profile",
        choices=("auto", "application", "library"),
        default="auto",
        help="application keeps authored severity; library downranks app-oriented rules",
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        default=False,
        help="Include test-scoped findings in gate failure evaluation",
    )
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument(
        "--history",
        action="store_true",
        default=False,
        help="Scan git history for secrets that were added and later removed (requires git)",
    )
    parser.add_argument(
        "--min-confidence",
        choices=("high", "medium", "low"),
        default=None,
        help="Only report findings at or above this confidence level",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude a repository-relative glob; repeat for multiple patterns",
    )
    parser.add_argument(
        "--fix-prompt",
        action="store_true",
        default=False,
        help="Generate AI-ready fix prompts for each finding",
    )
    parser.add_argument(
        "--context-level",
        choices=CONTEXT_LEVELS,
        default="full",
        help="Detail level for --explain or --fix-prompt (default: full)",
    )
    parser.add_argument(
        "--packet-out",
        metavar="DIR",
        default=None,
        help=(
            "Write bounded opt-in review packets for the user's own agent to an "
            "existing directory (local artifacts only, never sent anywhere; "
            "does not change the gate verdict)"
        ),
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        default=False,
        help="Include a bounded, content-free decision trace in scan output",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        default=False,
        help="Automatically apply deterministic fixes for supported rules",
    )
    parser.add_argument(
        "--fix-dry-run",
        action="store_true",
        default=False,
        help="Preview deterministic autofixes without modifying files",
    )
    parser.add_argument(
        "--explain",
        metavar="RULE_ID",
        default=None,
        help="Print a detailed explanation for a rule (e.g. --explain SP108)",
    )
    snippet_group = parser.add_mutually_exclusive_group()
    snippet_group.add_argument(
        "--snippet",
        metavar="CODE",
        default=None,
        help="Lint an in-memory code snippet directly without scanning a repository",
    )
    snippet_group.add_argument(
        "--snippet-stdin",
        action="store_true",
        help="Read a bounded UTF-8 code snippet from stdin without scanning a repository",
    )
    parser.add_argument(
        "--snippet-file",
        metavar="FILENAME",
        default="snippet.py",
        help="Virtual filename for the snippet to guide language detection",
    )
    parser.add_argument(
        "--changed-since",
        metavar="GIT_REF",
        default=None,
        help="Scan only files changed relative to a git ref (also includes untracked files)",
    )
    parser.add_argument(
        "--cross-file",
        action="store_true",
        default=False,
        help="Augment findings with interprocedural taint flows across files (slower)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Scan files with N worker processes (deterministic; 1 stays sequential)",
    )
    parser.add_argument(
        "--inspect-archives",
        action="store_true",
        default=False,
        help="Opt-in bounded ZIP/Office member inspection; default omits containers",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    arguments = parse_arguments(argv)

    if arguments.context_level != "full" and not (arguments.explain or arguments.fix_prompt):
        print("shipproof: --context-level requires --explain or --fix-prompt", file=sys.stderr)
        return 2
    if arguments.trace and (
        arguments.explain
        or arguments.fix_prompt
        or arguments.fix
        or arguments.fix_dry_run
        or arguments.snippet is not None
        or arguments.snippet_stdin
        or arguments.format in {"sarif", "github"}
    ):
        print(
            "shipproof: --trace is supported only for repository scan output in json, markdown, or terminal format",
            file=sys.stderr,
        )
        return 2

    if arguments.show_suppressed and (
        arguments.explain
        or arguments.fix_prompt
        or arguments.fix
        or arguments.fix_dry_run
        or arguments.snippet is not None
        or arguments.snippet_stdin
        or arguments.format == "github"
    ):
        print(
            "shipproof: --show-suppressed requires a repository report in json, markdown, terminal, or sarif",
            file=sys.stderr,
        )
        return 2
    if (arguments.fail_on_incomplete or arguments.allow_incomplete) and (
        arguments.explain or arguments.snippet is not None or arguments.snippet_stdin
    ):
        print("shipproof: coverage override requires a repository scan", file=sys.stderr)
        return 2

    # Handle --explain mode (no scan needed)
    if arguments.explain:
        as_json = arguments.format == "json"
        print(
            render_explain(
                arguments.explain,
                as_json=as_json,
                context_level=arguments.context_level,
            )
        )
        return 0

    # Handle --snippet mode (in-memory linting). Stdin avoids argv limits and
    # keeps source code out of process listings for MCP callers.
    snippet = arguments.snippet
    if arguments.snippet_stdin:
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        raw_snippet = stream.read(MAX_SNIPPET_BYTES + 1)
        if isinstance(raw_snippet, str):
            encoded_snippet = raw_snippet.encode("utf-8")
        else:
            encoded_snippet = raw_snippet
        if len(encoded_snippet) > MAX_SNIPPET_BYTES:
            print(
                f"shipproof: snippet exceeds the {MAX_SNIPPET_BYTES}-byte limit",
                file=sys.stderr,
            )
            return 2
        try:
            snippet = encoded_snippet.decode("utf-8")
        except UnicodeDecodeError:
            print("shipproof: snippet stdin must be valid UTF-8", file=sys.stderr)
            return 2
    if snippet is not None:
        try:
            findings = lint_source_snippet(snippet, arguments.snippet_file)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"shipproof: {exc}", file=sys.stderr)
            return 2
        payload = build_json_report(arguments.root, findings, {"files_scanned": 1, "suppressed": 0})
        print(json.dumps(payload, indent=2))
        return 0 if not findings else 1

    # Repository scans are production evidence. Incomplete discovery must not
    # silently become a green exit code; only an explicit exploratory override
    # may opt out. The positive flag remains accepted for readable command
    # intent and backwards-compatible command lines.
    arguments.fail_on_incomplete = not arguments.allow_incomplete

    try:
        if arguments.max_file_bytes <= 0:
            raise ValueError("max-file-bytes must be positive")
        if arguments.jobs < 1:
            raise ValueError("jobs must be at least 1")
        include_paths = (
            changed_files(arguments.root, arguments.changed_since)
            if arguments.changed_since
            else None
        )
        baseline_data = load_baseline_fingerprints(arguments.baseline)
        if arguments.baseline_out:
            _baseline_reason(arguments.baseline_reason)
        if (
            baseline_data.scanner_version is not None
            and baseline_data.scanner_version.split(".", 1)[0] != VERSION.split(".", 1)[0]
        ):
            print(
                f"shipproof: warning: baseline was generated by scanner "
                f"{baseline_data.scanner_version}; fingerprints may not match {VERSION}",
                file=sys.stderr,
            )
        scan_root = Path(arguments.root).resolve()
        baseline_exclusions = frozenset(
            relative
            for relative in (
                _path_inside_root(scan_root, arguments.baseline),
                _path_inside_root(scan_root, arguments.baseline_out),
            )
            if relative is not None
        )
        findings, stats = scan_repository(
            arguments.root,
            max_file_bytes=arguments.max_file_bytes,
            # History findings must participate in the same deduplication and
            # baseline pass as live findings. Defer suppression until the two
            # evidence streams have been combined.
            baseline=None if arguments.history else baseline_data,
            exclude_patterns=arguments.exclude,
            include_paths=include_paths,
            cross_file=arguments.cross_file,
            jobs=arguments.jobs,
            excluded_paths=baseline_exclusions,
            scan_profile=None if arguments.scan_profile == "auto" else arguments.scan_profile,
            inspect_archives=arguments.inspect_archives,
        )
        suppressed_records = list(stats.pop("_suppressed", []))
        if arguments.changed_since:
            stats["changed_since"] = arguments.changed_since
        if arguments.history:
            history_findings, history_commits = _scan_history_secrets(arguments.root)
            if len(findings) + len(history_findings) > MAX_FINDINGS_TOTAL:
                raise FindingLimitError(
                    f"finding output exceeded the total limit of {MAX_FINDINGS_TOTAL}"
                )
            findings.extend(history_findings)
            findings, history_suppressed = deduplicate_and_suppress_findings(
                findings, baseline_data
            )
            stats["suppressed"] = int(stats["suppressed"]) + len(history_suppressed)
            suppressed_records.extend(history_suppressed)
            stats["history_commits_scanned"] = history_commits
            stats["history_findings"] = len(history_findings)

        findings_before_confidence_filter = len(findings)

        # Filter by confidence if requested
        if arguments.min_confidence:
            min_conf = CONFIDENCE[arguments.min_confidence]
            findings = [f for f in findings if CONFIDENCE[f.confidence] <= min_conf]

        decision_trace = None
        if arguments.trace:
            decision_trace = build_decision_trace(
                findings,
                stats,
                fail_on=arguments.fail_on,
                include_tests=arguments.include_tests,
                max_file_bytes=arguments.max_file_bytes,
                min_confidence=arguments.min_confidence,
                exclude_patterns=arguments.exclude,
                baseline_fingerprints=len(baseline_data.fingerprints),
                changed_candidates=len(include_paths) if include_paths is not None else None,
                findings_before_confidence_filter=findings_before_confidence_filter,
                fail_on_incomplete=arguments.fail_on_incomplete,
                block_min_proof=arguments.block_min_proof,
            )

        payload = build_json_report(
            arguments.root,
            findings,
            stats,
            include_tests=arguments.include_tests,
            decision_trace=decision_trace,
            block_min_proof=arguments.block_min_proof,
        )
        if arguments.show_suppressed and suppressed_records:
            payload["suppressed_findings"] = [
                {**_finding_payload(item), "suppression_reason": reason}
                for item, reason in suppressed_records
            ]
        if arguments.baseline_out:
            if len(findings) > MAX_BASELINE_FINGERPRINTS:
                raise ValueError("baseline output exceeds the fingerprint count limit")
            for item in findings:
                _baseline_matcher(item.path, "fingerprint path")
            baseline_output = (
                json.dumps(
                    {
                        "version": 2,
                        "scanner_version": VERSION,
                        "rules": [
                            {
                                key: value
                                for key, value in {
                                    "id": rule.rule_id,
                                    "path": rule.path,
                                    "evidence": rule.evidence,
                                    "reason": rule.reason,
                                }.items()
                                if value
                            }
                            for rule in baseline_data.rules
                        ],
                        "fingerprints": [
                            {
                                "hash": item.fingerprint,
                                "rule_id": item.rule_id,
                                "path": item.path,
                                "reason": arguments.baseline_reason,
                            }
                            for item in findings
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
            if len(baseline_output.encode("utf-8")) > MAX_BASELINE_BYTES:
                raise ValueError("baseline output exceeds the byte limit")
            safe_write_text(arguments.baseline_out, baseline_output, label="baseline output")

        # Handle --fix / --fix-dry-run mode
        if arguments.fix or arguments.fix_dry_run:
            fixed_count, fix_messages = run_autofix(
                arguments.root, findings, dry_run=arguments.fix_dry_run
            )
            for msg in fix_messages:
                print(msg)
            action_label = "Dry-run completed" if arguments.fix_dry_run else "Autofix completed"
            print(f"\n{action_label}: {fixed_count} findings remediated.")
            verified_findings = findings
            verified_stats = stats
            if fixed_count > 0 and not arguments.fix_dry_run:
                verified_findings, verified_stats = scan_repository(
                    arguments.root,
                    max_file_bytes=arguments.max_file_bytes,
                    baseline=load_baseline_fingerprints(arguments.baseline),
                    exclude_patterns=arguments.exclude,
                    include_paths=include_paths,
                    cross_file=arguments.cross_file,
                    jobs=arguments.jobs,
                    excluded_paths=baseline_exclusions,
                    scan_profile=None
                    if arguments.scan_profile == "auto"
                    else arguments.scan_profile,
                    inspect_archives=arguments.inspect_archives,
                )
                if arguments.min_confidence:
                    min_conf = CONFIDENCE[arguments.min_confidence]
                    verified_findings = [
                        item
                        for item in verified_findings
                        if CONFIDENCE[item.confidence] <= min_conf
                    ]
            return (
                1
                if gate_failed(
                    verified_findings,
                    arguments.fail_on,
                    include_tests=arguments.include_tests,
                    completeness=verified_stats.get("completeness"),
                    fail_on_incomplete=arguments.fail_on_incomplete,
                    block_min_proof=arguments.block_min_proof,
                )
                else 0
            )

        # Handle --fix-prompt mode
        if arguments.fix_prompt:
            as_json = arguments.format == "json"
            output = render_fix_prompts(
                arguments.root,
                findings,
                as_json=as_json,
                context_level=arguments.context_level,
            )
        else:
            # Determine format: default to terminal if TTY, else markdown
            fmt = arguments.format
            if fmt is None:
                fmt = "terminal" if (sys.stdout.isatty() and not arguments.output) else "markdown"

            if fmt == "terminal":
                output = render_terminal_report(
                    arguments.root,
                    findings,
                    stats,
                    decision_trace=decision_trace,
                    suppressed=suppressed_records if arguments.show_suppressed else (),
                    include_tests=arguments.include_tests,
                    block_min_proof=arguments.block_min_proof,
                )
            elif fmt == "markdown":
                output = render_markdown_report(
                    arguments.root,
                    findings,
                    stats,
                    decision_trace=decision_trace,
                    suppressed=suppressed_records if arguments.show_suppressed else (),
                    include_tests=arguments.include_tests,
                    block_min_proof=arguments.block_min_proof,
                )
            elif fmt == "sarif":
                output = json.dumps(
                    build_sarif_report(
                        findings,
                        arguments.root,
                        suppressed=suppressed_records,
                        completeness=stats.get("completeness"),
                    ),
                    indent=2,
                )
            elif fmt == "github":
                output = render_github_annotations(findings)
                if not stats["completeness"]["is_complete"]:
                    output += "\n::warning::ShipProof scan coverage is incomplete; zero findings do not establish a clean scan."
            else:
                output = json.dumps(payload, indent=2)

        if arguments.output:
            safe_write_text(
                arguments.output,
                output + ("" if output.endswith("\n") else "\n"),
                label="report output",
            )
        else:
            print(output)
        if arguments.packet_out is not None:
            # Opt-in review packets ride alongside the report; they never
            # change findings, verdicts, or exit codes on their own.
            try:
                import review_packets
            except ImportError as exc:
                raise ValueError(f"review packets unavailable: {exc}") from exc
            packet_report = review_packets.build_packets(
                arguments.root,
                findings,
                policy={
                    "fail_on": arguments.fail_on,
                    "block_min_proof": arguments.block_min_proof,
                    "include_tests": bool(arguments.include_tests),
                },
                scanner_version=f"shipproof-scan/{VERSION}",
                rules_identity=f"executable-rules/{len(RULES)}",
            )
            out_dir = Path(arguments.packet_out)
            if not out_dir.is_dir() or out_dir.is_symlink():
                raise ValueError(f"packet output must be an existing directory: {out_dir}")
            safe_write_text(
                out_dir / "ledger.json",
                json.dumps(packet_report, indent=2) + "\n",
                label="packet ledger",
            )
            for packet in packet_report["packets"]:
                safe_write_text(
                    out_dir / f"{packet['packet_id']}.json",
                    json.dumps(packet, indent=2) + "\n",
                    label="review packet",
                )
            counts = packet_report["counts"]
            print(
                f"review packets: {counts['packets']} packets, "
                f"{counts['scheduled']} scheduled, {counts['deferred']} deferred "
                f"-> {out_dir}",
                file=sys.stderr,
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # a scanner crash is invalid evidence, never a gate block
        print(f"shipproof: internal error ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 2

    # Gating: default evaluates app scope findings only unless --include-tests is set
    if gate_failed(
        findings,
        arguments.fail_on,
        include_tests=arguments.include_tests,
        block_min_proof=arguments.block_min_proof,
    ):
        return 1
    if arguments.fail_on_incomplete:
        completeness = stats.get("completeness")
        if isinstance(completeness, dict) and not completeness.get("is_complete", True):
            reasons = ", ".join(str(reason) for reason in completeness.get("reasons", []))
            print(f"shipproof: scan coverage incomplete ({reasons})", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
