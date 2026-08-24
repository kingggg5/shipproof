"""Runtime-built contract fixtures for the redacting secret rules.

The values are deliberately assembled at runtime so the quality corpus does not
put credential-shaped literals into the repository being scanned by ShipProof.
They are synthetic structural examples, not usable credentials.
"""

from __future__ import annotations


def positive_source(rule_id: str) -> str:
    """Return a synthetic source snippet that must trigger ``rule_id``."""

    a = "a"
    token = {
        "SP001": "-----BEGIN " + "RSA " + "PRIVATE KEY-----",
        "SP002": "AKIA" + "A" * 16,
        "SP003": "api" + '_key="' + "N7vK2mQ9xR4pT8wZ" + '"',
        "SP004": "os." + "get" + "env(" + '"APP_SECRET", "fallback")',
        "SP005": '"type":"service_account","private_key":"-----BEGIN '
        + "RSA "
        + "PRIVATE KEY-----",
        "SP006": "gh" + "p_" + "A" * 36,
        "SP007": 'aws_secret_access_key="' + "A" * 40 + '"',
        "SP008": "xoxb-" + "1" * 11 + "-" + "2" * 11 + "-" + "A" * 24,
        "SP009": "sk_live_" + "A" * 24,
        "SP010": "sk-" + "A" * 48,
        "SP011": "SG." + "A" * 22 + "." + "A" * 43,
        "SP012": "key-" + "A" * 32,
        "SP013": "https://discord.com/api/webhooks/123/" + "A" * 12,
        "SP014": "sq0atp-" + "A" * 22,
        "SP015": "hf_" + "A" * 34,
        "SP016": "Bearer eyJ" + "A" * 12 + "." + "B" * 12 + "." + "C" * 12,
        "SP017": "npm_" + "A" * 36,
        "SP018": "eyJhbGciOiJSUzI1NiIsImtpZCI6" + "A" * 8 + "." + "B" * 8 + "." + "C" * 8,
        "SP019": "postgres://user:" + "N7vK2mQ9xR4pT8wZ" + "@db.prod.internal/app",
        "SP020": "redis://user:" + "N7vK2mQ9xR4pT8wZ" + "@cache.prod.internal:6379",
        "SP021": "mongodb://user:" + "N7vK2mQ9xR4pT8wZ" + "@db.prod.internal",
        "SP022": 'CLOUDFLARE_API_KEY="' + "A" * 40 + '"',
        "SP023": "ddp_" + "A" * 32,
        "SP024": "sntrys_" + a * 64,
        "SP025": 'master_salt="' + "A" * 8 + '"',
        "SP026": "sk-ant-api03-" + "A" * 80,
        "SP027": "hf_" + "A" * 34,
        "SP028": "pcsk_" + "A" * 40,
        "SP029": 'cohere_api_key="' + "A" * 40 + '"',
        "SP030": 'dd_api_key="' + a * 32 + '"',
        "SP031": "NRAK-" + "A" * 27,
        "SP032": "sntrys_" + a * 64,
        "SP033": "PMAK-" + "A" * 56,
        "SP034": "shpat_" + a * 32,
        "SP035": "sq0csp-" + "A" * 43,
        "SP036": 'algolia_admin_key="' + a * 32 + '"',
        "SP037": "hvs." + "A" * 24,
        "SP038": "pul-" + a * 40,
        "SP039": "glsa_" + "A" * 32 + "_" + "B" * 8,
        "SP040": "M" + "A" * 23 + "." + "B" * 6 + "." + "C" * 27,
        "SP041": "12345678:AA" + "A" * 33,
        "SP042": "https://hooks."
        + "slack.com/services/T"
        + "A" * 8
        + "/B"
        + "B" * 8
        + "/"
        + "C" * 24,
        "SP043": "lin_api_" + "A" * 40,
        "SP044": "ntn_" + "1" * 11 + "A" * 32,
        "SP045": "pat" + "A" * 14 + "." + a * 64,
        "SP046": "re_" + "A" * 32,
        "SP047": "AC" + a * 32 + ":" + a * 32,
        "SP048": '"type"' + ':"service_account","private_key' + '_id":',
        "SP049": "AGE-SECRET-KEY-1" + "A" * 58,
        "SP050": "pypi-AgEIcHlwaS5vcmc" + "A" * 50,
    }.get(rule_id)
    if token is None:
        raise KeyError(rule_id)
    return token + "\n"


SECRET_CASE_IDS = frozenset(
    {
        "positive_a",
        "positive_b",
        "negative_prefix_fragment",
        "negative_suffix_fragment",
        "adversarial_split_literal",
    }
)


def contract_source(rule_id: str, case_id: str) -> str:
    """Resolve one deterministic secret-rule fixture without storing the token in JSON."""

    if case_id not in SECRET_CASE_IDS:
        raise KeyError(case_id)
    token = positive_source(rule_id).rstrip("\n")
    # Keep the prefix below provider minimum lengths while preserving a
    # recognizable prefix/suffix boundary for near-miss and split-literal cases.
    split_at = max(1, len(token) // 4)
    prefix = token[:split_at]
    suffix = token[split_at:]
    if case_id == "positive_a":
        return token + "\n"
    if case_id == "positive_b":
        return "\n" + token + "\n"
    if case_id == "negative_prefix_fragment":
        return f"provider_prefix_fragment = {prefix!r}\n"
    if case_id == "negative_suffix_fragment":
        return f"provider_suffix_fragment = {suffix!r}\n"
    return f"provider_token = {prefix!r} + {suffix!r}\n"
