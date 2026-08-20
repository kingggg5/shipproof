"""Build ShipProof's offline rule-research snapshots from public primary sources.

This is a maintainer-only network task. It is never imported or executed by the
default scanner, CLI, package smoke test, or GitHub Action.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
CWE_ZIP = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
USER_AGENT = "ShipProof rule research maintainer/0.6 (+https://github.com/kingggg5/shipproof)"
YEARS = tuple(range(2021, 2027))
QUARTERS = ((1, 3, 31), (4, 6, 30), (7, 9, 30), (10, 12, 31))
ANNUAL_FIRST_ID = 1651
EXPERT_FIRST_ID = 3451
PER_YEAR = 300
EXPERT_COUNT = 1000
NVD_QUARTER_SAMPLE = 300
SEVERITY_SCORE = {"CRITICAL": 400, "HIGH": 300, "MEDIUM": 200, "LOW": 100}
CWE_RE = re.compile(r"^CWE-\d+$")
SOURCE_HOSTS = {"services.nvd.nist.gov", "www.cisa.gov", "cwe.mitre.org"}
MAX_CWE_XML_BYTES = 64 * 1024 * 1024


def fetch_bytes(url: str, *, timeout: int = 180, attempts: int = 4) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in SOURCE_HOSTS:
        raise ValueError(f"research source is not allowlisted: {url}")
    request = urllib.request.Request(  # noqa: S310 - HTTPS host allowlist checked above
        url, headers={"User-Agent": USER_AGENT}
    )
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code not in {429, 500, 502, 503, 504} or attempt == attempts - 1:
                raise
        except (TimeoutError, urllib.error.URLError):
            if attempt == attempts - 1:
                raise
        delay = 2**attempt
        print(f"retrying {url} in {delay}s", file=sys.stderr, flush=True)
        time.sleep(delay)
    raise AssertionError("unreachable")


def cached_fetch(url: str, cache_path: Path, *, refresh: bool) -> bytes:
    if cache_path.is_file() and not refresh:
        print(f"cache: {cache_path.name}", file=sys.stderr, flush=True)
        return cache_path.read_bytes()
    print(f"fetch: {url}", file=sys.stderr, flush=True)
    payload = fetch_bytes(url)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = cache_path.with_suffix(cache_path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(cache_path)
    return payload


def english_value(values: list[dict[str, Any]], key: str = "value") -> str:
    for value in values:
        if value.get("lang") == "en" and isinstance(value.get(key), str):
            return value[key].strip()
    return ""


def bounded_text(value: str, limit: int = 320) -> str:
    normalized = " ".join(value.split())
    return normalized if len(normalized) <= limit else normalized[: limit - 1].rstrip() + "…"


def cvss_record(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        records = metrics.get(key, [])
        if not records:
            continue
        preferred = next(
            (record for record in records if record.get("type") == "Primary"), records[0]
        )
        data = preferred.get("cvssData", {})
        severity = data.get("baseSeverity") or preferred.get("baseSeverity") or "UNKNOWN"
        return {
            "version": str(data.get("version", "unknown")),
            "score": float(data.get("baseScore", 0.0)),
            "severity": str(severity).upper(),
            "vector": data.get("vectorString"),
        }
    return {"version": "unknown", "score": 0.0, "severity": "UNKNOWN", "vector": None}


def cwe_ids(cve: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if CWE_RE.fullmatch(value):
                values.add(value)
    return sorted(values, key=lambda value: int(value.removeprefix("CWE-")))


def vendor_reference(cve: dict[str, Any]) -> str | None:
    candidates: list[tuple[int, str]] = []
    for reference in cve.get("references", []):
        url = reference.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            continue
        tags = set(reference.get("tags", []))
        score = 0
        if "Vendor Advisory" in tags:
            score += 30
        if "Patch" in tags:
            score += 20
        if "Mitigation" in tags:
            score += 10
        if any(host in url for host in ("nvd.nist.gov", "cve.org", "github.com/advisories")):
            score -= 10
        candidates.append((score, url))
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1]))[1]


def annual_score(cve: dict[str, Any], kev: dict[str, Any] | None) -> tuple[int, str]:
    cvss = cvss_record(cve)
    score = 1_000_000 if kev else 0
    score += SEVERITY_SCORE.get(cvss["severity"], 0) * 1_000
    score += int(cvss["score"] * 100)
    score += 100 if cwe_ids(cve) else 0
    score += 50 if vendor_reference(cve) else 0
    return score, cve["id"]


def load_kev(cache_dir: Path, *, refresh: bool) -> tuple[dict[str, Any], str, str]:
    raw = cached_fetch(CISA_KEV, cache_dir / "cisa-kev.json", refresh=refresh)
    payload = json.loads(raw)
    records = {item["cveID"]: item for item in payload["vulnerabilities"]}
    return (
        records,
        str(payload.get("catalogVersion", "unknown")),
        hashlib.sha256(raw).hexdigest(),
    )


def load_nvd_year(
    year: int, cache_dir: Path, *, refresh: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    today = date.today()
    records: dict[str, dict[str, Any]] = {}
    snapshots: list[dict[str, Any]] = []
    for quarter, (start_month, end_month, end_day) in enumerate(QUARTERS, start=1):
        start = date(year, start_month, 1)
        if start > today:
            break
        end = min(date(year, end_month, end_day), today)
        query = urllib.parse.urlencode(
            {
                "pubStartDate": f"{start.isoformat()}T00:00:00.000",
                "pubEndDate": f"{end.isoformat()}T23:59:59.999",
                "cvssV3Severity": "CRITICAL",
                "noRejected": "",
                "resultsPerPage": NVD_QUARTER_SAMPLE,
            }
        )
        url = f"{NVD_API}?{query}"
        cache_path = cache_dir / f"nvd-{year}-q{quarter}-critical-{NVD_QUARTER_SAMPLE}.json"
        if not cache_path.is_file() or refresh:
            # The public API permits five requests in a rolling 30-second window.
            time.sleep(6.2)
        raw = cached_fetch(url, cache_path, refresh=refresh)
        payload = json.loads(raw)
        snapshots.append(
            {
                "quarter": quarter,
                "from": start.isoformat(),
                "through": end.isoformat(),
                "total_results": payload["totalResults"],
                "sampled_results": len(payload["vulnerabilities"]),
                "timestamp": str(payload.get("timestamp", "unknown")),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        for item in payload["vulnerabilities"]:
            records[item["cve"]["id"]] = item["cve"]
    return list(records.values()), snapshots


def build_annual_candidates(
    kev_records: dict[str, Any], cache_dir: Path, *, refresh: bool
) -> tuple[list[dict[str, Any]], dict]:
    candidates: list[dict[str, Any]] = []
    query_snapshots: dict[str, list[dict[str, Any]]] = {}
    next_id = ANNUAL_FIRST_ID
    for year in YEARS:
        print(f"annual cohort: {year}", file=sys.stderr, flush=True)
        cves, snapshots = load_nvd_year(year, cache_dir, refresh=refresh)
        query_snapshots[str(year)] = snapshots
        eligible = [
            cve
            for cve in cves
            if cve.get("vulnStatus") != "Rejected"
            and str(cve.get("published", "")).startswith(str(year))
        ]
        ranked = sorted(
            eligible,
            key=lambda cve: annual_score(cve, kev_records.get(cve["id"])),
            reverse=True,
        )
        if len(ranked) < PER_YEAR:
            raise RuntimeError(f"NVD {year} has only {len(ranked)} eligible CVEs")
        for cve in ranked[:PER_YEAR]:
            cve_id = cve["id"]
            kev = kev_records.get(cve_id)
            sources = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
            vendor = vendor_reference(cve)
            if vendor:
                sources.append(vendor)
            if kev:
                sources.append(CISA_CATALOG)
            candidates.append(
                {
                    "candidate_id": f"SP{next_id}",
                    "cohort_year": year,
                    "signal": cve_id,
                    "title": bounded_text(english_value(cve.get("descriptions", [])), 180),
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "cvss": cvss_record(cve),
                    "cwe": cwe_ids(cve),
                    "known_exploited": bool(kev),
                    "known_ransomware_use": (
                        kev.get("knownRansomwareCampaignUse", "Unknown") if kev else "Unknown"
                    ),
                    "recommended_route": "dependency_evidence",
                    "promotion_status": "research_only",
                    "source_urls": list(dict.fromkeys(sources)),
                }
            )
            next_id += 1
    return candidates, {"nvd_api_snapshots": query_snapshots}


def xml_text(element: ElementTree.Element | None) -> str:
    if element is None:
        return ""
    return bounded_text(" ".join(element.itertext()))


def applicable_platforms(weakness: ElementTree.Element, ns: dict[str, str]) -> list[dict[str, str]]:
    """Retain CWE's own applicability hints without inventing language support."""
    container = weakness.find("cwe:Applicable_Platforms", ns)
    if container is None:
        return []
    records: list[dict[str, str]] = []
    for platform in container:
        record = {"kind": platform.tag.rsplit("}", 1)[-1]}
        for key in ("Name", "Class", "Prevalence"):
            value = platform.attrib.get(key)
            if value:
                record[key.lower()] = value
        records.append(record)
    return records


def common_consequences(
    weakness: ElementTree.Element, ns: dict[str, str]
) -> list[dict[str, list[str]]]:
    """Retain structured CWE scopes/impacts; omit long narrative notes."""
    container = weakness.find("cwe:Common_Consequences", ns)
    if container is None:
        return []
    records: list[dict[str, list[str]]] = []
    for consequence in container.findall("cwe:Consequence", ns):
        scopes = [xml_text(item) for item in consequence.findall("cwe:Scope", ns)]
        impacts = [xml_text(item) for item in consequence.findall("cwe:Impact", ns)]
        records.append({"scopes": scopes, "impacts": impacts})
    return records


def build_expert_candidates(cache_dir: Path, *, refresh: bool) -> tuple[list[dict[str, Any]], dict]:
    print("expert cohort: CWE", file=sys.stderr, flush=True)
    cwe_archive = cached_fetch(CWE_ZIP, cache_dir / "cwe-latest.xml.zip", refresh=refresh)
    archive = zipfile.ZipFile(io.BytesIO(cwe_archive))
    xml_name = next(name for name in archive.namelist() if name.endswith(".xml"))
    xml_payload = archive.read(xml_name)
    if len(xml_payload) > MAX_CWE_XML_BYTES:
        raise ValueError("CWE XML exceeds the maintainer snapshot size bound")
    if b"<!DOCTYPE" in xml_payload.upper() or b"<!ENTITY" in xml_payload.upper():
        raise ValueError("CWE XML contains a prohibited DTD or entity declaration")
    root = ElementTree.fromstring(xml_payload)  # noqa: S314 - DTD/entity input rejected
    namespace_url = root.tag.split("}", 1)[0].removeprefix("{")
    ns = {"cwe": namespace_url}
    weaknesses = root.findall(".//cwe:Weakness", ns)
    categories = root.findall(".//cwe:Category", ns)

    weakness_records = []
    for weakness in weaknesses:
        cwe_id = weakness.attrib["ID"]
        weakness_records.append(
            {
                "source_kind": "weakness",
                "source_id": f"CWE-{cwe_id}",
                "title": weakness.attrib["Name"],
                "abstraction": weakness.attrib.get("Abstraction", "Unknown"),
                "status": weakness.attrib.get("Status", "Unknown"),
                "description": xml_text(weakness.find("cwe:Description", ns)),
                "applicable_platforms": applicable_platforms(weakness, ns),
                "common_consequences": common_consequences(weakness, ns),
                "recommended_route": (
                    "static_research"
                    if weakness.attrib.get("Abstraction") in {"Base", "Variant"}
                    else "taxonomy_research"
                ),
                "source_urls": [f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"],
            }
        )
    weakness_records.sort(key=lambda item: int(item["source_id"].removeprefix("CWE-")))

    membership = Counter()
    for relationship in root.findall(".//cwe:Related_Weakness", ns):
        if relationship.attrib.get("Nature") == "MemberOf":
            membership[relationship.attrib.get("CWE_ID", "")] += 1
    category_records = []
    for category in categories:
        category_id = category.attrib["ID"]
        category_records.append(
            {
                "source_kind": "category",
                "source_id": f"CWE-CATEGORY-{category_id}",
                "title": category.attrib["Name"],
                "abstraction": "Category",
                "status": category.attrib.get("Status", "Unknown"),
                "description": xml_text(category.find("cwe:Summary", ns)),
                "applicable_platforms": [],
                "common_consequences": [],
                "recommended_route": "taxonomy_research",
                "source_urls": [f"https://cwe.mitre.org/data/definitions/{category_id}.html"],
                "member_count": membership[category_id],
            }
        )
    category_records.sort(
        key=lambda item: (-item["member_count"], int(item["source_id"].rsplit("-", 1)[1]))
    )
    selected = weakness_records + category_records[: EXPERT_COUNT - len(weakness_records)]
    if len(weakness_records) > EXPERT_COUNT or len(selected) != EXPERT_COUNT:
        raise RuntimeError(
            f"expected at most {EXPERT_COUNT} CWE weaknesses and enough categories; "
            f"found {len(weakness_records)} weaknesses and {len(categories)} categories"
        )
    candidates = []
    for offset, record in enumerate(selected):
        candidates.append(
            {
                "candidate_id": f"SP{EXPERT_FIRST_ID + offset}",
                **record,
                "promotion_status": "research_only",
            }
        )
    return candidates, {
        "cwe_catalog_name": root.attrib.get("Name", "CWE"),
        "cwe_catalog_version": root.attrib.get("Version", "unknown"),
        "cwe_catalog_date": root.attrib.get("Date", "unknown"),
        "cwe_archive_sha256": hashlib.sha256(cwe_archive).hexdigest(),
        "weaknesses_selected": len(weakness_records),
        "categories_selected": EXPERT_COUNT - len(weakness_records),
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", "utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("research"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".shipproof-research-cache"))
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args(argv)

    kev_records, kev_version, kev_sha256 = load_kev(args.cache_dir, refresh=args.refresh)
    annual, annual_meta = build_annual_candidates(kev_records, args.cache_dir, refresh=args.refresh)
    expert, expert_meta = build_expert_candidates(args.cache_dir, refresh=args.refresh)
    generated = date.today().isoformat()

    write_json(
        args.output_dir / "annual-rule-candidates.json",
        {
            "schema_version": 1,
            "generated_on": generated,
            "status": "research_only",
            "selection": (
                "300 critical NVD CVEs per publication year selected from a bounded "
                "300-record sample in each available calendar quarter, then ranked by "
                "CISA KEV membership, CVSS score, CWE availability, and vendor advisory "
                "availability"
            ),
            "cisa_kev_catalog_version": kev_version,
            "cisa_kev_sha256": kev_sha256,
            **annual_meta,
            "candidates": annual,
        },
    )
    write_json(
        args.output_dir / "expert-rule-candidates.json",
        {
            "schema_version": 1,
            "generated_on": generated,
            "status": "research_only",
            "selection": (
                "All current CWE weaknesses plus the highest-membership CWE categories "
                "needed to reach exactly 1,000 independently reviewable candidates"
            ),
            **expert_meta,
            "candidates": expert,
        },
    )
    print(
        json.dumps(
            {
                "annual_candidates": len(annual),
                "expert_candidates": len(expert),
                "candidate_range": f"SP{ANNUAL_FIRST_ID}-SP{EXPERT_FIRST_ID + len(expert) - 1}",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
