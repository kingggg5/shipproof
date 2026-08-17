#!/usr/bin/env python3
"""Report near-duplicate rows in docs/knowledge/failure-catalog.md.

Compares normalized failure-mode text (Jaccard over word tokens) and prints
pairs above the threshold so maintainers can merge or differentiate them.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

STOPWORDS = {
    "a",
    "an",
    "the",
    "and",
    "or",
    "to",
    "of",
    "in",
    "on",
    "for",
    "with",
    "without",
    "into",
    "from",
    "by",
    "is",
    "are",
    "be",
    "not",
    "your",
    "you",
    "instead",
    "use",
    "using",
    "only",
    "per",
    "it",
    "its",
    "at",
    "as",
    "when",
}


def tokenize(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {word for word in words if word not in STOPWORDS and len(word) > 2}


def main(catalog_path: Path, threshold: float = 0.62) -> int:
    rows: list[tuple[str, str]] = []
    for line in catalog_path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| ([A-Z][A-Z0-9]{0,5}(?:-[A-Z]{1,3})?-\d{3}) \| (.+?) \|", line)
        if match:
            rows.append((match.group(1), match.group(2)))
    duplicates = 0
    for index, (item_id, text) in enumerate(rows):
        tokens = tokenize(text)
        for other_id, other_text in rows[index + 1 :]:
            other_tokens = tokenize(other_text)
            if not tokens or not other_tokens:
                continue
            overlap = len(tokens & other_tokens) / len(tokens | other_tokens)
            if overlap >= threshold:
                duplicates += 1
                percent = round(overlap * 100)
                print(f"{item_id} ~ {other_id} ({percent}%): {text[:70]} | {other_text[:70]}")
    print(
        f"\nchecked {len(rows)} rows; {duplicates} near-duplicate pair(s) at threshold {threshold}"
    )
    return 1 if duplicates else 0


if __name__ == "__main__":
    catalog = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/knowledge/failure-catalog.md")
    sys.exit(main(catalog))
