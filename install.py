#!/usr/bin/env python3
"""Install the ShipProof skill into a Codex skills directory."""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path
from typing import Sequence

SKILL_NAME = "audit-production-readiness"


def destination(codex_home: Path | None = None) -> Path:
    base = codex_home or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    return base.expanduser().resolve() / "skills" / SKILL_NAME


def install(codex_home: Path | None = None) -> Path:
    source = Path(__file__).resolve().parent / "skills" / SKILL_NAME
    target = destination(codex_home)
    if not source.joinpath("SKILL.md").is_file():
        raise FileNotFoundError(f"skill source is incomplete: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target, dirs_exist_ok=True)
    return target


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-home", type=Path, help="Override CODEX_HOME")
    args = parser.parse_args(argv)
    print(f"Installed ShipProof at {install(args.codex_home)}")
    print("Restart Codex, then invoke $audit-production-readiness.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
