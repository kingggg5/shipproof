#!/usr/bin/env python3
"""Install ShipProof skills for Codex, Claude Code, or both."""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path
from typing import Sequence

SKILL_NAMES = ("engineer-production-systems", "audit-production-readiness")


def skill_root(host: str, codex_home: Path | None = None, claude_home: Path | None = None) -> Path:
    if host == "codex":
        base = codex_home or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    elif host == "claude":
        base = claude_home or Path.home() / ".claude"
    else:
        raise ValueError(f"unsupported host: {host}")
    return base.expanduser().resolve() / "skills"


def install(
    target: str = "both",
    codex_home: Path | None = None,
    claude_home: Path | None = None,
) -> list[tuple[str, Path]]:
    hosts = ("codex", "claude") if target == "both" else (target,)
    source_root = Path(__file__).resolve().parent / "skills"
    installed: list[tuple[str, Path]] = []
    for host in hosts:
        root = skill_root(host, codex_home, claude_home)
        root.mkdir(parents=True, exist_ok=True)
        for name in SKILL_NAMES:
            source = source_root / name
            if not source.joinpath("SKILL.md").is_file():
                raise FileNotFoundError(f"skill source is incomplete: {source}")
            destination = root / name
            shutil.copytree(source, destination, dirs_exist_ok=True)
            installed.append((host, destination))
    return installed


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("codex", "claude", "both"), default="both")
    parser.add_argument("--codex-home", type=Path, help="Override CODEX_HOME")
    parser.add_argument("--claude-home", type=Path, help="Override ~/.claude")
    args = parser.parse_args(argv)
    for host, path in install(args.target, args.codex_home, args.claude_home):
        print(f"Installed for {host}: {path}")
    print("Invoke engineer-production-systems while building and audit-production-readiness before release.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
