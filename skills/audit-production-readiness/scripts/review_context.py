"""Bounded local-import context hints; never evaluate project code or settings."""

from __future__ import annotations

import ast
import posixpath
import re
from pathlib import Path

import snapshot_identity as identity

SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".cs",
        ".dart",
        ".lua",
        ".luau",
        ".go",
        ".rs",
        ".php",
        ".java",
        ".rb",
        ".sql",
        ".c",
        ".h",
        ".cpp",
    }
)
MAX_SCOPE_FILES = 5000
MAX_CONTEXT_BYTES = 4 * 1024 * 1024
REVIEW_FOCUS = {
    "typescript/javascript": "Trace untrusted input and authorization to side effects; check async error/cleanup ownership, server/client boundaries and unbounded work.",
    "csharp/dotnet": "Check target authorization, query construction, async cancellation, disposable ownership and database/concurrency bounds.",
    "dart": "Check async errors, stream/subscription ownership, widget lifecycle, trusted destinations and unbounded work.",
    "lua/luau": "Trace client-controlled remote arguments to server actions; check authoritative validation, yielding callbacks, connection cleanup and work limits.",
    "sql": "Check parameterization, privilege/search-path boundaries, transaction behavior and query/resource bounds; do not execute statements.",
    "other": "Trace inputs to side effects; check authorization, error paths, resource ownership and work limits. Report unsupported assumptions.",
}


def review_focus(paths: list[str]) -> dict[str, str]:
    families = set()
    for path in paths:
        suffix = Path(path).suffix.lower()
        family = (
            "typescript/javascript"
            if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
            else "csharp/dotnet"
            if suffix == ".cs"
            else "dart"
            if suffix == ".dart"
            else "lua/luau"
            if suffix in {".lua", ".luau"}
            else "sql"
            if suffix == ".sql"
            else "other"
        )
        families.add(family)
    return {family: REVIEW_FOCUS[family] for family in sorted(families)}


def relative_path(value: str) -> str:
    """Keep lexical paths: resolving first would erase evidence of symlinks."""
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("review path must be a nonempty repository-relative POSIX path")
    parts = value.split("/")
    if value.startswith("/") or ":" in value or any(p in {"", ".", ".."} for p in parts):
        raise ValueError("review path must stay inside the selected repository")
    return value


def read_source(root: Path, relative: str, limit: int) -> bytes:
    relative = relative_path(relative)
    candidate = root
    for component in relative.split("/"):
        candidate /= component
        if identity._is_link_or_reparse(candidate.lstat()):
            raise ValueError("linked review source is not eligible")
    if not identity.contains(root, candidate.resolve()):
        raise ValueError("review source escapes repository")
    return identity.read_bytes_guarded(candidate, limit)


class ContextIndex:
    """Resolve literal imports only within an authoritative eligible-file set.

    These are review hints, not proof of runtime import resolution or reachability.
    Package aliases, namespace/type binding, and dynamic imports remain unknown.
    """

    def __init__(self, root: Path, paths: set[str] | frozenset[str]):
        if len(paths) > MAX_SCOPE_FILES:
            raise ValueError("review context exceeds 5000 files; narrow the scan scope")
        self.root = identity.resolve_root(root)
        self.paths = frozenset(relative_path(p) for p in paths)
        self.remaining_bytes = MAX_CONTEXT_BYTES
        self.cache: dict[str, tuple[list[str], list[str]]] = {}
        self.notes: dict[str, list[str]] = {}

    def _resolve(self, base: str, suffixes: tuple[str, ...]) -> str | None:
        base = posixpath.normpath(base)
        if base.startswith(("../", "/")) or base == "..":
            return None
        candidates = {base}
        if not Path(base).suffix:
            candidates.update(base + suffix for suffix in suffixes)
            candidates.update(base + "/index" + suffix for suffix in suffixes)
            candidates.update(
                base + "/init" + suffix for suffix in (".lua", ".luau") if suffix in suffixes
            )
            if ".py" in suffixes:
                candidates.add(base + "/__init__.py")
        elif Path(base).suffix in {".js", ".mjs", ".cjs"} and ".ts" in suffixes:
            candidates.update(posixpath.splitext(base)[0] + s for s in (".ts", ".tsx"))
        matches = sorted(candidates & self.paths)
        return matches[0] if len(matches) == 1 else None

    def imports(self, relative: str) -> tuple[list[str], list[str]]:
        if relative in self.cache:
            return self.cache[relative]
        found: list[str] = []
        notes: list[str] = []
        self.cache[relative] = (found, notes)
        if relative not in self.paths:
            return found, ["source outside eligible context scope"]
        try:
            content = read_source(self.root, relative, min(131072, self.remaining_bytes))
            self.remaining_bytes -= len(content)
            source = content.decode("utf-8")
            suffix = Path(relative).suffix.lower()
            parent = posixpath.dirname(relative)
            requests: list[tuple[str, tuple[str, ...]]] = []
            if suffix in {".py", ".pyi"}:
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        if node.level:
                            base = parent
                            for _ in range(node.level - 1):
                                base = posixpath.normpath(posixpath.join(base, ".."))
                            if node.module:
                                requests.append(
                                    (posixpath.join(base, node.module.replace(".", "/")), (".py",))
                                )
                            else:
                                requests.extend(
                                    (posixpath.join(base, n.name), (".py",)) for n in node.names
                                )
                        elif node.module:
                            requests.append((node.module.replace(".", "/"), (".py",)))
                    elif isinstance(node, ast.Import):
                        requests.extend((n.name.replace(".", "/"), (".py",)) for n in node.names)
            elif suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".dart", ".lua", ".luau"}:
                if suffix in {".dart", ".lua", ".luau"}:
                    from polyglot_checks import tokens

                    values = [t[0] for t in tokens(source, "dart" if suffix == ".dart" else "lua")]
                else:
                    from js_config_checks import js_context_tokens

                    values = [t[0] for t in js_context_tokens(source)]
                    if not values and source.strip():
                        notes.append("JS/TS lexical context unresolved")
                suffixes = (
                    (".dart",)
                    if suffix == ".dart"
                    else (
                        (".lua", ".luau")
                        if suffix in {".lua", ".luau"}
                        else (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
                    )
                )
                for i, lexeme in enumerate(values):
                    literal = None
                    if lexeme in {"from", "import", "export"} and i + 1 < len(values):
                        literal = values[i + 1]
                    elif lexeme in {"require", "import"} and values[i + 1 : i + 2] == ["("]:
                        if values[i + 2 : i + 3] == ["script"]:
                            cursor, base = i + 3, relative
                            while values[cursor : cursor + 1] == ["."] and cursor + 1 < len(values):
                                name = values[cursor + 1]
                                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name):
                                    break
                                base = (
                                    posixpath.normpath(posixpath.join(base, ".."))
                                    if name == "Parent"
                                    else posixpath.join(base, name)
                                )
                                cursor += 2
                            if values[cursor : cursor + 1] == [")"]:
                                requests.append((base, suffixes))
                            continue
                        literal = values[i + 2] if i + 2 < len(values) else None
                        if values[i + 3 : i + 4] != [")"]:
                            literal = None
                        if literal is None or not literal.startswith(("'", '"')):
                            notes.append("dynamic import unresolved")
                    if (
                        literal
                        and len(literal) > 2
                        and literal[0] in {"'", '"'}
                        and literal[-1] == literal[0]
                    ):
                        name = literal[1:-1]
                        if "\\" in name or "$" in name or not name.startswith("."):
                            notes.append("nonlocal or escaped import unresolved")
                        else:
                            requests.append((posixpath.join(parent, name), suffixes))
            else:
                notes.append("import binding unsupported for this language")
            for base, suffixes in requests[:128]:
                match = self._resolve(base, suffixes)
                if match is None:
                    notes.append("local import missing, excluded, or ambiguous")
                elif match != relative and match not in found:
                    found.append(match)
            if len(requests) > 128:
                notes.append("import request budget exhausted")
        except (OSError, ValueError, SyntaxError, RecursionError):
            notes.append("context source unavailable or parser/byte budget exhausted")
        return found, notes

    def __call__(self, relative: str, _root: Path) -> list[str]:
        related, notes = self.imports(relative)
        self.notes[relative] = list(notes)
        stem = Path(relative).stem
        test_names = {f"test_{stem}.py", f"{stem}_test.go"}
        test_names.update(
            f"{stem}.{kind}{suffix}"
            for kind in ("test", "spec")
            for suffix in (".ts", ".tsx", ".js", ".jsx", ".lua", ".luau", ".dart")
        )
        test_candidates = sorted(p for p in self.paths if Path(p).name in test_names)
        for candidate in test_candidates[:8]:
            imports, _notes = self.imports(candidate)
            if relative in imports and candidate not in related:
                related = [*related, candidate]
        if len(test_candidates) > 8:
            self.notes[relative].append("test-candidate budget exhausted")
        if len(related) > 4:
            self.notes[relative].append("related-file hint budget exhausted")
        return related[:4]
