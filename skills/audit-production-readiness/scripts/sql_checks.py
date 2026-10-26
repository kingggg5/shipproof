"""Small bounded PostgreSQL signatures. Never connect, execute or expand SQL."""

from __future__ import annotations

import re

WORD = re.compile(r"[A-Za-z_][A-Za-z_0-9$]*", re.ASCII)
DOLLAR = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$", re.ASCII)
MAX_TOKENS = 50_000


class LexicalLimitError(ValueError):
    """SQL lexical evidence is unavailable; callers must not report complete proof."""


def tokens(source: str) -> list[tuple[str, int, int]]:
    result = []
    index = 0
    while index < len(source):
        start = index
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("--", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source.startswith("/*", index):
                    depth += 1
                    if depth > 128:
                        raise LexicalLimitError("comment nesting")
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise LexicalLimitError("unterminated comment")
            continue
        dollar = DOLLAR.match(source, index) if char == "$" else None
        if dollar:
            end = source.find(dollar.group(), dollar.end())
            if end < 0:
                raise LexicalLimitError("unterminated dollar body")
            index = end + len(dollar.group())
            value = source[start:index]
        elif char in {"'", '"'}:
            escaped = (
                char == "'"
                and start > 0
                and source[start - 1] in {"e", "E"}
                and (start < 2 or not (source[start - 2].isalnum() or source[start - 2] == "_"))
            )
            index += 1
            while index < len(source):
                if source[index] == "\\" and char == "'":
                    if not escaped:
                        raise LexicalLimitError("ambiguous string escape policy")
                    index += 2
                elif source[index] == char:
                    index += 1
                    if index < len(source) and source[index] == char:
                        index += 1
                    else:
                        break
                else:
                    index += 1
            else:
                raise LexicalLimitError("unterminated quote")
            value = source[start:index]
        elif char == "\\":
            raise LexicalLimitError("psql metacommand")
        else:
            match = WORD.match(source, index)
            index = match.end() if match else index + 1
            value = source[start:index].upper()
        result.append((value, start, index))
        if len(result) > MAX_TOKENS:
            raise LexicalLimitError("token budget")
    return result


def literal_body(value: str) -> str | None:
    if value.startswith("$"):
        delimiter = DOLLAR.match(value)
        if delimiter:
            return value[delimiter.end() : -len(delimiter.group())]
    if value.startswith("'") and value.endswith("'") and "\\" not in value:
        return value[1:-1].replace("''", "'")
    return None


def temp_first_definer(values: list[str]) -> bool:
    """A single SQL SELECT reads a bare relation with explicit temp-first lookup."""
    prefix = values[1:]
    if prefix[:2] == ["OR", "REPLACE"]:
        prefix = prefix[2:]
    if not values or values[0] != "CREATE" or prefix[:1] != ["FUNCTION"]:
        return False
    if len(values) > 512 or values.count("SECURITY") != 1 or values.count("SEARCH_PATH") != 1:
        return False
    security = values.index("SECURITY")
    path = values.index("SEARCH_PATH")
    if (
        values[security + 1 : security + 2] != ["DEFINER"]
        or not path
        or values[path - 1] != "SET"
        or values[path + 1 : path + 2] not in (["="], ["TO"])
    ):
        return False
    if not any(
        values[i : i + 2] in (["LANGUAGE", "SQL"], ["LANGUAGE", "'sql'"])
        for i in range(len(values) - 1)
    ):
        return False
    start = path + 2
    end = start
    while end < len(values) and (end == start or values[end - 1] == "," or values[end] == ","):
        end += 1
    if end < len(values) and values[end] not in {
        "AS",
        "LANGUAGE",
        "SECURITY",
        "SET",
        "IMMUTABLE",
        "STABLE",
        "VOLATILE",
        "STRICT",
        "PARALLEL",
        "COST",
        "ROWS",
        "SUPPORT",
        "CALLED",
        "RETURNS",
        "TRANSFORM",
        "WINDOW",
        "NOT",
        "LEAKPROOF",
    }:
        return False
    names = values[start:end]
    if len(names) == 1 and names[0].startswith("'"):
        body = literal_body(names[0])
        names = [part.strip().upper() for part in body.split(",")] if body is not None else []
    else:
        if len(names) % 2 == 0 or any(value != "," for value in names[1::2]):
            return False
        names = [
            value[1:-1] if value.startswith('"') and value.endswith('"') else value.lower()
            for value in names[::2]
        ]
        names = [name.upper() if name == name.lower() else "" for name in names]
    if len(names) < 2 or names[0] != "PG_TEMP" or any(not WORD.fullmatch(name) for name in names):
        return False
    bodies = [literal_body(values[i + 1]) for i, value in enumerate(values[:-1]) if value == "AS"]
    if len(bodies) != 1 or bodies[0] is None:
        return False
    body = [value for value, _start, _end in tokens(bodies[0])]
    if body[-1:] == [";"]:
        body.pop()
    if not body or body[0] != "SELECT" or ";" in body or "SEARCH_PATH" in body:
        return False
    depth = 0
    for i, value in enumerate(body[:-1]):
        depth += int(value == "(") - int(value == ")")
        if (
            value == "FROM"
            and depth == 0
            and WORD.fullmatch(body[i + 1])
            and body[i + 1] not in {"ONLY", "LATERAL", "ROWS", "SELECT", "VALUES", "TABLE"}
            and body[i + 2 : i + 3] not in (["."], ["("])
        ):
            return True
    return False


def signature_spans(source: str) -> list[tuple[str, int, int, str]]:
    stream = tokens(source)
    values = [value for value, _start, _end in stream]
    # Unquoted procedural bodies need a grammar-aware parser. Never treat their
    # BEGIN/END or internal semicolons as top-level transaction control.
    if any(values[i : i + 2] == ["BEGIN", "ATOMIC"] for i in range(len(values))):
        return []
    statements = []
    start = depth = 0
    for index, value in enumerate(values):
        if value == "(":
            depth += 1
        elif value == ")":
            depth -= 1
            if depth < 0:
                raise LexicalLimitError("unbalanced delimiters")
        elif value == ";" and depth == 0:
            statements.append((start, index))
            start = index + 1
    if depth:
        raise LexicalLimitError("unbalanced delimiters")
    if start < len(values):
        statements.append((start, len(values)))
    lifecycle_unknown = any(
        values[first : first + 2] in (["ALTER", "FUNCTION"], ["DROP", "FUNCTION"])
        for first, _last in statements
    )
    active = False
    hits = []
    for first, last in statements:
        statement = values[first:last]
        if not statement:
            continue
        if statement in (
            ["BEGIN"],
            ["BEGIN", "WORK"],
            ["BEGIN", "TRANSACTION"],
            ["START", "TRANSACTION"],
        ):
            active = True
        elif statement[0] in {"COMMIT", "END", "ROLLBACK", "ABORT", "PREPARE"} and statement[
            1:2
        ] != ["TO"]:
            active = statement[-2:] == ["AND", "CHAIN"]
        prefix = statement[1:] if statement[:1] == ["CREATE"] else []
        if prefix[:1] == ["UNIQUE"]:
            prefix = prefix[1:]
        operation = "CREATE" if prefix[:2] == ["INDEX", "CONCURRENTLY"] else ""
        if statement[:3] == ["DROP", "INDEX", "CONCURRENTLY"]:
            operation = "DROP"
        if (
            statement[:1] == ["REINDEX"]
            and statement[1:2] in (["INDEX"], ["TABLE"])
            and statement[2:3] == ["CONCURRENTLY"]
        ):
            operation = "REINDEX"
        if active and operation:
            hits.append(
                (
                    "SP705",
                    stream[first][1],
                    stream[last - 1][2],
                    f"PostgreSQL {operation} concurrent index operation occurs inside an explicit transaction block",
                )
            )
        if not lifecycle_unknown and temp_first_definer(statement):
            hits.append(
                (
                    "SP706",
                    stream[first][1],
                    stream[last - 1][2],
                    "SQL SECURITY DEFINER SELECT uses an unqualified relation with pg_temp first in its explicit search_path",
                )
            )
    return hits
