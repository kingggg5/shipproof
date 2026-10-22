"""Bounded, original Luau/Rust/Go signatures with lexical source positions.

This is intentionally not a compiler or a general taint engine. Unrecognized
bindings/flows stay outside these advisory checks; lexical exhaustion is an
explicit coverage error rather than a clean result.
"""

from __future__ import annotations

import re
from collections import Counter

MAX_TOKENS = 50_000
WORD = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|[0-9]+|::|[.][.][.]")
LUA_LONG = re.compile(r"\[(=*)\[")
RUST_RAW = re.compile(r'(?:br|r)(#*)"')
RUST_LIFETIME = re.compile(r"'[A-Za-z_][A-Za-z_0-9]*")


class LexicalLimitError(ValueError):
    """Unsupported incomplete lexical input or exhausted token budget."""


def tokens(source: str, language: str) -> list[tuple[str, int, int]]:
    result: list[tuple[str, int, int]] = []

    def record(value: str, start: int, end: int) -> None:
        if len(result) >= MAX_TOKENS:
            raise LexicalLimitError("polyglot token budget exceeded")
        result.append((value, start, end))

    index = 0
    while index < len(source):
        start = index
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if language == "lua":
            comment = source.startswith("--", index)
            opening = LUA_LONG.match(source, index + 2 if comment else index)
            if opening:
                closing = "]" + opening[1] + "]"
                end = source.find(closing, opening.end())
                if end < 0:
                    raise LexicalLimitError("unterminated Lua long literal")
                index = end + len(closing)
                if not comment:
                    record("<literal>", start, index)
                continue
            if comment:
                end = source.find("\n", index)
                index = len(source) if end < 0 else end
                continue
        else:
            if language == "go" and char == "`":
                end = source.find("`", index + 1)
                if end < 0:
                    raise LexicalLimitError("unterminated Go raw string")
                index = end + 1
                record(source[start:index], start, index)
                continue
            if source.startswith("//", index):
                end = source.find("\n", index)
                index = len(source) if end < 0 else end
                continue
            if source.startswith("/*", index):
                depth = 1
                index += 2
                while index < len(source) and depth:
                    if language == "rust" and source.startswith("/*", index):
                        depth += 1
                        index += 2
                    elif source.startswith("*/", index):
                        depth -= 1
                        index += 2
                    else:
                        index += 1
                if depth:
                    raise LexicalLimitError("unterminated native block comment")
                continue
            raw = RUST_RAW.match(source, index) if language == "rust" else None
            if raw:
                end = source.find('"' + raw[1], raw.end())
                if end < 0:
                    raise LexicalLimitError("unterminated Rust raw string")
                index = end + 1 + len(raw[1])
                record("<literal>", start, index)
                continue
            # A Rust lifetime is not a character literal.
            lifetime = (
                RUST_LIFETIME.match(source, index) if language == "rust" and char == "'" else None
            )
            if lifetime:
                end = lifetime.end()
                if source[end : end + 1] != "'":
                    record(source[index:end], start, end)
                    index = end
                    continue
        if char in ({"'", '"', "`"} if language == "lua" else {"'", '"'}):
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == char:
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise LexicalLimitError("unterminated quoted literal")
            record(source[start:index], start, index)
        else:
            word = WORD.match(source, index)
            index = word.end() if word else index + 1
            record(source[start:index], start, index)
    return result


def shadowed(values: list[str], name: str) -> bool:
    for i, value in enumerate(values):
        if value == "function":
            opening = i + 1
            # Named/dotted/method declarations can shadow a builtin too.
            while opening < min(len(values), i + 32) and values[opening] != "(":
                if values[opening] in {"end", "=", ";"}:
                    break
                opening += 1
            if values[opening : opening + 1] != ["("]:
                continue
            closing = opening + 1
            while closing < min(len(values), opening + 128) and values[closing] != ")":
                if values[closing] == name:
                    return True
                closing += 1
            if closing == min(len(values), opening + 128):
                return True  # ambiguous/oversized declaration: do not guess binding
    return any(
        value == name
        and (
            (index > 0 and values[index - 1] in {"local", "function", "fn", "mod", "as", "struct"})
            or values[index + 1 : index + 2] == ["="]
        )
        for index, value in enumerate(values)
    )


def delimiter_pairs(values: list[str]) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stack: list[int] = []
    closing = {")": "(", "]": "[", "}": "{"}
    for index, value in enumerate(values):
        if value in {"(", "[", "{"}:
            stack.append(index)
            if len(stack) > 128:
                raise LexicalLimitError("native delimiter nesting exceeded")
        elif value in closing:
            if not stack or values[stack[-1]] != closing[value]:
                raise LexicalLimitError("unbalanced native delimiters")
            opening = stack.pop()
            pairs[opening] = index
    if stack:
        raise LexicalLimitError("unbalanced native delimiters")
    return pairs


def go_duration(expression: list[str] | None, imports: dict[str, str]) -> str:
    if expression is None:
        return "zero"
    sign = -1 if expression[:1] == ["-"] else 1
    expression = expression[1:] if sign < 0 else expression
    constant = len(expression) == 1 or (
        len(expression) == 5
        and expression[1] == "*"
        and imports.get(expression[2]) == "time"
        and expression[3] == "."
        and expression[4]
        in {"Nanosecond", "Microsecond", "Millisecond", "Second", "Minute", "Hour"}
    )
    if constant and expression and expression[0].isdigit():
        return ("negative" if sign < 0 else "positive") if expression[0].lstrip("0") else "zero"
    return "unknown"


def go_spans(stream: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    values = [item[0] for item in stream]
    if "import" not in values or not any(
        value.strip('"`') in {"context", "net/http"} for value in values
    ):
        return []
    pairs = delimiter_pairs(values)
    imports: dict[str, str] = {}
    for index, value in enumerate(values[:-1]):
        if value != "import":
            continue
        end = pairs.get(index + 1, index + 2)
        for cursor in range(index + 1, min(end + 1, len(values))):
            literal = values[cursor]
            if literal.strip('"`') not in {"context", "net/http", "time"}:
                continue
            previous = values[cursor - 1]
            alias = (
                previous
                if re.fullmatch(r"[A-Za-z_]\w*", previous) and previous != "import"
                else literal[1:-1].split("/")[-1]
            )
            if alias != "_" and previous != ".":
                imports[alias] = literal[1:-1]
    hits: list[tuple[str, int, int]] = []
    shadowed_aliases = {
        value
        for index, value in enumerate(values[:-2])
        if values[index + 1 : index + 3] == [":", "="]
        or (index > 0 and values[index - 1] in {"var", "type"})
    }
    deadline_writes = {
        value: index
        for index, value in enumerate(values[:-3])
        if values[index + 1] == "."
        and values[index + 2] in {"ReadHeaderTimeout", "ReadTimeout"}
        and values[index + 3] == "="
    }
    # A package-looking name in a function's parameter list is not a proven
    # package binding. Conservatively leave that file's binding unresolved.
    for index, value in enumerate(values):
        if value != "func":
            continue
        cursor = index + 1
        while cursor < min(len(values), index + 128) and values[cursor] not in {"{", ";"}:
            if values[cursor] == "(" and cursor in pairs:
                shadowed_aliases.update(
                    values[pos]
                    for pos in range(cursor + 1, pairs[cursor])
                    if values[pos] in imports
                    and values[pos + 1] != "."
                    and values[pos - 1] not in {".", "*"}
                )
                cursor = pairs[cursor]
            cursor += 1
    for index in range(len(values) - 4):
        alias = values[index]
        if alias not in imports or values[index + 1] != ".":
            continue
        if alias in shadowed_aliases:
            continue
        name, opening = values[index + 2], index + 3
        if imports[alias] == "context" and name in {"WithCancel", "WithTimeout", "WithDeadline"}:
            discarded = values[max(0, index - 4) : index] in ([",", "_", ":", "="],) or values[
                max(0, index - 3) : index
            ] == [",", "_", "="]
            if discarded and values[opening] == "(" and opening in pairs:
                hits.append(("SP378", stream[index][1], stream[pairs[opening]][2]))
        if (
            imports[alias] != "net/http"
            or name != "Server"
            or values[opening] != "{"
            or opening not in pairs
        ):
            continue
        end = pairs[opening]
        fields: dict[str, list[str]] = {}
        cursor = opening + 1
        supported_fields = True
        while cursor + 1 < end:
            if values[cursor + 1] != ":":
                supported_fields = False
                break
            field, first = values[cursor], cursor + 2
            cursor = first
            while cursor < end and values[cursor] != ",":
                cursor = pairs.get(cursor, cursor) + 1
            fields[field] = values[first:cursor]
            cursor += 1
        if not supported_fields or (cursor < end and values[cursor] != ","):
            continue

        header = go_duration(fields.get("ReadHeaderTimeout"), imports)
        total = go_duration(fields.get("ReadTimeout"), imports)
        # Later configuration of this local object is outside a literal-only
        # claim. Do not mistake a construction default for the served state.
        before = values[max(0, index - 4) : index]
        if before[-1:] == ["&"]:
            before = before[:-1]
        variable = (
            before[-3]
            if before[-2:] == [":", "="]
            else before[-2]
            if before[-1:] == ["="] and len(before) >= 2
            else None
        )
        if variable and deadline_writes.get(variable, -1) > end:
            continue
        if header == "negative" or (header == "zero" and total in {"zero", "negative"}):
            hits.append(("SP377", stream[index][1], stream[end][2]))
    return hits


def rust_http_spans(stream: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    values = [item[0] for item in stream]
    if not any(value in {"unwrap", "expect"} for value in values) or not set(values) & {
        "actix_web",
        "rocket",
        "axum",
    }:
        return []
    pairs = delimiter_pairs(values)
    reverse = {last: first for first, last in pairs.items()}
    methods = {"get", "post", "put", "delete", "patch", "head", "options", "route"}
    hidden = {name for name in ("actix_web", "rocket", "axum") if shadowed(values, name)}
    declared = {
        token
        for pos, token in enumerate(values)
        if pos > 0 and values[pos - 1] in {"fn", "mod", "struct", "let"}
    }
    route_imports: dict[str, str] = {}
    for index, value in enumerate(values):
        if value != "use":
            continue
        cursor = index + 1
        imported: list[str] = []
        while cursor < min(len(values), index + 128) and values[cursor] != ";":
            imported.append(values[cursor])
            cursor += 1
        for prefix, kind in (
            (["actix_web", "::"], "attribute"),
            (["rocket", "::"], "attribute"),
            (["axum", "::", "routing", "::"], "call"),
        ):
            if prefix[0] in hidden or imported[: len(prefix)] != prefix:
                continue
            names = imported[len(prefix) :]
            if names[:1] == ["{"] and names[-1:] == ["}"]:
                names = names[1:-1]
            for segment in " ".join(names).split(","):
                parts = segment.split()
                if parts and parts[0] in methods:
                    alias = (
                        parts[0]
                        if len(parts) == 1
                        else parts[2]
                        if len(parts) == 3 and parts[1] == "as"
                        else None
                    )
                    if alias and alias not in declared:
                        route_imports[alias] = kind
    functions: dict[int, tuple[str, int]] = {}
    handlers: set[str] = set()
    counts: Counter[str] = Counter()
    for index, value in enumerate(values[:-2]):
        if value != "fn" or not re.fullmatch(r"[A-Za-z_]\w*", values[index + 1]):
            continue
        name = values[index + 1]
        cursor = index + 2
        limit = min(len(values), index + 256)
        while cursor < limit and values[cursor] not in {"{", ";"}:
            if values[cursor] == "(" and cursor in pairs:
                for pos in range(cursor + 1, pairs[cursor]):
                    if values[pos + 1] == ":" and route_imports.get(values[pos]) == "call":
                        route_imports.pop(values[pos])
            cursor = pairs.get(cursor, cursor) + 1
        if cursor >= limit or values[cursor] != "{" or cursor not in pairs:
            continue
        functions[cursor] = (name, pairs[cursor])
        counts[name] += 1
        before = index - 1
        while before >= 0 and values[before] in {"pub", "async", "unsafe"}:
            before -= 1
        if (
            before in reverse
            and values[before] == ")"
            and values[max(0, reverse[before] - 1) : reverse[before]] == ["pub"]
        ):
            before = reverse[before] - 2
        bound, test_only = False, False
        for _ in range(8):
            if (
                before not in reverse
                or values[before] != "]"
                or values[max(0, reverse[before] - 1) : reverse[before]] != ["#"]
            ):
                break
            opening = reverse[before]
            attribute = values[opening + 1 : before]
            test_only |= attribute == ["cfg", "(", "test", ")"]
            if (
                len(attribute) >= 4
                and attribute[0] in {"actix_web", "rocket"}
                and attribute[0] not in hidden
                and attribute[1] == "::"
                and attribute[2] in methods
            ) or (
                attribute
                and route_imports.get(attribute[0]) == "attribute"
                and attribute[1:2] == ["("]
            ):
                bound = True
            before = opening - 2
        if bound and not test_only:
            handlers.add(name)
    for index in range(len(values) - 3):
        if (
            "axum" not in hidden
            and values[index : index + 4] == ["axum", "::", "routing", "::"]
            and len(values[index : index + 8]) == 8
            and values[index + 4] in methods
            and values[index + 5] == "("
            and values[index + 7] == ")"
        ):
            handlers.add(values[index + 6])
        if (
            route_imports.get(values[index]) == "call"
            and (index == 0 or values[index - 1] not in {".", "::"})
            and values[index + 1] == "("
            and re.fullmatch(r"[A-Za-z_]\w*", values[index + 2])
            and values[index + 3] == ")"
        ):
            handlers.add(values[index + 2])
    owners: list[tuple[str, int]] = []
    hits: list[tuple[str, int, int]] = []
    for index, value in enumerate(values):
        while owners and index > owners[-1][1]:
            owners.pop()
        if index in functions:
            owners.append(functions[index])
        if not owners or owners[-1][0] not in handlers or counts[owners[-1][0]] != 1:
            continue
        if value != "." or values[index + 1 : index + 3] not in (["unwrap", "("], ["expect", "("]):
            continue
        opening = index + 2
        end = pairs.get(opening)
        if (
            end is None
            or (values[index + 1] == "unwrap" and end != opening + 1)
            or (values[index + 1] == "expect" and end == opening + 1)
        ):
            continue
        receiver = reverse.get(index - 1)
        if receiver is not None and values[max(0, receiver - 1) : receiver] in (["Some"], ["Ok"]):
            # Explicit success constructors cannot fail at this unwrap site.
            continue
        hits.append(("SP621", stream[index][1], stream[end][2]))
    return hits


def signature_spans(source: str, language: str) -> list[tuple[str, int, int]]:
    if language == "go" and not any(
        name in source for name in ("Server", "WithCancel", "WithTimeout", "WithDeadline")
    ):
        return []
    stream = tokens(source, language)
    if language == "go":
        return go_spans(stream)
    values = [item[0] for item in stream]
    hits: list[tuple[str, int, int]] = []

    def emit(rule_id: str, first: int, last: int) -> None:
        hits.append((rule_id, stream[first][1], stream[last][2]))

    if language == "lua":
        if shadowed(values, "loadstring") or shadowed(values, "game"):
            return []
        services: set[str] = set()
        counts = Counter(values)
        for i in range(len(values) - 9):
            if (
                values[i] == "local"
                and values[i + 2 : i + 7] == ["=", "game", ":", "GetService", "("]
                and values[i + 7] in {'"HttpService"', "'HttpService'"}
                and values[i + 8] == ")"
            ):
                name = values[i + 1]
                # Require one binding and no later assignments/parameters.
                if counts[name] == 2:
                    services.add(name)
        for i in range(len(values) - 8):
            if values[i : i + 2] != ["loadstring", "("]:
                continue
            if i and values[i - 1] in {".", ":"}:
                continue
            if (
                values[i + 2] in services
                and values[i + 3 : i + 6] == [":", "GetAsync", "("]
                and values[i + 7 : i + 11] == [")", ")", "(", ")"]
                and not values[i + 6].startswith("<")
            ):
                emit("SP671", i, i + 10)
        # Deliberately require the sink as the entire first callback statement.
        # Guards, aliases and arbitrary callback bodies need a real flow engine.
        for i in range(len(values) - 15):
            if values[i : i + 6] != [".", "OnServerEvent", ":", "Connect", "(", "function"]:
                continue
            if values[i + 6] != "(":
                continue
            end = i + 7
            while end < min(len(values), i + 24) and values[end] != ")":
                end += 1
            params = values[i + 7 : end]
            if (
                len(params) != 3
                or params[1] != ","
                or not all(re.fullmatch(r"[A-Za-z_]\w*", p) for p in (params[0], params[2]))
            ):
                continue
            body = end + 1
            if values[body : body + 8] == ["loadstring", "(", params[2], ")", "(", ")", "end", ")"]:
                emit("SP672", body, body + 5)
    else:
        hidden = {name for name in ("std", "core", "reqwest") if shadowed(values, name)}
        for i in range(len(values) - 6):
            if i >= 2 and values[i - 1] == "::" and re.fullmatch(r"\w+", values[i - 2]):
                continue
            if (
                values[i] in {"std", "core"}
                and values[i] not in hidden
                and values[i + 1 : i + 6] == ["::", "mem", "::", "zeroed", "::"]
            ):
                opening = i + 6
                if values[opening : opening + 2] != ["<", "&"]:
                    continue
                closing = opening + 2
                while closing < min(len(values), opening + 32) and values[closing] != ">":
                    closing += 1
                if values[closing : closing + 3] == [">", "(", ")"]:
                    emit("SP673", i, closing + 2)
            if values[i] != "reqwest" or "reqwest" in hidden:
                continue
            cursor = i + 1
            if values[cursor : cursor + 2] == ["::", "blocking"]:
                cursor += 2
            if values[cursor : cursor + 6] != ["::", "Client", "::", "builder", "(", ")"]:
                continue
            cursor += 6
            # Read one bounded chain to build(), keeping the final value of
            # each TLS switch. A later false/unknown overrides an earlier true.
            methods = {
                "danger_accept_invalid_certs",
                "danger_accept_invalid_hostnames",
                "tls_danger_accept_invalid_certs",
                "tls_danger_accept_invalid_hostnames",
            }
            settings: dict[str, tuple[str, int, int]] = {}
            limit = min(len(values), cursor + 256)
            while cursor + 3 < limit and values[cursor] == ".":
                if values[cursor + 2] != "(":
                    break
                closing = cursor + 3
                depth = 1
                while closing < limit and depth:
                    if values[closing] == "(":
                        depth += 1
                    elif values[closing] == ")":
                        depth -= 1
                    closing += 1
                if depth:
                    break
                method = values[cursor + 1]
                arguments = values[cursor + 3 : closing - 1]
                if method in methods:
                    key = method.removeprefix("tls_")
                    state = arguments[0] if len(arguments) == 1 else "unknown"
                    settings[key] = (state, cursor + 1, closing - 1)
                if method == "build":
                    if not arguments:
                        for state, first, last in settings.values():
                            if state == "true":
                                emit("SP104", first, last)
                    break
                cursor = closing
    if language == "rust":
        hits.extend(rust_http_spans(stream))
    return list(dict.fromkeys(hits))
