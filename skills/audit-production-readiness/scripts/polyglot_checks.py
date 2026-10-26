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


def dart_literal_end(source: str, start: int, nesting: int = 0) -> int:
    """Skip raw, multiline and interpolated Dart strings without evaluating them."""
    if nesting > 32:
        raise LexicalLimitError("Dart interpolation nesting exceeded")
    raw = source[start] == "r"
    quote_start = start + int(raw)
    quote = source[quote_start]
    delimiter = quote * 3 if source.startswith(quote * 3, quote_start) else quote
    cursor = quote_start + len(delimiter)
    while cursor < len(source):
        if source.startswith(delimiter, cursor):
            return cursor + len(delimiter)
        if not raw and source[cursor] == "\\":
            cursor += 2
            continue
        if not raw and source.startswith("${", cursor):
            cursor += 2
            depth = 1
            while cursor < len(source) and depth:
                char = source[cursor]
                if char in {"'", '"'} or (
                    char == "r" and source[cursor + 1 : cursor + 2] in {"'", '"'}
                ):
                    cursor = dart_literal_end(source, cursor, nesting + 1)
                elif source.startswith("//", cursor):
                    end = source.find("\n", cursor)
                    cursor = len(source) if end < 0 else end
                elif source.startswith("/*", cursor):
                    comment_depth = 1
                    cursor += 2
                    while cursor < len(source) and comment_depth:
                        if source.startswith("/*", cursor):
                            comment_depth += 1
                            cursor += 2
                        elif source.startswith("*/", cursor):
                            comment_depth -= 1
                            cursor += 2
                        else:
                            cursor += 1
                        if comment_depth > 128:
                            raise LexicalLimitError("Dart comment nesting exceeded")
                else:
                    depth += int(char == "{") - int(char == "}")
                    if depth > 128:
                        raise LexicalLimitError("Dart interpolation braces exceeded")
                    cursor += 1
            if depth:
                raise LexicalLimitError("unterminated Dart interpolation")
            continue
        if len(delimiter) == 1 and source[cursor] in "\r\n":
            raise LexicalLimitError("newline in Dart single-line literal")
        cursor += 1
    raise LexicalLimitError("unterminated Dart literal")


def lua_literal_end(source: str, start: int, nesting: int = 0) -> int:
    """Keep the whole interpolated string opaque, including nested backticks."""
    if nesting > 32:
        raise LexicalLimitError("Luau interpolation nesting exceeded")
    quote = source[start]
    cursor = start + 1
    while cursor < len(source):
        char = source[cursor]
        if char == "\\":
            cursor += 2
        elif char == quote:
            return cursor + 1
        elif quote == "`" and char == "{":
            depth = 1
            cursor += 1
            while cursor < len(source) and depth:
                char = source[cursor]
                if char in {"'", '"', "`"}:
                    cursor = lua_literal_end(source, cursor, nesting + 1)
                    continue
                comment = source.startswith("--", cursor)
                opening = LUA_LONG.match(source, cursor + 2 if comment else cursor)
                if opening:
                    delimiter = "]" + opening[1] + "]"
                    end = source.find(delimiter, opening.end())
                    if end < 0:
                        raise LexicalLimitError("unterminated Luau interpolation literal")
                    cursor = end + len(delimiter)
                elif comment:
                    end = source.find("\n", cursor)
                    cursor = len(source) if end < 0 else end + 1
                else:
                    depth += int(char == "{") - int(char == "}")
                    if depth > 128:
                        raise LexicalLimitError("Luau interpolation braces exceeded")
                    cursor += 1
            if depth:
                raise LexicalLimitError("unterminated Luau interpolation")
        else:
            cursor += 1
    raise LexicalLimitError("unterminated Lua quoted literal")


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
            comment = char == "-" and source.startswith("--", index)
            opening = (
                LUA_LONG.match(source, index + 2 if comment else index)
                if comment or char == "["
                else None
            )
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
            if char == "/" and source.startswith("//", index):
                end = source.find("\n", index)
                index = len(source) if end < 0 else end
                continue
            if char == "/" and source.startswith("/*", index):
                depth = 1
                index += 2
                while index < len(source) and depth:
                    if language in {"rust", "dart"} and source.startswith("/*", index):
                        depth += 1
                        if language == "dart" and depth > 128:
                            raise LexicalLimitError("Dart comment nesting exceeded")
                        index += 2
                    elif source.startswith("*/", index):
                        depth -= 1
                        index += 2
                    else:
                        index += 1
                if depth:
                    raise LexicalLimitError("unterminated native block comment")
                continue
            raw = (
                RUST_RAW.match(source, index) if language == "rust" and char in {"r", "b"} else None
            )
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
        if language == "dart" and (
            char in {"'", '"'} or (char == "r" and source[index + 1 : index + 2] in {"'", '"'})
        ):
            index = dart_literal_end(source, start)
            record(source[start:index], start, index)
            continue
        if language == "lua" and char in {"'", '"', "`"}:
            index = lua_literal_end(source, start)
            record(source[start:index], start, index)
        elif char in {"'", '"'}:
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


def lua_spans(stream: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """Direct remote boundaries only; no execution, type inference or alias flow."""
    values = [item[0] for item in stream]
    if not {"loadstring", "OnServerEvent", "OnServerInvoke"}.intersection(values):
        return []
    counts = Counter(values)
    positions: dict[str, list[int]] = {}
    boundary_at: list[int] = []
    boundary = 0
    for index, value in enumerate(values):
        positions.setdefault(value, []).append(index)
        boundary_at.append(boundary)
        boundary += int(value in {"end", "else", "elseif", "until"})
    hits: list[tuple[str, int, int]] = []

    def emit(rule_id: str, first: int, last: int) -> None:
        hits.append((rule_id, stream[first][1], stream[last][2]))

    def expression_continues(index: int) -> bool:
        return index < len(values) and values[index] in {
            ".",
            ":",
            "::",
            "[",
            "(",
            "and",
            "or",
            "+",
            "-",
            "*",
            "/",
            "%",
            "^",
            "<",
            ">",
            "=",
            "~",
        }

    def builtin(name: str, suffix: list[str]) -> bool:
        # Escapes, multi-local declarations, loop variables and function names
        # all invalidate builtin identity. Type/member spellings are not uses.
        for index, value in enumerate(values):
            if value != name:
                continue
            previous = values[index - 1] if index else ""
            if previous in {".", ":", "::"}:
                continue
            if previous == "function" or values[index + 1 : index + 1 + len(suffix)] != suffix:
                return False
        return not any(value in {"getfenv", "setfenv"} for value in values)

    evaluator = "loadstring" in positions and builtin("loadstring", ["("])
    if evaluator and not shadowed(values, "game"):
        services: set[str] = set()
        for i in range(len(values) - 8):
            if (
                values[i] == "local"
                and values[i + 2 : i + 7] == ["=", "game", ":", "GetService", "("]
                and values[i + 7] in {'"HttpService"', "'HttpService'"}
                and values[i + 8] == ")"
                and counts[values[i + 1]] == 2
            ):
                services.add(values[i + 1])
        for i in range(len(values) - 10):
            if (
                values[i : i + 2] == ["loadstring", "("]
                and (i == 0 or values[i - 1] not in {".", ":"})
                and values[i + 2] in services
                and values[i + 3 : i + 6] == [":", "GetAsync", "("]
                and values[i + 7 : i + 11] == [")", ")", "(", ")"]
                and not values[i + 6].startswith("<")
            ):
                emit("SP671", i, i + 10)

    # New rules require a local native construction, not just an event-like name.
    remotes: dict[str, tuple[str, int]] = {}
    if builtin("Instance", [".", "new", "("]):
        for i in range(len(values) - 8):
            if values[i] != "local" or not re.fullmatch(r"[A-Za-z_]\w*", values[i + 1]):
                continue
            cursor = i + 2
            if values[cursor : cursor + 1] == [":"]:
                cursor += 2  # one simple type name, not a cast/provenance proof
            if values[cursor : cursor + 5] != ["=", "Instance", ".", "new", "("]:
                continue
            kind = values[cursor + 5 : cursor + 6]
            if (
                kind
                and kind[0]
                in {'"RemoteEvent"', "'RemoteEvent'", '"RemoteFunction"', "'RemoteFunction'"}
                and values[cursor + 6 : cursor + 7] == [")"]
                and not expression_continues(cursor + 7)
            ):
                remotes[values[i + 1]] = (kind[0][1:-1], i + 1)
    for name, (_kind, declaration) in list(remotes.items()):
        handlers = 0
        for index in positions[name]:
            if index == declaration:
                continue
            if (index and values[index - 1] in {".", ":"}) or values[index + 1 : index + 2] != [
                "."
            ]:
                remotes.pop(name, None)
                break
            member = values[index + 2 : index + 3]
            if member in (["OnServerEvent"], ["OnServerInvoke"]):
                handlers += 1
            elif member not in (["Parent"], ["Name"]) or values[index + 3 : index + 4] != ["="]:
                remotes.pop(name, None)
                break
        if handlers != 1:
            remotes.pop(name, None)

    module_loader = builtin("require", ["("])
    native_game = "game" in positions and builtin("game", [":", "GetService", "("])
    for i in range(1, len(values) - 12):
        event = values[i : i + 6] == [".", "OnServerEvent", ":", "Connect", "(", "function"]
        invoke = values[i : i + 4] == [".", "OnServerInvoke", "=", "function"]
        if not (event or invoke):
            continue
        opening = i + (6 if event else 4)
        if values[opening] != "(":
            continue
        end = opening + 1
        while end < min(len(values), opening + 24) and values[end] != ")":
            end += 1
        parts = " ".join(values[opening + 1 : end]).split(",")
        parameters = []
        for part in parts:
            match = re.fullmatch(r"\s*([A-Za-z_]\w*)(?:\s*:\s*[A-Za-z_]\w*(?:\s*\?)?)?\s*", part)
            if match:
                parameters.append(match[1])
        if (
            len(parts) not in {2, 3}
            or len(parameters) != len(parts)
            or len(set(parameters)) != len(parameters)
        ):
            continue
        body = end + 1
        if values[body : body + 1] == [":"]:
            if not re.fullmatch(
                r"[A-Za-z_]\w*", values[body + 1] if body + 1 < len(values) else ""
            ):
                continue
            body += 2
        if values[body : body + 1] == ["return"]:
            body += 1
        data = parameters[1]
        binding = remotes.get(values[i - 1])
        native = binding is not None and binding[0] == (
            "RemoteEvent" if event else "RemoteFunction"
        )
        native = native and binding[1] < i - 1 and boundary_at[binding[1]] == boundary_at[i]
        candidates = []
        if evaluator and len(parameters) == 2:
            candidates.append(("SP672", ["loadstring", "(", data, ")", "(", ")"]))
        if native and module_loader and len(parameters) == 2:
            candidates.append(("SP690", ["require", "(", data, ")"]))
        if native and len(parameters) == 2:
            candidates.append(("SP691", [data, ":", "Destroy", "(", ")"]))
            candidates.append(("SP691", [data, ":", "Kick", "(", ")"]))
        if native and native_game and len(parameters) == 3:
            store = values[body + 9 : body + 10]
            if (
                store
                and re.fullmatch(r"[\"'][A-Za-z0-9_ -]{1,32}[\"']", store[0])
                and store[0][0] == store[0][-1]
            ):
                for quote in ("'", '"'):
                    candidates.append(
                        (
                            "SP707",
                            [
                                "game",
                                ":",
                                "GetService",
                                "(",
                                quote + "DataStoreService" + quote,
                                ")",
                                ":",
                                "GetDataStore",
                                "(",
                                store[0],
                                ")",
                                ":",
                                "SetAsync",
                                "(",
                                parameters[1],
                                ",",
                                parameters[2],
                                ")",
                            ],
                        )
                    )
        for rule_id, signature in candidates:
            last = body + len(signature)
            terminator = last + int(values[last : last + 1] == [";"])
            if (
                values[body:last] == signature
                and values[terminator : terminator + (2 if event else 1)]
                == (["end", ")"] if event else ["end"])
                and (event or not expression_continues(terminator + 1))
            ):
                emit(rule_id, body, last - 1)
    return hits


def signature_spans(source: str, language: str) -> list[tuple[str, int, int]]:
    if language == "go" and not any(
        name in source for name in ("Server", "WithCancel", "WithTimeout", "WithDeadline")
    ):
        return []
    stream = tokens(source, language)
    if language == "go":
        return go_spans(stream)
    if language == "lua":
        return lua_spans(stream)
    values = [item[0] for item in stream]
    hits: list[tuple[str, int, int]] = []

    def emit(rule_id: str, first: int, last: int) -> None:
        hits.append((rule_id, stream[first][1], stream[last][2]))

    if language == "rust":
        hidden = {name for name in ("std", "core", "reqwest") if shadowed(values, name)}
        hidden.update(
            name
            for name in ("std", "core", "reqwest")
            if any(values[i : i + 3] == ["r", "#", name] for i in range(len(values)))
        )
        # stringify! consumes token data, not a call expression. Other macros are
        # not expanded; this lexer is not a Rust compiler.
        quoted = set()
        if "stringify" in values:
            pairs = delimiter_pairs(values)
            quoted_through = -1
            for index, value in enumerate(values):
                if index <= quoted_through:
                    continue
                if (
                    value == "stringify"
                    and values[index + 1 : index + 2] == ["!"]
                    and index + 2 in pairs
                ):
                    quoted_through = pairs[index + 2]
                    quoted.update(range(index + 2, quoted_through + 1))
        for index, value in enumerate(values):
            if value != "use":
                continue
            end = index + 1
            while end < min(len(values), index + 129) and values[end] != ";":
                end += 1
            if end == min(len(values), index + 129):
                hidden.update({"std", "core", "reqwest"})
            else:
                # An imported custom path/group can bind a standard-looking module.
                # Longer/grouped imports stay unresolved rather than implying std identity.
                hidden.update(
                    name for name in ("std", "core", "reqwest") if name in values[index + 2 : end]
                )
        for i in range(len(values) - 6):
            if i in quoted:
                continue
            if i >= 2 and values[i - 1] == "::" and re.fullmatch(r"\w+", values[i - 2]):
                continue
            if (
                values[i] in {"std", "core"}
                and values[i] not in hidden
                and values[i + 1 : i + 4] == ["::", "mem", "::"]
                and values[i + 4] in {"zeroed", "uninitialized"}
                and values[i + 5] == "::"
            ):
                opening = i + 6
                if values[opening : opening + 2] != ["<", "&"]:
                    continue
                closing = opening + 2
                while closing < min(len(values), opening + 32) and values[closing] != ">":
                    closing += 1
                if values[closing : closing + 3] == [">", "(", ")"]:
                    emit("SP673", i, closing + 2)
            if (
                values[i] in {"std", "core"}
                and values[i] not in hidden
                and values[i + 1 : i + 4] == ["::", "num", "::"]
                and re.fullmatch(r"NonZero[UI](?:8|16|32|64|128|size)", values[i + 4])
                and values[i + 5 : i + 9] == ["::", "new_unchecked", "(", "0"]
            ):
                end = i + 9
                suffix = values[i + 4].removeprefix("NonZero").lower()
                if values[end : end + 1] in ([suffix], ["_" + suffix]):
                    end += 1
                if values[end : end + 1] == [")"]:
                    emit("SP699", i, end)
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
