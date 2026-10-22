"""Bounded, original Luau/Rust signatures with lexical source positions.

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
            if source.startswith("//", index):
                end = source.find("\n", index)
                index = len(source) if end < 0 else end
                continue
            if source.startswith("/*", index):
                depth = 1
                index += 2
                while index < len(source) and depth:
                    if source.startswith("/*", index):
                        depth += 1
                        index += 2
                    elif source.startswith("*/", index):
                        depth -= 1
                        index += 2
                    else:
                        index += 1
                if depth:
                    raise LexicalLimitError("unterminated Rust block comment")
                continue
            raw = RUST_RAW.match(source, index)
            if raw:
                end = source.find('"' + raw[1], raw.end())
                if end < 0:
                    raise LexicalLimitError("unterminated Rust raw string")
                index = end + 1 + len(raw[1])
                record("<literal>", start, index)
                continue
            # A Rust lifetime is not a character literal.
            lifetime = RUST_LIFETIME.match(source, index) if char == "'" else None
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


def signature_spans(source: str, language: str) -> list[tuple[str, int, int]]:
    stream = tokens(source, language)
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
    return list(dict.fromkeys(hits))
