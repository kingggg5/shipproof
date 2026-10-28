"""Bounded Luau API contracts over an opaque-literal token stream; never execute it."""

from __future__ import annotations

import re
from collections import Counter, defaultdict

NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*", re.ASCII)
INTEREST = {
    "clamp",
    "random",
    "sort",
    "insert",
    "clear",
    "freeze",
    "spawn",
    "defer",
    "delay",
    "UpdateAsync",
    "Wait",
}
EVENTS = {
    "Players": {"PlayerAdded", "PlayerRemoving"},
    "RunService": {
        "Heartbeat",
        "Stepped",
        "RenderStepped",
        "PreRender",
        "PreSimulation",
        "PostSimulation",
    },
    "BindableEvent": {"Event"},
    "RemoteEvent": {"OnServerEvent", "OnClientEvent"},
}


def text(value):
    return (
        value[1:-1]
        if len(value) >= 2
        and value[0] in {"'", '"'}
        and value[-1] == value[0]
        and "\\" not in value
        else None
    )


def integer(values):
    if len(values) == 2 and values[0] == "-":
        sign, values = -1, values[1:]
    else:
        sign = 1
    if len(values) != 1 or not re.fullmatch(r"[0-9]{1,10}", values[0]):
        return None
    number = sign * int(values[0])
    return number if -(2**31) <= number <= 2**31 - 1 else None


def signatures(stream, pair_builder):
    values = [item[0] for item in stream]
    if not INTEREST.intersection(values) or {"getfenv", "setfenv"}.intersection(values):
        return []
    pairs = pair_builder(values)
    counts = Counter(values)
    positions = defaultdict(list)
    boundary, boundaries = 0, []
    for i, value in enumerate(values):
        positions[value].append(i)
        boundaries.append(boundary)
        boundary += int(value in {"end", "else", "elseif", "until"})

    def native(name, library=False):
        for i in positions[name]:
            if i and values[i - 1] in {".", ":", "::"}:
                continue
            if i and values[i - 1] == "function":
                return False
            tail = i + 1
            if library:
                if (
                    values[tail : tail + 1] != ["."]
                    or tail + 2 >= len(values)
                    or not NAME.fullmatch(values[tail + 1])
                ):
                    return False
                tail += 2
            if values[tail : tail + 1] != ["("]:
                return False
        return bool(positions[name])

    libraries = {name for name in ("math", "table", "task", "Instance") if native(name, True)}
    functions = {name for name in ("ipairs", "pairs", "print", "warn", "wait") if native(name)}
    native_game = all(
        (i == 0 or values[i - 1] not in {"local", "function"})
        and values[i + 1 : i + 4] == [":", "GetService", "("]
        for i in positions["game"]
    ) and bool(positions["game"])
    hits = []

    def emit(rule_id, first, last):
        hits.append((rule_id, stream[first][1], stream[last - 1][2]))

    def args(opening):
        end = pairs.get(opening)
        if end is None or end - opening > 256:
            return []
        result, start, cursor = [], opening + 1, opening + 1
        while cursor < end:
            if values[cursor] == ",":
                if start == cursor:
                    return []
                result.append((start, cursor))
                start = cursor + 1
            cursor = pairs.get(cursor, cursor) + 1
        if start < end:
            result.append((start, end))
        return result

    def call(first, last):
        if first >= last:
            return None
        name = values[first]
        opening = first + 1
        member = ""
        if name in libraries:
            if values[opening : opening + 1] != ["."] or opening + 1 >= last:
                return None
            member = values[opening + 1]
            opening += 2
        elif name not in functions:
            return None
        if values[opening : opening + 1] != ["("] or pairs.get(opening) != last - 1:
            return None
        return name, member, args(opening)

    # A unique unescaped name must be used in the same conservative block region.
    bindings = {}
    continuation = {
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

    def receiver(first):
        name = values[first]
        if name in bindings:
            kind, declaration, end = bindings[name]
            if declaration < first and boundaries[declaration] == boundaries[first]:
                return kind, first + 1
        if native_game and values[first : first + 4] == ["game", ":", "GetService", "("]:
            parts = args(first + 3)
            if len(parts) == 1 and parts[0][1] == parts[0][0] + 1:
                kind = text(values[parts[0][0]])
                if kind in {"DataStoreService", "Players", "RunService"}:
                    end = pairs[first + 3] + 1
                    if kind == "DataStoreService" and values[end : end + 3] == [
                        ":",
                        "GetDataStore",
                        "(",
                    ]:
                        return store(end + 2)
                    return kind, end
        if "Instance" in libraries and values[first : first + 4] == ["Instance", ".", "new", "("]:
            parts = args(first + 3)
            if len(parts) == 1 and parts[0][1] == parts[0][0] + 1:
                kind = text(values[parts[0][0]])
                if kind in {"BindableEvent", "RemoteEvent"}:
                    return kind, pairs[first + 3] + 1
        return None

    def store(opening):
        parts = args(opening)
        if len(parts) == 1 and parts[0][1] == parts[0][0] + 1:
            name = text(values[parts[0][0]])
            if name and re.fullmatch(r"[A-Za-z0-9_ -]{1,32}", name):
                return "DataStore", pairs[opening] + 1
        return None

    for i, value in enumerate(values):
        if (
            value != "local"
            or i + 3 >= len(values)
            or not NAME.fullmatch(values[i + 1])
            or counts[values[i + 1]] != 2
        ):
            continue
        cursor = i + 2
        if values[cursor : cursor + 1] == [":"]:
            cursor += 2
        if values[cursor : cursor + 1] != ["="]:
            continue
        found = receiver(cursor + 1)
        if (
            found
            and found[0] == "DataStoreService"
            and values[found[1] : found[1] + 3] == [":", "GetDataStore", "("]
        ):
            found = store(found[1] + 2)
        if found and values[found[1] : found[1] + 1] not in [[token] for token in continuation]:
            bindings[values[i + 1]] = (found[0], i + 1, found[1])

    for i, value in enumerate(values):
        if i and values[i - 1] in {".", ":", "::"}:
            continue
        if (
            value in libraries
            and values[i + 1 : i + 2] == ["."]
            and values[i + 3 : i + 4] == ["("]
            and i + 3 in pairs
        ):
            end = pairs[i + 3] + 1
            invocation = call(i, end)
            if invocation:
                name, member, parts = invocation
                if name == "math" and (member, len(parts)) in {("clamp", 3), ("random", 2)}:
                    limits = [integer(values[a:b]) for a, b in parts[-2:]]
                    if None not in limits and limits[0] > limits[1]:
                        emit("SP708", i, end)
                if (
                    name == "table"
                    and member in {"sort", "insert", "clear"}
                    and len(parts) in {"sort": {1, 2}, "insert": {2, 3}, "clear": {1}}[member]
                    and (
                        (i and values[i - 1] == "#")
                        or values[end : end + 1] in (["."], ["["])
                        or (i and values[i - 1] == "in" and values[end : end + 1] == ["do"])
                    )
                ):
                    emit("SP709", i, end)
                if name == "task" and member in {"spawn", "defer", "delay"}:
                    position = 1 if member == "delay" else 0
                    if len(parts) > position:
                        inner = call(*parts[position])
                        if inner and (
                            (inner[0] in {"print", "warn"}) or inner[:2] == ("task", "wait")
                        ):
                            emit("SP711", i, end)
                if (
                    name == "table"
                    and member == "freeze"
                    and len(parts) == 1
                    and values[parts[0][0]] == "{"
                    and pairs.get(parts[0][0]) == parts[0][1] - 1
                ):
                    target = end
                    first = i
                    if (
                        i >= 3
                        and values[i - 1] == "="
                        and values[i - 3] == "local"
                        and counts[values[i - 2]] == 2
                        and (end == len(values) or values[end] not in continuation)
                    ):
                        uses = [p for p in positions[values[i - 2]] if p != i - 2]
                        if uses and uses[0] > i and boundaries[uses[0]] == boundaries[i]:
                            first, target = uses[0], uses[0] + 1
                    if values[target : target + 1] == ["."] and target + 2 < len(values):
                        stop = target + 2
                    elif values[target : target + 1] == ["["] and target in pairs:
                        stop = pairs[target] + 1
                    else:
                        continue
                    if values[stop : stop + 1] == ["="] and values[stop + 1 : stop + 2] != ["="]:
                        emit("SP710", first, stop + 1)
        if (
            value in {"ipairs", "pairs"}
            and value in functions
            and values[i + 1 : i + 2] == ["("]
            and i + 1 in pairs
        ):
            parts = args(i + 1)
            inner = call(*parts[0]) if len(parts) == 1 else None
            if inner and inner[0] == "table" and inner[1] in {"sort", "insert", "clear"}:
                emit("SP709", i, pairs[i + 1] + 1)
        found = receiver(i)
        if not found:
            continue
        kind, cursor = found
        if kind == "DataStoreService" and values[cursor : cursor + 3] == [":", "GetDataStore", "("]:
            found = store(cursor + 2)
            if found is None:
                continue
            kind, cursor = found
        if (
            kind in EVENTS
            and values[cursor : cursor + 1] == ["."]
            and values[cursor + 1 : cursor + 2]
            and values[cursor + 1] in EVENTS[kind]
            and values[cursor + 2 : cursor + 5] == [":", "Wait", "("]
            and cursor + 4 in pairs
        ):
            parts = args(cursor + 4)
            delay = integer(values[parts[0][0] : parts[0][1]]) if len(parts) == 1 else None
            if delay is not None and delay > 0:
                emit("SP713", i, pairs[cursor + 4] + 1)
        if (
            kind == "DataStore"
            and values[cursor : cursor + 3] == [":", "UpdateAsync", "("]
            and cursor + 2 in pairs
        ):
            parts = args(cursor + 2)
            if len(parts) != 2:
                continue
            first, last = parts[1]
            if (
                values[first : first + 2] != ["function", "("]
                or first + 1 not in pairs
                or values[last - 1 : last] != ["end"]
            ):
                continue
            body = pairs[first + 1] + 1
            wait_end = (
                body + 3
                if values[body : body + 3] == ["task", ".", "wait"] and "task" in libraries
                else body + 1
                if values[body : body + 1] == ["wait"] and "wait" in functions
                else -1
            )
            if wait_end in pairs and values[wait_end] == "(":
                after = pairs[wait_end] + 1
                if values[after : after + 1] == [";"]:
                    after += 1
                if values[after : after + 1] == ["return"] and not {
                    "function",
                    "end",
                    "if",
                    "for",
                    "while",
                    "repeat",
                }.intersection(values[after + 1 : last - 1]):
                    emit("SP712", i, pairs[cursor + 2] + 1)
    return list(dict.fromkeys(hits))
