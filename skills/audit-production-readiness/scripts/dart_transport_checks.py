"""Original import-aware Dart HTTP observations; no DNS, execution or full taint inference."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from js_config_checks import IDENTIFIER, properties, segments
from polyglot_checks import delimiter_pairs, tokens


def literal(value: str) -> str | None:
    raw = value.startswith("r")
    if raw:
        value = value[1:]
    if len(value) < 2 or value[0] not in {"'", '"'} or value[-1] != value[0]:
        return None
    if value.startswith(value[0] * 3) or "\\" in value or (not raw and "$" in value):
        return None
    return value[1:-1]


def external_http(value: str | None) -> bool:
    if not value or len(value) > 4096 or any(char.isspace() for char in value):
        return False
    try:
        url = urlsplit(value)
        host = (url.hostname or "").lower().rstrip(".")
        if url.scheme != "http" or url.username or url.password or url.fragment or not host:
            return False
        if url.port is not None and not 0 < url.port <= 65535:
            return False
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan")):
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return (
                not all(char.isdigit() or char == "." for char in host)
                and "." in host
                and all(char.isascii() and (char.isalnum() or char in ".-") for char in host)
            )
    except ValueError:
        return False


def signature_offsets(source: str) -> list[tuple[str, int]]:
    stream = tokens(source, "dart")
    values = [value for value, _, _ in stream]
    pairs = delimiter_pairs(values)
    if "runWithClient" in values or "part" in values:
        return []
    bindings = {}
    for index, value in enumerate(values):
        if (
            value == "import"
            and index + 4 < len(values)
            and literal(values[index + 1]) == "package:http/http.dart"
            and values[index + 2] == "as"
            and values[index + 4] == ";"
        ):
            name = values[index + 3]
            if IDENTIFIER.fullmatch(name):
                bindings.setdefault(name, []).append(index + 3)
    bindings = {name: positions[0] for name, positions in bindings.items() if len(positions) == 1}
    # Names used as parameters, assignments, escapes or non-call members need resolution.
    for index, value in enumerate(values):
        if (
            value in bindings
            and index != bindings[value]
            and (
                (index and values[index - 1] == ".")
                or values[index + 1 : index + 2] != ["."]
                or values[index + 3 : index + 4] != ["("]
            )
        ):
            bindings.pop(value, None)
        if value == "Uri" and values[index + 1 : index + 2] != ["."]:
            return []
    hits = []
    for index, value in enumerate(values):
        if value not in bindings or index == bindings[value]:
            continue
        if values[index + 2 : index + 3] not in (
            [method] for method in ("get", "post", "put", "patch", "delete", "head")
        ):
            continue
        args = segments(values, pairs, index + 3)
        if not args or values[args[0][0] : args[0][0] + 4] != ["Uri", ".", "parse", "("]:
            continue
        uri_open = args[0][0] + 3
        uri_args = segments(values, pairs, uri_open)
        if (
            pairs.get(uri_open) != args[0][1] - 1
            or len(uri_args) != 1
            or uri_args[0][1] != uri_args[0][0] + 1
        ):
            continue
        if not external_http(literal(values[uri_args[0][0]])):
            continue
        headers = [span for span in args[1:] if values[span[0] : span[0] + 2] == ["headers", ":"]]
        if len(headers) != 1:
            continue
        start, end = headers[0]
        mapping = properties(values, pairs, (start + 2, end))
        auth = [span for key, span in mapping.items() if key.lower() == "authorization"]
        if len(auth) != 1:
            continue
        first, last = auth[0]
        if last != first + 1:
            continue
        text = literal(values[first])
        if (
            (text is not None and text.strip())
            or values[first].startswith(("'Bearer ", '"Bearer '))
            or (
                IDENTIFIER.fullmatch(values[first])
                and values[first] not in {"null", "false", "true"}
            )
        ):
            hits.append(("SP170", stream[index][1]))
    return list(dict.fromkeys(hits))
