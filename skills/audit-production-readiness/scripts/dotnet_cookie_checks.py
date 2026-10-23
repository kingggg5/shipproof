"""Narrow typed ASP.NET option checks, not general C# type/data-flow analysis."""

from __future__ import annotations

import re
from collections import Counter

from js_config_checks import IDENTIFIER, literal, segments

NAMESPACE = ["Microsoft", ".", "AspNetCore", ".", "Http", "."]
OPTION_NAMESPACES = {
    "CookieAuthenticationOptions": [
        "Microsoft",
        ".",
        "AspNetCore",
        ".",
        "Authentication",
        ".",
        "Cookies",
        ".",
    ],
    "KestrelServerOptions": [
        "Microsoft",
        ".",
        "AspNetCore",
        ".",
        "Server",
        ".",
        "Kestrel",
        ".",
        "Core",
        ".",
    ],
}
RECEIVERS = {
    "IResponseCookies": [".", "Append", "("],
    "HttpResponse": [".", "Cookies", ".", "Append", "("],
    "HttpContext": [".", "Response", ".", "Cookies", ".", "Append", "("],
    "CookieAuthenticationOptions": [],
    "KestrelServerOptions": [],
}
SENSITIVE_NAMES = frozenset(
    {
        "session",
        "sessionid",
        "sid",
        "auth",
        "auth_token",
        "token",
        "access_token",
        "refresh_token",
        "jwt",
    }
)


def xml_precision_lines(source: str, tokenize, structure) -> list[int]:
    """Narrow initializer-to-reader evidence; not a general C# parser."""
    if any(marker in source for marker in ('@"', '$"', '"""')):
        return []
    tokens = tokenize(source)
    values = [value for value, _ in tokens]
    pairs, depths = structure(values)
    if not depths:
        return []
    types = {"XmlReaderSettings", "XmlReader", "XmlUrlResolver", "DtdProcessing"}
    if any(
        values[i] in {"class", "struct", "record", "interface"} and values[i + 1] in types
        for i in range(len(values) - 1)
    ):
        return []
    if any(
        values[i] == "using" and values[i + 1] in types and values[i + 2] == "="
        for i in range(len(values) - 2)
    ):
        return []
    if any(
        values[i] in {"var", "const"} and values[i + 1] in types for i in range(len(values) - 1)
    ):
        return []
    counts = Counter(values)

    def qualified(start: int, name: str) -> int:
        if values[start : start + 5] == ["System", ".", "Xml", ".", name]:
            return start + 5
        return start + 1 if values[start : start + 1] == [name] else -1

    hits = []
    for index, value in enumerate(values):
        if value != "new" or index < 2 or values[index - 1] != "=":
            continue
        if index < 3 or values[index - 3] not in {"var", "XmlReaderSettings"}:
            continue
        name = values[index - 2]
        if not re.fullmatch(r"[A-Za-z_][\w]*", name) or counts[name] != 2:
            continue
        opening = qualified(index + 1, "XmlReaderSettings")
        if opening < 0:
            continue
        if values[opening : opening + 2] == ["(", ")"]:
            opening += 2
        closing = pairs.get(opening)
        if closing is None or values[opening] != "{":
            continue
        options = {}
        for start, end in segments(values, pairs, opening):
            if values[start + 1 : start + 2] != ["="] or values[start] in options:
                options = {}
                break
            options[values[start]] = (start + 2, end)
        dtd = options.get("DtdProcessing")
        resolver = options.get("XmlResolver")
        if dtd is None or resolver is None:
            continue
        dtd_end = qualified(dtd[0], "DtdProcessing")
        resolver_type = qualified(resolver[0] + 1, "XmlUrlResolver")
        if (
            dtd_end < 0
            or values[dtd_end : dtd[1]] != [".", "Parse"]
            or values[resolver[0]] != "new"
            or resolver_type < 0
            or values[resolver_type : resolver[1]] != ["(", ")"]
        ):
            continue
        for cursor in range(closing + 1, min(len(values), closing + 513)):
            if cursor and values[cursor - 1] == ".":
                continue
            member = qualified(cursor, "XmlReader")
            if member < 0 or values[member : member + 3] != [".", "Create", "("]:
                continue
            args = segments(values, pairs, member + 2)
            if len(args) == 2 and values[args[1][0] : args[1][1]] == [name]:
                hits.append(source.count("\n", 0, tokens[index][1]) + 1)
                break
    return list(dict.fromkeys(hits))


def xml_entity_offsets(tokens, pairs) -> list[tuple[str, int]]:
    """Only an inline, locally named settings object consumed by XmlReader.Create."""
    values = [value for value, _ in tokens]
    types = {"XmlReader", "XmlReaderSettings", "DtdProcessing", "System"}
    if "#" in values or "dynamic" in values:
        return []
    for index, value in enumerate(values[:-1]):
        if (
            value in {"class", "struct", "record", "interface", "var", "const"}
            and values[index + 1] in types
        ):
            return []
        if value == "using" and values[index + 2 : index + 3] == ["="]:
            return []
        if value == "XmlReader" and values[index + 1 : index + 4] != [".", "Create", "("]:
            return []
    imported = any(
        values[index : index + 5] == ["using", "System", ".", "Xml", ";"]
        for index in range(len(values))
    )

    def qualified(start, name):
        if values[start : start + 3] == ["global", ":", ":"]:
            start += 3
        if values[start : start + 5] == ["System", ".", "Xml", ".", name]:
            return start + 5
        return start + 1 if imported and values[start : start + 1] == [name] else -1

    def zero(expression):
        return expression in (["0"], ["0", "L"], ["0", "l"])

    hits = []
    for index in range(len(values)):
        if index and values[index - 1] in {".", ":"}:
            continue
        member = qualified(index, "XmlReader")
        if member < 0 or values[member : member + 3] != [".", "Create", "("]:
            continue
        args = segments(values, pairs, member + 2)
        if len(args) != 2:
            continue
        start, stop = args[1]
        if values[start] != "new":
            continue
        opening = qualified(start + 1, "XmlReaderSettings")
        if opening < 0:
            continue
        if values[opening : opening + 2] == ["(", ")"]:
            opening += 2
        if values[opening : opening + 1] != ["{"] or pairs.get(opening) != stop - 1:
            continue
        options = {}
        for first, last in segments(values, pairs, opening):
            if values[first + 1 : first + 2] != ["="] or values[first] in options:
                options = {}
                break
            options[values[first]] = (first + 2, last)
        dtd = options.get("DtdProcessing")
        entity = options.get("MaxCharactersFromEntities")
        document = options.get("MaxCharactersInDocument")
        if set(options) - {
            "DtdProcessing",
            "MaxCharactersFromEntities",
            "MaxCharactersInDocument",
            "XmlResolver",
        }:
            continue  # Other reader modes/validation settings need their own model.
        if not dtd or not entity or not zero(values[entity[0] : entity[1]]):
            continue
        enum = qualified(dtd[0], "DtdProcessing")
        if (
            enum < 0
            or values[enum : dtd[1]] != [".", "Parse"]
            or (document and not zero(values[document[0] : document[1]]))
        ):
            continue
        hits.append(("SP696", tokens[index][1]))
    return hits


def signature_offsets(
    tokens: list[tuple[str, int]], pairs: dict[int, int]
) -> list[tuple[str, int]]:
    values = [value for value, _ in tokens]
    types = {*RECEIVERS, "CookieOptions", "CookieSecurePolicy"}
    # Using aliases, local types, dynamic dispatch and policy hooks need semantic analysis.
    if any(value in {"dynamic", "UseCookiePolicy", "CookiePolicyOptions", "#"} for value in values):
        return []
    for i, value in enumerate(values):
        if (
            value in {"class", "struct", "record", "interface"}
            and values[i + 1 : i + 2]
            and values[i + 1] in types | {"Microsoft"}
        ):
            return []
        if value == "using" and values[i + 2 : i + 3] == ["="]:
            return []
    imports = {
        name: any(
            values[i : i + len(namespace) + 1] == ["using", *namespace[:-1], ";"]
            for i in range(len(values))
        )
        for name in types
        for namespace in [OPTION_NAMESPACES.get(name, NAMESPACE)]
    }

    def type_end(start: int, expected: str) -> int:
        namespace = OPTION_NAMESPACES.get(expected, NAMESPACE)
        global_name = values[start : start + 3] == ["global", ":", ":"]
        if global_name:
            start += 3
        if values[start : start + len(namespace)] == namespace and values[
            start + len(namespace) : start + len(namespace) + 1
        ] == [expected]:
            return start + len(namespace) + 1
        return (
            start + 1
            if not global_name and imports[expected] and values[start : start + 1] == [expected]
            else -1
        )

    counts = Counter(values)
    last_use = {value: index for index, value in enumerate(values)}
    hits = []
    for start in range(1, len(values)):
        if values[start - 1] not in {"(", ","}:
            continue
        for receiver, members in RECEIVERS.items():
            end = type_end(start, receiver)
            if end < 0 or end + 1 >= len(values) or values[end + 1] not in {",", ")"}:
                continue
            name = values[end]
            if not IDENTIFIER.fullmatch(name) or counts[name] < 2:
                continue
            # A declaration and exactly one call, with no reassignment, shadow or escape.
            use = last_use[name]
            parameter_open = next(
                (
                    i
                    for i in range(start - 1, max(-1, start - 513), -1)
                    if values[i] == "(" and pairs.get(i, -1) > end
                ),
                -1,
            )
            body = pairs.get(parameter_open, -2) + 1
            if values[body : body + 1] == ["=>"]:
                body += 1
            if (
                not end < use < pairs.get(body, -1)
                or values[body : body + 1] != ["{"]
                or values[use - 1] in {".", "?."}
                or values[use + 1 : use + 1 + len(members)] != members
            ):
                continue
            if receiver in OPTION_NAMESPACES:
                closing = pairs[body]
                if closing - body > 512:
                    continue
                fields = {}
                cursor = body + 1
                uses = 0
                while cursor < closing:
                    prefix = [
                        name,
                        ".",
                        "Cookie" if receiver == "CookieAuthenticationOptions" else "Limits",
                        ".",
                    ]
                    if values[cursor : cursor + 4] != prefix or values[cursor + 5 : cursor + 6] != [
                        "="
                    ]:
                        break
                    key = values[cursor + 4]
                    end_value = cursor + 6
                    while end_value < closing and values[end_value] != ";":
                        end_value += 1
                    if end_value == closing:
                        break
                    allowed = (
                        {"HttpOnly", "SecurePolicy"}
                        if receiver == "CookieAuthenticationOptions"
                        else {"MaxRequestBodySize"}
                    )
                    if key not in allowed:
                        break
                    fields[key] = (cursor + 6, end_value, cursor)
                    uses += 1
                    cursor = end_value + 1
                if cursor != closing or uses + 1 != counts[name]:
                    continue  # Branches, escapes and later reconfiguration are unresolved.
                for key, (first, last, statement) in fields.items():
                    rule = None
                    if key == "HttpOnly" and values[first:last] == ["false"]:
                        rule = "SP056"
                    elif key == "SecurePolicy":
                        enum_end = type_end(first, "CookieSecurePolicy")
                        if enum_end >= 0 and values[enum_end:last] == [".", "None"]:
                            rule = "SP084"
                    elif key == "MaxRequestBodySize" and values[first:last] == ["null"]:
                        rule = "SP689"
                    if rule:
                        hits.append((rule, tokens[statement][1]))
                continue
            if counts[name] != 2:
                continue
            opening = use + len(members)
            args = segments(values, pairs, opening)
            if len(args) != 3 or args[0][1] != args[0][0] + 1:
                continue
            if literal(values[args[0][0]]) not in SENSITIVE_NAMES:
                continue
            first, stop = args[2]
            if values[first] != "new":
                continue
            options_start = type_end(first + 1, "CookieOptions")
            if options_start < 0:
                continue
            if values[options_start : options_start + 2] == ["(", ")"]:
                options_start += 2
            if (
                values[options_start : options_start + 1] != ["{"]
                or pairs.get(options_start) != stop - 1
            ):
                continue
            options = {}
            for key, option_end in segments(values, pairs, options_start):
                if values[key + 1 : key + 2] != ["="] or values[key] in options:
                    options = {}
                    break
                options[values[key]] = values[key + 2 : option_end]
            # Header extensions can alter the final flags even for an otherwise literal object.
            if "Extensions" in options:
                continue
            for key, rule in (("HttpOnly", "SP056"), ("Secure", "SP084")):
                if options.get(key) == ["false"]:
                    hits.append((rule, tokens[use][1]))
    return list(dict.fromkeys(hits))
