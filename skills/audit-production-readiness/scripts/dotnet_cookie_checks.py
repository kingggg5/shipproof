"""Narrow typed-parameter cookie checks, not general C# type/data-flow analysis."""

from __future__ import annotations

from collections import Counter

from js_config_checks import IDENTIFIER, literal, segments

NAMESPACE = ["Microsoft", ".", "AspNetCore", ".", "Http", "."]
RECEIVERS = {
    "IResponseCookies": [".", "Append", "("],
    "HttpResponse": [".", "Cookies", ".", "Append", "("],
    "HttpContext": [".", "Response", ".", "Cookies", ".", "Append", "("],
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


def signature_lines(tokens: list[tuple[str, int]], pairs: dict[int, int]) -> list[tuple[str, int]]:
    values = [value for value, _ in tokens]
    types = {*RECEIVERS, "CookieOptions"}
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
        if value == "using" and "=" in values[i + 1 : min(i + 12, len(values))]:
            return []
    imported = any(values[i : i + 7] == ["using", *NAMESPACE[:-1], ";"] for i in range(len(values)))

    def type_end(start: int, expected: str) -> int:
        global_name = values[start : start + 3] == ["global", ":", ":"]
        if global_name:
            start += 3
        if values[start : start + 6] == NAMESPACE and values[start + 6 : start + 7] == [expected]:
            return start + 7
        return (
            start + 1
            if not global_name and imported and values[start : start + 1] == [expected]
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
            if not IDENTIFIER.fullmatch(name) or counts[name] != 2:
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
            if (
                not end < use < pairs.get(body, -1)
                or values[body : body + 1] != ["{"]
                or values[use - 1] in {".", "?."}
                or values[use + 1 : use + 1 + len(members)] != members
            ):
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
