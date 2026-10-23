"""Bounded import-aware JS/TS configuration checks; never evaluate source code."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

MODULES = frozenset(
    {
        "jsonwebtoken",
        "crypto",
        "http",
        "https",
        "tls",
        "ws",
        "react",
        "buffer",
        "zlib",
        "electron",
        "puppeteer",
        "puppeteer-core",
    }
)
IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*", re.ASCII)
MAX_EXPRESSION_TOKENS = 512


def js_context_tokens(source: str) -> list[tuple[str, int]]:
    """Small bounded lexical view for precision checks, not a JS parser.

    Comments, strings, and regex literals remain opaque. Template interpolation
    and excessive token counts are unresolved, never affirmative evidence.
    """
    tokens: list[tuple[str, int]] = []
    paren_context: list[str] = []
    regex_after_control = False
    index = 0
    token_pattern = re.compile(
        r"[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|=>|\.\.\.|\?\.|===|!==|==|!=|&&|\|\||[^\s]", re.ASCII
    )
    regex_prefixes = {
        "=",
        "(",
        "[",
        "{",
        ",",
        ":",
        ";",
        "!",
        "?",
        "return",
        "=>",
        "&&",
        "||",
        "throw",
        "case",
        "yield",
        "typeof",
        "void",
        "delete",
        "else",
        "do",
    }
    while index < len(source):
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                return []
            index = end + 2
            continue
        start = index
        if char in {'"', "'", "`"}:
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                    continue
                if char == "`" and source.startswith("${", index):
                    return []
                if source[index] == char:
                    index += 1
                    break
                index += 1
            else:
                return []
            tokens.append((source[start:index], start))
            regex_after_control = False
        elif char == "/" and (not tokens or tokens[-1][0] in regex_prefixes or regex_after_control):
            index += 1
            in_class = False
            while index < len(source) and source[index] not in "\r\n":
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == "[":
                    in_class = True
                elif source[index] == "]":
                    in_class = False
                elif source[index] == "/" and not in_class:
                    index += 1
                    break
                index += 1
            else:
                return []
            while index < len(source) and source[index].isalpha():
                index += 1
            tokens.append((source[start:index], start))
            regex_after_control = False
        elif char == "/" and tokens and tokens[-1][0] == "}":
            # Object-division versus a new statement regex needs a full parser.
            # Do not interpret regex text as constructors or JSON dereferences.
            return []
        else:
            match = token_pattern.match(source, index)
            if match is None:
                return []
            value = match.group()
            regex_after_control = False
            if value == "(":
                paren_context.append(tokens[-1][0] if tokens else "")
            elif value == ")" and paren_context:
                regex_after_control = paren_context.pop() in {
                    "if",
                    "while",
                    "for",
                    "with",
                    "switch",
                    "catch",
                }
            tokens.append((value, start))
            index = match.end()
        if len(tokens) > 50_000:
            return []
    return tokens


def js_context_structure(values: Sequence[str]) -> tuple[dict[int, int], list[int]]:
    pairs: dict[int, int] = {}
    stack: list[int] = []
    depths: list[int] = []
    for index, value in enumerate(values):
        depths.append(len(stack))
        if value in {"(", "{", "["}:
            stack.append(index)
        elif value in {")", "}", "]"}:
            if not stack or {"(": ")", "{": "}", "[": "]"}[values[stack[-1]]] != value:
                return {}, []
            opening = stack.pop()
            pairs[opening] = index
    return ({}, []) if stack else (pairs, depths)


def literal(value: str) -> str | None:
    if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
        # Escaped/computed names are deliberately unresolved, including overrides.
        return value[1:-1] if "\\" not in value else None
    return None


def module_name(value: str) -> str:
    module = literal(value) or ""
    if module.startswith("node:"):
        builtin = module[5:]
        return builtin if builtin in {"buffer", "crypto", "http", "https", "tls", "zlib"} else ""
    return module


def segments(values: list[str], pairs: dict[int, int], opening: int) -> list[tuple[int, int]]:
    closing = pairs.get(opening)
    if closing is None or closing - opening > MAX_EXPRESSION_TOKENS:
        return []
    result: list[tuple[int, int]] = []
    start = cursor = opening + 1
    while cursor < closing:
        if values[cursor] == ",":
            if start == cursor:
                return []
            result.append((start, cursor))
            start = cursor + 1
        cursor = pairs.get(cursor, cursor) + 1
    if start < closing:
        result.append((start, closing))
    return result


def properties(
    values: list[str], pairs: dict[int, int], expression: tuple[int, int]
) -> dict[str, tuple[int, int]]:
    opening, end = expression
    if values[opening] != "{" or pairs.get(opening) != end - 1:
        return {}
    result = {}
    for start, stop in segments(values, pairs, opening):
        key = values[start] if IDENTIFIER.fullmatch(values[start]) else literal(values[start])
        if key is None or stop - start < 3 or values[start + 1] != ":":
            # Spreads, computed names, shorthand and accessors can override settings.
            return {}
        result[key] = (start + 2, stop)
    return result


def imports(values: list[str], pairs: dict[int, int], depths: list[int]) -> dict:
    """Only direct top-level runtime ESM or const-require bindings establish identity."""
    result: dict[str, tuple[str, str, int]] = {}
    duplicates: set[str] = set()

    def add(name: str, module: str, member: str, position: int) -> None:
        if name in result:
            duplicates.add(name)
        result[name] = (module, member, position)

    def named(opening: int, module: str, commonjs: bool = False) -> None:
        for start, end in segments(values, pairs, opening):
            chunk = values[start:end]
            if len(chunk) == 1 and IDENTIFIER.fullmatch(chunk[0]):
                add(chunk[0], module, chunk[0], start)
            elif len(chunk) == 3 and chunk[1] == (":" if commonjs else "as"):
                add(chunk[2], module, chunk[0], start + 2)

    require_shadowed = any(
        value == "require" and values[i + 1 : i + 2] != ["("] for i, value in enumerate(values)
    )
    for index, value in enumerate(values):
        if depths[index] != 0:
            continue
        if value == "import" and values[index + 1 : index + 2] not in (["type"], ["("]):
            cursor = index + 1
            end = cursor
            while end < len(values) and end - cursor < 256 and values[end] not in {"from", ";"}:
                end = pairs.get(end, end) + 1
            if end + 1 >= len(values) or values[end] != "from":
                continue
            module = module_name(values[end + 1])
            if module not in MODULES:
                continue
            if IDENTIFIER.fullmatch(values[cursor]):
                add(values[cursor], module, "*", cursor)
                cursor += 1
                if values[cursor : cursor + 1] == [","]:
                    cursor += 1
            if values[cursor : cursor + 2] == ["*", "as"] and cursor + 3 == end:
                add(values[cursor + 2], module, "*", cursor + 2)
            elif values[cursor : cursor + 1] == ["{"] and pairs.get(cursor) == end - 1:
                named(cursor, module)
        if value != "const" or require_shadowed or index + 2 >= len(values):
            continue
        binding = index + 1
        end = pairs.get(binding, binding) + 1
        if values[end : end + 3] != ["=", "require", "("]:
            continue
        if values[end + 4 : end + 5] != [")"]:
            continue
        if end + 5 < len(values) and values[end + 5] != ";":
            continue
        module = module_name(values[end + 3])
        if module in MODULES:
            if values[binding] == "{":
                named(binding, module, True)
            elif IDENTIFIER.fullmatch(values[binding]):
                add(values[binding], module, "*", binding)
    # Any non-call use/escape or local shadow makes identity unresolved for this file.
    for index, value in enumerate(values):
        if value not in result or index == result[value][2]:
            continue
        if index and values[index - 1] in {".", "?.", "function", "class"}:
            duplicates.add(value)
            continue
        cursor = index + 1
        while values[cursor : cursor + 1] == ["."] and cursor + 1 < len(values):
            cursor += 2
        if values[cursor : cursor + 1] != ["("]:
            duplicates.add(value)
    return {name: binding for name, binding in result.items() if name not in duplicates}


def exported_config(
    values: list[str], pairs: dict[int, int], depths: list[int], commonjs: bool
) -> list[int]:
    objects = []
    counts = Counter(values)
    module_positions = [index for index, value in enumerate(values) if value == "module"]
    native_module = len(module_positions) == 1 and values[
        module_positions[0] : module_positions[0] + 4
    ] == ["module", ".", "exports", "="]
    exports = [
        index
        for index in range(len(values))
        if values[index : index + 2] == ["export", "default"]
        or values[index : index + 4] == ["module", ".", "exports", "="]
    ]
    # Multiple/conditional exports and module shadowing require actual evaluation.
    if len(exports) != 1:
        return []

    def terminal(end: int) -> bool:
        if (
            values[end : end + 1] == ["satisfies"]
            and end + 1 < len(values)
            and IDENTIFIER.fullmatch(values[end + 1])
        ):
            end += 2
        return end == len(values) or values[end] == ";"

    for index in range(len(values)):
        if depths[index] != 0:
            continue
        if values[index : index + 2] == ["export", "default"]:
            start = index + 2
        elif (
            commonjs
            and native_module
            and values[index : index + 4] == ["module", ".", "exports", "="]
        ):
            start = index + 4
        else:
            continue
        if start >= len(values):
            continue
        if values[start] == "{":
            if start in pairs and terminal(pairs[start] + 1):
                objects.append(start)
            continue
        name = values[start]
        if counts[name] != 2 or not IDENTIFIER.fullmatch(name) or not terminal(start + 1):
            continue
        for cursor in range(start):
            if depths[cursor] != 0 or values[cursor : cursor + 2] != ["const", name]:
                continue
            opening = cursor + 2
            # A simple optional type annotation; no wrapper functions or assertions.
            if values[opening : opening + 1] == [":"]:
                opening += 2
            if (
                values[opening : opening + 2] == ["=", "{"]
                and opening + 1 in pairs
                and terminal(pairs[opening + 1] + 1)
            ):
                objects.append(opening + 1)
    return objects


def client_runtime_imports(
    values: list[str], pairs: dict[int, int], depths: list[int]
) -> list[int]:
    """Caller establishes the actual client directive, not an arbitrary string."""
    server_modules = {"@prisma/client", "drizzle-orm/node-postgres", "server-only", "pg", "mysql2"}
    result = []
    for index, value in enumerate(values):
        if value != "import" or depths[index] != 0:
            continue
        cursor = index + 1
        if cursor >= len(values) or values[cursor] in {"type", "("}:
            continue
        if literal(values[cursor]) in server_modules:
            result.append(index)
            continue
        if values[cursor] == "{":
            specifiers = segments(values, pairs, cursor)
            if not specifiers or all(
                values[start] == "type" and end - start in {2, 4} for start, end in specifiers
            ):
                continue
        end = cursor
        while end < len(values) and end - cursor < 256 and values[end] not in {"from", ";"}:
            end = pairs.get(end, end) + 1
        if (
            end + 1 < len(values)
            and values[end] == "from"
            and literal(values[end + 1]) in server_modules
        ):
            result.append(index)
    return result


def next_server_hook_indices(path, values, pairs, depths, frameworks, directives) -> list[int]:
    if not (
        frameworks is not None
        and "nextjs" in frameworks
        and re.search(r"(?:^|/)app/(?:[^/]+/)*(?:page|layout)\.(?:tsx|jsx)$", path.as_posix())
        and not directives.intersection({'"use client"', "'use client'"})
        and any(
            values[i : i + 2] == ["export", "default"] and depths[i] == 0
            for i in range(len(values))
        )
    ):
        return []
    react = imports(values, pairs, depths)
    for index, value in enumerate(values):
        if value not in react or index == react[value][2]:
            continue
        module, member, _position = react[value]
        cursor = index + 1
        if member == "*" and values[cursor : cursor + 1] == ["."] and cursor + 1 < len(values):
            member = values[cursor + 1]
            cursor += 2
        if (
            module == "react"
            and member in {"useState", "useEffect", "useLayoutEffect", "useReducer"}
            and values[cursor : cursor + 1] == ["("]
        ):
            return [index]
    return []


def signature_spans(
    path: Path,
    tokens: list[tuple[str, int]],
    pairs: dict[int, int],
    depths: list[int],
    evidence: dict[tuple[str, int], str] | None = None,
) -> list[tuple[str, int, int]]:
    values = [value for value, _ in tokens]
    if not depths:
        return []
    bindings = imports(values, pairs, depths)
    hits: list[tuple[str, int, int]] = []

    def emit(rule_id: str, start: int, end: int, excerpt: str) -> None:
        hits.append((rule_id, tokens[start][1], tokens[end - 1][1] + len(values[end - 1])))
        if evidence is not None:
            evidence[(rule_id, tokens[start][1])] = excerpt

    def is_value(options: dict, key: str, expected: str) -> bool:
        span = options.get(key)
        return span is not None and values[span[0] : span[1]] == [expected]

    # Any local Promise declaration, type use, escape or member reassignment is
    # unresolved. Do not guess builtin identity from a method's spelling alone.
    native_promise = all(
        (index == 0 or values[index - 1] not in {".", "?."})
        and values[index + 1 : index + 2] == ["."]
        and values[index + 3 : index + 4] == ["("]
        for index, value in enumerate(values)
        if value == "Promise"
    )
    reverse = {end: start for start, end in pairs.items()}
    for index, value in enumerate(values):
        if (
            native_promise
            and index
            and values[index - 1] == "await"
            and values[index + 7 : index + 8] not in (["."], ["?."], ["["])
            and values[index : index + 7]
            == [
                "Promise",
                ".",
                "race",
                "(",
                "[",
                "]",
                ")",
            ]
        ):
            emit(
                "SP694",
                index,
                index + 7,
                "Promise.race: literal empty input cannot settle this promise",
            )
        if value != "." or values[index + 1 : index + 2] not in (["sort"], ["toSorted"]):
            continue
        if values[index + 2 : index + 3] != ["("]:
            continue
        array = reverse.get(index - 1, -1)
        if (
            array < 0
            or values[array] != "["
            or (
                array
                and values[array - 1] not in {"=", "return", "(", "[", ",", ":", "=>", ";", "{"}
            )
            or "prototype" in values
        ):
            continue
        items = segments(values, pairs, array)
        if len(items) < 2 or any(values[first] == "..." for first, _ in items):
            continue
        arguments = segments(values, pairs, index + 2)
        if len(arguments) != 1:
            continue
        first, last = arguments[0]
        parameters = segments(values, pairs, first) if values[first] == "(" else []
        if len(parameters) != 2:
            continue
        names = []
        for start, stop in parameters:
            chunk = values[start:stop]
            if (
                len(chunk) == 1
                or (len(chunk) == 3 and chunk[1] == ":" and IDENTIFIER.fullmatch(chunk[2]))
            ) and IDENTIFIER.fullmatch(chunk[0]):
                names.append(chunk[0])
        body = pairs.get(first, last) + 1
        if len(names) != 2 or names[0] == names[1] or values[body : body + 1] != ["=>"]:
            continue
        body += 1
        if values[body : body + 1] == ["{"]:
            if pairs.get(body) != last - 1 or values[body + 1 : body + 2] != ["return"]:
                continue
            body += 2
            last -= 1
            if values[last - 1 : last] == [";"]:
                last -= 1
        elif values[body : body + 1] == ["("] and pairs.get(body) == last - 1:
            body += 1
            last -= 1
        expression = values[body:last]
        if (
            len(expression) in {3, 4}
            and expression[0] in names
            and expression[-1] in names
            and expression[0] != expression[-1]
            and expression[1:-1] in (["<"], [">"], ["<", "="], [">", "="])
        ):
            emit(
                "SP695",
                index,
                pairs[index + 2] + 1,
                "Native array sort comparator returns a boolean instead of a signed comparison",
            )

    if path.name.lower() in {"next.config.ts", "next.config.js", "next.config.mjs"}:
        for opening in exported_config(values, pairs, depths, path.suffix.lower() != ".mjs"):
            options = properties(values, pairs, (opening, pairs.get(opening, opening) + 1))
            images = properties(values, pairs, options["images"]) if "images" in options else {}
            if is_value(images, "dangerouslyAllowLocalIP", "true"):
                start, end = images["dangerouslyAllowLocalIP"]
                emit("SP674", start - 2, end, "images.dangerouslyAllowLocalIP = true")
            if (
                is_value(images, "dangerouslyAllowSVG", "true")
                and any(
                    is_value(images, "contentDispositionType", quote + "inline" + quote)
                    for quote in ("'", '"')
                )
                and any(
                    is_value(images, "contentSecurityPolicy", quote * 2) for quote in ("'", '"')
                )
                and (
                    "loader" not in images
                    or any(
                        is_value(images, "loader", quote + "default" + quote)
                        for quote in ("'", '"')
                    )
                )
                and "loaderFile" not in images
                and ("unoptimized" not in images or is_value(images, "unoptimized", "false"))
                and "output" not in options
            ):
                emit(
                    "SP688",
                    opening,
                    pairs[opening] + 1,
                    "Next image options: SVG enabled, inline disposition and explicitly empty CSP",
                )

    for index, value in enumerate(values):
        if value not in bindings or (index and values[index - 1] in {".", "?."}):
            continue
        module, member, position = bindings[value]
        if index == position:
            continue
        cursor = index + 1
        if member == "*":
            if values[cursor : cursor + 1] != ["."] or cursor + 1 >= len(values):
                continue
            member = values[cursor + 1]
            cursor += 2
        if module == "buffer":
            if member != "Buffer":
                continue
            if values[cursor : cursor + 1] != ["."] or cursor + 1 >= len(values):
                continue
            member = values[cursor + 1]
            cursor += 2
        if values[cursor : cursor + 1] != ["("] or cursor not in pairs:
            continue
        args = segments(values, pairs, cursor)
        if not args or any(values[start] == "..." for start, _ in args):
            continue
        closing = pairs[cursor]
        if module in {"http", "https"} and member == "createServer":
            options = properties(values, pairs, args[0])
            if is_value(options, "requestTimeout", "0") and is_value(
                options, "headersTimeout", "0"
            ):
                emit(
                    "SP693",
                    index,
                    closing + 1,
                    f"{module}.createServer: requestTimeout=0 and headersTimeout=0",
                )
        if (
            module == "zlib"
            and member
            in {
                "gzipSync",
                "gunzipSync",
                "deflateSync",
                "deflateRawSync",
                "inflateSync",
                "inflateRawSync",
                "unzipSync",
                "brotliCompressSync",
                "brotliDecompressSync",
            }
            and index
            and values[index - 1] == "await"
            and len(args) in {1, 2}
        ):
            emit(
                "SP698",
                index - 1,
                closing + 1,
                f"await zlib.{member}: compression completes synchronously before the await",
            )
        if (module == "tls" and member in {"createSecureContext", "createServer", "connect"}) or (
            module == "https" and member in {"createServer", "request", "get"}
        ):
            # Only the options-first overload; URL/port overloads need more provenance.
            options = properties(values, pairs, args[0])
            versions = {"TLSv1": 10, "TLSv1.1": 11, "TLSv1.2": 12, "TLSv1.3": 13}

            def string_option(key: str, options: dict = options) -> str | None:
                span = options.get(key)
                return literal(values[span[0]]) if span and span[1] == span[0] + 1 else None

            floor = string_option("minVersion")
            ceiling = string_option("maxVersion")
            protocol = string_option("secureProtocol")
            legacy_range = (
                floor in {"TLSv1", "TLSv1.1"}
                and "secureProtocol" not in options
                and ("maxVersion" not in options or versions.get(ceiling, 0) >= versions[floor])
            )
            legacy_method = protocol in {
                "TLSv1_method",
                "TLSv1_client_method",
                "TLSv1_server_method",
                "TLSv1_1_method",
                "TLSv1_1_client_method",
                "TLSv1_1_server_method",
            } and not {"minVersion", "maxVersion"}.intersection(options)
            if (legacy_range or legacy_method) and not {
                "secureOptions",
                "secureContext",
                "agent",
                "_defaultAgent",
                "createConnection",
            }.intersection(options):
                emit(
                    "SP686",
                    index,
                    closing + 1,
                    f"{module}.{member}: explicit legacy TLS protocol selection",
                )
        elif (
            module == "ws"
            and member in {"WebSocketServer", "Server"}
            and index
            and values[index - 1] == "new"
        ):
            options = properties(values, pairs, args[0])
            span = options.get("maxPayload")
            if (
                span
                and span[1] == span[0] + 1
                and re.fullmatch(r"(?:0|[1-9][0-9]{0,15})", values[span[0]])
            ):
                size = int(values[span[0]])
                # ws uses ToInt32, then checks only positive caps. Do not parse arbitrary expressions.
                narrowed = size & 0xFFFFFFFF
                if size <= 2**53 - 1 and (narrowed == 0 or narrowed >= 2**31):
                    emit(
                        "SP687",
                        index,
                        closing + 1,
                        "ws.WebSocketServer: maxPayload becomes a nonpositive signed-32-bit limit",
                    )
        if module == "jsonwebtoken" and member in {"sign", "verify"} and len(args) in {3, 4}:
            options = properties(values, pairs, args[2])
            algorithm = options.get("algorithm")
            signing_algorithm = (
                literal(values[algorithm[0]])
                if algorithm and algorithm[1] == algorithm[0] + 1 and "header" not in options
                else None
            )
            if member == "verify" and any(
                is_value(options, key, "true") for key in ("ignoreExpiration", "ignoreNotBefore")
            ):
                flags = ", ".join(
                    key + "=true"
                    for key in ("ignoreExpiration", "ignoreNotBefore")
                    if is_value(options, key, "true")
                )
                emit("SP675", index, closing + 1, "jsonwebtoken.verify: " + flags)
            if is_value(options, "allowInvalidAsymmetricKeyTypes", "true") and (
                member == "verify"
                or signing_algorithm
                in {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
            ):
                emit(
                    "SP676",
                    index,
                    closing + 1,
                    f"jsonwebtoken.{member}: allowInvalidAsymmetricKeyTypes=true",
                )
            if (
                member == "sign"
                and is_value(options, "allowInsecureKeySizes", "true")
                and signing_algorithm in {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
            ):
                emit(
                    "SP692",
                    index,
                    closing + 1,
                    "jsonwebtoken.sign: RSA key-size safeguard explicitly disabled",
                )
        elif (
            module == "crypto"
            and member in {"createCipheriv", "createDecipheriv"}
            and len(args) == 4
        ):
            algorithm = literal(values[args[0][0]]) if args[0][1] == args[0][0] + 1 else None
            options = properties(values, pairs, args[3])
            if (
                algorithm
                and re.fullmatch(r"aes-(128|192|256)-gcm", algorithm.lower())
                and any(is_value(options, "authTagLength", size) for size in ("4", "8"))
            ):
                tag = values[options["authTagLength"][0]]
                emit(
                    "SP677",
                    index,
                    closing + 1,
                    f"crypto.{member}: algorithm={algorithm}, authTagLength={tag}",
                )
        elif module == "buffer" and member in {"allocUnsafe", "allocUnsafeSlow"} and len(args) == 1:
            size = values[args[0][0] : args[0][1]]
            if (
                len(size) != 1
                or not re.fullmatch(r"[0-9]{1,10}", size[0])
                or not 0 < int(size[0]) <= 2**31 - 1
            ):
                continue
            if values[closing + 1 : closing + 4] == [".", "toString", "("]:
                end = pairs.get(closing + 3)
                string_args = segments(values, pairs, closing + 3)
                encodings = {
                    "utf8",
                    "utf-8",
                    "hex",
                    "base64",
                    "base64url",
                    "ascii",
                    "latin1",
                    "binary",
                    "ucs2",
                    "ucs-2",
                    "utf16le",
                    "utf-16le",
                }
                if end is not None and (
                    end == closing + 4
                    or (
                        len(string_args) == 1
                        and string_args[0][1] == string_args[0][0] + 1
                        and literal(values[string_args[0][0]]) in encodings
                    )
                ):
                    emit(
                        "SP678",
                        index,
                        end + 1,
                        f"Buffer.{member}({size[0]}): immediate full string read before overwrite",
                    )
        elif module in {"http", "https"} and member in {"createServer", "request", "get"}:
            option = args[0]
            if values[option[0]] != "{" and member != "createServer" and len(args) > 1:
                option = args[1]
            options = properties(values, pairs, option)
            if "httpValidation" not in options and is_value(options, "insecureHTTPParser", "true"):
                emit("SP679", index, closing + 1, f"{module}.{member}: insecureHTTPParser=true")
            elif "insecureHTTPParser" not in options and any(
                is_value(options, "httpValidation", quote + "insecure" + quote)
                for quote in ("'", '"')
            ):
                emit(
                    "SP679",
                    index,
                    closing + 1,
                    f"{module}.{member}: httpValidation=insecure (requires a supporting Node version)",
                )
        elif (
            module == "electron"
            and member == "BrowserWindow"
            and index
            and values[index - 1] == "new"
        ):
            options = properties(values, pairs, args[0])
            prefs = (
                properties(values, pairs, options["webPreferences"])
                if "webPreferences" in options
                else {}
            )
            if is_value(prefs, "webSecurity", "false"):
                emit(
                    "SP680",
                    index,
                    closing + 1,
                    "electron.BrowserWindow: webPreferences.webSecurity=false",
                )
            if (
                is_value(prefs, "nodeIntegration", "true")
                and is_value(prefs, "contextIsolation", "false")
                and ("sandbox" not in prefs or is_value(prefs, "sandbox", "false"))
                and "enableSandbox" not in values
            ):
                emit(
                    "SP681",
                    index,
                    closing + 1,
                    "electron.BrowserWindow: nodeIntegration=true, contextIsolation=false",
                )
        elif module in {"puppeteer", "puppeteer-core"} and member == "launch":
            options = properties(values, pairs, args[0])
            if any(
                key in options and literal(values[options[key][0]]) != "chrome"
                for key in ("browser", "product")
            ):
                continue
            argument = options.get("args")
            if (
                argument is None
                or values[argument[0]] != "["
                or pairs.get(argument[0]) != argument[1] - 1
            ):
                continue
            flags = segments(values, pairs, argument[0])
            if all(
                end == start + 1 and literal(values[start]) is not None for start, end in flags
            ) and any(literal(values[start]) == "--no-sandbox" for start, _ in flags):
                emit("SP682", index, closing + 1, f"{module}.launch: args include --no-sandbox")
    return list(dict.fromkeys(hits))
