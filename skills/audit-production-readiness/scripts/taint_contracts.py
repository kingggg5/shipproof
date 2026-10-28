"""Bounded value-specific protection contracts, never a name-based safety vote."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

INJECTION = frozenset({"SP101", "SP102", "SP103"})
HTML = frozenset({"SP080", "SP146", "SP147"})
ALL = INJECTION | HTML | {"SP110", "SP124"}
PROTECTOR = re.compile(r"saniti[sz]|validat|escap|clean|quote|uuid|basename", re.I)


@dataclass(frozen=True)
class Trace:
    root: str | None
    transforms: tuple[str, ...] = ()


class ContractLimitError(RecursionError):
    """The bounded value-contract expression budget is unavailable evidence."""


def transfer(proofs, transforms):
    proofs = set(proofs)
    uncertain = False
    for kind in transforms:
        if kind == "constant":
            proofs, uncertain = {"constant"}, False
        elif kind == "scalar":
            proofs, uncertain = {"scalar"}, False
        elif kind in {"html", "shell", "basename", "contained"}:
            proofs = (proofs & {"constant", "scalar"}) | {kind}
        elif kind == "unknown" or kind == "opaque":
            proofs, uncertain = set(), True
    return frozenset(proofs), uncertain


def protected(proofs, rule):
    return bool(
        "constant" in proofs
        or ("scalar" in proofs and rule in INJECTION | HTML)
        or ("shell" in proofs and rule == "SP102")
        or ("html" in proofs and rule in HTML)
        or ("contained" in proofs and rule == "SP110")
    )


def merge(traces):
    traces = list(traces)
    live = [t for t in traces if t is not None and t.root is not None]
    candidates = live or [t for t in traces if t is not None]
    if not candidates:
        return Trace(None, ("constant",))
    if not live:
        kinds = {kind for trace in candidates for kind in trace.transforms}
        if "unknown" in kinds:
            return Trace(None, ("unknown",))
        if "opaque" in kinds:
            return Trace(None, ("opaque",))
    if all(t == candidates[0] for t in candidates):
        return candidates[0]
    if len({t.root for t in live}) == 1 and any(not t.transforms for t in live):
        return next(t for t in live if not t.transforms)
    return Trace(candidates[0].root, ("unknown",))


def join_values(states, fallback):
    return {
        name: merge(state.get(name, fallback(name)) for state in states)
        for name in set().union(*states)
    }


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def scope_nodes(node):
    pending = list(reversed(getattr(node, "body", [])))
    while pending:
        item = pending.pop()
        yield item
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            pending.extend(reversed(list(ast.iter_child_nodes(item))))


class PythonContracts:
    def __init__(self, node, parent=None):
        self.imports = dict(parent.imports) if parent else {}
        self.shadowed = set(parent.shadowed) if parent else set()
        self.identities = set(parent.identities) if parent else set()
        self.posix = False
        self.posix_after = 0
        rebound = set()
        for item in scope_nodes(node):
            if isinstance(item, ast.Import):
                for alias in item.names:
                    head = alias.name.split(".")[0]
                    self._bind(alias.asname or head, alias.name if alias.asname else head)
            elif isinstance(item, ast.ImportFrom):
                for alias in item.names:
                    self._bind(alias.asname or alias.name, f"{item.module}.{alias.name}")
            elif isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
                self.shadowed.add(item.id)
                rebound.add(item.id)
            elif isinstance(item, ast.Attribute) and isinstance(item.ctx, (ast.Store, ast.Del)):
                head = dotted(item).split(".")[0]
                self.shadowed.add(head)
                rebound.add(head)
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.shadowed.add(item.name)
                self.identities.discard(item.name)
                if (
                    isinstance(item, ast.FunctionDef)
                    and not item.decorator_list
                    and len(item.args.args) == 1
                    and not (
                        item.args.posonlyargs
                        or item.args.kwonlyargs
                        or item.args.vararg
                        or item.args.kwarg
                    )
                ):
                    body = [
                        b
                        for b in item.body
                        if not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))
                    ]
                    if (
                        len(body) == 1
                        and isinstance(body[0], ast.Return)
                        and isinstance(body[0].value, ast.Name)
                        and body[0].value.id == item.args.args[0].arg
                    ):
                        self.identities.add(item.name)
        self.identities.difference_update(rebound)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = {
                a.arg for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            }
            for arg in (node.args.vararg, node.args.kwarg):
                if arg:
                    arguments.add(arg.arg)
            self.shadowed.update(arguments)
            self.identities.difference_update(arguments)
            for statement in node.body:
                if isinstance(statement, ast.If) and isinstance(statement.test, ast.Compare):
                    test = statement.test
                    if (
                        dotted(test.left) == "os.name"
                        and len(test.ops) == 1
                        and isinstance(test.ops[0], ast.NotEq)
                        and len(test.comparators) == 1
                        and isinstance(test.comparators[0], ast.Constant)
                        and test.comparators[0].value == "posix"
                        and statement.body
                        and isinstance(statement.body[-1], (ast.Raise, ast.Return))
                    ):
                        self.posix = self.imports.get("os") == "os" and "os" not in self.shadowed
                        if self.posix:
                            self.posix_after = statement.end_lineno

    def _bind(self, name, target):
        if name in self.imports and self.imports[name] != target:
            self.shadowed.add(name)
        self.imports[name] = target

    def resolve(self, name):
        head, _, tail = name.partition(".")
        return self.imports.get(head, head) + ("." + tail if tail else "")

    def code_sink(self, name):
        head = name.split(".", 1)[0]
        return head not in self.shadowed and (
            name in {"eval", "exec", "compile"}
            or (
                head in self.imports
                and self.resolve(name) in {"builtins.eval", "builtins.exec", "builtins.compile"}
            )
        )

    def kind(self, name, line=None):
        head = name.split(".", 1)[0]
        if name in self.identities:
            return "identity"
        if head in self.shadowed:
            return (
                "unknown"
                if PROTECTOR.search(name) or head in {"int", "float", "bool", "len", "str"}
                else "opaque"
            )
        resolved = self.resolve(name)
        if ("." not in resolved or head in self.imports) and resolved in {
            "int",
            "float",
            "bool",
            "len",
            "builtins.int",
            "builtins.float",
            "builtins.bool",
            "builtins.len",
        }:
            return "scalar"
        if resolved == "str" or (head in self.imports and resolved == "builtins.str"):
            return "identity"
        if head in self.imports:
            if resolved == "uuid.UUID":
                return "scalar"
            if resolved in {"html.escape", "markupsafe.escape", "bleach.clean"}:
                return "html"
            if resolved == "shlex.quote":
                return (
                    "shell"
                    if self.posix and line is not None and line > self.posix_after
                    else "unknown"
                )
            if resolved in {"os.path.basename", "posixpath.basename", "ntpath.basename"}:
                return "basename"
        return "unknown" if PROTECTOR.search(name) else "opaque"


def python_trace(node, lookup, source, contracts, depth=0):
    if depth > 24:
        raise ContractLimitError("taint expression contract depth exceeded")
    if source(node):
        return Trace("@source")
    if isinstance(node, ast.Name):
        return lookup(node.id)
    if isinstance(node, ast.Constant):
        return Trace(None, ("constant",))
    if isinstance(node, ast.Call):
        inputs = [
            python_trace(n, lookup, source, contracts, depth + 1)
            for n in [*node.args, *(k.value for k in node.keywords)]
        ]
        if isinstance(node.func, ast.Attribute):
            receiver = python_trace(node.func.value, lookup, source, contracts, depth + 1)
            if receiver.root is not None:
                inputs.append(receiver)
        base = merge(inputs)
        kind = contracts.kind(dotted(node.func), getattr(node, "lineno", 0))
        chain = base.transforms + (() if kind == "identity" else (kind,))
        if len(chain) > 12:
            raise ContractLimitError("taint transform chain budget exceeded")
        return Trace(base.root, chain)
    if isinstance(node, ast.IfExp):
        return merge(
            python_trace(n, lookup, source, contracts, depth + 1) for n in (node.body, node.orelse)
        )
    children = list(ast.iter_child_nodes(node))
    trace = merge(
        python_trace(n, lookup, source, contracts, depth + 1)
        for n in children
        if isinstance(n, ast.expr)
    )
    proofs, _ = transfer((), trace.transforms)
    if "shell" in proofs and isinstance(node, (ast.BinOp, ast.JoinedStr)):
        return Trace(trace.root, (*trace.transforms, "unknown"))
    if proofs and isinstance(node, (ast.Subscript, ast.Attribute)):
        return Trace(trace.root, (*trace.transforms, "opaque"))
    return trace


def js_kind(name, imports, shadowed):
    head = name.split(".")[0]
    if head in shadowed:
        return "unknown"
    if name in {"Number", "parseInt", "parseFloat"}:
        return "scalar"
    if name == "String":
        return "identity"
    if imports.get(head) == "dompurify" and name == head + ".sanitize":
        return "html"
    if imports.get(head) in {"path", "node:path"} and name == head + ".basename":
        return "basename"
    if imports.get(head) in {"path", "node:path"} and name in {head + ".resolve", head + ".join"}:
        return "identity"
    return "unknown" if PROTECTOR.search(name) else "opaque"


def js_chain(expression, carrier, inherited, imports, shadowed, depth=0):
    if depth > 12 or len(inherited) > 12:
        raise ContractLimitError("JS taint expression contract depth exceeded")
    text = expression.strip().rstrip(";").strip()
    match = re.fullmatch(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\((.*)\)", text, re.S)
    if match and _whole_js_call(text):
        kind = js_kind(match[1], imports, shadowed)
        if kind == "html" and not _whole_js_call(text, single_arg=True):
            kind = "unknown"
        inner = js_chain(match[2], carrier, inherited, imports, shadowed, depth + 1)
        return inner + (() if kind == "identity" else (kind,))
    # A bare alias or ordinary string interpolation keeps its input contract;
    # unknown calls cannot preserve a previous protection silently.
    if re.search(r"[A-Za-z_$][\w$]*\s*\(", text):
        return (*inherited, "opaque")
    if "html" in transfer((), inherited)[0] and text != carrier:
        return (*inherited, "unknown")
    return inherited


def js_value_chain(expression, carriers, transforms, imports, shadowed):
    live = [
        name
        for name in carriers
        if re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", expression)
    ]
    inherited = (
        merge(Trace("value", transforms.get(name, ())) for name in live).transforms if live else ()
    )
    return js_chain(expression, live[0] if live else "", inherited, imports, shadowed)


def _whole_js_call(text, single_arg=False):
    from js_config_checks import js_context_tokens

    tokens = js_context_tokens(text)
    depth = 0
    opened = False
    for index, (value, _) in enumerate(tokens):
        if value == "(":
            depth += 1
            opened = True
        elif single_arg and value == "," and depth == 1:
            return False
        elif value == ")":
            depth -= 1
            if depth == 0:
                return opened and index == len(tokens) - 1
            if depth < 0:
                return False
    return False
