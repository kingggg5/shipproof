"""Import-bound standard-library observations, without executing target code."""

from __future__ import annotations

import ast
from collections import Counter

MAX_NODES = 50_000


class AnalysisLimitError(ValueError):
    pass


def observations(tree: ast.Module) -> list[tuple[str, ast.AST]]:
    # These signatures require a direct top-level import. Skip unrelated ASTs
    # before allocating a parent map or charging the API-analysis node budget.
    relevant = any(
        (
            isinstance(node, ast.Import)
            and any(alias.name in {"asyncio", "logging.config"} for alias in node.names)
        )
        or (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module in {"asyncio", "logging.config"}
        )
        for node in tree.body
    )
    if not relevant:
        return []
    nodes = []
    parents = {}
    stack = [tree]
    while stack:
        node = stack.pop()
        nodes.append(node)
        children = list(ast.iter_child_nodes(node))
        if len(nodes) + len(stack) + len(children) > MAX_NODES:
            raise AnalysisLimitError("Python API observation node budget exceeded")
        for child in children:
            parents[child] = node
        stack.extend(children)
    bindings = {}
    invalid = set()
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name not in {"asyncio", "logging.config"}:
                    continue
                name = alias.asname or alias.name.split(".")[0]
                if name in bindings:
                    invalid.add(name)
                bindings[name] = alias.name if alias.asname else name
        elif (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module in {"asyncio", "logging.config"}
        ):
            for alias in statement.names:
                name = alias.asname or alias.name
                if name in bindings:
                    invalid.add(name)
                bindings[name] = statement.module + "." + alias.name
    import_counts = Counter(
        alias.asname or alias.name.split(".")[0]
        for node in nodes
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    )
    invalid.update(name for name, count in import_counts.items() if count > 1)
    if "*" in import_counts:
        return []
    for node in nodes:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id
            in {"eval", "exec", "globals", "locals", "setattr", "delattr", "__import__"}
        ):
            return []
        if isinstance(node, ast.arg):
            invalid.add(node.arg)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            invalid.add(node.name)
        elif isinstance(node, ast.MatchMapping):
            invalid.add(node.rest)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            invalid.add(node.name)
        elif isinstance(node, ast.Name) and node.id in bindings:
            top = node
            while isinstance(parents.get(top), ast.Attribute):
                top = parents[top]
                if top.attr in {"__dict__", "__getattribute__"}:
                    invalid.add(node.id)
            parent = parents.get(top)
            if (
                not isinstance(node.ctx, ast.Load)
                or not isinstance(parent, ast.Call)
                or parent.func is not top
            ):
                invalid.add(node.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)) and node not in tree.body:
            for alias in node.names:
                invalid.add(alias.asname or alias.name.split(".")[0])
    bindings = {name: qualified for name, qualified in bindings.items() if name not in invalid}

    def qualified(node):
        if isinstance(node, ast.Name):
            return bindings.get(node.id, "")
        if isinstance(node, ast.Attribute):
            prefix = qualified(node.value)
            return prefix + "." + node.attr if prefix else ""
        return ""

    custom_tasks = any(
        isinstance(node, ast.Attribute) and node.attr in {"set_task_factory", "eager_task_factory"}
        for node in nodes
    )
    hits = []
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        if (
            not custom_tasks
            and qualified(node.func) == "asyncio.create_task"
            and isinstance(parents.get(node), ast.Expr)
            and len(node.args) == 1
            and isinstance(node.args[0], (ast.Call, ast.Name))
            and all(item.arg in {"name", "context"} for item in node.keywords)
            and len({item.arg for item in node.keywords}) == len(node.keywords)
        ):
            hits.append(("SP346", node))
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "start"
            and not node.args
            and not node.keywords
            and isinstance(node.func.value, ast.Call)
        ):
            continue
        listener = node.func.value
        if qualified(listener.func) != "logging.config.listen" or any(
            item.arg is None for item in listener.keywords
        ):
            continue
        keywords = {item.arg: item.value for item in listener.keywords}
        if (
            len(keywords) != len(listener.keywords)
            or set(keywords) - {"port", "verify"}
            or len(listener.args) > 2
        ):
            continue
        if (listener.args and "port" in keywords) or (
            len(listener.args) == 2 and "verify" in keywords
        ):
            continue
        port = listener.args[0] if listener.args else keywords.get("port", ast.Constant(9030))
        verify = listener.args[1] if len(listener.args) == 2 else keywords.get("verify")
        if (
            isinstance(port, ast.Constant)
            and type(port.value) is int
            and 0 <= port.value <= 65535
            and isinstance(verify, ast.Constant)
            and verify.value is None
        ):
            hits.append(("SP697", listener))
    return sorted(hits, key=lambda hit: (hit[1].lineno, hit[1].col_offset, hit[0]))
