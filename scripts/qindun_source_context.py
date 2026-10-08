"""Shared, bounded source-context checks; never executes package content."""

from __future__ import annotations

import ast
import io
import re
import shlex
import tokenize
from pathlib import PurePosixPath
from string import Formatter
from urllib.parse import parse_qsl, unquote, urlsplit


class PythonFlowValue(set[str]):
    """Own provenance and bounded child references, separate from variable bindings."""

    def __init__(self, values=(), *, kind: str = "", fields=None) -> None:
        super().__init__(values)
        self.kind = kind
        self.fields = fields
        self.optional_fields = set()
        # HTTP transport/purpose proof, separate from the raw URL's credential flags.
        self.http_url_taints = None
        self.literal_string = None


def python_flow_selection(node, environment, depth=0):
    """Return an exact reference (or a missing .get default AST), never a parent alias."""
    if depth >= 16:
        return None
    if isinstance(node, ast.Name):
        return environment.get(node.id)
    if isinstance(node, ast.Call) and hasattr(node, "_qindun_flow_value"):
        return node._qindun_flow_value
    default = None
    if isinstance(node, ast.Subscript):
        owner, key = node.value, node.slice
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and 1 <= len(node.args) <= 2
        and not node.keywords
    ):
        owner, key = node.func.value, node.args[0]
        default = node.args[1] if len(node.args) == 2 else ast.Constant(value=None)
    else:
        return None
    parent = python_flow_selection(owner, environment, depth + 1)
    fields = getattr(parent, "fields", None)
    if fields is None or not isinstance(key, ast.Constant) or type(key.value) not in (str, int):
        return None
    if default is not None and getattr(parent, "kind", "") != "dict":
        return None
    if key.value in parent.optional_fields:
        return None
    return fields.get(key.value, default)


def python_flow_taints(value, map_field, depth=0, active=None, budget=None):
    """Read live children; cycles/bounds remain visible to the analyzer as partial coverage."""
    active = set() if active is None else active
    budget = [1024] if budget is None else budget
    if depth >= 16 or id(value) in active or budget[0] <= 0:
        return set(value) | {"flow_graph_incomplete"}
    budget[0] -= 1
    result = set(value)
    if getattr(value, "kind", "") == "dict":
        result.add("mapping_value")
    fields = getattr(value, "fields", None)
    if fields is not None:
        for key, child in fields.items():
            flags = python_flow_taints(child, map_field, depth + 1, active | {id(value)}, budget)
            result.update(map_field(ast.Constant(key), flags) if value.kind == "dict" else flags)
    return result


def python_flow_value(node, environment, taints, evaluate=None, depth=0):
    selected = python_flow_selection(node, environment)
    if isinstance(selected, set):
        return selected
    if isinstance(selected, ast.AST) and evaluate is not None:
        return python_flow_value(selected, environment, evaluate(selected), evaluate, depth + 1)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "dict"
        and "dict" not in environment
        and len(node.args) <= 1
        and not node.keywords
    ):
        if not node.args:
            return PythonFlowValue(kind="dict", fields={})
        source = python_flow_selection(node.args[0], environment)
        fields = getattr(source, "fields", None)
        result = PythonFlowValue(taints, kind="dict")
        if fields is not None and source.kind == "dict":
            result.clear()
            result.update(source)
            result.fields = dict(fields)
            result.optional_fields = set(source.optional_fields)
        return result
    kind = (
        "immutable"
        if isinstance(node, (ast.Constant, ast.Tuple, ast.JoinedStr))
        else "list"
        if isinstance(node, ast.List)
        else "dict"
        if isinstance(node, ast.Dict)
        else "set"
        if isinstance(node, ast.Set)
        else ""
    )
    value = PythonFlowValue(taints, kind=kind)
    if isinstance(node, ast.Constant) and type(node.value) is str and len(node.value) <= 8192:
        value.literal_string = node.value
    items = None
    if isinstance(node, ast.Dict) and all(
        isinstance(key, ast.Constant) and type(key.value) in (str, int) for key in node.keys
    ):
        items = [(key.value, child) for key, child in zip(node.keys, node.values)]
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)) and all(
        not isinstance(child, ast.Starred) for child in node.elts
    ):
        items = list(enumerate(node.elts))
    if items is not None and evaluate is not None:
        if depth >= 16 or len(items) > 64:
            value.add("flow_graph_incomplete")
        else:
            value.clear()
            if isinstance(node, ast.Dict):
                for key, _ in items:
                    value.update(evaluate(ast.Constant(key)))
            else:
                value.add("sequence_value")
            value.fields = {
                key: python_flow_value(child, environment, evaluate(child), evaluate, depth + 1)
                for key, child in items
            }
    return value


def python_append_flow_child(value, child, *, unknown_length=False):
    fields = value.fields
    if len(fields) >= 64:
        return False
    exact = (
        not unknown_length and not value.optional_fields and all(type(key) is int for key in fields)
    )
    fields[len(fields) if exact else (None, len(fields))] = child
    return True


def python_update_flow_fields(target, source, map_field):
    """Apply definite fields strongly and optional fields as possible replacements."""
    incomplete = False
    for key, child in source.fields.items():
        if key in source.optional_fields:
            previous = target.fields.get(key)
            if previous is None:
                target.optional_fields.add(key)
            elif previous is not child:
                kind = getattr(previous, "kind", "")
                child = PythonFlowValue(
                    python_flow_taints(previous, map_field) | python_flow_taints(child, map_field),
                    kind=kind if kind == getattr(child, "kind", "") else "",
                )
                incomplete |= python_mutable_flow_value(previous) or python_mutable_flow_value(
                    source.fields[key]
                )
        else:
            target.optional_fields.discard(key)
        target.fields[key] = child
    return incomplete


def python_merge_fresh_flow_values(values, map_field):
    """Join newly allocated return containers; shared child identities stay shared."""
    kinds = {getattr(value, "kind", "") for value in values}
    result = PythonFlowValue(
        set().union(*(set(value) for value in values)), kind=kinds.pop() if len(kinds) == 1 else ""
    )
    auth = [getattr(value, "http_url_taints", None) for value in values]
    if all(item is not None for item in auth):
        result.http_url_taints = frozenset().union(*auth)
    literals = [getattr(value, "literal_string", None) for value in values]
    if literals and all(item == literals[0] for item in literals):
        result.literal_string = literals[0]
    field_sets = [getattr(value, "fields", None) for value in values]
    if any(fields is None for fields in field_sets):
        result.update(set().union(*(python_flow_taints(value, map_field) for value in values)))
        return result
    keys = set().union(*(set(fields) for fields in field_sets))
    if len(keys) > 64:
        result.update(set().union(*(python_flow_taints(value, map_field) for value in values)))
        result.add("flow_graph_incomplete")
        return result
    fields = {}
    for key in keys:
        children = [mapping[key] for mapping in field_sets if key in mapping]
        if len(children) != len(values) or any(key in value.optional_fields for value in values):
            result.optional_fields.add(key)
        if all(child is children[0] for child in children):
            fields[key] = children[0]
        else:
            fields[key] = PythonFlowValue(
                set().union(*(python_flow_taints(child, map_field) for child in children))
            )
            if any(python_mutable_flow_value(child) for child in children):
                result.add("flow_graph_incomplete")
    result.fields = fields
    return result


def python_copy_flow_value(value, copies=None, *, share_mutable=False, depth=0):
    copies = {} if copies is None else copies
    if id(value) in copies:
        return copies[id(value)]
    if share_mutable and python_mutable_flow_value(value):
        return value
    result = PythonFlowValue(value, kind=getattr(value, "kind", ""))
    result.http_url_taints = getattr(value, "http_url_taints", None)
    result.literal_string = getattr(value, "literal_string", None)
    copies[id(value)] = result
    fields = getattr(value, "fields", None)
    if fields is not None:
        if depth >= 16 or len(copies) >= 1024:
            result.add("flow_graph_incomplete")
        else:
            result.fields = {
                key: python_copy_flow_value(
                    child, copies, share_mutable=share_mutable, depth=depth + 1
                )
                for key, child in fields.items()
            }
            result.optional_fields = set(value.optional_fields)
    return result


def python_mutable_flow_value(value: set[str]) -> bool:
    # An immutable tuple can still expose mutable descendants.
    return (
        getattr(value, "kind", "") in {"list", "dict", "set"}
        or getattr(value, "fields", None) is not None
    )


def python_flow_snapshot(roots):
    objects, pending = {}, [value for frame in roots for value in frame.values()]
    while pending:
        value = pending.pop()
        if id(value) in objects:
            continue
        fields = getattr(value, "fields", None)
        objects[id(value)] = (
            value,
            set(value),
            None if fields is None else dict(fields),
            set(getattr(value, "optional_fields", set())),
        )
        if fields is not None:
            if len(objects) >= 1024:
                value.add("flow_graph_incomplete")
                break
            pending.extend(fields.values())
    return objects


def python_restore_flow_snapshot(objects):
    for value, flags, fields, optional in objects.values():
        value.clear()
        value.update(flags)
        if isinstance(value, PythonFlowValue):
            value.fields = None if fields is None else dict(fields)
            value.optional_fields = set(optional)


def python_join_flow_snapshot(body, map_field):
    incomplete = False
    for value, flags, fields, optional in body.values():
        value.update(flags)
        current = getattr(value, "fields", None)
        if fields is None or current is None:
            continue
        for key in fields.keys() | current.keys():
            first, second = fields.get(key), current.get(key)
            if first is None or second is None:
                current[key] = first if first is not None else second
                value.optional_fields.add(key)
            elif first is not second:
                # A points-to union loses path correlation and future alias effects.
                current[key] = PythonFlowValue(
                    python_flow_taints(first, map_field) | python_flow_taints(second, map_field),
                    kind=getattr(first, "kind", "")
                    if getattr(first, "kind", "") == getattr(second, "kind", "")
                    else "",
                )
                incomplete |= python_mutable_flow_value(first) or python_mutable_flow_value(second)
        value.optional_fields.update(optional)
    return incomplete


def python_call_argument_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call | None
) -> dict[str, ast.AST]:
    """Bind explicit arguments only; unknown expansion keeps the existing fallback."""
    if call is None or any(isinstance(value, ast.Starred) for value in call.args):
        return {}
    if any(keyword.arg is None for keyword in call.keywords):
        return {}
    positional = [*function.args.posonlyargs, *function.args.args]
    result = {argument.arg: value for argument, value in zip(positional, call.args)}
    keyword_names = {item.arg for item in [*function.args.args, *function.args.kwonlyargs]}
    for keyword in call.keywords:
        if keyword.arg in keyword_names:
            if keyword.arg in result:
                return {}
            result[keyword.arg] = keyword.value
    return result


def python_copy_flow_environment(
    environment: dict[str, set[str]], *, share_mutable: bool = False
) -> dict[str, set[str]]:
    """Isolate a frame while preserving aliases within that frame."""
    copies: dict[int, set[str]] = {}
    result = {}
    for name, value in environment.items():
        if id(value) not in copies:
            copies[id(value)] = (
                value
                if share_mutable and python_mutable_flow_value(value)
                else python_copy_flow_value(value, copies, share_mutable=share_mutable)
            )
        result[name] = copies[id(value)]
    return result


def python_merge_flow_bindings(
    left: dict[str, set[str]],
    right: dict[str, set[str]],
    referenced: set[int],
    map_field=lambda key, flags: flags,
) -> tuple[dict[str, set[str]], bool]:
    """Keep common identities; divergent mutable references require a points-to join."""
    result, incomplete = {}, False
    aliases: dict[int, set[str]] = {}
    for frame in (left, right):
        for name, value in frame.items():
            aliases.setdefault(id(value), set()).add(name)
    for name in left.keys() | right.keys():
        first, second = left.get(name, set()), right.get(name, set())
        if first is second:
            result[name] = first
        else:
            kind = getattr(first, "kind", "")
            result[name] = PythonFlowValue(
                python_flow_taints(first, map_field) | python_flow_taints(second, map_field),
                kind=kind if kind == getattr(second, "kind", "") else "",
            )
            first_auth = getattr(first, "http_url_taints", None)
            second_auth = getattr(second, "http_url_taints", None)
            if first_auth is not None and second_auth is not None:
                result[name].http_url_taints = first_auth | second_auth
            literal = getattr(first, "literal_string", None)
            if literal == getattr(second, "literal_string", None):
                result[name].literal_string = literal
            incomplete |= any(
                python_mutable_flow_value(value)
                and (id(value) in referenced or len(aliases.get(id(value), set())) > 1)
                for value in (first, second)
            )
    return result, incomplete


def python_flow_environment_key(environment: dict[str, set[str]]) -> tuple:
    """Memoized reads depend on alias topology and type as well as flags."""
    labels, nodes, pending = {}, [], []
    roots = []
    for name, value in sorted(environment.items()):
        if id(value) not in labels:
            labels[id(value)] = len(pending)
            pending.append((value, 0))
        roots.append((name, labels[id(value)]))
    position = 0
    while position < len(pending):
        value, depth = pending[position]
        position += 1
        fields = getattr(value, "fields", None)
        children = []
        for key, child in sorted((fields or {}).items(), key=lambda item: repr(item[0])):
            if id(child) not in labels:
                if depth >= 16 or len(pending) >= 1024:
                    children.append((repr(key), ("partial", id(child))))
                    continue
                labels[id(child)] = len(pending)
                pending.append((child, depth + 1))
            children.append((repr(key), labels[id(child)]))
        auth = getattr(value, "http_url_taints", None)
        nodes.append(
            (
                getattr(value, "kind", ""),
                tuple(sorted(value)),
                getattr(value, "literal_string", None),
                None if auth is None else tuple(sorted(auth)),
                None if fields is None else tuple(children),
                tuple(sorted(map(repr, getattr(value, "optional_fields", set())))),
            )
        )
    return tuple(roots), tuple(nodes)


def python_mutated_names(node: ast.AST) -> set[str]:
    """Roots of modeled writes, for bounding recursive shared-object effects."""
    names = set()
    for item in ast.walk(node):
        target = None
        if isinstance(item, ast.AugAssign):
            target = item.target
        elif isinstance(item, ast.Subscript) and isinstance(item.ctx, ast.Store):
            target = item.value
        elif (
            isinstance(item, ast.Call)
            and isinstance(item.func, ast.Attribute)
            and item.func.attr in {"append", "extend", "add", "update"}
        ):
            target = item.func.value
        while isinstance(target, ast.Subscript):
            target = target.value
        if isinstance(target, ast.Name):
            names.add(target.id)
    return names


def python_mutating_method_receiver(
    node: ast.Call, environment: dict[str, set[str]]
) -> set[str] | None:
    if not isinstance(node.func, ast.Attribute):
        return None
    value = python_flow_selection(node.func.value, environment)
    kind = getattr(value, "kind", "")
    supported = (
        kind == "list"
        and node.func.attr in {"append", "extend"}
        or kind == "set"
        and node.func.attr == "add"
        or kind == "dict"
        and node.func.attr == "update"
    )
    return value if supported else None


def python_literal_mapping_selection(node: ast.AST, depth: int = 0) -> ast.AST | None:
    """Resolve a literal mapping selection, without evaluating any expression."""
    if depth >= 16:
        return None
    default = None
    if isinstance(node, ast.Subscript):
        mapping, key = node.value, node.slice
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and 1 <= len(node.args) <= 2
        and not node.keywords
    ):
        mapping, key = node.func.value, node.args[0]
        default = node.args[1] if len(node.args) == 2 else ast.Constant(value=None)
    else:
        return None
    selected_mapping = python_literal_mapping_selection(mapping, depth + 1)
    if selected_mapping is not None:
        mapping = selected_mapping
    if (
        not isinstance(mapping, ast.Dict)
        or not isinstance(key, ast.Constant)
        or not isinstance(key.value, str)
        or any(
            not isinstance(item, ast.Constant) or not isinstance(item.value, str)
            for item in mapping.keys
        )
    ):
        return None
    # Python uses the last value for a repeated literal key. The normal visitor
    # still visits every expression, including unselected/default side effects.
    fields = {item.value: value for item, value in zip(mapping.keys, mapping.values)}
    return fields.get(key.value, default)


def python_expand_literal_arguments(tree: ast.AST) -> None:
    """Normalize explicit tuple/list and unique literal-dict call unpacking only."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        node.args = [
            value
            for argument in node.args
            for value in (
                argument.value.elts
                if isinstance(argument, ast.Starred)
                and isinstance(argument.value, (ast.List, ast.Tuple))
                and all(not isinstance(item, ast.Starred) for item in argument.value.elts)
                else [argument]
            )
        ]
        keywords = []
        for keyword in node.keywords:
            value = keyword.value
            if (
                keyword.arg is None
                and isinstance(value, ast.Dict)
                and all(
                    isinstance(key, ast.Constant) and isinstance(key.value, str)
                    for key in value.keys
                )
                and len({key.value for key in value.keys}) == len(value.keys)
            ):
                keywords.extend(
                    ast.keyword(arg=key.value, value=item)
                    for key, item in zip(value.keys, value.values)
                )
            else:
                keywords.append(keyword)
        names = [keyword.arg for keyword in keywords if keyword.arg is not None]
        if len(names) == len(set(names)):
            node.keywords = keywords


def python_global_bindings(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Explicit global declarations in this scope, excluding nested bodies."""
    names: set[str] = set()

    class Globals(ast.NodeVisitor):
        def visit_Global(self, item: ast.Global) -> None:
            names.update(item.names)

        def visit_FunctionDef(self, item: ast.FunctionDef) -> None:
            pass

        visit_AsyncFunctionDef = visit_FunctionDef
        visit_ClassDef = visit_FunctionDef
        visit_Lambda = visit_FunctionDef

    visitor = Globals()
    for statement in node.body:
        visitor.visit(statement)
    return names


def python_local_bindings(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names bound in this lexical scope; nested function bodies have their own scope."""
    bound: set[str] = set()
    external: set[str] = set()

    class Bindings(ast.NodeVisitor):
        def visit_Name(self, item: ast.Name) -> None:
            if isinstance(item.ctx, (ast.Store, ast.Del)):
                bound.add(item.id)

        def visit_FunctionDef(self, item: ast.FunctionDef) -> None:
            bound.add(item.name)

        visit_AsyncFunctionDef = visit_FunctionDef
        visit_ClassDef = visit_FunctionDef

        def visit_Lambda(self, item: ast.Lambda) -> None:
            pass

        def visit_comprehension(self, item: ast.comprehension) -> None:
            # Comprehension iteration targets belong to a separate implicit scope.
            self.visit(item.iter)
            for condition in item.ifs:
                self.visit(condition)

        def visit_ExceptHandler(self, item: ast.ExceptHandler) -> None:
            if item.name:
                bound.add(item.name)
            self.generic_visit(item)

        def visit_Global(self, item: ast.Global) -> None:
            external.update(item.names)

        visit_Nonlocal = visit_Global

        def visit_Import(self, item: ast.Import) -> None:
            bound.update(alias.asname or alias.name.split(".")[0] for alias in item.names)

        def visit_ImportFrom(self, item: ast.ImportFrom) -> None:
            bound.update(alias.asname or alias.name for alias in item.names)

    visitor = Bindings()
    for statement in node.body:
        visitor.visit(statement)
    return bound - external


def _literal_format_url(node: ast.AST, environment=None) -> ast.AST:
    """Translate a known literal template; never evaluate fields or values."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and all(not isinstance(value, ast.Starred) for value in node.args)
        and all(keyword.arg is not None for keyword in node.keywords)
    ):
        return node
    owner = node.func.value
    literal = (
        owner.value
        if isinstance(owner, ast.Constant) and type(owner.value) is str
        else getattr(python_flow_selection(owner, environment or {}), "literal_string", None)
    )
    if literal is None or len(literal) > 8192:
        return node
    arguments = {str(index): value for index, value in enumerate(node.args)}
    arguments.update({keyword.arg: keyword.value for keyword in node.keywords})
    if len(arguments) != len(node.args) + len(node.keywords):
        return node
    values, used = [], set()
    automatic = explicit = False
    next_index = 0
    try:
        for fragment, field, spec, conversion in Formatter().parse(literal):
            values.append(ast.Constant(value=fragment))
            if field is None:
                continue
            if spec or conversion is not None:
                return node
            if field == "":
                automatic = True
                field = str(next_index)
                next_index += 1
            elif field.isdecimal():
                explicit = True
            elif not field.isidentifier():
                return node
            if automatic and explicit or field not in arguments:
                return node
            used.add(field)
            values.append(ast.FormattedValue(value=arguments[field], conversion=-1))
    except ValueError:
        return node
    return ast.JoinedStr(values=values) if used == set(arguments) else node


def python_http_url_prefix(node: ast.AST, environment=None) -> ast.AST | None:
    """Bound a proven HTTP URL before its literal fragment delimiter; never execute it."""
    environment = environment or {}
    parts = []

    def flatten(item, depth=0):
        if depth >= 16 or len(parts) >= 128:
            return False
        item = _literal_format_url(item, environment)
        selected = python_flow_selection(item, environment)
        literal = (
            item.value
            if isinstance(item, ast.Constant) and type(item.value) is str
            else getattr(selected, "literal_string", None)
            if not selected
            else None
        )
        if literal is not None:
            parts.append(literal)
        elif isinstance(item, ast.BinOp) and isinstance(item.op, ast.Add):
            return flatten(item.left, depth + 1) and flatten(item.right, depth + 1)
        elif isinstance(item, ast.JoinedStr):
            for child in item.values:
                if isinstance(child, ast.FormattedValue):
                    if child.conversion != -1 or child.format_spec is not None:
                        return False
                    if not flatten(child.value, depth + 1):
                        return False
                elif not flatten(child, depth + 1):
                    return False
        else:
            parts.append(item)
        return True

    if not flatten(node) or sum(len(p) for p in parts if isinstance(p, str)) > 8192:
        return None
    leading = ""
    for part in parts:
        if not isinstance(part, str):
            break
        leading += part
    # Prove the scheme/authority boundary before any unresolved interpolation.
    if re.match(r"https?://[^/?#\s\\]+[/#?]", leading) is None:
        return None
    try:
        target = urlsplit(leading)
        if not target.hostname:
            return None
        target.port
    except ValueError:
        return None
    values = []
    for part in parts:
        if isinstance(part, str):
            prefix, separator, _fragment = part.partition("#")
            values.append(ast.Constant(value=prefix))
            if separator:
                return ast.JoinedStr(values=values)
        else:
            values.append(ast.FormattedValue(value=part, conversion=-1))
    return None


def python_query_url_values(node: ast.AST, environment=None) -> list[ast.AST]:
    """Locate whole scalar auth values in a fixed-authority HTTPS URL template."""
    node = _literal_format_url(node, environment)
    if not isinstance(node, ast.JoinedStr):
        return []
    fragments, values, markers = [], [], []
    for item in node.values:
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            if "QINDUNQUERYVALUE" in unquote(item.value):
                return []
            fragments.append(item.value)
        elif (
            isinstance(item, ast.FormattedValue)
            and item.conversion == -1
            and item.format_spec is None
        ):
            selected = python_flow_selection(item.value, environment or {})
            literal = (
                item.value.value
                if isinstance(item.value, ast.Constant) and type(item.value.value) is str
                else getattr(selected, "literal_string", None)
            )
            if literal is not None and len(literal) <= 8192 and not selected:
                if "QINDUNQUERYVALUE" in unquote(literal):
                    return []
                fragments.append(literal)
                continue
            marker = f"QINDUNQUERYVALUE{len(values)}END"
            markers.append(marker)
            values.append(item.value)
            fragments.append(marker)
        else:
            return []
    text = "".join(fragments)
    try:
        target = urlsplit(text)
        fields = parse_qsl(target.query, keep_blank_values=True)
        if (
            target.scheme != "https"
            or not target.hostname
            or target.username is not None
            or target.password is not None
            or target.port not in {None, 443}
            or target.fragment
            or re.search(r"[\s{}\\]", text)
            or len({name for name, _value in fields}) != len(fields)
        ):
            return []
    except ValueError:
        return []
    auth_names = {"key", "api_key", "apikey", "access_token", "token"}
    if any(
        sum(name in auth_names and value == marker for name, value in fields) != 1
        for marker in markers
    ):
        return []
    return values


def actionable_secret_match(text: str, start: int, end: int, path: str) -> bool:
    fragment = text[start:end]
    if path.lower().endswith((".md", ".rst")) and re.fullmatch(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", fragment
    ):
        # An inline marker followed by a complete prose/fence line is a
        # reference, not PEM data. An incomplete read window stays actionable.
        prefix = text[text.rfind("\n", 0, start) + 1 : start].strip()
        following = re.match(r"[ \t]*\r?\n([^\r\n]+)\r?\n", text[end:])
        if prefix and following is not None:
            next_line = following[1].strip()
            if (
                next_line
                and re.fullmatch(r"[A-Za-z0-9+/= \t]+", next_line) is None
                and not next_line.startswith(("Proc-Type:", "DEK-Info:"))
            ):
                return False
    # A raw detector made only of character classes has no concrete username,
    # password or host. Keep literal credentials, including those inside regexes.
    if path.lower().endswith((".py", ".pyw")) and text[max(0, start - 2) : start] in {
        "r'",
        'r"',
        "R'",
        'R"',
    }:
        detector = re.fullmatch(
            r"(?:postgres(?:ql)?|mysql|mongodb|redis)://"
            r"\[\^[^\]\r\n]+\]\+:\[\^[^\]\r\n]+\]\+@(['\"])[,)\]]*",
            fragment,
            re.I,
        )
        if detector is not None and detector[1] == text[start - 1]:
            return False
    value = re.search(r"[:=]\s*([\"']?)([A-Za-z0-9_./+=-]+)", fragment)
    if value:
        token = value[2]
        # A service label may have a numeric prefix in a complete doc placeholder.
        # Keep runtime values and strings with additional credential characters.
        if path.lower().endswith((".md", ".rst")) and re.fullmatch(
            r"(?:YOUR_[0-9]*[A-Z]{1,20}_(?:API_KEY|ACCESS_TOKEN)|YOUR_KEY_HERE)",
            token.replace("-", "_"),
            re.I,
        ):
            return False
        if re.fullmatch(
            r"(?:YOUR_(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET|PASSWORD)(?:_HERE)?|OPENAI_KEY_HERE|REPLACE_ME|CHANGEME|EXAMPLE_(?:API_KEY|TOKEN|PASSWORD))",
            token.replace("-", "_"),
            re.I,
        ):
            return False
        # An unquoted attribute read is an expression, not a fixed secret value.
        if (
            path.endswith((".py", ".pyw"))
            and not value[1]
            and re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", token)
        ):
            try:
                if isinstance(ast.parse(token, mode="eval").body, ast.Attribute):
                    return False
            except (SyntaxError, ValueError):
                pass
    if path.lower().endswith((".md", ".rst")) and re.match(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://", fragment, re.I
    ):
        try:
            url = urlsplit(fragment.rstrip("\"'.,;)"))
            if url.hostname in {"localhost", "127.0.0.1", "::1"} and (
                url.username,
                url.password,
            ) == ("user", "pass"):
                return False
        except ValueError:
            pass
    return True


def explicit_operation_prohibition(text: str, start: int) -> bool:
    """Recognize a Chinese prohibition that directly governs the matched operation."""
    prefix = text[max(0, start - 96) : start].replace("**", "").replace("__", "")
    return bool(re.search(r"(?:不要|不可|禁止|严禁|不得|勿)[^。！？；;，,\n]{0,40}$", prefix))


def success_reporting_prohibition(text: str, start: int, end: int, path: str) -> bool:
    """Recognize a clause requiring transparent success reporting, per match."""
    if not path.lower().endswith((".md", ".rst")):
        return False
    if (
        re.fullmatch(
            r"without[ \t]+(?:telling|notifying|informing)[ \t]+the[ \t]+user",
            text[start:end],
            re.I,
        )
        is None
    ):
        return False
    prefix = text[max(0, start - 200) : start]
    return bool(
        re.search(
            r"(?:^|[.!?;\n])[ \t]*(?:[-*+][ \t]+)?"
            r"(?:don't|do[ \t]+not|never)[ \t]+"
            r"(?:claim|report|announce)[ \t]+(?:success|completion)"
            r"(?:[ \t]+(?:on|with)[ \t]+(?:empty|incomplete|unverified|failed)"
            r"[ \t]+(?:results|output|checks))?[ \t]+$",
            prefix,
            re.I,
        )
        and re.match(r"[ \t]*(?:[.!?;\r\n]|$)", text[end:])
    )


def command_recommendation_prohibition(text: str, start: int, end: int, path: str) -> bool:
    """A complete instruction against recommending commands is not concealment."""
    if not path.lower().endswith((".md", ".rst")):
        return False
    if re.fullmatch(r"do\s+not\s+tell\s+the\s+user", text[start:end], re.I) is None:
        return False
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    return bool(
        re.fullmatch(r"[ \t]*(?:[-*+]\s+)?", text[line_start:start])
        and re.fullmatch(
            r"[ \t]+to[ \t]+run[ \t]+(?:shell|terminal)[ \t]+commands[.!]?[ \t\r]*",
            text[end:line_end],
            re.I,
        )
    )


def documented_query_auth_overrides(text: str, start: int, path: str) -> dict[str, str]:
    """Recognize a bounded documented GET example, never bless its other behavior."""
    if not path.lower().endswith((".md", ".rst")):
        return {}
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end < 0:
        line_end = len(text)
    prefix = text[line_start:start].strip()
    suffix = text[start:line_end].strip()
    if prefix not in {'curl "', "curl '"} or not suffix.endswith(prefix[-1]):
        return {}
    endpoint = suffix[:-1]
    try:
        url = urlsplit(endpoint)
        if (
            url.scheme != "https"
            or url.username is not None
            or url.password is not None
            or url.port not in {None, 443}
            or url.fragment
            or re.search(r"[\s\"'\\]", endpoint)
        ):
            return {}
        pairs = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return {}
    params = dict(pairs)
    if len(params) != len(pairs):
        return {}
    if url.hostname == "www.googleapis.com" and re.fullmatch(
        r"/youtube/v3/(?:videos|search|channels|playlists|playlistItems)", url.path
    ):
        expected = {"key": "YOUTUBE_API_KEY"}
        allowed = {
            "key",
            "id",
            "part",
            "q",
            "type",
            "maxResults",
            "pageToken",
            "channelId",
            "playlistId",
        }
    elif url.hostname == "api.trello.com" and re.fullmatch(
        r"/1/(?:members/me|boards/\$(?:BOARD_ID|\{BOARD_ID\})(?:/(?:lists|cards))?)", url.path
    ):
        expected = {"key": "TRELLO_KEY", "token": "TRELLO_TOKEN"}
        allowed = set(expected)
    else:
        return {}
    if set(params) - allowed or any(
        params.get(key) not in {"$" + variable, "${" + variable + "}"}
        for key, variable in expected.items()
    ):
        return {}
    if any(
        re.search(r"[$`{}]|process\.env\.", value) for key, value in pairs if key not in expected
    ):
        return {}
    # Standard authentication still creates URL/logging exposure; retain a finding.
    return {
        "severity": "medium",
        "title": "标准鉴权示例仍需保护网址中的凭据",
        "summary": "文档示例符合已核对的服务鉴权形式；仍需避免含凭据的网址进入日志、历史记录或共享内容",
    }


def required_frontmatter(content: str) -> dict[str, str]:
    """Validate portable required YAML string fields, without evaluating YAML tags."""
    lines = content.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    end = next((i for i, line in enumerate(lines[1:513], 1) if line.strip() == "---"), None)
    if end is None:
        return {}
    values: dict[str, str] = {}
    current = ""
    mode = ""
    optional_quoted = ""
    quoted_scalar = r"""(?:'((?:[^']|'')*)'|"(?:[^"\\]|\\.)*")(?:\s+#.*)?"""
    for line in lines[1:end]:
        if mode == "optional_quote":
            optional_quoted += "\n" + line
            if re.fullmatch(quoted_scalar, optional_quoted, flags=re.S):
                mode = "closed_scalar"
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t")):
            if mode in {"closed_collection", "closed_scalar"}:
                return {}
            if current in {"name", "description"}:
                if mode not in {"plain", "block"} or "\t" in line[: len(line) - len(line.lstrip())]:
                    return {}
                if mode == "plain" and re.search(r":\s", line):
                    return {}
                values[current] += "\n" + line.strip()
            elif mode == "empty":
                mode = "nested"
            continue
        match = re.fullmatch(r"([A-Za-z][\w-]*):\s*(.*)", line)
        if match is None:
            if current and mode in {"empty", "indentless"} and line.startswith("- "):
                mode = "indentless"
                continue
            return {}
        current, value = match.groups()
        if current not in {"name", "description"}:
            mode = "empty" if not value or value.startswith("#") else "other"
            # A completed empty flow collection cannot own a following block.
            if re.fullmatch(r"(?:\[\s*\]|\{\s*\})(?:\s+#.*)?", value):
                mode = "closed_collection"
            elif value.startswith(("'", '"')):
                optional_quoted = value
                mode = "closed_scalar" if re.fullmatch(quoted_scalar, value) else "optional_quote"
            continue
        if current in values:
            return {}
        mode = "plain"
        if value.startswith(("|", ">")):
            if re.fullmatch(r"[|>][+-]?(?:\s+#.*)?", value) is None:
                return {}
            values[current] = ""
            mode = "block"
            continue
        if value.startswith("'"):
            quoted = re.fullmatch(r"'((?:[^']|'')*)'(?:\s+#.*)?", value)
            if quoted is None:
                return {}
            value = quoted[1].replace("''", "'")
            mode = "quoted"
        elif value.startswith('"'):
            quoted = re.fullmatch(r'("(?:[^"\\]|\\.)*")(?:\s+#.*)?', value)
            if quoted is None:
                return {}
            try:
                value = ast.literal_eval(quoted[1])
            except (SyntaxError, ValueError):
                return {}
            mode = "quoted"
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
            if not value or value[0] in "[{&*!|>" or re.search(r":\s", value):
                return {}
            if value.casefold() in {
                "null",
                "~",
                "true",
                "false",
                "yes",
                "no",
                "on",
                "off",
            } or re.fullmatch(r"[-+]?\d+(?:\.\d+)?", value):
                return {}
        values[current] = value
    if mode == "optional_quote":
        return {}
    return {key: value.strip() for key, value in values.items() if value.strip()}


def installed_skill_relative_path(candidate: str, path: str, text: str) -> str:
    """Map a named installation alias to this package, without touching the host."""
    alias = re.fullmatch(r"~/\.(?:claude|codex)/skills/([a-z0-9][a-z0-9-]*)/(.+)", candidate)
    if alias is None or PurePosixPath(path).name != "SKILL.md":
        return candidate
    if required_frontmatter(text).get("name") != alias[1]:
        return candidate
    relative = alias[2]
    if (
        relative.startswith("/")
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        return candidate
    return relative


def powershell_direct_execution_pipeline(command: str) -> bool:
    """Confirm a direct pipeline only outside quoted, escaped or commented text."""
    visible: list[str] = []
    quote = ""
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            visible.append(" ")
            escaped = False
        elif char == "\x60" and quote != "'":
            visible.append(" ")
            escaped = True
        elif quote:
            visible.append(" ")
            if char == quote:
                quote = ""
        elif char in {"'", '"'}:
            visible.append(" ")
            quote = char
        elif char == "#" and (index == 0 or command[index - 1].isspace()):
            break
        else:
            visible.append(char)
    return bool(
        re.match(
            r"^\s*(?:iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b[^|;\r\n]*\|\s*(?:iex|Invoke-Expression)\b",
            "".join(visible),
            re.I,
        )
    )


def _shell_word_variables(
    source: str, following_lines: list[str] | None = None
) -> tuple[set[str], str] | None:
    """Read a bounded shell word's variable-value sources and unconsumed text."""
    remaining = iter((following_lines or [])[:128])
    variables: set[str] = set()
    quote = ""
    index = 0
    while len(source) <= 8192:
        if index == len(source):
            if not quote:
                return variables, ""
            try:
                source += "\n" + next(remaining)
            except StopIteration:
                return None
            continue
        char = source[index]
        if char == "\\" and quote != "'":
            if index + 1 == len(source):
                return None
            # In double quotes only these characters lose their backslash.
            if quote != '"' or source[index + 1] in {"$", "`", '"', "\\", "\n"}:
                index += 2
                continue
        if quote == "'":
            if char == "'":
                quote = ""
        elif char == quote:
            quote = ""
        elif not quote and char in {"'", '"'}:
            quote = char
        elif not quote and (char.isspace() or char in ");|&<>"):
            return variables, source[index:]
        elif char == "`" or source[index : index + 2] == "$(":
            return None
        elif char == "$":
            parameter = re.match(r"\$\{([A-Za-z_]\w*)(:?[-+])([A-Za-z0-9_.:/-]*)\}", source[index:])
            if parameter:
                # A literal alternative emits only fixed text; a default may emit the variable.
                if parameter[2].endswith("-"):
                    variables.add(parameter[1])
                index += parameter.end()
                continue
            variable = re.match(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))", source[index:])
            if variable:
                variables.add(variable[1] or variable[2])
                index += variable.end()
                continue
            return None
        index += 1
    return None


def shell_curl_status_only(expression: str) -> bool:
    """Prove curl stdout contains only a fixed numeric status write-out."""
    if not expression.startswith("$(curl ") or not expression.endswith(")"):
        return False
    try:
        tokens = shlex.split(expression[2:-1])
    except ValueError:
        return False
    output = status = False
    urls = 0
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if re.fullmatch(r"-[sSLf]+", token):
            index += 1
            continue
        if token in {"-o", "--output", "-w", "--write-out", "-H", "--header", "-X", "--request"}:
            if index + 1 == len(tokens):
                return False
            value = tokens[index + 1]
            if token in {"-o", "--output"}:
                if (
                    output
                    or value == "-"
                    or value.startswith(("/dev/", "/proc/"))
                    or any(char in value for char in "$`")
                ):
                    return False
                output = bool(value)
            elif token in {"-w", "--write-out"}:
                if status or value != "%{http_code}":
                    return False
                status = True
            index += 2
            continue
        if token.startswith("-"):
            return False
        urls += 1
        index += 1
    return output and status and urls == 1


def shell_assignment_value(expression: str) -> str:
    """Separate a trailing comment from a complete assignment word, including empty."""
    word = _shell_word_variables(expression)
    if word is not None and word[1].lstrip().startswith("#"):
        return expression[: len(expression) - len(word[1])]
    return expression


def shell_assignment_variables(expression: str) -> set[str] | None:
    """Read actual expansions in a complete assignment word; unknown forms return None."""
    word = _shell_word_variables(expression)
    if word is not None and (not word[1].strip() or word[1].lstrip().startswith("#")):
        return word[0]
    return None


def shell_literal_assignment(expression: str) -> bool:
    """Prove a complete assignment word whose output contains only fixed text."""
    return shell_assignment_variables(expression) == set()


def shell_python_program_variables(
    command: str, following_lines: list[str] | None = None
) -> set[str]:
    """Read expansions in a direct Python -c word, never its argv data.

    Handle direct invocations and assignment command substitutions. Other shell
    wrappers/options, nested substitutions and dynamic parameter words remain outside
    this proof; absence of a match is not a safe-program verdict.
    """
    start = re.match(
        r"^\s*(?:(?:export\s+)?[A-Za-z_]\w*=\$\(\s*)?"
        r"python(?:3(?:\.\d+)?)?\s+-c\s+",
        command,
    )
    if start is None:
        return set()
    word = _shell_word_variables(command[start.end() :], following_lines)
    return word[0] if word is not None else set()


def shell_safe_date_interpolation(expression: str) -> bool:
    """Recognize fixed UTC date output with an alphabet safe for Python strings."""
    return shell_assignment_value(expression).strip() in {
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "$(date -u +%s)",
    }


def shell_update_safe_date_interpolations(
    line: str,
    safe_interpolations: set[str],
    function_names: set[str] | None = None,
) -> None:
    """Track fixed date assignments until a possible write or dynamic shell scope."""
    assignment = re.match(r"^\s*(?:export\s+)?([A-Za-z_]\w*)=(.*)$", line)
    if assignment:
        name, expression = assignment.groups()
        if shell_safe_date_interpolation(expression):
            safe_interpolations.add(name)
        else:
            safe_interpolations.discard(name)
        for other in tuple(safe_interpolations):
            if other != name and re.search(rf"\b{re.escape(other)}\s*=", line):
                safe_interpolations.discard(other)
        return

    stripped = line.strip()
    if re.match(r"^(?:source|eval|read|trap|declare|typeset|local)\b", stripped) or re.match(
        r"^\.(?:\s|$)", stripped
    ):
        safe_interpolations.clear()
        return
    if re.match(r"^(?:while|until)\b.*\bread\b", stripped):
        safe_interpolations.clear()
        return
    if function_names and re.match(
        rf"^(?:command\s+)?(?:{'|'.join(re.escape(name) for name in sorted(function_names))})\b",
        stripped,
    ):
        safe_interpolations.clear()
        return
    if re.search(r"\beval\b|\bprintf\s+-v\b", stripped):
        safe_interpolations.clear()
        return

    for name in tuple(safe_interpolations):
        escaped = re.escape(name)
        if re.search(rf"(?:^|[;&|\s]){escaped}=", line) or re.search(
            rf"\b(?:for|unset)\b[^\n]*\b{escaped}\b", line
        ):
            safe_interpolations.discard(name)


def _shell_interpolated_python_program(program: str, safe_interpolations: set[str]) -> str | None:
    references = list(re.finditer(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", program))
    if not references:
        return program
    names = {match.group(1) or match.group(2) for match in references}
    if not names.issubset(safe_interpolations):
        return None
    markers = {name: f"QINDUN_SAFE_VALUE_{index}" for index, name in enumerate(sorted(names))}
    normalized = re.sub(
        r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)",
        lambda match: markers[match.group(1) or match.group(2)],
        program,
    )
    if "$" in normalized:
        return None
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(normalized).readline))
    except (IndentationError, tokenize.TokenError):
        return None
    for marker in markers.values():
        containing = [token for token in tokens if marker in token.string]
        if not containing or any(
            token.type != tokenize.STRING
            or "f" in re.match(r"(?i)^([rubf]*)", token.string).group(1)
            for token in containing
        ):
            return None
    return normalized


def _shell_json_data_only_program(tree: ast.AST) -> bool:
    safe_nodes = (
        ast.Module,
        ast.Import,
        ast.alias,
        ast.Assign,
        ast.AnnAssign,
        ast.Expr,
        ast.If,
        ast.For,
        ast.Try,
        ast.ExceptHandler,
        ast.Pass,
        ast.Break,
        ast.Continue,
        ast.Name,
        ast.Load,
        ast.Store,
        ast.Attribute,
        ast.Subscript,
        ast.Constant,
        ast.Call,
        ast.keyword,
        ast.Dict,
        ast.List,
        ast.Tuple,
        ast.Set,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
        ast.comprehension,
        ast.UnaryOp,
        ast.Not,
        ast.UAdd,
        ast.USub,
        ast.BinOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.FloorDiv,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Is,
        ast.IsNot,
        ast.In,
        ast.NotIn,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.IfExp,
        ast.Slice,
    )
    imports: set[str] = set()
    has_json_reader = False
    safe_functions = {
        "json.load",
        "json.loads",
        "json.dumps",
        "sys.stdin.read",
        "sys.exit",
        "print",
        "str",
        "int",
        "float",
        "bool",
        "list",
        "dict",
        "len",
        "sorted",
        "enumerate",
        "range",
    }
    safe_methods = {
        "get",
        "append",
        "extend",
        "strip",
        "rstrip",
        "lstrip",
        "lower",
        "upper",
        "casefold",
        "items",
        "keys",
        "values",
        "join",
        "split",
        "replace",
        "startswith",
        "endswith",
        "count",
    }
    reserved_names = safe_functions | {"json", "sys"}
    writes: dict[str, list[tuple[tuple[int, int], bool]]] = {}
    parsed_text_variables: list[tuple[tuple[int, int], str]] = []

    def reads_stdin_text(node: ast.AST) -> bool:
        while (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"strip", "rstrip", "lstrip"}
        ):
            node = node.func.value
        return ast.unparse(node) == "sys.stdin.read()"

    for node in ast.walk(tree):
        if not isinstance(node, safe_nodes):
            return False
        if isinstance(node, ast.Import):
            if any(alias.name not in {"json", "sys"} or alias.asname for alias in node.names):
                return False
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            return False
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if node.id in reserved_names:
                return False
        elif (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)) or (
            isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store)
        ):
            return False
        elif isinstance(node, ast.Call):
            call_name = ast.unparse(node.func)
            if call_name not in safe_functions and not (
                isinstance(node.func, ast.Attribute) and node.func.attr in safe_methods
            ):
                return False
            if call_name == "print" and any(
                keyword.arg not in {"sep", "end", "flush"}
                or not isinstance(keyword.value, ast.Constant)
                for keyword in node.keywords
            ):
                return False
            if call_name == "json.dumps" and any(
                keyword.arg not in {"indent", "ensure_ascii", "sort_keys"}
                or not isinstance(keyword.value, ast.Constant)
                or type(keyword.value.value) not in {int, bool}
                for keyword in node.keywords
            ):
                return False
            if ast.unparse(node) in {
                "json.load(sys.stdin)",
                "json.loads(sys.stdin.read())",
                "json.loads(sys.stdin.read().strip())",
            }:
                has_json_reader = True
            if call_name == "json.loads" and node.args and isinstance(node.args[0], ast.Name):
                parsed_text_variables.append(((node.lineno, node.col_offset), node.args[0].id))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if isinstance(value, ast.Name) and value.id in {"json", "sys"}:
                return False
            from_stdin = reads_stdin_text(value)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    writes.setdefault(target.id, []).append(
                        ((node.lineno, node.col_offset), from_stdin)
                    )
    for position, name in parsed_text_variables:
        preceding = [item for item in writes.get(name, []) if item[0] < position]
        if preceding and max(preceding)[1]:
            has_json_reader = True
    return imports == {"json", "sys"} and has_json_reader


def shell_fixed_json_pipeline(
    command: str,
    following_lines: list[str] | None = None,
    safe_interpolations: set[str] | None = None,
) -> bool:
    """Identify a bounded JSON-data consumer, not stdin-as-program execution.

    This only lowers confirmation to a candidate: imports may be shadowed and
    network access still needs review. Unknown or dynamically supplied code stays
    confirmed.
    """
    try:
        source = ""
        for line in [command, *(following_lines or [])[:128]]:
            source += ("\n" if source else "") + line
            if len(source) > 8192 or "$(" in source or "`" in source:
                return False
            lexer = shlex.shlex(source, posix=True, punctuation_chars="();|&<>")
            lexer.whitespace_split = True
            try:
                tokens = list(lexer)
            except ValueError:
                continue
            break
        else:
            return False
        if tokens.count("|") != 1 or tokens[0] not in {"curl", "wget"}:
            return False
        consumer = tokens[tokens.index("|") + 1 :]
        if len(consumer) != 3 or consumer[1] != "-c":
            return False
        if re.fullmatch(r"python(?:3(?:\.\d+)?)?", consumer[0]) is None:
            return False
        program = _shell_interpolated_python_program(consumer[2], safe_interpolations or set())
        if program is None:
            return False
        tree = ast.parse(program)
        if sum(1 for _node in ast.walk(tree)) > 512:
            return False
    except (ValueError, IndexError, SyntaxError, RecursionError):
        return False
    return _shell_json_data_only_program(tree)


def _shell_open_pipeline(line: str) -> str | None:
    """Return a command awaiting its pipe consumer, respecting quotes/comments."""
    quote = ""
    escaped = False
    pipe = -1
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in {"'", '"', "`"}:
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t;|&()<>"):
            line = line[:index]
            break
        elif char == "|":
            pipe = index
    trimmed = line.rstrip()
    if not quote and pipe == len(trimmed) - 1 and trimmed.endswith("|"):
        if not trimmed.endswith("||"):
            return trimmed
    return None


def shell_logical_lines(text: str) -> list[tuple[int, str]]:
    """Join explicit continuations and open pipes, retaining physical start lines."""
    result: list[tuple[int, str]] = []
    pending = ""
    start_line = 1
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        if not pending:
            start_line = number
        if line.endswith("\\\n"):
            pending += line[:-2] + " "
        else:
            command = pending + line.rstrip("\r\n")
            pipeline = _shell_open_pipeline(command)
            if pipeline is not None:
                pending = pipeline + " "
            else:
                result.append((start_line, command))
                pending = ""
    if pending:
        result.append((start_line, pending))
    return result


class ShellRequestFrame:
    """Keep direct request inputs separate from bytes consumed through stdin."""

    def __init__(self, command, variables, stdin_variables=None, stdin_credential_path=False):
        self.command = command
        self.variables = variables
        self.stdin_variables = stdin_variables or set()
        self.stdin_credential_path = stdin_credential_path


def _shell_curl_io(tokens: list[str]) -> tuple[bool | None, bool]:
    """Return possible stdin consumption and a bounded response-only proof."""
    if not tokens or tokens[0] != "curl":
        return None, False
    data_options = {"-d", "--data", "--data-ascii", "--data-binary", "--json"}
    value_options = data_options | {"--data-raw", "-H", "--header", "-X", "--request", "--url"}
    flags = {
        "-s",
        "-S",
        "-sS",
        "-L",
        "-sL",
        "-f",
        "-fsSL",
        "--silent",
        "--show-error",
        "--location",
        "--fail",
        "--compressed",
    }
    stdin = False
    urls = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        option, equals, value = token.partition("=") if token.startswith("--") else (token, "", "")
        if token.startswith("-d") and token != "-d":
            option, equals, value = "-d", "=", token[2:]
        if option in value_options:
            if not equals:
                index += 1
                if index >= len(tokens):
                    return None, False
                value = tokens[index]
            if option in data_options:
                # A dynamic value might expand to a file/stdin selector.
                if "$" in value:
                    stdin = True if stdin is True else None
                elif value in {"@-", "@/dev/stdin", "@/dev/fd/0", "@/proc/self/fd/0"}:
                    stdin = True
                elif value.startswith("@"):
                    stdin = True if stdin is True else None
            elif option in {"-H", "--header"}:
                # Header files and dynamic header shapes need separate provenance.
                if ":" not in value or value.startswith("@"):
                    return None, False
            elif option == "--url":
                urls.append(value)
        elif token in flags:
            pass
        elif token.startswith("-"):
            return None, False
        else:
            urls.append(token)
        index += 1
    if len(urls) != 1 or not re.match(r"^https?://", urls[0]) or "$" in urls[0]:
        return None, False
    return stdin, True


def _shell_substitution_frames(expression: str) -> list[str] | None:
    """Frame one bounded substitution, preserving inner quotes and pipelines."""
    if len(expression) > 8192:
        return None
    if expression.startswith('"') and expression.endswith('"'):
        expression = expression[1:-1]
    if not expression.startswith("$(") or not expression.endswith(")"):
        return None
    command = expression[2:-1]
    remaining = command
    words = 0
    frames: list[str] = []
    start = 0
    while remaining.strip():
        remaining = remaining.lstrip()
        if remaining.startswith("|"):
            if words == 0 or remaining.startswith("||") or len(frames) >= 15:
                return None
            offset = len(command) - len(remaining)
            frames.append(command[start:offset].strip())
            words = 0
            remaining = remaining[1:]
            start = len(command) - len(remaining)
            continue
        if remaining.startswith("#"):
            return None
        word = _shell_word_variables(remaining)
        if word is None or word[1] == remaining:
            return None
        words += 1
        remaining = word[1]
    if words == 0:
        return None
    frames.append(command[start:].strip())
    return frames


def shell_substitution_command(expression: str) -> str | None:
    """Unwrap the same known frames used to prove captured output provenance."""
    frames = _shell_substitution_frames(expression)
    return " | ".join(frames) if frames is not None else None


def shell_curl_response_only(expression: str) -> bool:
    """Prove a simple HTTP response optionally forwarded through stdin-only cat."""
    frames = _shell_substitution_frames(expression)
    if frames is None:
        return False
    if shell_request_variables(frames[0]) is None:
        return False
    if not _shell_curl_io(shlex.split(frames[0], comments=False, posix=True))[1]:
        return False
    for frame in frames[1:]:
        tokens = shlex.split(frame, comments=False, posix=True)
        if not tokens or tokens[0] != "cat":
            return False
        if any(
            value not in {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}
            and not re.fullmatch(r"-[benstuvAET]+", value)
            for value in tokens[1:]
        ):
            return False
    return True


def shell_compound_requests(command: str) -> tuple[list[ShellRequestFrame], bool] | None:
    """Return reachable requests and whether their input sources are complete.

    Only requests and fixed non-mutating shell command forms are framed here.
    Unknown syntax returns None. Known echo/cat streams and bounded HTTP curl
    input/output shapes preserve stream provenance. Unknown consumers/producers
    retain whole-line evidence when their input sources cannot be established.
    """
    if len(command) > 8192:
        return None
    frames: list[str] = []
    operators: list[str] = []
    frame_variables: list[set[str]] = []
    variables: set[str] = set()
    remaining = command
    start = 0
    while remaining.strip():
        remaining = remaining.lstrip()
        offset = len(command) - len(remaining)
        if remaining.startswith("#"):
            remaining = ""
            command = command[:offset]
            break
        operator = re.match(r"&&|\|\||[;|]", remaining)
        if operator:
            frame = command[start:offset].strip()
            if not frame or len(frames) >= 16:
                return None
            frames.append(frame)
            frame_variables.append(variables)
            variables = set()
            operators.append(operator[0])
            remaining = remaining[operator.end() :]
            start = len(command) - len(remaining)
            continue
        word = _shell_word_variables(remaining)
        if word is None or word[1] == remaining:
            return None
        variables.update(word[0])
        remaining = word[1]
    tail = command[start:].strip()
    if tail:
        frames.append(tail)
        frame_variables.append(variables)
    elif operators and operators[-1] != ";":
        return None
    if len(frames) < 2 or len(frames) > 16:
        return None
    frame_requests: list[tuple[str, set[str]] | None] = []
    for frame in frames:
        head = re.match(r"([A-Za-z_][\w.-]*)(?:\s|$)", frame)
        if head is None or head[1] not in {"curl", "wget", "cat", "echo", "true", "false"}:
            return None
        if head[1] in {"curl", "wget"}:
            variables = shell_request_variables(frame)
            if variables is None:
                return None
            frame_requests.append((frame, variables))
        else:
            frame_requests.append(None)
    requests: list[ShellRequestFrame] = []
    inputs_complete = True
    statuses = {True, False}
    start = 0
    while start < len(frames):
        end = start
        while end < len(frames) - 1 and operators[end] == "|":
            end += 1
        # Pipelines bind before &&/||; boolean lists are left associative.
        incoming = operators[start - 1] if start else ";"
        execute = (
            incoming == ";"
            or (incoming == "&&" and True in statuses)
            or (incoming == "||" and False in statuses)
        )
        skipped = statuses & ({False} if incoming == "&&" else {True}) if incoming != ";" else set()
        statuses = skipped
        if execute:
            stream_variables: set[str] = set()
            stream_path = False
            stream_known = True
            for index in range(start, end + 1):
                frame = frames[index]
                tokens = shlex.split(frame, comments=False, posix=True)
                request = frame_requests[index]
                if request is not None:
                    consumes, response_only = _shell_curl_io(tokens)
                    if index > start and (consumes is None or consumes and not stream_known):
                        inputs_complete = False
                    requests.append(
                        ShellRequestFrame(
                            request[0],
                            request[1],
                            stream_variables.copy() if consumes else set(),
                            stream_path if consumes else False,
                        )
                    )
                    # Ordinary HTTP response bytes do not inherit request secrets.
                    stream_variables, stream_path = set(), False
                    stream_known = response_only
                elif tokens[0] == "echo":
                    stream_variables = frame_variables[index].copy()
                    stream_path, stream_known = False, True
                elif tokens[0] in {"true", "false"}:
                    stream_variables, stream_path, stream_known = set(), False, True
                else:  # cat: no operands or '-' forwards stdin; file operands replace it.
                    operands = [
                        value for value in tokens[1:] if value == "-" or not value.startswith("-")
                    ]
                    forwards = (
                        not operands
                        or bool(frame_variables[index])
                        or any(
                            value in {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"}
                            for value in operands
                        )
                    )
                    if not forwards:
                        stream_variables, stream_path, stream_known = set(), False, True
                    stream_variables.update(frame_variables[index])
                    stream_path |= bool(
                        re.search(
                            r"(?:\.ssh/|\.aws/credentials|\.config/gcloud|login\.keychain)",
                            frame,
                            re.I,
                        )
                    )
                    if any(
                        value.startswith("-")
                        and value not in {"-", "--"}
                        and not re.fullmatch(r"-[benstuvAET]+", value)
                        for value in tokens[1:]
                    ):
                        stream_known = False
            # A multi-command pipeline may inherit pipefail; its exit is unknown.
            if start == end and frames[start] in {"true", "false"}:
                statuses.add(frames[start] == "true")
            else:
                statuses.update({True, False})
        start = end + 1
    return requests, inputs_complete


def shell_request_command(
    command: str,
    following_lines: list[str] | None = None,
    safe_interpolations: set[str] | None = None,
) -> str:
    """Isolate a simple producer only when its sole consumer is a fixed JSON reader.

    Preserve raw quoting for request-variable analysis. Other compounds retain
    the original command and conservative handling, including independent sinks.
    """
    if not shell_fixed_json_pipeline(command, following_lines, safe_interpolations):
        return command
    remaining = command
    while remaining.strip():
        remaining = remaining.lstrip()
        if remaining.startswith("|"):
            producer = command[: len(command) - len(remaining)].rstrip()
            if shell_request_variables(producer) is not None:
                return producer
            break
        word = _shell_word_variables(remaining)
        if word is None or word[1] == remaining:
            break
        remaining = word[1]
    return command


def shell_request_variables(command: str) -> set[str] | None:
    """Read actual expansions of a simple request or assignment substitution.

    Compound commands, nested substitutions and dynamic parameter words keep the
    caller's conservative fallback. Quoted/escaped dollar text is not a read.
    """
    assigned = re.fullmatch(r"\s*(?:export\s+)?[A-Za-z_]\w*=\$\((.*)\)\s*", command)
    if assigned:
        command = assigned[1]
    start = re.match(r"^\s*(?:curl|wget)\s+", command)
    if start is None:
        return None
    remaining = command[start.end() :]
    variables: set[str] = set()
    while remaining.strip():
        remaining = remaining.lstrip()
        if remaining.startswith("#"):
            break
        word = _shell_word_variables(remaining)
        if word is None or word[1] == remaining:
            return None
        variables.update(word[0])
        remaining = word[1]
    return variables


def shell_header_auth_only(
    command: str, credential_variables: set[str], credential_path_variables: set[str]
) -> bool:
    """Recognize a bounded curl auth sink; never establish endpoint authorization."""
    assigned = re.fullmatch(r"\s*(?:export\s+)?[A-Za-z_]\w*=\$\((.*)\)\s*", command)
    if assigned:
        command = assigned[1]
    if "$(" in command or "`" in command:
        return False
    if shell_request_variables(command) is None:
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="();|&<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens or tokens[0] != "curl":
        return False
    residual: list[str] = []
    auth_variables: set[str] = set()
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token and all(char in "();|&<>" for char in token):
            return False
        if token in {"-H", "--header"} and index + 1 < len(tokens):
            header = re.fullmatch(
                r"(?:Authorization:\s*(?:(?:Bearer|Basic)\s+)?|(?:X-API-Key|API-Key|X-Goog-API-Key):\s*)"
                r"\$(?:\{([A-Za-z_]\w*)(?::?-[A-Za-z0-9_.:/-]*)?\}|([A-Za-z_]\w*))",
                tokens[index + 1],
                re.I,
            )
            if header:
                auth_variables.add(header[1] or header[2])
                index += 2
                continue
            residual.extend(tokens[index : index + 2])
            index += 2
            continue
        if token in {
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
            "-o",
            "--output",
            "-w",
            "--write-out",
            "-X",
            "--request",
        }:
            if index + 1 >= len(tokens):
                return False
            residual.extend(tokens[index : index + 2])
            index += 2
            continue
        if token.startswith("-") and token not in {
            "-s",
            "--silent",
            "-S",
            "--show-error",
            "-sS",
            "-L",
            "--location",
            "-sL",
            "-f",
            "--fail",
            "-fsSL",
            "--compressed",
        }:
            return False
        residual.append(token)
        index += 1
    if not auth_variables or auth_variables & credential_path_variables:
        return False
    residual_variables = {
        first or second
        for first, second in re.findall(
            r"\$(?:\{([A-Za-z_]\w*)(?::?-[A-Za-z0-9_.:/-]*)?\}|([A-Za-z_]\w*))",
            " ".join(residual),
        )
    }
    return bool(auth_variables & credential_variables) and not (
        residual_variables & (credential_variables | credential_path_variables)
        or re.search(r"(?:\.ssh/|\.aws/credentials|\.config/gcloud|login\.keychain)", command, re.I)
    )


def shell_requirement_lines(text: str) -> set[int]:
    """Identify plain shell runtime labels in dependency sections, not commands."""
    labels: set[int] = set()
    section_level: int | None = None
    in_fence = False
    for index, line in enumerate(text.splitlines()):
        if re.match(r"^\s*(?:`{3,}|~{3,})", line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        heading = re.match(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if heading:
            level = len(heading[1])
            if section_level is not None and level <= section_level:
                section_level = None
            if heading[2].casefold() in {"dependencies", "requirements", "prerequisites"}:
                section_level = level
        if section_level is not None and re.fullmatch(
            r"\s*[-*+]\s+(?:Bash|Zsh|Ksh|PowerShell) shell\s*", line
        ):
            labels.add(index)
    return labels


def markdown_document_reference_lines(text: str) -> set[int]:
    """Locate prose reference bullets; executable commands still use the full line."""
    references: set[int] = set()
    reference_section = False
    fence: tuple[str, int] | None = None
    for index, line in enumerate(text.splitlines()):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = (token[0], len(token))
            elif token[0] == fence[0] and len(token) >= fence[1]:
                fence = None
            continue
        if fence is not None:
            continue
        heading = re.match(r"^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if heading:
            reference_section = heading[2].casefold() in {
                "references",
                "resources",
                "documentation",
                "参考资料",
                "参考文档",
            }
        if reference_section and re.fullmatch(
            r" {0,3}[-*+]\s+\./[^\s`$;&|<>(){}\[\]*?\\]+\.(?:md|rst|txt)"
            r"\s+(?:--|—|–)\s+[^\s\-][^\n`$;&|<>(){}\\]*",
            line,
            re.I,
        ):
            references.add(index)
    return references


def interpreter_file(tokens: list[str], role: str) -> str | None:
    """Identify the file operand after interpreter options, not their values."""
    skip_value = False
    for token in tokens:
        if skip_value:
            skip_value = False
            continue
        option = token.casefold()
        if option in {"-c", "-command", "-encodedcommand", "-enc", "-e", "--eval"} or (
            role == "python" and option == "-m"
        ):
            return None
        if option in {
            "-executionpolicy",
            "-ep",
            "-windowstyle",
            "-inputformat",
            "-outputformat",
            "-version",
        } or (role == "python" and token in {"-W", "-X"}):
            skip_value = True
            continue
        if token.startswith("-"):
            continue
        return token
    return None
