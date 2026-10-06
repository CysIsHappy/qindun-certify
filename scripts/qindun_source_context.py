"""Shared, bounded source-context checks; never executes package content."""

from __future__ import annotations

import ast
import re
from urllib.parse import urlsplit


def actionable_secret_match(text: str, start: int, end: int, path: str) -> bool:
    fragment = text[start:end]
    value = re.search(r"[:=]\s*([\"']?)([A-Za-z0-9_./+=-]+)", fragment)
    if value:
        token = value[2]
        if re.fullmatch(
            r"(?:YOUR_(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET|PASSWORD)(?:_HERE)?|OPENAI_KEY_HERE|REPLACE_ME|CHANGEME|EXAMPLE_(?:API_KEY|TOKEN|PASSWORD))",
            token,
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
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t")):
            if current in {"name", "description"}:
                if mode not in {"plain", "block"} or "\t" in line[: len(line) - len(line.lstrip())]:
                    return {}
                if mode == "plain" and re.search(r":\s", line):
                    return {}
                values[current] += "\n" + line.strip()
            continue
        match = re.fullmatch(r"([A-Za-z][\w-]*):\s*(.*)", line)
        if match is None:
            if current and current not in {"name", "description"} and line.startswith("- "):
                continue
            return {}
        current, value = match.groups()
        if current not in {"name", "description"}:
            mode = ""
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
    return {key: value.strip() for key, value in values.items() if value.strip()}


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
