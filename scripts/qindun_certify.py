#!/usr/bin/env python3
"""Portable QinDun basic preflight scanner. It never executes target code."""

from __future__ import annotations

import argparse
import ast
import hashlib
import html
import ipaddress
import json
import os
import re
import shlex
import stat
import sys
import tempfile
import unicodedata
import zlib
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Iterable
from urllib.parse import urlsplit
from zipfile import BadZipFile, ZipFile

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from qindun_dependencies import (  # noqa: E402 - 支持脚本在任意工作目录独立运行
    DEFAULT_OSV_URL,
    DEPENDENCY_FILES,
    extract,
    query_osv,
)
from qindun_source_context import actionable_secret_match, interpreter_file, required_frontmatter  # noqa: E402


MAX_FILES = 2_000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_SOURCE_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 500
MAX_FINDINGS_PER_RULE = 25
MAX_STRUCTURED_CODE_BYTES = 1024 * 1024
MAX_STRUCTURED_AST_NODES = 250_000
EXIT_OK = 0
EXIT_SCAN_ERROR = 3
EXIT_RISK = 10
EXIT_PARTIAL = 11
GRADE_ORDER = {
    "none": 0,
    "D": 1,
    "C": 2,
    "B": 3,
    "A": 4,
    "A_PLUS": 5,
    "S": 6,
    "S_PLUS": 7,
}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
DISPOSITIONS = {"candidate", "confirmed"}
RULE_FLAG_MAP = {
    "": 0,
    "IGNORECASE": re.IGNORECASE,
    "DOTALL": re.DOTALL,
    "IGNORECASE|DOTALL": re.IGNORECASE | re.DOTALL,
}
ARCHIVE_SUFFIXES = {
    ".7z",
    ".bz2",
    ".gz",
    ".jar",
    ".rar",
    ".tar",
    ".tgz",
    ".whl",
    ".xz",
    ".zip",
}
INERT_BINARY_SUFFIXES = {".eot", ".otf", ".ttf", ".woff", ".woff2"}
MULTIMODAL_SUFFIXES = {
    ".avif",
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".mp3",
    ".mp4",
    ".ogg",
    ".pdf",
    ".png",
    ".wav",
    ".webm",
    ".webp",
}
INERT_BINARY_NAMES = {".DS_Store", "Thumbs.db"}
MAX_PNG_TEXT_BYTES = 1024 * 1024
MAX_PNG_TEXT_TOTAL_BYTES = 2 * 1024 * 1024
MAX_PNG_TEXT_CHUNKS = 64
DRIVE_PATH = re.compile(r"^[A-Za-z]:")
URL_PATTERN = re.compile(r'https?://[^\s\]})>"\'`，。；、！？：]+', re.I)
SOCKET_ENDPOINT_PATTERN = re.compile(
    r"(?:socket\.(?:create_connection|connect)|net\.connect)\s*\(\s*\(?\s*"
    r"[\"'](?P<host>[A-Za-z0-9.-]+)[\"']\s*,\s*(?P<port>\d{1,5})",
    re.I,
)
SHORT_LINK_DOMAINS = {"bit.ly", "buff.ly", "is.gd", "ow.ly", "t.co", "tinyurl.com"}
DYNAMIC_DNS_SUFFIXES = (".localtunnel.me", ".ngrok.io", ".serveo.net")
SUSPICIOUS_TLDS = (".buzz", ".cf", ".ga", ".ml", ".tk", ".top", ".xyz")
KNOWN_DOMAIN_CATEGORIES = {
    "api.anthropic.com": "人工智能服务",
    "api.deepseek.com": "人工智能服务",
    "api.github.com": "开发工具",
    "api.moonshot.cn": "人工智能服务",
    "api.openai.com": "人工智能服务",
    "api.stripe.com": "支付服务",
    "discord.com": "通信服务",
    "generativelanguage.googleapis.com": "人工智能服务",
    "github.com": "开发工具",
    "pypi.org": "依赖仓库",
    "registry.npmjs.org": "依赖仓库",
    "slack.com": "通信服务",
}
PROCESS_PATTERN = re.compile(
    r"\b(?:subprocess\.|os\.system\(|child_process|execFile\(|spawn\(|Runtime\.getRuntime\()"
)
SECRET_SCRUB_PATTERN = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)"
    r"\s*[:=]\s*[\"']?)([A-Za-z0-9_./+=-]{8,})([\"']?)"
)
KNOWN_SECRET_PATTERN = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
    r"\bAIza[0-9A-Za-z_-]{35}\b|"
    r"\bLTAI[A-Za-z0-9]{12,20}\b|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b|"
    r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b|"
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s@/]{4,}@[^\s]+|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
EXECUTABLE_MAGICS = (
    b"\x7fELF",
    b"MZ",
    b"\x00asm",
    b"\xca\xfe\xba\xbe",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
)
SKILL_ROOT = Path(__file__).parents[1]
RULE_INDEX_FILE = SKILL_ROOT / "rules" / "current.json"
VERSION_FILE = SKILL_ROOT / "VERSION"

SAFETY_CONTEXT_PARTS = {
    "docs",
    "documentation",
    "examples",
    "fixtures",
    "references",
    "rules",
    "samples",
    "test",
    "tests",
}
DOCUMENT_NAMES = {
    "AGENTS.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "SKILL.md",
}
PYTHON_SUFFIXES = {".py", ".pyw"}
SHELL_SUFFIXES = {".bash", ".command", ".ksh", ".sh", ".zsh"}
POWERSHELL_SUFFIXES = {".ps1", ".psm1"}
JAVASCRIPT_SUFFIXES = {".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"}
UNSUPPORTED_EXECUTABLE_SUFFIXES = {
    ".bat",
    ".c",
    ".cc",
    ".clj",
    ".cmd",
    ".cpp",
    ".cs",
    ".dart",
    ".ex",
    ".exs",
    ".fish",
    ".go",
    ".groovy",
    ".java",
    ".jl",
    ".kt",
    ".kts",
    ".lua",
    ".php",
    ".pl",
    ".rb",
    ".rs",
    ".scala",
    ".swift",
    ".tcl",
    ".vb",
}
KNOWN_EXTENSIONLESS_DATA_NAMES = {
    ".env",
    ".gitignore",
    ".gitmodules",
    ".npmrc",
    "dockerfile",
    "gemfile",
    "makefile",
    "procfile",
    "rakefile",
}
PLAIN_METADATA_NAMES = {
    "authors",
    "changelog",
    "contributors",
    "copying",
    "license",
    "notice",
    "version",
}
CAPABILITY_KEYS = {
    "format",
    "filesystem",
    "network",
    "process",
    "environment",
    "mcp_tools",
    "persistent_state",
    "browser",
    "databases",
    "dynamic",
}
MAX_CAPABILITY_ITEMS = 200
MAX_CAPABILITY_VALUE_LENGTH = 500


DIMENSION_REMEDIATIONS = {
    "D2": "修正作品包结构后重新扫描；不要包含链接、嵌套压缩包或无法检查的文件。",
    "D3": "删除危险行为，或改成固定、可审查且最小权限的实现后重新扫描。",
    "D4": "锁定依赖的精确版本，升级存在漏洞的组件并重新生成依赖锁文件。",
    "D5": "立即撤销并轮换已暴露的密钥，从作品包删除密钥并改用运行时密钥注入。",
    "D6": "删除不必要的外部传输，只保留明确业务域名并在能力声明中如实列出。",
    "D7": "更新能力声明，使其与作品实际读取、写入、联网和启动进程的行为一致。",
}
RULE_REMEDIATIONS = {
    "QINDUN.D5.CREDENTIAL_OUTPUT": "输出前删除或脱敏凭据字段；仅输出必要的状态信息，检查已保存日志是否需要清理或轮换密钥。",
    "QINDUN.D3.CREDENTIAL_EXFILTRATION": (
        "停止向外部请求发送令牌、密码、私钥或凭据文件；改用服务端代理或最小权限凭据。"
    ),
    "QINDUN.D3.RECURSIVE_ROOT_DELETE": (
        "删除面向根目录或宽泛路径的递归删除命令，并把删除范围限制到明确的临时目录。"
    ),
    "QINDUN.D3.REMOTE_PIPE_SHELL": (
        "不要把网络下载内容直接交给 shell；先固定版本和摘要，下载后校验再执行。"
    ),
    "QINDUN.D5.PRIVATE_KEY": (
        "立即撤销该私钥并生成新密钥；从历史记录和作品包删除私钥，改用密钥管理服务。"
    ),
    "QINDUN.D4.OSV_VULNERABILITY": (
        "升级到漏洞库标记的修复版本；无法升级时移除依赖或记录隔离和缓解措施。"
    ),
    "QINDUN.LOCAL.D3.UNSUPPORTED_ENTRYPOINT": (
        "为入口使用受支持的脚本格式和明确解释器，或移除无法静态分析的执行入口。"
    ),
}
DIMENSION_HELP_URIS = {
    "D2": "https://cwe.mitre.org/data/definitions/22.html",
    "D3": "https://cwe.mitre.org/data/definitions/94.html",
    "D4": "https://cwe.mitre.org/data/definitions/1104.html",
    "D5": "https://cwe.mitre.org/data/definitions/798.html",
    "D6": "https://cwe.mitre.org/data/definitions/200.html",
    "D7": "https://cwe.mitre.org/data/definitions/16.html",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    summary: str
    path: str
    line: int | None
    evidence: str
    evidence_digest: str
    dimension: str
    rule_version: str
    disposition: str = "candidate"
    source: str = "deterministic"
    deterministic: bool = True
    remediation: str = ""
    help_uri: str = ""

    def __post_init__(self) -> None:
        if not self.remediation:
            object.__setattr__(
                self,
                "remediation",
                RULE_REMEDIATIONS.get(
                    self.rule_id,
                    DIMENSION_REMEDIATIONS.get(
                        self.dimension,
                        "根据证据定位相关文件，修正问题后重新扫描。",
                    ),
                ),
            )
        if not self.help_uri:
            object.__setattr__(
                self,
                "help_uri",
                DIMENSION_HELP_URIS.get(
                    self.dimension,
                    "https://cwe.mitre.org/",
                ),
            )


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    version: str
    dimension: str
    severity: str
    title: str
    summary: str
    disposition: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class PackageEntry:
    name: str
    data: bytes | None
    kind: str
    declared_size: int
    content_sha256: str | None
    mode: int


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _current_rule_bundle_file() -> Path:
    payload = json.loads(RULE_INDEX_FILE.read_text(encoding="utf-8"))
    if payload.get("format") != "qindun-rule-index/v1":
        raise ValueError("不支持的秦盾规则索引格式")
    current = str(payload.get("current") or "")
    if not re.fullmatch(r"rules-[0-9]{4}\.[0-9]{2}\.[0-9]+\.json", current):
        raise ValueError("秦盾规则索引没有指定有效的当前规则包")
    return RULE_INDEX_FILE.parent / current


def _validate_grade_policy(value: object) -> dict:
    if not isinstance(value, dict) or value.get("format") != "qindun-grade-policy/v1":
        raise ValueError("秦盾规则包缺少有效的等级策略")
    danger = value.get("confirmed_danger")
    caps = value.get("finding_grade_caps")
    if not isinstance(danger, dict) or (
        danger.get("severity") not in SEVERITIES or danger.get("disposition") not in DISPOSITIONS
    ):
        raise ValueError("秦盾规则包的确定危险策略无效")
    if not isinstance(caps, dict) or set(caps) != SEVERITIES:
        raise ValueError("秦盾规则包的风险等级上限不完整")
    if any(str(grade) not in GRADE_ORDER for grade in caps.values()):
        raise ValueError("秦盾规则包包含无效等级")
    if value.get("local_maximum_grade") != "B":
        raise ValueError("本地预检等级上限必须为 B")
    return dict(value)


def _rule_corpus_name(value: object) -> str:
    if not isinstance(value, dict) or value.get("format") != "qindun-static-evidence-policy/v1":
        raise ValueError("秦盾规则包缺少有效的证据策略")
    if value.get("text_pattern_disposition") != "candidate":
        raise ValueError("秦盾文本规则必须保持为需要复核的候选证据")
    required = {
        "javascript_data_flow",
        "powershell_structure",
        "python_ast",
        "shell_structure",
    }
    confirmed_by = value.get("confirmed_by")
    if not isinstance(confirmed_by, list) or not required.issubset(
        {str(item) for item in confirmed_by}
    ):
        raise ValueError("秦盾规则包的确认依据不完整")
    name = str(value.get("rule_test_corpus") or "")
    if not re.fullmatch(r"rule-corpus-[0-9]{4}\.[0-9]{2}\.[0-9]+\.json", name):
        raise ValueError("秦盾规则包没有有效的正反例语料引用")
    return name


def _compile_rule_bundle(
    payload: object,
) -> tuple[str, str, dict, tuple[CompiledRule, ...]]:
    if not isinstance(payload, dict) or payload.get("format") != "qindun-rule-bundle/v1":
        raise ValueError("不支持的秦盾规则包格式")
    version = str(payload.get("version") or "").strip()
    raw_rules = payload.get("rules")
    if not version or not isinstance(raw_rules, list) or not raw_rules:
        raise ValueError("秦盾规则包内容不完整")
    if len(raw_rules) > 200:
        raise ValueError("秦盾规则包规则数量超过上限")
    grade_policy = _validate_grade_policy(payload.get("grade_policy"))
    _rule_corpus_name(payload.get("evidence_policy"))
    rules: list[CompiledRule] = []
    seen: set[str] = set()
    for raw in raw_rules:
        if not isinstance(raw, dict):
            raise ValueError("秦盾规则必须是对象")
        consumers = tuple(str(item) for item in raw.get("consumers") or [])
        if not consumers or any(item not in {"local", "platform"} for item in consumers):
            raise ValueError("秦盾规则包含无效使用方")
        rule_id = str(raw.get("id") or "")
        rule_version = str(raw.get("version") or "").strip()
        dimension = str(raw.get("dimension") or "")
        severity = str(raw.get("severity") or "")
        disposition = str(raw.get("disposition") or "")
        title = str(raw.get("title") or "").strip()
        summary = str(raw.get("summary") or "").strip()
        flags = str(raw.get("flags") or "")
        pattern_text = str(raw.get("pattern") or "")
        match = re.fullmatch(r"QINDUN\.(D[0-9]+)\.[A-Z0-9_]+", rule_id)
        if (
            match is None
            or rule_id in seen
            or match.group(1) != dimension
            or not rule_version
            or severity not in SEVERITIES
            or disposition not in DISPOSITIONS
            or not title
            or not summary
            or flags not in RULE_FLAG_MAP
            or not pattern_text
            or len(pattern_text) > 5_000
        ):
            raise ValueError(f"秦盾规则无效或重复：{rule_id or '<unknown>'}")
        try:
            pattern = re.compile(pattern_text, RULE_FLAG_MAP[flags])
        except re.error as error:
            raise ValueError(f"秦盾规则正则表达式无效：{rule_id}") from error
        seen.add(rule_id)
        if "local" not in consumers:
            continue
        rules.append(
            CompiledRule(
                rule_id,
                rule_version,
                dimension,
                severity,
                title,
                summary,
                disposition,
                pattern,
            )
        )
    if not rules:
        raise ValueError("秦盾规则包没有本地规则")
    digest = f"sha256:{hashlib.sha256(_canonical_json(payload)).hexdigest()}"
    return version, digest, grade_policy, tuple(rules)


def _validate_rule_corpus(payload: object, path: Path) -> str:
    if not isinstance(payload, dict):
        raise ValueError("秦盾规则包内容不完整")
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("秦盾规则包没有规则")
    patterns = {
        str(item["id"]): re.compile(
            str(item["pattern"]), RULE_FLAG_MAP[str(item.get("flags") or "")]
        )
        for item in raw_rules
        if isinstance(item, dict)
    }
    source = path.read_bytes()
    corpus: object = json.loads(source.decode("utf-8"))
    if not isinstance(corpus, dict) or corpus.get("format") != "qindun-rule-corpus/v1":
        raise ValueError("不支持的秦盾规则语料格式")
    if corpus.get("bundle_version") != payload.get("version"):
        raise ValueError("秦盾规则语料与当前规则包版本不一致")
    raw_cases = corpus.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("秦盾规则语料没有测试用例")
    seen: set[str] = set()
    for raw in raw_cases:
        if not isinstance(raw, dict):
            raise ValueError("秦盾规则语料用例必须是对象")
        rule_id = str(raw.get("rule_id") or "")
        positive = raw.get("positive")
        negative = raw.get("negative")
        if rule_id not in patterns or rule_id in seen:
            raise ValueError(f"秦盾规则语料编号无效或重复：{rule_id}")
        if (
            not isinstance(positive, list)
            or len(positive) < 2
            or any(not isinstance(item, str) or not item for item in positive)
            or len(set(positive)) != len(positive)
            or not isinstance(negative, list)
            or len(negative) < 2
            or any(not isinstance(item, str) or not item for item in negative)
            or len(set(negative)) != len(negative)
        ):
            raise ValueError(f"秦盾规则语料用例不完整：{rule_id}")
        pattern = patterns[rule_id]
        if any(pattern.search(item) is None for item in positive):
            raise ValueError(f"秦盾规则正例未命中：{rule_id}")
        if any(pattern.search(item) is not None for item in negative):
            raise ValueError(f"秦盾规则反例发生误报：{rule_id}")
        seen.add(rule_id)
    if seen != set(patterns):
        raise ValueError("秦盾规则语料没有覆盖全部规则")
    return hashlib.sha256(source).hexdigest()


RULE_BUNDLE_FILE = _current_rule_bundle_file()
RULE_BUNDLE_PAYLOAD = json.loads(RULE_BUNDLE_FILE.read_text(encoding="utf-8"))
RULE_BUNDLE_VERSION, RULE_BUNDLE_DIGEST, GRADE_POLICY, RULES = _compile_rule_bundle(
    RULE_BUNDLE_PAYLOAD
)
RULE_CORPUS_FILE = RULE_BUNDLE_FILE.parent / _rule_corpus_name(
    RULE_BUNDLE_PAYLOAD.get("evidence_policy")
)
RULE_CORPUS_DIGEST = _validate_rule_corpus(RULE_BUNDLE_PAYLOAD, RULE_CORPUS_FILE)
RULES_BY_ID = {rule.rule_id: rule for rule in RULES}


@lru_cache(maxsize=1)
def _python_condition_ranges(text: str) -> dict[int, tuple[bool, list[tuple[int, int]]]] | None:
    try:
        tree = ast.parse(text)
        return {
            node.lineno: (
                bool(
                    re.search(
                        r"datetime|time\.|date\b|hostname|username|counter|attempt",
                        ast.unparse(node.test),
                        re.I,
                    )
                ),
                [
                    (statement.lineno, statement.end_lineno)
                    for statement in [*node.body, *node.orelse]
                ],
            )
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
        }
    except (SyntaxError, ValueError, RecursionError):
        return None


def _conditional_text_match(text: str, start: int, end: int, path: str) -> bool:
    fragment = text[start:end]
    if re.search(r"(?m)^\s*(?:\x60{3,}|~{3,})", fragment):
        return False
    sink = re.search(r"(?<![\w.$])(?:eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.)", fragment)
    if sink is None:
        return False
    if path.lower().endswith(".py"):
        conditions = _python_condition_ranges(text)
        if conditions is not None:
            start_line = text.count("\n", 0, start) + 1
            end_line = text.count("\n", 0, end) + 1
            trigger, ranges = conditions.get(start_line, (False, []))
            return trigger and any(first <= end_line <= last for first, last in ranges)
    # Without an AST, associate a trigger with its condition, not later prose.
    condition = re.match(r"(?:if|when)\b([^:\n{]{0,180})", fragment, re.I)
    if condition is None or not re.search(
        r"datetime|time\.|date\b|hostname|username|counter|attempt", condition[1], re.I
    ):
        return False
    prefix = fragment[: sink.start()]
    if "{" in prefix and prefix.count("{") <= prefix.count("}"):
        return False
    return True


def _quoted_attack_warning(text: str, start: int, end: int) -> bool:
    # Only an explicitly rejected quotation is excluded, not its whole paragraph.
    line_start = text.rfind("\n", 0, start) + 1
    for opening, closing in [('"', '"'), ("“", "”"), ("'", "'"), ("\x60", "\x60")]:
        left = text.rfind(opening, line_start, start + 1)
        if left < 0 or (text.count(opening, line_start, start) % 2 == 0 and opening == closing):
            continue
        right = text.find(closing, end)
        if right < 0 or "\n" in text[left:right]:
            continue
        introduction = text[max(line_start, left - 60) : left]
        rejection = text[right + 1 : right + 120]
        if re.search(
            r"(?:page\s+(?:saying|says)|attack\s+example|页面(?:写着|要求)|攻击示例)\s*$",
            introduction,
            re.I,
        ) and re.match(
            r"\s*(?:is\s+an?\s+(?:attack|injection)|是(?:攻击|恶意指令))", rejection, re.I
        ):
            return True
    return False


def text_match_overrides(
    rule_id: str, text: str, start: int, end: int, path: str
) -> dict[str, str]:
    if (
        rule_id == "QINDUN.D7.SAFETY_DISABLE"
        and re.match(r"\s+bounds\b", text[end:], re.I)
        and re.search(r"mouse|鼠标", path + text[max(0, start - 160) : end + 120], re.I)
    ):
        return {
            "severity": "medium",
            "title": "发现可关闭鼠标坐标保护",
            "summary": "代码提供关闭鼠标坐标边界检查的选项，需确认误操作风险；这不等于关闭沙箱或审批",
        }
    return {}


def _actionable_text_match(
    rule_id: str, text: str, start: int, end: int | None = None, path: str = ""
) -> bool:
    end = end if end is not None else start
    if rule_id in {"QINDUN.D5.GENERIC_SECRET", "QINDUN.D5.DATABASE_CONNECTION"}:
        return actionable_secret_match(text, start, end, path)
    if rule_id == "QINDUN.D3.CONDITIONAL_DANGEROUS_EXECUTION":
        return _conditional_text_match(text, start, end, path)
    if rule_id == "QINDUN.D7.PROMPT_OVERRIDE_INSTRUCTION" and _quoted_attack_warning(
        text, start, end
    ):
        return False
    if rule_id not in {
        "QINDUN.D7.AGENT_TOOL_ABUSE",
        "QINDUN.D7.PROMPT_SECRET_EXFILTRATION",
        "QINDUN.D7.SILENT_OPERATION",
        "QINDUN.D7.PROMPT_OVERRIDE_INSTRUCTION",
    }:
        return True
    prefix = text[max(0, start - 40) : start].replace("**", "").replace("__", "")
    return (
        re.search(r"(?:\b(?:do\s+not|don't|never|avoid)\s+|(?:禁止|不要|勿)\s*)$", prefix, re.I)
        is None
    )


SCANNER_VERSION = VERSION_FILE.read_text(encoding="utf-8").strip()
TRUSTED_INTERNAL_DIGESTS = {
    hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    hashlib.sha256(RULE_INDEX_FILE.read_bytes()).hexdigest(),
    hashlib.sha256(RULE_BUNDLE_FILE.read_bytes()).hexdigest(),
    hashlib.sha256(RULE_CORPUS_FILE.read_bytes()).hexdigest(),
    *(
        hashlib.sha256(path.read_bytes()).hexdigest()
        for path in RULE_BUNDLE_FILE.parent.glob("rules-*.json")
        if path.is_file()
    ),
}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return bool(
        normalized
        and "\x00" not in normalized
        and not normalized.startswith("/")
        and DRIVE_PATH.match(normalized) is None
        and ".." not in path.parts
        and bool(path.parts)
    )


def _decode(data: bytes) -> str | None:
    encodings: list[str] = []
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings.append("utf-16")
    elif len(data) >= 8:
        sample = data[:4096]
        even = sample[0::2]
        odd = sample[1::2]
        even_nulls = even.count(0) / max(len(even), 1)
        odd_nulls = odd.count(0) / max(len(odd), 1)
        if odd_nulls >= 0.3 and even_nulls <= 0.1:
            encodings.append("utf-16-le")
        elif even_nulls >= 0.3 and odd_nulls <= 0.1:
            encodings.append("utf-16-be")
    if not encodings:
        if b"\x00" in data[:4096]:
            return None
        encodings.extend(("utf-8", "utf-8-sig", "gb18030"))
    for encoding in encodings:
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if not text:
            return ""
        sample = text[:8192]
        printable = sum(character.isprintable() or character in "\r\n\t" for character in sample)
        if printable / len(sample) >= 0.85:
            return text
    return None


INTERPRETER_ROLES = {
    "bash": "shell",
    "bun": "javascript",
    "deno": "javascript",
    "ksh": "shell",
    "node": "javascript",
    "powershell": "powershell",
    "pwsh": "powershell",
    "python": "python",
    "python3": "python",
    "sh": "shell",
    "zsh": "shell",
}
DECLARED_EXECUTABLE_ROLE = "declared"
CONFLICTING_EXECUTABLE_ROLE = "conflict"


def _merge_executable_role(roles: dict[str, str], path: str, role: str) -> bool:
    """Merge declarations without allowing archive order to choose an interpreter."""

    previous = roles.get(path)
    if previous is None:
        roles[path] = role
        return False
    if previous == CONFLICTING_EXECUTABLE_ROLE:
        return True
    if previous == role or role == DECLARED_EXECUTABLE_ROLE:
        return False
    if previous == DECLARED_EXECUTABLE_ROLE:
        roles[path] = role
        return False
    roles[path] = CONFLICTING_EXECUTABLE_ROLE
    return True


def _instruction_entrypoint_roles(path: str, text: str) -> dict[str, str]:
    roles: dict[str, str] = {}
    parent = PurePosixPath(path).parent
    in_fence = False
    for raw_line in text.splitlines():
        if re.match(r"^\s*(?:`{3,}|~{3,})", raw_line):
            in_fence = not in_fence
            continue
        segments = [*re.findall(r"`([^`\n]+)`", raw_line), raw_line]
        for segment in dict.fromkeys(segments):
            line = segment.strip().strip("`").strip()
            line = re.sub(r"^(?:[-*+]\s+|\$\s+)", "", line)
            if not line:
                continue
            try:
                tokens = [
                    token.strip("`.,:：") for token in shlex.split(line, comments=True, posix=True)
                ]
            except ValueError:
                continue
            interpreter_index = next(
                (
                    index
                    for index, token in enumerate(tokens)
                    if PurePosixPath(token).name.casefold() in INTERPRETER_ROLES
                    and (
                        index == 0
                        or tokens[index - 1].casefold()
                        in {
                            "env",
                            "execute",
                            "launch",
                            "run",
                            "start",
                            "sudo",
                            "use",
                            "使用",
                            "启动",
                            "执行",
                            "运行",
                        }
                        or re.fullmatch(
                            r"[A-Za-z_][A-Za-z0-9_]*=.*",
                            tokens[index - 1],
                        )
                    )
                ),
                None,
            )
            if interpreter_index is None:
                direct = next(
                    (
                        token
                        for token in tokens
                        if token.startswith("./")
                        and "://" not in token
                        and re.search(r"[<>{}\[\]$*?]", token) is None
                    ),
                    None,
                )
                if direct is not None:
                    resolved = (parent / direct.removeprefix("./")).as_posix()
                    if _safe_relative(resolved):
                        _merge_executable_role(
                            roles,
                            resolved,
                            DECLARED_EXECUTABLE_ROLE,
                        )
                continue
            tokens = tokens[interpreter_index:]
            while tokens and (
                tokens[0] in {"env", "sudo"}
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]) is not None
            ):
                tokens.pop(0)
            if len(tokens) >= 2 and tokens[:2] in (["uv", "run"], ["poetry", "run"]):
                tokens = tokens[2:]
            if not tokens:
                continue
            role = INTERPRETER_ROLES.get(PurePosixPath(tokens.pop(0)).name.casefold())
            if role is None:
                continue
            candidate = interpreter_file(tokens, role)
            if candidate is None or "://" in candidate or re.search(r"[<>{}\[\]$*?]", candidate):
                continue
            if not in_fence and re.fullmatch(r"\d+(?:\.\d+)*(?:\+|[xX])?", candidate):
                continue
            if not in_fence and "/" not in candidate and "." not in candidate:
                if not candidate.isascii() or any(
                    not token.startswith("-") for token in tokens[tokens.index(candidate) + 1 :]
                ):
                    continue
            resolved = (parent / candidate.removeprefix("./")).as_posix()
            if _safe_relative(resolved):
                _merge_executable_role(roles, resolved, role)
    return roles


def _capability_entrypoint_roles(_path: str, manifest: object) -> dict[str, str]:
    if not isinstance(manifest, dict):
        return {}
    dynamic = manifest.get("dynamic")
    if not isinstance(dynamic, dict) or not isinstance(dynamic.get("entrypoint"), list):
        return {}
    entrypoint = dynamic["entrypoint"]
    if not entrypoint or not isinstance(entrypoint[0], str):
        return {}
    role = INTERPRETER_ROLES.get(PurePosixPath(entrypoint[0]).name.casefold())
    if role is not None:
        if (
            len(entrypoint) < 2
            or not isinstance(entrypoint[1], str)
            or entrypoint[1].startswith("-")
        ):
            return {}
        raw_candidate = entrypoint[1]
    else:
        raw_candidate = entrypoint[0]
        role = DECLARED_EXECUTABLE_ROLE
    working_directory = str(dynamic.get("working_directory") or ".")
    candidate = (
        PurePosixPath(working_directory) / raw_candidate.removeprefix("./")
        if working_directory != "."
        else PurePosixPath(raw_candidate.removeprefix("./"))
    ).as_posix()
    return {candidate: role} if _safe_relative(candidate) else {}


def _capability_inline_entrypoint(manifest: object) -> tuple[str, str] | None:
    if not isinstance(manifest, dict):
        return None
    dynamic = manifest.get("dynamic")
    entrypoint = dynamic.get("entrypoint") if isinstance(dynamic, dict) else None
    if not isinstance(entrypoint, list) or len(entrypoint) < 3:
        return None
    if not all(isinstance(item, str) for item in entrypoint[:3]):
        return None
    role = INTERPRETER_ROLES.get(PurePosixPath(entrypoint[0]).name.casefold())
    flag = entrypoint[1].casefold()
    allowed_flags = {
        "javascript": {"-e", "--eval"},
        "powershell": {"-c", "-command"},
        "python": {"-c"},
        "shell": {"-c"},
    }
    if role is None or flag not in allowed_flags.get(role, set()):
        return None
    return role, entrypoint[2]


def _decompress_png_text(data: bytes) -> bytes:
    decompressor = zlib.decompressobj()
    output = decompressor.decompress(data, MAX_PNG_TEXT_BYTES + 1)
    if len(output) > MAX_PNG_TEXT_BYTES or decompressor.unconsumed_tail:
        raise ValueError("PNG 文本元数据超过检查上限")
    output += decompressor.flush(MAX_PNG_TEXT_BYTES + 1 - len(output))
    if len(output) > MAX_PNG_TEXT_BYTES or not decompressor.eof:
        raise ValueError("PNG 压缩文本元数据不完整")
    return output


def _png_text_metadata(data: bytes) -> tuple[list[str], list[str]]:
    """Extract bounded PNG textual chunks without decoding image pixels."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return [], ["PNG 文件头无效"]
    texts: list[str] = []
    errors: list[str] = []
    total_text_bytes = 0
    text_chunks = 0

    def append_text(value: str) -> bool:
        nonlocal total_text_bytes, text_chunks
        encoded_size = len(value.encode("utf-8", errors="replace"))
        if text_chunks >= MAX_PNG_TEXT_CHUNKS:
            errors.append("PNG 文本元数据块数量超过检查上限")
            return False
        if total_text_bytes + encoded_size > MAX_PNG_TEXT_TOTAL_BYTES:
            errors.append("PNG 文本元数据累计大小超过检查上限")
            return False
        texts.append(value)
        text_chunks += 1
        total_text_bytes += encoded_size
        return True

    offset = 8
    saw_end = False
    while offset < len(data):
        if offset + 12 > len(data):
            errors.append("PNG 数据块头不完整")
            break
        length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if length > MAX_FILE_BYTES or chunk_end > len(data):
            errors.append("PNG 数据块长度无效")
            break
        payload = data[offset + 8 : offset + 8 + length]
        expected_crc = int.from_bytes(data[offset + 8 + length : chunk_end], "big")
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            errors.append(f"PNG {chunk_type.decode('ascii', errors='replace')} 数据块校验失败")
            offset = chunk_end
            continue
        try:
            if chunk_type == b"tEXt":
                _, separator, raw_text = payload.partition(b"\x00")
                if not separator:
                    raise ValueError("PNG tEXt 数据块缺少关键字分隔符")
                if not append_text(raw_text.decode("latin-1")):
                    break
            elif chunk_type == b"zTXt":
                _, separator, remainder = payload.partition(b"\x00")
                if not separator or len(remainder) < 2 or remainder[0] != 0:
                    raise ValueError("PNG zTXt 数据块格式无效")
                if not append_text(_decompress_png_text(remainder[1:]).decode("latin-1")):
                    break
            elif chunk_type == b"iTXt":
                _, separator, remainder = payload.partition(b"\x00")
                if not separator or len(remainder) < 3:
                    raise ValueError("PNG iTXt 数据块格式无效")
                compressed, method = remainder[0], remainder[1]
                remainder = remainder[2:]
                _, separator, remainder = remainder.partition(b"\x00")
                if not separator:
                    raise ValueError("PNG iTXt 数据块缺少语言分隔符")
                _, separator, raw_text = remainder.partition(b"\x00")
                if not separator or compressed not in {0, 1} or method != 0:
                    raise ValueError("PNG iTXt 数据块压缩声明无效")
                if compressed:
                    raw_text = _decompress_png_text(raw_text)
                if not append_text(raw_text.decode("utf-8")):
                    break
        except (UnicodeDecodeError, ValueError, zlib.error) as error:
            errors.append(str(error))
        if chunk_type == b"IEND":
            saw_end = True
            break
        offset = chunk_end
    if not saw_end:
        errors.append("PNG 缺少结束数据块")
    return texts, errors


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _redact_known_secrets(text: str) -> str:
    def redact_assignment(match: re.Match[str]) -> str:
        return f"{match.group(1)}[已脱敏]{match.group(3)}"

    text = SECRET_SCRUB_PATTERN.sub(redact_assignment, text)

    def redact_token(match: re.Match[str]) -> str:
        return "[已脱敏]"

    return KNOWN_SECRET_PATTERN.sub(redact_token, text)


def _evidence(
    text: str,
    dimension: str,
    *,
    rule_id: str,
    path: str,
    line: int | None,
) -> tuple[str, str]:
    normalized = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    if dimension == "D5":
        public = "已脱敏（密钥值已隐藏）"
        category = "secret"
    else:
        public = _redact_known_secrets(normalized)[:180]
        category = "redacted" if public != normalized[:180] else "evidence"
    identity = {
        "category": category,
        "dimension": dimension,
        "line": line,
        "path": path,
        "public_evidence": public,
        "rule_id": rule_id,
    }
    digest = hashlib.sha256(_canonical_json(identity)).hexdigest()
    return public, f"sha256:{digest}"


def _read_stable_regular_file(
    path: Path,
    metadata: os.stat_result,
    *,
    capture: bool,
) -> tuple[bytes | None, str]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != identity
            or opened.st_size != metadata.st_size
        ):
            raise ValueError("文件在属性检查后被替换")
        digest = hashlib.sha256()
        chunks = bytearray() if capture else None
        actual_size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            actual_size += len(chunk)
            if actual_size > opened.st_size:
                raise ValueError("文件读取大小超过已检查范围")
            digest.update(chunk)
            if chunks is not None:
                chunks.extend(chunk)
        completed = os.fstat(descriptor)
        if (
            (completed.st_dev, completed.st_ino) != identity
            or not stat.S_ISREG(completed.st_mode)
            or actual_size != opened.st_size
            or completed.st_size != opened.st_size
            or completed.st_mtime_ns != opened.st_mtime_ns
            or completed.st_ctime_ns != opened.st_ctime_ns
        ):
            raise ValueError("文件在读取期间发生变化")
        return (bytes(chunks) if chunks is not None else None), digest.hexdigest()
    finally:
        os.close(descriptor)


def _directory_entries(root: Path):
    pending = [root]
    visited_nodes = 0
    declared_total = 0
    while pending:
        directory = pending.pop()
        try:
            iterator = os.scandir(directory)
        except OSError as error:
            raise ValueError(f"无法读取目录：{directory}") from error
        with iterator:
            for item in iterator:
                path = Path(item.path)
                relative = path.relative_to(root)
                if relative.parts and relative.parts[0] == ".git":
                    continue
                visited_nodes += 1
                if visited_nodes > MAX_FILES:
                    yield PackageEntry(relative.as_posix(), None, "file_limit", 0, None, 0)
                    return
                name = relative.as_posix()
                try:
                    metadata = path.lstat()
                except OSError as error:
                    raise ValueError(f"无法读取文件属性：{name}") from error
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
                    continue
                mode = stat.S_IMODE(metadata.st_mode)
                if stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(path).encode("utf-8", errors="surrogateescape")
                    yield PackageEntry(
                        name,
                        None,
                        "symlink",
                        len(target),
                        hashlib.sha256(target).hexdigest(),
                        mode,
                    )
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    yield PackageEntry(name, None, "special", 0, None, mode)
                    continue
                size = metadata.st_size
                declared_total += max(size, 0)
                if declared_total > MAX_TOTAL_BYTES:
                    yield PackageEntry(name, None, "total_limit", size, None, mode)
                    return
                try:
                    data, content_sha256 = _read_stable_regular_file(
                        path,
                        metadata,
                        capture=size <= MAX_FILE_BYTES,
                    )
                except (OSError, ValueError):
                    yield PackageEntry(name, None, "unstable", size, None, mode)
                    continue
                yield PackageEntry(name, data, "file", size, content_sha256, mode)


def _validate_zip_central_directory(target: Path) -> None:
    size = target.stat().st_size
    tail_size = min(size, 65_557)
    with target.open("rb") as source:
        source.seek(size - tail_size)
        tail = source.read(tail_size)
    signature = b"PK\x05\x06"
    position = len(tail)
    eocd = None
    while True:
        position = tail.rfind(signature, 0, position)
        if position < 0:
            break
        if position + 22 <= len(tail):
            comment_length = int.from_bytes(tail[position + 20 : position + 22], "little")
            if position + 22 + comment_length == len(tail):
                eocd = tail[position : position + 22]
                eocd_offset = size - tail_size + position
                break
        if position == 0:
            break
    if eocd is None:
        raise ValueError("ZIP 缺少有效的中央目录尾记录")
    disk_number = int.from_bytes(eocd[4:6], "little")
    central_disk = int.from_bytes(eocd[6:8], "little")
    disk_entries = int.from_bytes(eocd[8:10], "little")
    total_entries = int.from_bytes(eocd[10:12], "little")
    central_size = int.from_bytes(eocd[12:16], "little")
    central_offset = int.from_bytes(eocd[16:20], "little")
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise ValueError("ZIP64 中央目录超出本地预检支持范围")
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        raise ValueError("不支持跨磁盘 ZIP")
    if total_entries > MAX_FILES:
        raise ValueError("ZIP 中央目录声明的条目数超过本地预检上限")
    if central_size > MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        raise ValueError("ZIP 中央目录大小超过本地预检上限")
    if central_offset + central_size > eocd_offset:
        raise ValueError("ZIP 中央目录边界无效")


def _zip_entries(target: Path):
    _validate_zip_central_directory(target)
    try:
        archive = ZipFile(target)
    except (BadZipFile, OSError) as error:
        raise ValueError("目标不是有效 ZIP") from error
    with archive:
        declared_total = 0
        discovered_entries = 0
        for info in archive.infolist():
            if info.is_dir():
                continue
            discovered_entries += 1
            if discovered_entries > MAX_FILES:
                yield PackageEntry(
                    info.filename,
                    None,
                    "file_limit",
                    0,
                    None,
                    0,
                )
                return
            name = info.filename
            mode = info.external_attr >> 16
            declared_total += max(info.file_size, 0)
            if not _safe_relative(name):
                yield PackageEntry(name, None, "unsafe_path", info.file_size, None, mode)
                continue
            if info.flag_bits & 0x1:
                yield PackageEntry(name, None, "encrypted", info.file_size, None, mode)
                continue
            file_type = stat.S_IFMT(mode)
            if stat.S_ISLNK(mode) or file_type not in {0, stat.S_IFREG}:
                yield PackageEntry(name, None, "special", info.file_size, None, mode)
                continue
            if declared_total > MAX_TOTAL_BYTES:
                yield PackageEntry(name, None, "total_limit", info.file_size, None, mode)
                break
            compression_ratio = info.file_size / max(info.compress_size, 1)
            if info.file_size > 1024 * 1024 and compression_ratio > 100:
                yield PackageEntry(name, None, "compression_bomb", info.file_size, None, mode)
                continue
            if "\\" in name:
                yield PackageEntry(
                    name, None, "unsupported_path_separator", info.file_size, None, mode
                )
                continue
            digest = hashlib.sha256()
            captured = bytearray() if info.file_size <= MAX_FILE_BYTES else None
            actual_size = 0
            try:
                with archive.open(info, "r") as source:
                    while chunk := source.read(1024 * 1024):
                        actual_size += len(chunk)
                        digest.update(chunk)
                        if captured is not None:
                            captured.extend(chunk)
            except (BadZipFile, EOFError, OSError, RuntimeError, NotImplementedError) as error:
                raise ValueError(f"无法安全读取 ZIP 条目：{name}") from error
            if actual_size != info.file_size:
                raise ValueError(f"ZIP 条目展开大小不一致：{name}")
            data = bytes(captured) if captured is not None else None
            yield PackageEntry(name, data, "file", info.file_size, digest.hexdigest(), mode)


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    summary: str,
    path: str,
    evidence_text: str,
    *,
    dimension: str,
    disposition: str = "confirmed",
    line: int | None = None,
    rule_version: str = "qindun-local-v2",
) -> Finding:
    public, digest = _evidence(
        evidence_text,
        dimension,
        rule_id=rule_id,
        path=path,
        line=line,
    )
    return Finding(
        rule_id,
        severity,
        title,
        summary,
        path,
        line,
        public,
        digest,
        dimension,
        rule_version,
        disposition,
    )


LOCAL_STRUCTURED_RULES = {
    "QINDUN.D5.CREDENTIAL_OUTPUT": (
        "high",
        "发现敏感凭据进入输出",
        "结构分析发现令牌、凭据或令牌响应进入日志或标准输出，可能暴露给日志读取者或智能体上下文",
    ),
    "QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW": (
        "critical",
        "发现下载内容进入执行入口",
        "结构分析确认网络返回内容未经校验进入代码或命令执行入口",
    ),
    "QINDUN.LOCAL.D3.DECODE_EXECUTION_FLOW": (
        "critical",
        "发现解码内容进入执行入口",
        "结构分析确认动态解码结果进入代码或命令执行入口",
    ),
}


def _confirmed_structural_finding(
    rule_id: str,
    path: str,
    line: int,
    evidence_text: str,
) -> Finding:
    rule = RULES_BY_ID.get(rule_id)
    if rule is not None:
        return _finding(
            rule.rule_id,
            rule.severity,
            rule.title,
            rule.summary,
            path,
            evidence_text,
            dimension=rule.dimension,
            disposition="confirmed",
            line=line,
            rule_version=rule.version,
        )
    severity, title, summary = LOCAL_STRUCTURED_RULES[rule_id]
    return _finding(
        rule_id,
        severity,
        title,
        summary,
        path,
        evidence_text,
        dimension="D5" if rule_id == "QINDUN.D5.CREDENTIAL_OUTPUT" else "D3",
        disposition="confirmed",
        line=line,
        rule_version="qindun-local-structure-v1",
    )


def _sensitive_env_name(value: str) -> bool:
    normalized = re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")
    if not normalized:
        return False
    parts = normalized.split("_")
    if any(
        part in {"TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "CREDENTIALS"}
        for part in parts
    ):
        return True
    if "KEY" in parts and any(part in {"API", "ACCESS", "PRIVATE"} for part in parts):
        return True
    if normalized in {"AUTH", "AUTHORIZATION", "COOKIE", "COOKIES", "SESSION"}:
        return True
    if normalized.endswith(("_AUTH", "_COOKIE", "_COOKIES", "_SESSION")):
        return True
    return normalized in {"AUTH_KEY", "AUTH_TOKEN", "SESSION_ID", "SESSION_KEY", "SESSION_TOKEN"}


def _file_role(path: str, text: str, *, mode: int = 0) -> str:
    pure_path = PurePosixPath(path)
    lowered_parts = {part.casefold() for part in pure_path.parts[:-1]}
    lowered_name = pure_path.name.casefold()
    safety_context = bool(
        lowered_parts & SAFETY_CONTEXT_PARTS
        or lowered_name.startswith("test_")
        or lowered_name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
    )
    suffix = pure_path.suffix.casefold()
    if lowered_name == "conftest.py":
        return "python"
    code_role = (
        "python"
        if suffix in PYTHON_SUFFIXES
        else "shell"
        if suffix in SHELL_SUFFIXES
        else "powershell"
        if suffix in POWERSHELL_SUFFIXES
        else "javascript"
        if suffix in JAVASCRIPT_SUFFIXES
        else None
    )
    if code_role:
        return f"safety_{code_role}" if safety_context else code_role
    if suffix in UNSUPPORTED_EXECUTABLE_SUFFIXES:
        return "unsupported_executable"
    if safety_context:
        return "safety_material"
    if pure_path.name in DOCUMENT_NAMES or suffix in {
        ".adoc",
        ".markdown",
        ".md",
        ".rst",
    }:
        return "instructions"
    if not suffix and lowered_name in PLAIN_METADATA_NAMES:
        return "data"
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if first_line.startswith("#!"):
        if re.search(r"\bpython(?:3)?\b", first_line):
            return "python"
        if re.search(r"\b(?:ba|z|k)?sh\b", first_line):
            return "shell"
        if re.search(r"\b(?:node|deno|bun)\b", first_line):
            return "javascript"
        if re.search(r"\b(?:pwsh|powershell)\b", first_line):
            return "powershell"
    # Extensionless entrypoints commonly are shell programs. Require a command shape,
    # rather than treating every unknown text file as executable code.
    if not suffix and re.search(r"(?m)^\s*(?:curl|wget|rm|bash|sh|nc|ncat|sudo)\b", text):
        return "shell"
    if not suffix and re.search(
        r"(?m)^\s*(?:from\s+[A-Za-z_][\w.]*\s+import\s+|import\s+[A-Za-z_]|"
        r"def\s+[A-Za-z_]\w*\s*\(|class\s+[A-Za-z_]\w*\s*[:(])",
        text,
    ):
        return "python"
    if not suffix and re.search(r"(?m)^\s*(?:const|let|var|function|import|export)\b", text):
        return "javascript"
    if mode & 0o111:
        return "unsupported_executable"
    if not suffix and lowered_name not in KNOWN_EXTENSIONLESS_DATA_NAMES:
        return "unsupported_executable"
    return "data"


def _ast_qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


_UNKNOWN_STATIC_VALUE = object()


def _static_ast_value(node: ast.AST) -> object:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        values = [_static_ast_value(item) for item in node.elts]
        if any(item is _UNKNOWN_STATIC_VALUE for item in values):
            return _UNKNOWN_STATIC_VALUE
        return tuple(values) if isinstance(node, ast.Tuple) else values
    if isinstance(node, ast.Dict):
        keys = [_static_ast_value(item) for item in node.keys]
        values = [_static_ast_value(item) for item in node.values]
        if any(item is _UNKNOWN_STATIC_VALUE for item in [*keys, *values]):
            return _UNKNOWN_STATIC_VALUE
        try:
            return dict(zip(keys, values))
        except (TypeError, ValueError):
            return _UNKNOWN_STATIC_VALUE
    if isinstance(node, ast.UnaryOp):
        value = _static_ast_value(node.operand)
        if value is _UNKNOWN_STATIC_VALUE:
            return value
        try:
            if isinstance(node.op, ast.Not):
                return not bool(value)
            if isinstance(node.op, ast.UAdd):
                return +value  # type: ignore[operator]
            if isinstance(node.op, ast.USub):
                return -value  # type: ignore[operator]
        except (TypeError, ValueError, OverflowError):
            return _UNKNOWN_STATIC_VALUE
    if isinstance(node, ast.BoolOp):
        values = [_static_ast_value(item) for item in node.values]
        if any(item is _UNKNOWN_STATIC_VALUE for item in values):
            return _UNKNOWN_STATIC_VALUE
        return (
            all(bool(item) for item in values)
            if isinstance(node.op, ast.And)
            else any(bool(item) for item in values)
        )
    if isinstance(node, ast.Compare):
        left = _static_ast_value(node.left)
        comparators = [_static_ast_value(item) for item in node.comparators]
        if left is _UNKNOWN_STATIC_VALUE or any(
            item is _UNKNOWN_STATIC_VALUE for item in comparators
        ):
            return _UNKNOWN_STATIC_VALUE
        for operation, right in zip(node.ops, comparators):
            try:
                matched = (
                    left == right
                    if isinstance(operation, ast.Eq)
                    else left != right
                    if isinstance(operation, ast.NotEq)
                    else left < right
                    if isinstance(operation, ast.Lt)
                    else left <= right
                    if isinstance(operation, ast.LtE)
                    else left > right
                    if isinstance(operation, ast.Gt)
                    else left >= right
                    if isinstance(operation, ast.GtE)
                    else left in right
                    if isinstance(operation, ast.In)
                    else left not in right
                    if isinstance(operation, ast.NotIn)
                    else left is right
                    if isinstance(operation, ast.Is)
                    else left is not right
                    if isinstance(operation, ast.IsNot)
                    else False
                )
            except (TypeError, ValueError):
                return _UNKNOWN_STATIC_VALUE
            if not matched:
                return False
            left = right
        return True
    return _UNKNOWN_STATIC_VALUE


def _static_truth_value(node: ast.AST) -> bool | None:
    value = _static_ast_value(node)
    return None if value is _UNKNOWN_STATIC_VALUE else bool(value)


def _resolve_python_alias(name: str, aliases: dict[str, str]) -> str:
    current = name
    seen_heads: set[str] = set()
    for _depth in range(32):
        if not current:
            break
        head, separator, tail = current.partition(".")
        if head in seen_heads:
            break
        seen_heads.add(head)
        replacement = aliases.get(head)
        if replacement is None or replacement == head:
            break
        candidate = f"{replacement}.{tail}" if separator else replacement
        if candidate == current or len(candidate) > 4096:
            break
        current = candidate
    return current


def _python_callable_name(node: ast.AST, aliases: dict[str, str]) -> str:
    raw_name = _ast_qualified_name(node)
    if raw_name:
        return _resolve_python_alias(raw_name, aliases)
    if (
        isinstance(node, ast.Call)
        and _ast_qualified_name(node.func) == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        owner = _python_callable_name(node.args[0], aliases)
        attribute = node.args[1].value
        if owner and attribute.isidentifier():
            return f"{owner}.{attribute}"
    return ""


_PYTHON_CALLBACK_CALLS = {
    "atexit.register",
    "asyncio.to_thread",
    "concurrent.futures.executor.submit",
    "concurrent.futures.threadpoolexecutor.submit",
    "concurrent.futures.processpoolexecutor.submit",
    "signal.signal",
    "threading.thread",
    "threading.timer",
}


class _PythonCallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()
        self.aliases: dict[str, str] = {}

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        name = _python_callable_name(node.func, self.aliases).casefold()
        if name:
            self.names.add(name)
        callback_nodes: list[ast.AST] = []
        if name in _PYTHON_CALLBACK_CALLS or name.endswith(
            (".add_done_callback", ".apply_async", ".call_soon", ".call_later", ".map", ".submit")
        ):
            callback_nodes.extend(node.args[:1])
        callback_nodes.extend(
            item.value
            for item in node.keywords
            if item.arg in {"callback", "func", "function", "target"}
        )
        for callback in callback_nodes:
            callback_name = _python_callable_name(callback, self.aliases).casefold()
            if callback_name:
                self.names.add(callback_name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802 - ast API
        callable_name = _python_callable_name(node.value, self.aliases).casefold()
        if callable_name:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.aliases[target.id] = callable_name
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802 - ast API
        if node.value is not None and isinstance(node.target, ast.Name):
            callable_name = _python_callable_name(node.value, self.aliases).casefold()
            if callable_name:
                self.aliases[node.target.id] = callable_name
            self.visit(node.value)

    def visit_If(self, node: ast.If) -> None:  # noqa: N802 - ast API
        truth = _static_truth_value(node.test)
        if truth is not None:
            for statement in node.body if truth else node.orelse:
                self.visit(statement)
            return
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:  # noqa: N802 - ast API
        truth = _static_truth_value(node.test)
        if truth is False:
            for statement in node.orelse:
                self.visit(statement)
            return
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:  # noqa: N802 - ast API
        return

    visit_AsyncFunctionDef = visit_FunctionDef


def _python_function_identities(tree: ast.Module) -> dict[int, str]:
    identities: dict[int, str] = {}

    def register(body: list[ast.stmt], prefix: tuple[str, ...]) -> None:
        for statement in body:
            if isinstance(statement, ast.ClassDef):
                register(statement.body, (*prefix, statement.name.casefold()))
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                identity = ".".join((*prefix, statement.name.casefold()))
                identities[id(statement)] = identity
                register(statement.body, (*prefix, statement.name.casefold()))

    register(tree.body, ())
    return identities


def _python_reachable_functions(
    tree: ast.Module,
) -> tuple[set[str], dict[int, str]]:
    identities = _python_function_identities(tree)
    roots = _PythonCallCollector()
    for statement in tree.body:
        roots.visit(statement)
    graph: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        collector = _PythonCallCollector()
        for statement in node.body:
            collector.visit(statement)
        name = identities.get(id(node), node.name.casefold())
        owner = name.rpartition(".")[0]
        normalized_calls = {
            f"{owner}.{called.partition('.')[2]}"
            if owner and called.startswith(("self.", "cls."))
            else called
            for called in collector.names
        }
        graph.setdefault(name, set()).update(normalized_calls)
        if any(
            _ast_qualified_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
            .casefold()
            .rsplit(".", 1)[-1]
            not in {"classmethod", "getter", "property", "setter", "staticmethod"}
            for decorator in node.decorator_list
        ):
            roots.names.add(name)
    reachable = set(roots.names)
    pending = list(reachable)
    while pending:
        for called in graph.get(pending.pop(), set()):
            if called not in reachable:
                reachable.add(called)
                pending.append(called)
    return reachable, identities


def _brace_delta(line: str) -> int:
    delta = 0
    quote = ""
    escaped = False
    for character in line:
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = ""
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character == "{":
            delta += 1
        elif character == "}":
            delta -= 1
    return delta


_SHELL_FUNCTION_CALL = re.compile(r"(?<![\w.-])([A-Za-z_][\w-]*)(?=\s|;|&|\||$)")
_JAVASCRIPT_FUNCTION_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")


def _function_call_names(line: str, *, language: str) -> set[str]:
    pattern = _SHELL_FUNCTION_CALL if language == "shell" else _JAVASCRIPT_FUNCTION_CALL
    return {match.group(1).casefold() for match in pattern.finditer(line)}


def _function_reachability(
    text: str,
    *,
    language: str,
) -> tuple[list[tuple[str, int, int]], set[str]]:
    lines = text.splitlines()
    ranges: list[tuple[str, int, int]] = []
    active_name: str | None = None
    active_start = 0
    balance = 0
    for line_number, line in enumerate(lines, 1):
        if active_name is None:
            if language == "shell":
                match = re.match(
                    r"^\s*(?:function\s+)?([A-Za-z_][\w-]*)\s*"
                    r"(?:\(\s*\))?\s*\{",
                    line,
                )
            else:
                match = re.search(
                    r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"
                    r"\s*\([^)]*\)\s*\{",
                    line,
                )
                if match is None:
                    match = re.search(
                        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                        r"(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{",
                        line,
                    )
                if match is None:
                    method = re.match(
                        r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*"
                        r"\([^)]*\)\s*\{",
                        line,
                    )
                    if method and method.group(1) not in {
                        "catch",
                        "for",
                        "if",
                        "switch",
                        "while",
                        "with",
                    }:
                        match = method
            if match is None:
                continue
            active_name = match.group(1).casefold()
            active_start = line_number
            balance = _brace_delta(line[match.start() :])
            if balance <= 0:
                ranges.append((active_name, active_start, line_number))
                active_name = None
            continue
        balance += _brace_delta(line)
        if balance <= 0:
            ranges.append((active_name, active_start, line_number))
            active_name = None
    if active_name is not None:
        ranges.append((active_name, active_start, len(lines)))

    names = {name for name, _start, _end in ranges}
    graph = {name: set() for name in names}
    roots: set[str] = set()
    aliases: dict[str, str] = {}
    if language == "javascript":
        for line in lines:
            alias_match = re.search(
                r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                r"([A-Za-z_$][\w$]*)\s*;?\s*$",
                line,
            )
            if alias_match and alias_match.group(2).casefold() in names:
                aliases[alias_match.group(1).casefold()] = alias_match.group(2).casefold()

    def resolve_alias(name: str) -> str:
        current = name
        seen: set[str] = set()
        while current in aliases and current not in seen:
            seen.add(current)
            current = aliases[current]
        return current

    owners: list[str | None] = [None] * (len(lines) + 1)
    declarations = {(name, start) for name, start, _end in ranges}
    for name, start, end in ranges:
        for line_number in range(start, min(end, len(lines)) + 1):
            owners[line_number] = name
    for line_number, line in enumerate(lines, 1):
        owner = owners[line_number]
        called_names = {
            resolve_alias(name) for name in _function_call_names(line, language=language)
        }
        if language == "javascript":
            for callback_match in re.finditer(
                r"(?:\b(?:setTimeout|setInterval|queueMicrotask)\s*\(\s*|"
                r"\.(?:addEventListener|catch|finally|forEach|map|filter|then)\s*\(\s*)"
                r"([A-Za-z_$][\w$]*)\b",
                line,
            ):
                candidate = resolve_alias(callback_match.group(1).casefold())
                if candidate in names:
                    called_names.add(candidate)
        for name in called_names:
            if name not in names:
                continue
            if owner == name and (name, line_number) in declarations:
                continue
            (graph[owner] if owner is not None else roots).add(name)
    reachable = set(roots)
    pending = list(reachable)
    while pending:
        for called in graph.get(pending.pop(), set()):
            if called not in reachable:
                reachable.add(called)
                pending.append(called)
    return ranges, reachable


def _structured_disposition(
    line: int,
    ranges: list[tuple[str, int, int]],
    reachable: set[str],
) -> str:
    owner = next(
        (name for name, start, end in ranges if start <= line <= end),
        None,
    )
    return "candidate" if owner is not None and owner not in reachable else "confirmed"


def _ast_string_values(node: ast.AST) -> list[str]:
    return [
        value.value
        for value in ast.walk(node)
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    ]


def _canonical_python_name(name: str, aliases: dict[str, str]) -> str:
    return _resolve_python_alias(name, aliases)


HTTP_CLIENT_CONSTRUCTORS = {
    "aiohttp.clientsession",
    "httpx.asyncclient",
    "httpx.client",
    "requests.session",
    "requests.sessions.session",
}
HTTP_SINK_METHODS = {
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "send",
}


def _is_python_http_sink(name: str) -> bool:
    normalized = name.casefold()
    if normalized in {"urllib.request.urlopen", "urllib3.request"}:
        return True
    owner, separator, method = normalized.rpartition(".")
    if not separator or method not in HTTP_SINK_METHODS:
        return False
    return owner in {"requests", "httpx", "aiohttp"} or owner.startswith(
        ("requests.", "httpx.", "aiohttp.")
    )


def _is_python_http_download(name: str) -> bool:
    normalized = name.casefold()
    return normalized in {
        "requests.get",
        "httpx.get",
        "urllib.request.urlopen",
        "aiohttp.request",
    } or normalized.endswith((".download", ".downloadstring"))


def _python_taint_role(taints: set[str], source: str, target: str) -> set[str]:
    """Preserve purpose on both actual secrets and symbolic function parameters."""
    if "credential_path" in taints:
        return taints
    return {
        target + value[len(source) :]
        if value == source + "credential" or value.startswith(source + "parameter:")
        else value
        for value in taints
    }


def _python_bound_taints(node: ast.Call, arguments: list[set[str]], summary: set[str]) -> set[str]:
    bindings = {
        int(v.split(":", 2)[1]): v.split(":", 2)[2] for v in summary if v.startswith("binding:")
    }
    actual = {index: value for index, value in enumerate(arguments[: len(node.args)])}
    for keyword, value in zip(node.keywords, arguments[len(node.args) :]):
        for index, name in bindings.items():
            if keyword.arg == name:
                actual[index] = value
    result = set()
    for value in summary:
        parameter = re.fullmatch(r"(auth_field_|auth_)?parameter:(\d+)", value)
        if parameter:
            result.update(
                _python_taint_role(actual.get(int(parameter[2]), set()), "", parameter[1] or "")
            )
        elif not value.startswith("binding:"):
            result.add(value)
    # Unresolved argument expansion remains conservative, never grants an exemption.
    for keyword, value in zip(node.keywords, arguments[len(node.args) :]):
        if keyword.arg is None:
            result.update(value)
    return result


def _python_mapping_item_taints(key: ast.AST | None, taints: set[str]) -> set[str]:
    """Retain direct authentication fields until their HTTP argument is known."""
    if any(v.startswith("auth_field_") for v in taints):
        # A nested mapping is data, not a scalar authentication header.
        return _python_taint_role(taints, "auth_field_", "")
    if (
        isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and key.value.casefold() in {"authorization", "proxy-authorization", "x-api-key", "api-key"}
        and "credential_path" not in taints
    ):
        return _python_taint_role(taints, "", "auth_field_")
    return taints


def _python_oauth_refresh_fields(
    node: ast.AST, environment: dict[str, set[str]], aliases: dict[str, str]
) -> bool:
    """Recognize the complete supported protocol shape, never an author claim."""
    if not isinstance(node, ast.Dict) or any(not isinstance(k, ast.Constant) for k in node.keys):
        return False
    fields = {k.value: v for k, v in zip(node.keys, node.values)}
    if len(fields) != len(node.keys) or set(fields) - {
        "client_id",
        "client_secret",
        "refresh_token",
        "grant_type",
    }:
        return False
    grant = fields.get("grant_type")
    if (
        not isinstance(grant, ast.Constant)
        or grant.value != "refresh_token"
        or "refresh_token" not in fields
    ):
        return False
    for field, expected in {
        "client_id": "GOOGLE_CLIENT_ID",
        "client_secret": "GOOGLE_CLIENT_SECRET",
        "refresh_token": "GOOGLE_REFRESH_TOKEN",
    }.items():
        if field not in fields:
            continue
        value = fields[field]
        if isinstance(value, ast.Name):
            origins = environment.get(value.id, set())
            if f"env:{expected}" in origins and origins <= {"credential", f"env:{expected}"}:
                continue
            return False
        if isinstance(value, ast.Call) and _python_callable_name(value.func, aliases) in {
            "os.getenv",
            "os.environ.get",
        }:
            key = value.args[0] if len(value.args) == 1 else None
        elif (
            isinstance(value, ast.Subscript)
            and _canonical_python_name(_ast_qualified_name(value.value), aliases) == "os.environ"
        ):
            key = value.slice
        else:
            return False
        if not isinstance(key, ast.Constant) or key.value != expected:
            return False
    return True


def _python_call_argument_taints(
    node: ast.Call,
    environment: dict[str, set[str]],
    aliases: dict[str, str],
    function_returns: dict[str, set[str]],
) -> list[set[str]]:
    """Keep authentication headers reviewable without treating them as proven theft."""
    name = _python_callable_name(node.func, aliases).casefold()
    owner, _, method = name.rpartition(".")
    http_call = (
        _is_python_http_sink(name)
        or name == "urllib.request.request"
        or (method in HTTP_SINK_METHODS and "network_client" in environment.get(owner, set()))
    )
    arguments = []
    keywords = {k.arg: k.value for k in node.keywords}
    url = node.args[0] if node.args else keywords.get("url")
    method_value = keywords.get("method")
    oauth_request = (
        name == "urllib.request.request"
        and isinstance(url, ast.Constant)
        and url.value == "https://oauth2.googleapis.com/token"
        and isinstance(method_value, ast.Constant)
        and method_value.value == "POST"
    )
    for value in node.args:
        taints = _python_expr_taints(value, environment, aliases, function_returns)
        taints = _python_taint_role(taints, "auth_field_", "")
        arguments.append(taints)
    for keyword in node.keywords:
        taints = _python_expr_taints(keyword.value, environment, aliases, function_returns)
        purpose = "auth_" if http_call and keyword.arg == "headers" else ""
        taints = _python_taint_role(taints, "auth_field_", purpose)
        if keyword.arg in {"data", "json", "params"}:
            taints = _python_taint_role(taints, "auth_", "")
        if oauth_request and keyword.arg == "data" and "oauth_refresh_body" in taints:
            taints = _python_taint_role(taints, "", "auth_") | {"oauth_token_request"}
        arguments.append(taints)
    if (
        method in {"add_header", "add_unredirected_header"}
        and "network_request" in environment.get(owner, set())
        and len(node.args) == 2
    ):
        arguments[1] = _python_taint_role(
            _python_mapping_item_taints(node.args[0], arguments[1]), "auth_field_", "auth_"
        )
    return arguments


def _python_expr_taints(
    node: ast.AST | None,
    environment: dict[str, set[str]],
    aliases: dict[str, str] | None = None,
    function_returns: dict[str, set[str]] | None = None,
) -> set[str]:
    if node is None:
        return set()
    aliases = aliases or {}
    function_returns = function_returns or {}
    if isinstance(node, ast.Name):
        return set(environment.get(node.id, set()))
    if isinstance(node, ast.Dict):
        taints: set[str] = set()
        for key, value in zip(node.keys, node.values):
            item = _python_expr_taints(value, environment, aliases, function_returns)
            taints.update(item if key is None else _python_mapping_item_taints(key, item))
            taints.update(_python_expr_taints(key, environment, aliases, function_returns))
        return taints
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and re.search(
            r"(?:\.ssh/|\.aws/credentials|\.config/gcloud|login\.keychain)",
            node.value,
            re.I,
        )
    ):
        return {"credential_path"}
    if (
        isinstance(node, ast.Subscript)
        and _canonical_python_name(_ast_qualified_name(node.value), aliases) == "os.environ"
    ):
        names = _ast_string_values(node.slice)
        return ({"credential"} if any(_sensitive_env_name(name) for name in names) else set()) | {
            f"env:{name}" for name in names
        }
    if (
        isinstance(node, ast.Attribute)
        and _canonical_python_name(_ast_qualified_name(node), aliases) == "os.environ"
    ):
        return {"credential"}
    if isinstance(node, ast.IfExp) and isinstance(node.test, ast.Constant):
        branch = node.body if bool(node.test.value) else node.orelse
        return _python_expr_taints(branch, environment, aliases, function_returns)
    if isinstance(node, ast.Subscript):
        taints = _python_expr_taints(node.value, environment, aliases, function_returns)
        if (
            "token_response" in taints
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in {"expires_in", "token_type", "scope"}
        ):
            taints -= {"credential", "token_response"}
        taints.update(_python_expr_taints(node.slice, environment, aliases, function_returns))
        taints = _python_taint_role(taints, "auth_field_", "")
        return taints
    if isinstance(node, ast.Call):
        name = _python_callable_name(node.func, aliases).casefold()
        strings = " ".join(_ast_string_values(node)).casefold()
        taints: set[str] = set()
        if isinstance(node.func, ast.Attribute) and name != "os.environ.get":
            taints.update(
                _python_expr_taints(node.func.value, environment, aliases, function_returns)
            )
            if (
                "token_response" in taints
                and node.func.attr == "get"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in {"expires_in", "token_type", "scope"}
            ):
                taints -= {"credential", "token_response"}
        for argument_taints in _python_call_argument_taints(
            node, environment, aliases, function_returns
        ):
            taints.update(argument_taints)
        if name in {"os.getenv", "os.environ.get"}:
            if any(_sensitive_env_name(value) for value in _ast_string_values(node)):
                taints.add("credential")
            if len(node.args) == 1 and isinstance(node.args[0], ast.Constant):
                taints.add(f"env:{node.args[0].value}")
        if (
            name in {"open", "pathlib.path.read_bytes", "pathlib.path.read_text"}
            or name.endswith((".read_bytes", ".read_text"))
        ) and (
            "credential_path" in taints
            or re.search(r"(?:\.ssh/|\.aws/credentials|\.config/gcloud|login\.keychain)", strings)
        ):
            taints.add("credential")
        if _is_python_http_download(name):
            taints.add("download")
        if _is_python_http_sink(name):
            taints.add("network_sink")
            # A service response is not a copy of the caller's authentication header.
            taints = {v for v in taints if not v.startswith("auth_")}
            if "oauth_token_request" in taints:
                taints.update({"token_response", "credential"})
                taints.discard("oauth_refresh_body")
        if name in {"urllib.request.request", "requests.request"}:
            taints.add("network_request")
        if name in {"base64.b64decode", "binascii.a2b_base64", "codecs.decode"}:
            taints.add("decoded")
        if name in HTTP_CLIENT_CONSTRUCTORS:
            taints.add("network_client")
        if (
            name == "urllib.parse.urlencode"
            and len(node.args) == 1
            and _python_oauth_refresh_fields(node.args[0], environment, aliases)
        ):
            taints.add("oauth_refresh_body")
        elif "oauth_refresh_body" in taints and not (
            name == "urllib.request.request"
            or name.rsplit(".", 1)[-1] == "encode"
            or _is_python_http_sink(name)
        ):
            taints.discard("oauth_refresh_body")
        if name in function_returns:
            return _python_bound_taints(
                node,
                _python_call_argument_taints(node, environment, aliases, function_returns),
                function_returns[name],
            )
        return taints
    if isinstance(node, ast.Attribute):
        name = _python_callable_name(node, aliases).casefold()
        if (
            _is_python_http_sink(name)
            or name.endswith((".send", ".sendall", ".sendto"))
            or (isinstance(node, ast.Attribute) and name in {"send", "sendall", "sendto"})
        ):
            return {"network_sink"}
    taints: set[str] = set()
    for child in ast.iter_child_nodes(node):
        taints.update(_python_expr_taints(child, environment, aliases, function_returns))
    strings = _ast_string_values(node)
    taints.discard("oauth_refresh_body")
    if any(value.casefold() == ".aws" for value in strings) and any(
        value.casefold() == "credentials" for value in strings
    ):
        taints.add("credential_path")
    return taints


def _assignment_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        result: set[str] = set()
        for item in node.elts:
            result.update(_assignment_names(item))
        return result
    return set()


class _PythonFlowAnalyzer(ast.NodeVisitor):
    def __init__(
        self,
        path: str,
        text: str,
        *,
        reachable_functions: set[str],
        function_identities: dict[int, str],
    ) -> None:
        self.path = path
        self.text = text
        self.lines = text.splitlines()
        self.environment: dict[str, set[str]] = {}
        self.aliases: dict[str, str] = {}
        self.function_returns: dict[str, set[str]] = {}
        self.function_network_parameters: dict[str, set[str]] = {}
        self.current_function: str | None = None
        self.current_return_taints: set[str] = set()
        self.current_network_parameters: set[str] = set()
        self.reachable_functions = reachable_functions
        self.function_identities = function_identities
        self.findings: list[Finding] = []
        self.seen: set[tuple[str, int]] = set()

    def _source(self, node: ast.AST) -> str:
        segment = ast.get_source_segment(self.text, node)
        if segment:
            return segment
        line = getattr(node, "lineno", 1)
        return self.lines[line - 1] if 0 < line <= len(self.lines) else self.path

    def _add(self, rule_id: str, node: ast.AST, *, disposition: str = "confirmed") -> None:
        unproven_reachability = (
            self.current_function is not None
            and self.current_function not in self.reachable_functions
        )
        line = int(getattr(node, "lineno", 1))
        key = (rule_id, line)
        if key not in self.seen:
            self.seen.add(key)
            finding = _confirmed_structural_finding(
                rule_id,
                self.path,
                line,
                self._source(node),
            )
            self.findings.append(
                replace(finding, disposition="candidate")
                if unproven_reachability or disposition == "candidate"
                else finding
            )

    def _inspect_call(self, node: ast.Call) -> None:
        name = _python_callable_name(node.func, self.aliases).casefold()
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "update"
            and isinstance(node.func.value, ast.Name)
        ):
            mapping = self.environment.setdefault(node.func.value.id, set())
            for value in node.args:
                mapping.update(
                    _python_expr_taints(
                        value, self.environment, self.aliases, self.function_returns
                    )
                )
            for keyword in node.keywords:
                item = _python_expr_taints(
                    keyword.value, self.environment, self.aliases, self.function_returns
                )
                mapping.update(_python_mapping_item_taints(ast.Constant(keyword.arg), item))
        taints_by_argument = _python_call_argument_taints(
            node, self.environment, self.aliases, self.function_returns
        )
        argument_taints = set().union(*taints_by_argument) if taints_by_argument else set()
        raw_name = _ast_qualified_name(node.func)
        base_name = raw_name.partition(".")[0]
        network_sink = (
            _is_python_http_sink(name)
            or name.endswith((".send", ".sendall", ".sendto"))
            or (isinstance(node.func, ast.Attribute) and name in {"send", "sendall", "sendto"})
            or "network_sink"
            in _python_expr_taints(
                node.func,
                self.environment,
                self.aliases,
                self.function_returns,
            )
            or (
                name.rsplit(".", 1)[-1] in HTTP_SINK_METHODS
                and "network_client" in self.environment.get(base_name, set())
            )
        )
        wrapper_parameters = self.function_network_parameters.get(name, set())
        if wrapper_parameters:
            network_sink = True
            argument_taints = _python_bound_taints(node, taints_by_argument, wrapper_parameters)
        if network_sink and self.current_function is not None:
            self.current_network_parameters.update(
                value
                for value in argument_taints
                if re.fullmatch(r"(auth_field_|auth_)?parameter:\d+", value)
            )
        execution_sink = name in {
            "eval",
            "exec",
            "compile",
            "os.system",
            "os.popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.popen",
            "subprocess.run",
        }
        output_sink = (
            name == "print"
            or name in {"sys.stdout.write", "sys.stderr.write"}
            or (
                name.rsplit(".", 1)[-1]
                in {"debug", "info", "warning", "error", "exception", "critical", "log"}
                and re.search(r"(?:^|\.)(?:logging|logger|log)(?:\.|$)", name)
            )
        )
        if output_sink and argument_taints & {
            "credential",
            "auth_credential",
            "auth_field_credential",
            "token_response",
        }:
            self._add("QINDUN.D5.CREDENTIAL_OUTPUT", node, disposition="candidate")
        if network_sink and "credential" in argument_taints:
            self._add("QINDUN.D3.CREDENTIAL_EXFILTRATION", node)
        elif network_sink and "auth_credential" in argument_taints:
            self._add("QINDUN.D3.CREDENTIAL_EXFILTRATION", node, disposition="candidate")
        if name.endswith((".add_header", ".add_unredirected_header")) and base_name:
            self.environment.setdefault(base_name, set()).update(argument_taints)
        if execution_sink and "download" in argument_taints:
            self._add("QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW", node)
        if execution_sink and "decoded" in argument_taints:
            self._add("QINDUN.LOCAL.D3.DECODE_EXECUTION_FLOW", node)
        if execution_sink:
            command = " ".join(_ast_string_values(node))
            for rule_id in (
                "QINDUN.D3.RECURSIVE_ROOT_DELETE",
                "QINDUN.D3.REMOTE_PIPE_SHELL",
                "QINDUN.D3.POWERSHELL_DOWNLOAD_EXECUTION",
                "QINDUN.D3.REVERSE_SHELL",
            ):
                if command and RULES_BY_ID[rule_id].pattern.search(command):
                    self._add(rule_id, node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
        self._inspect_call(node)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:  # noqa: N802 - ast API
        for item in node.items:
            self.visit(item.context_expr)
            taints = _python_expr_taints(
                item.context_expr, self.environment, self.aliases, self.function_returns
            )
            for name in _assignment_names(item.optional_vars):
                self.environment[name] = taints
        for statement in node.body:
            self.visit(statement)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802 - ast API
        self.visit(node.value)
        taints = _python_expr_taints(
            node.value, self.environment, self.aliases, self.function_returns
        )
        for name in _assignment_names(node.target):
            self.environment.setdefault(name, set()).update(taints)
            self.environment[name].discard("oauth_refresh_body")

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802 - ast API
        self.visit(node.value)
        taints = _python_expr_taints(
            node.value, self.environment, self.aliases, self.function_returns
        )
        for target in node.targets:
            if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                self.environment.setdefault(target.value.id, set()).update(
                    _python_mapping_item_taints(target.slice, taints)
                )
            for name in _assignment_names(target):
                self.environment[name] = (
                    self.environment.setdefault(node.value.id, set())
                    if isinstance(node.value, ast.Name)
                    else set(taints)
                )
                callable_name = _python_callable_name(node.value, self.aliases)
                if callable_name:
                    self.aliases[name] = callable_name

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802 - ast API
        if node.value is not None:
            self.visit(node.value)
        taints = _python_expr_taints(
            node.value, self.environment, self.aliases, self.function_returns
        )
        for name in _assignment_names(node.target):
            self.environment[name] = set(taints)
            callable_name = _python_callable_name(node.value, self.aliases) if node.value else ""
            if callable_name:
                self.aliases[name] = callable_name

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802 - ast API
        previous_environment = self.environment
        previous_function = self.current_function
        previous_returns = self.current_return_taints
        previous_network_parameters = self.current_network_parameters
        self.environment = {name: set(value) for name, value in previous_environment.items()}
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        for index, argument in enumerate(arguments):
            self.environment[argument.arg] = {f"parameter:{index}"}
        self.current_function = self.function_identities.get(
            id(node),
            node.name.casefold(),
        )
        self.current_return_taints = set()
        self.current_network_parameters = set()
        for statement in node.body:
            self.visit(statement)
        bindings = {f"binding:{index}:{argument.arg}" for index, argument in enumerate(arguments)}
        self.function_returns[self.current_function] = set(self.current_return_taints) | bindings
        self.function_network_parameters[self.current_function] = set(
            self.current_network_parameters
        ) | (bindings if self.current_network_parameters else set())
        self.environment = previous_environment
        self.current_function = previous_function
        self.current_return_taints = previous_returns
        self.current_network_parameters = previous_network_parameters

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802 - ast API
        if node.value is not None:
            self.visit(node.value)
        self.current_return_taints.update(
            _python_expr_taints(
                node.value,
                self.environment,
                self.aliases,
                self.function_returns,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802 - ast API
        for item in node.names:
            if item.asname:
                self.aliases[item.asname] = item.name
            else:
                root = item.name.split(".", 1)[0]
                self.aliases.setdefault(root, root)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802 - ast API
        module = node.module or ""
        for item in node.names:
            self.aliases[item.asname or item.name] = f"{module}.{item.name}".strip(".")

    def visit_If(self, node: ast.If) -> None:  # noqa: N802 - ast API
        truth = _static_truth_value(node.test)
        if truth is not None:
            branch = node.body if truth else node.orelse
            for statement in branch:
                self.visit(statement)
            return
        before = {name: set(value) for name, value in self.environment.items()}
        self.environment = {name: set(value) for name, value in before.items()}
        for statement in node.body:
            self.visit(statement)
        body_environment = self.environment
        self.environment = {name: set(value) for name, value in before.items()}
        for statement in node.orelse:
            self.visit(statement)
        else_environment = self.environment
        self.environment = {
            name: set(body_environment.get(name, set())) | set(else_environment.get(name, set()))
            for name in set(before) | set(body_environment) | set(else_environment)
        }

    def visit_While(self, node: ast.While) -> None:  # noqa: N802 - ast API
        truth = _static_truth_value(node.test)
        if truth is False:
            for statement in node.orelse:
                self.visit(statement)
            return
        self.generic_visit(node)


def _python_flow_findings(path: str, text: str) -> tuple[list[Finding], str | None]:
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return [], f"Python 结构分析失败：{path}"
    if sum(1 for _node in ast.walk(tree)) > MAX_STRUCTURED_AST_NODES:
        return [], f"Python 结构节点超过上限：{path}"
    reachable_functions, function_identities = _python_reachable_functions(tree)
    analyzer = _PythonFlowAnalyzer(
        path,
        text,
        reachable_functions=reachable_functions,
        function_identities=function_identities,
    )
    analyzer.visit(tree)
    return analyzer.findings, None


def _shell_flow_findings(path: str, text: str, *, powershell: bool = False) -> list[Finding]:
    environment: dict[str, set[str]] = {}
    downloaded_files: set[str] = set()
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    normalized_text = text.replace("\\\n", " ")
    function_ranges, reachable_functions = _function_reachability(
        normalized_text,
        language="shell",
    )

    def add(rule_id: str, line: int, source: str) -> None:
        key = (rule_id, line)
        if key not in seen:
            seen.add(key)
            finding = _confirmed_structural_finding(rule_id, path, line, source)
            findings.append(
                replace(finding, disposition="candidate")
                if _structured_disposition(
                    line,
                    function_ranges,
                    reachable_functions,
                )
                == "candidate"
                else finding
            )

    lines = normalized_text.splitlines()
    for line_number, original in enumerate(lines, 1):
        stripped = original.strip()
        if not stripped or stripped.startswith("#"):
            continue
        command_line = re.sub(r"^\s*(?:sudo\s+)?", "", original)
        command_start = re.match(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\b", command_line)
        start = command_start.group(1).casefold() if command_start else ""
        if start == "rm" and RULES_BY_ID["QINDUN.D3.RECURSIVE_ROOT_DELETE"].pattern.search(
            command_line
        ):
            add("QINDUN.D3.RECURSIVE_ROOT_DELETE", line_number, original)
        if start in {"curl", "wget"} and RULES_BY_ID["QINDUN.D3.REMOTE_PIPE_SHELL"].pattern.search(
            command_line
        ):
            add("QINDUN.D3.REMOTE_PIPE_SHELL", line_number, original)
        if start in {"bash", "nc", "ncat"} and RULES_BY_ID[
            "QINDUN.D3.REVERSE_SHELL"
        ].pattern.search(command_line):
            add("QINDUN.D3.REVERSE_SHELL", line_number, original)
        if (
            powershell
            and start
            in {"iex", "invoke-expression", "invoke-webrequest", "iwr", "powershell", "pwsh"}
            and RULES_BY_ID["QINDUN.D3.POWERSHELL_DOWNLOAD_EXECUTION"].pattern.search(command_line)
        ):
            add("QINDUN.D3.POWERSHELL_DOWNLOAD_EXECUTION", line_number, original)

        assignment = re.match(r"^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$", original)
        if assignment:
            name, expression = assignment.groups()
            taints: set[str] = set()
            referenced_variables = re.findall(
                r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))", expression
            )
            if re.search(
                r"(?:\.ssh/|\.aws/credentials|\.config/gcloud|login\.keychain)",
                expression,
                re.I,
            ) or any(
                _sensitive_env_name(first or second) for first, second in referenced_variables
            ):
                taints.add("credential")
            if re.search(r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b", expression, re.I):
                taints.add("download")
            if re.search(
                r"\b(?:base64\s+(?:-[A-Za-z]*d|--decode)|FromBase64String)\b", expression, re.I
            ):
                taints.add("decoded")
            for variable, variable_taints in environment.items():
                if re.search(
                    rf"\$(?:\{{{re.escape(variable)}\}}|{re.escape(variable)}\b)", expression
                ):
                    taints.update(variable_taints)
            environment[name] = taints

        download_target = re.search(
            r"\b(?:curl\b[^\n]*?(?:-o|--output)\s+|wget\b[^\n]*?(?:-O|--output-document)\s+)([^\s;&|]+)",
            original,
            re.I,
        )
        redirected_download = re.search(r"\b(?:curl|wget)\b[^\n]*?>\s*([^\s;&|]+)", original, re.I)
        target_match = download_target or redirected_download
        if target_match:
            downloaded_files.add(target_match.group(1).strip("\"'"))

        line_taints: set[str] = set()
        for variable, variable_taints in environment.items():
            if re.search(rf"\$(?:\{{{re.escape(variable)}\}}|{re.escape(variable)}\b)", original):
                line_taints.update(variable_taints)
        if re.search(r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b", original, re.I) and re.search(
            r"(?:\.ssh/|\.aws/credentials|\.config/gcloud|login\.keychain)", original, re.I
        ):
            line_taints.add("credential")
        network_sink = bool(re.search(r"\b(?:curl|wget|Invoke-RestMethod|irm)\b", original, re.I))
        execution_sink = bool(
            re.search(r"\b(?:eval|exec|bash\s+-c|sh\s+-c|iex|Invoke-Expression)\b", original, re.I)
        )
        executed_file = re.match(
            r"^\s*(?:(?:bash|sh|source|\.)\s+([^\s;&|]+)|([./][^\s;&|]+))",
            command_line,
        )
        executed_path = (
            (executed_file.group(1) or executed_file.group(2)).strip("\"'")
            if executed_file
            else None
        )
        if executed_path in downloaded_files:
            add("QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW", line_number, original)
        if network_sink and "credential" in line_taints:
            add("QINDUN.D3.CREDENTIAL_EXFILTRATION", line_number, original)
        if execution_sink and (
            "download" in line_taints
            or re.search(r"\$\([^)]*\b(?:curl|wget|iwr|Invoke-WebRequest)\b", original, re.I)
        ):
            add("QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW", line_number, original)
        if execution_sink and "decoded" in line_taints:
            add("QINDUN.LOCAL.D3.DECODE_EXECUTION_FLOW", line_number, original)
    return findings


def _mask_javascript_comments(text: str) -> str:
    output = list(text)
    index = 0
    quote = ""
    escaped = False
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            index += 1
            continue
        if character == "/" and following == "/":
            while index < len(text) and text[index] != "\n":
                output[index] = " "
                index += 1
            continue
        if character == "/" and following == "*":
            output[index] = output[index + 1] = " "
            index += 2
            while index + 1 < len(text) and text[index : index + 2] != "*/":
                if text[index] != "\n":
                    output[index] = " "
                index += 1
            if index + 1 < len(text):
                output[index] = output[index + 1] = " "
                index += 2
            continue
        index += 1
    return "".join(output)


def _javascript_env_names(text: str) -> set[str]:
    names = set(re.findall(r"\b(?:process|Deno)\.env\.([A-Za-z_$][\w$]*)", text))
    names.update(
        first or second
        for first, second in re.findall(
            r"\b(?:process|Deno)\.env(?:\.get)?\(?(?:\[)?\s*(?:\"([^\"]+)\"|'([^']+)')",
            text,
        )
        if first or second
    )
    return names


def _javascript_has_sensitive_environment(text: str) -> bool:
    names = _javascript_env_names(text)
    if any(_sensitive_env_name(name) for name in names):
        return True
    stripped = re.sub(
        r"\b(?:process|Deno)\.env(?:\.[A-Za-z_$][\w$]*|\[[^]]+\]|\.get\([^)]*\))",
        "",
        text,
    )
    return bool(re.search(r"\b(?:process|Deno)\.env\b", stripped))


JAVASCRIPT_HTTP_SINK_PATTERN = re.compile(
    r"\b(?:fetch|axios\.(?:delete|get|head|options|patch|post|put|request)|"
    r"https?\.(?:get|request))\s*\(",
    re.I,
)
JAVASCRIPT_HTTP_DOWNLOAD_PATTERN = re.compile(
    r"\b(?:fetch|axios\.get|https?\.get)\s*\(",
    re.I,
)


def _javascript_http_calls(code: str):
    """Read bounded balanced calls; an inner call must not truncate the request."""
    for sink in JAVASCRIPT_HTTP_SINK_PATTERN.finditer(code):
        depth, quote, escaped = 1, "", False
        for index in range(sink.end(), min(len(code), sink.end() + 4000)):
            char = code[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
            elif char in "'\"\x60":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    yield (
                        sink.start(),
                        sink.group(0).rstrip().removesuffix("(").strip(),
                        code[sink.end() : index],
                    )
                    break
        else:
            yield sink.start(), "", code[sink.end() : sink.end() + 4000]


def _javascript_auth_header_context(prefix: str, sink_name: str) -> bool:
    # A header-looking string or an object in the request payload is not an
    # authentication option. Count only delimiters outside literal strings.
    argument = 0
    stack: list[str] = []
    quote, escaped = "", False
    for char in prefix:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"\x60":
            quote = char
        elif char in "({[":
            stack.append(char)
        elif char in ")}]" and stack:
            stack.pop()
        elif char == "," and not stack:
            argument += 1
    expected = (
        {2}
        if sink_name in {"axios.post", "axios.put", "axios.patch"}
        else {0}
        if sink_name == "axios.request"
        else {0, 1}
        if sink_name.startswith(("http.", "https."))
        else {1}
        if sink_name
        else set()
    )
    return not quote and stack == ["{"] and argument in expected


def _javascript_request_taints(
    body: str, environment: dict[str, set[str]], sink_name: str
) -> set[str]:
    def taints(text: str) -> set[str]:
        result: set[str] = set()
        if _javascript_has_sensitive_environment(text):
            result.add("credential")
        if re.search(r"(?:\.ssh/|\.aws/credentials|login\.keychain)", text, re.I):
            result.update({"credential", "credential_path"})
        for variable, variable_taints in environment.items():
            if re.search(rf"\b{re.escape(variable)}\b", text):
                result.update(variable_taints)
        return result

    auth_taints: set[str] = set()

    def headers(match: re.Match[str]) -> str:
        if not _javascript_auth_header_context(body[: match.start()], sink_name):
            return match.group(0)

        def field(pair: re.Match[str]) -> str:
            value_taints = taints(pair.group("value"))
            if "credential" in value_taints and "credential_path" not in value_taints:
                auth_taints.add("auth_credential")
                return pair.group("prefix") + "'<authentication>'"
            return pair.group(0)

        # Only simple literal header values qualify. Computed keys, spreads and
        # calls remain ordinary data flow; no URL or publisher is exempted.
        fields = re.sub(
            r"""(?P<prefix>(?:^|,)\s*['"]?(?:Authorization|X-API-Key|API-Key)['"]?\s*:\s*)"""
            r"""(?P<value>process\.env(?:\.[A-Za-z_$][\w$]*|\[['"][A-Za-z_$][\w$]*['"]\])"""
            r"""|[A-Za-z_$][\w$]*|'[^'\\]*'|"[^"\\]*"|\x60[^\x60\\]*\x60)"""
            r"(?=\s*(?:,|$))",
            field,
            match.group("fields"),
            flags=re.I,
        )
        return "headers:{" + fields + "}"

    residual = re.sub(
        r"""(?<![\w$])['"]?headers['"]?\s*:\s*\{(?P<fields>(?:[^{}\x60]|\x60[^\x60]*\x60)*?)\}""",
        headers,
        body,
        flags=re.I,
    )
    return taints(residual) | auth_taints


def _javascript_flow_findings(path: str, text: str) -> list[Finding]:
    code = _mask_javascript_comments(text)
    environment: dict[str, set[str]] = {}
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    function_ranges, reachable_functions = _function_reachability(
        code,
        language="javascript",
    )

    def add(rule_id: str, line: int, source: str, *, auth_only: bool = False) -> None:
        key = (rule_id, line)
        if key in seen and not auth_only:
            for index, finding in enumerate(findings):
                if (finding.rule_id, finding.line) == key and finding.disposition == "candidate":
                    if (
                        _structured_disposition(line, function_ranges, reachable_functions)
                        == "confirmed"
                    ):
                        findings[index] = _confirmed_structural_finding(rule_id, path, line, source)
        if key not in seen:
            seen.add(key)
            finding = _confirmed_structural_finding(rule_id, path, line, source)
            findings.append(
                replace(finding, disposition="candidate")
                if auth_only
                or _structured_disposition(
                    line,
                    function_ranges,
                    reachable_functions,
                )
                == "candidate"
                else finding
            )

    for line_number, line in enumerate(code.splitlines(), 1):
        assignment = re.search(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^=;]+)?\s*=\s*(.+)",
            line,
        )
        if assignment:
            name, expression = assignment.groups()
            taints: set[str] = set()
            if _javascript_has_sensitive_environment(expression) or re.search(
                r"(?:\.ssh/|\.aws/credentials|login\.keychain)", expression, re.I
            ):
                taints.add("credential")
            if re.search(r"(?:\.ssh/|\.aws/credentials|login\.keychain)", expression, re.I):
                taints.add("credential_path")
            if JAVASCRIPT_HTTP_DOWNLOAD_PATTERN.search(expression):
                taints.add("download")
            if re.search(r"\b(?:atob|Buffer\.from)\s*\(", expression):
                taints.add("decoded")
            for variable, variable_taints in environment.items():
                if re.search(rf"\b{re.escape(variable)}\b", expression):
                    taints.update(variable_taints)
            environment[name] = taints

        line_taints: set[str] = set()
        if _javascript_has_sensitive_environment(line) or re.search(
            r"(?:\.ssh/|\.aws/credentials|login\.keychain)", line, re.I
        ):
            line_taints.add("credential")
        if JAVASCRIPT_HTTP_DOWNLOAD_PATTERN.search(line):
            line_taints.add("download")
        if re.search(r"\b(?:atob|Buffer\.from)\s*\(", line):
            line_taints.add("decoded")
        for variable, variable_taints in environment.items():
            if re.search(rf"\b{re.escape(variable)}\b", line):
                line_taints.update(variable_taints)
        execution_sink = bool(
            re.search(r"\b(?:eval|Function|exec|execSync|spawn|spawnSync)\s*\(", line)
        )
        if execution_sink and "download" in line_taints:
            add("QINDUN.LOCAL.D3.DOWNLOAD_EXECUTION_FLOW", line_number, line)
        if execution_sink and "decoded" in line_taints:
            add("QINDUN.LOCAL.D3.DECODE_EXECUTION_FLOW", line_number, line)

        command_match = re.search(
            r"\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(['\"`])(.+?)\1",
            line,
        )
        if command_match:
            command = command_match.group(2)
            for rule_id in (
                "QINDUN.D3.RECURSIVE_ROOT_DELETE",
                "QINDUN.D3.REMOTE_PIPE_SHELL",
                "QINDUN.D3.POWERSHELL_DOWNLOAD_EXECUTION",
                "QINDUN.D3.REVERSE_SHELL",
            ):
                if RULES_BY_ID[rule_id].pattern.search(command):
                    add(rule_id, line_number, line)

    for start, sink_name, body in _javascript_http_calls(code):
        body_taints = _javascript_request_taints(body, environment, sink_name)
        if body_taints & {"credential", "auth_credential"}:
            add(
                "QINDUN.D3.CREDENTIAL_EXFILTRATION",
                _line(code, start),
                body,
                auth_only="credential" not in body_taints,
            )
    return findings


def _private_key_finding(path: str, text: str, role: str) -> list[Finding]:
    if role in {"instructions", "safety_material"}:
        return []
    match = re.search(
        r"-----BEGIN (?P<kind>(?:RSA |EC |OPENSSH )?PRIVATE KEY)-----\s*"
        r"(?P<body>(?:[A-Za-z0-9+/=]{16,}\s*){4,})"
        r"-----END (?P=kind)-----",
        text,
    )
    if match is None:
        return []
    return [
        _confirmed_structural_finding(
            "QINDUN.D5.PRIVATE_KEY",
            path,
            _line(text, match.start()),
            match.group(0),
        )
    ]


def _structured_code_findings(
    path: str,
    text: str,
    *,
    mode: int = 0,
    forced_role: str | None = None,
) -> tuple[str, list[Finding], str | None]:
    if forced_role == CONFLICTING_EXECUTABLE_ROLE:
        role = "unsupported_executable"
    elif forced_role == DECLARED_EXECUTABLE_ROLE:
        role = _file_role(path, text, mode=mode | 0o111)
    else:
        role = forced_role or _file_role(path, text, mode=mode)
    findings = _private_key_finding(path, text, role)
    executable_role = role.removeprefix("safety_")
    safety_code = role.startswith("safety_") and executable_role in {
        "python",
        "shell",
        "powershell",
        "javascript",
    }
    if (
        executable_role in {"python", "shell", "powershell", "javascript"}
        and len(text.encode("utf-8", errors="replace")) > MAX_STRUCTURED_CODE_BYTES
    ):
        return role, findings, f"代码结构分析超过大小上限：{path}"
    if executable_role == "python":
        python_findings, error = _python_flow_findings(path, text)
        findings.extend(python_findings)
    elif executable_role == "shell":
        findings.extend(_shell_flow_findings(path, text))
        error = None
    elif executable_role == "powershell":
        findings.extend(_shell_flow_findings(path, text, powershell=True))
        error = None
    elif executable_role == "javascript":
        findings.extend(_javascript_flow_findings(path, text))
        error = None
    elif executable_role == "unsupported_executable":
        error = f"不支持的可执行源码或入口文件：{path}"
    else:
        error = None
    if safety_code:
        findings = [replace(item, disposition="candidate") for item in findings]
    return role, findings, error


def _manifest_digest(entries: list[dict], *, complete: bool) -> str | None:
    if not complete:
        return None
    return hashlib.sha256(
        _canonical_json(sorted(entries, key=lambda item: _canonical_json(item)))
    ).hexdigest()


def _local_grade(findings: list[Finding], *, coverage_complete: bool) -> str | None:
    danger = GRADE_POLICY["confirmed_danger"]
    if any(
        item.severity == danger["severity"]
        and item.disposition == danger["disposition"]
        and item.deterministic
        for item in findings
    ):
        return "D"
    if not coverage_complete:
        return None
    caps = GRADE_POLICY["finding_grade_caps"]
    grade = GRADE_POLICY["local_maximum_grade"]
    for item in findings:
        candidate = str(caps[item.severity])
        if GRADE_ORDER[candidate] < GRADE_ORDER[grade]:
            grade = candidate
    return grade


def _relative_root(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "" if parent == "." else f"{parent}/"


def _frontmatter_valid(text: str) -> bool:
    return all(required_frontmatter(text).get(field) for field in ("name", "description"))


def _structure_findings(
    paths: set[str],
    marker_texts: dict[str, str],
) -> tuple[str, list[Finding]]:
    detected: set[str] = set()
    findings: list[Finding] = []
    skill_paths = sorted(path for path in paths if PurePosixPath(path).name == "SKILL.md")
    agent_paths = sorted(
        path for path in paths if PurePosixPath(path).name in {"AGENTS.md", "CLAUDE.md"}
    )
    manifest_paths = sorted(
        path for path in paths if PurePosixPath(path).name in {"chinmarket.yaml", "chinmarket.yml"}
    )
    workflow_paths = sorted(path for path in paths if PurePosixPath(path).name == "langgraph.json")
    for path in skill_paths:
        detected.add("skill")
        if not _frontmatter_valid(marker_texts.get(path, "")):
            findings.append(
                _finding(
                    "QINDUN.LOCAL.D2.SKILL_METADATA",
                    "high",
                    "Skill 基本信息不完整",
                    "SKILL.md 必须包含非空的 name 和 description 头部字段",
                    path,
                    path,
                    dimension="D2",
                    disposition="candidate",
                )
            )
    for path in agent_paths:
        detected.add("agent")
        if not marker_texts.get(path, "").strip():
            findings.append(
                _finding(
                    "QINDUN.LOCAL.D2.AGENT_METADATA",
                    "high",
                    "Agent 说明文件为空",
                    "AGENTS.md 或 CLAUDE.md 必须包含有效说明",
                    path,
                    path,
                    dimension="D2",
                    disposition="candidate",
                )
            )
    for path in workflow_paths:
        detected.add("workflow")
        try:
            value = json.loads(marker_texts.get(path, ""))
        except json.JSONDecodeError:
            value = None
        if not isinstance(value, dict):
            findings.append(
                _finding(
                    "QINDUN.LOCAL.D2.WORKFLOW_METADATA",
                    "high",
                    "工作流配置无效",
                    "langgraph.json 必须是有效的 JSON 对象",
                    path,
                    path,
                    dimension="D2",
                    disposition="candidate",
                )
            )
    for path in manifest_paths:
        text = marker_texts.get(path, "")
        artifact_type_match = re.search(
            r"(?m)^type\s*:\s*[\"']?(agent|skill|workflow)[\"']?\s*$",
            text,
        )
        entry_match = re.search(r"(?m)^entry\s*:\s*[\"']?([^\s#\"']+)[\"']?\s*$", text)
        if artifact_type_match is None:
            findings.append(
                _finding(
                    "QINDUN.LOCAL.D2.CHINMARKET_TYPE",
                    "high",
                    "作品类型声明无效",
                    "chinmarket.yaml 的 type 必须是 agent、skill 或 workflow",
                    path,
                    path,
                    dimension="D2",
                    disposition="candidate",
                )
            )
        else:
            detected.add(artifact_type_match.group(1))
        if entry_match is None:
            findings.append(
                _finding(
                    "QINDUN.LOCAL.D2.CHINMARKET_ENTRY",
                    "high",
                    "作品入口声明缺失",
                    "chinmarket.yaml 必须声明安全且存在的相对入口文件",
                    path,
                    path,
                    dimension="D2",
                    disposition="candidate",
                )
            )
            continue
        entry = entry_match.group(1)
        full_entry = f"{_relative_root(path)}{entry}"
        if not _safe_relative(entry) or full_entry not in paths:
            findings.append(
                _finding(
                    "QINDUN.LOCAL.D2.CHINMARKET_ENTRY",
                    "high",
                    "作品入口声明无效",
                    "chinmarket.yaml 声明的入口必须是包内已存在的安全相对路径",
                    path,
                    entry,
                    dimension="D2",
                    disposition="candidate",
                )
            )
    if not paths:
        findings.append(
            _finding(
                "QINDUN.LOCAL.D2.EMPTY_PACKAGE",
                "high",
                "作品包为空",
                "空作品包不能完成有效的基础安全预检",
                ".",
                "empty package",
                dimension="D2",
                disposition="candidate",
            )
        )
    elif not detected:
        findings.append(
            _finding(
                "QINDUN.LOCAL.D2.UNKNOWN_PROFILE",
                "high",
                "无法识别作品类型",
                "没有找到受支持的 Skill、Agent 或工作流标志文件",
                ".",
                "unrecognized package profile",
                dimension="D2",
                disposition="candidate",
            )
        )
    elif len(detected) > 1:
        findings.append(
            _finding(
                "QINDUN.LOCAL.D2.AMBIGUOUS_PROFILE",
                "high",
                "作品类型存在冲突",
                "同一作品包同时出现多个作品类型的标志文件",
                ".",
                ",".join(sorted(detected)),
                dimension="D2",
                disposition="candidate",
            )
        )
    profile = next(iter(detected)) if len(detected) == 1 else "unknown"
    return profile, findings


def _domain_declared(domain: str, declared: set[str]) -> bool:
    return domain in declared or any(
        item.startswith("*.") and domain.endswith(item[1:]) for item in declared
    )


def _network_profile(domain: str) -> dict[str, object]:
    try:
        address = ipaddress.ip_address(domain)
    except ValueError:
        address = None
    if address is not None and any(
        address in ipaddress.ip_network(network)
        for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    ):
        return {"domain": domain, "category": "文档示例地址", "risk": "low", "flags": []}
    flags: list[str] = []
    risk = "low"
    if domain in SHORT_LINK_DOMAINS:
        flags.append("short_link")
        risk = "high"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain):
        flags.append("ip_address")
        risk = "high"
    if domain.endswith(DYNAMIC_DNS_SUFFIXES):
        flags.append("dynamic_dns")
        risk = "high"
    if domain.endswith(SUSPICIOUS_TLDS):
        flags.append("suspicious_tld")
        if risk == "low":
            risk = "medium"
    if re.search(r"(?:^|\.)(?:beacon|collector|telemetry|tracker)(?:\.|$)", domain):
        flags.append("collection_endpoint")
        risk = "high"
    return {
        "domain": domain,
        "category": KNOWN_DOMAIN_CATEGORIES.get(domain, "未分类"),
        "risk": risk,
        "flags": flags,
    }


def _capability_string_list(value: object, label: str) -> tuple[list[str], list[str]]:
    if not isinstance(value, list):
        return [], [f"{label} 必须是字符串数组"]
    if len(value) > MAX_CAPABILITY_ITEMS:
        return [], [f"{label} 数量超过上限"]
    result: list[str] = []
    errors: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > MAX_CAPABILITY_VALUE_LENGTH:
            errors.append(f"{label} 包含无效字符串")
            continue
        result.append(item.strip())
    if len(set(result)) != len(result):
        errors.append(f"{label} 包含重复值")
    return result, errors


def _validate_capability_manifest(manifest: object) -> list[str]:
    if not isinstance(manifest, dict):
        return ["能力声明必须是 JSON 对象"]
    if set(manifest) - CAPABILITY_KEYS:
        return ["能力声明包含不支持的字段"]
    required = {
        "format",
        "filesystem",
        "network",
        "process",
        "environment",
        "mcp_tools",
        "persistent_state",
    }
    missing = required - set(manifest)
    if missing:
        return [f"能力声明缺少字段：{', '.join(sorted(missing))}"]
    errors: list[str] = []
    if manifest.get("format") != "qindun-capabilities/v1":
        errors.append("format 必须是 qindun-capabilities/v1")
    filesystem = manifest.get("filesystem")
    if not isinstance(filesystem, dict) or set(filesystem) != {"read", "write"}:
        errors.append("filesystem 必须只包含 read 和 write")
    else:
        for key in ("read", "write"):
            _values, item_errors = _capability_string_list(filesystem.get(key), f"filesystem.{key}")
            errors.extend(item_errors)
    network = manifest.get("network")
    if not isinstance(network, dict) or set(network) != {"required", "domains"}:
        errors.append("network 必须只包含 required 和 domains")
    else:
        if type(network.get("required")) is not bool:
            errors.append("network.required 必须是布尔值")
        domains, item_errors = _capability_string_list(network.get("domains"), "network.domains")
        errors.extend(item_errors)
        if any(re.fullmatch(r"(?:\*\.)?[A-Za-z0-9.-]+", domain) is None for domain in domains):
            errors.append("network.domains 包含无效域名")
        if domains and network.get("required") is False:
            errors.append("声明网络域名时 network.required 不能为 false")
    process = manifest.get("process")
    if not isinstance(process, dict) or set(process) != {"spawn", "commands"}:
        errors.append("process 必须只包含 spawn 和 commands")
    else:
        if type(process.get("spawn")) is not bool:
            errors.append("process.spawn 必须是布尔值")
        commands, item_errors = _capability_string_list(process.get("commands"), "process.commands")
        errors.extend(item_errors)
        if commands and process.get("spawn") is False:
            errors.append("声明进程命令时 process.spawn 不能为 false")
    environment = manifest.get("environment")
    if not isinstance(environment, dict) or set(environment) != {"variables", "secrets"}:
        errors.append("environment 必须只包含 variables 和 secrets")
    else:
        for key in ("variables", "secrets"):
            _values, item_errors = _capability_string_list(
                environment.get(key), f"environment.{key}"
            )
            errors.extend(item_errors)
    _tools, item_errors = _capability_string_list(manifest.get("mcp_tools"), "mcp_tools")
    errors.extend(item_errors)
    if type(manifest.get("persistent_state")) is not bool:
        errors.append("persistent_state 必须是布尔值")
    if "browser" in manifest and type(manifest.get("browser")) is not bool:
        errors.append("browser 必须是布尔值")
    if "databases" in manifest:
        _databases, item_errors = _capability_string_list(manifest.get("databases"), "databases")
        errors.extend(item_errors)
    if "dynamic" in manifest:
        dynamic = manifest.get("dynamic")
        if not isinstance(dynamic, dict) or set(dynamic) != {"entrypoint", "working_directory"}:
            errors.append("dynamic 必须只包含 entrypoint 和 working_directory")
        else:
            entrypoint = dynamic.get("entrypoint")
            if entrypoint is not None:
                _entrypoint, item_errors = _capability_string_list(entrypoint, "dynamic.entrypoint")
                errors.extend(item_errors)
            working_directory = dynamic.get("working_directory")
            if not isinstance(working_directory, str) or not working_directory.strip():
                errors.append("dynamic.working_directory 必须是非空字符串")
    return errors


def _python_process_observations(text: str) -> tuple[set[str], bool]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return set(), False

    commands: set[str] = set()
    dynamic = False

    class ProcessVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.aliases: dict[str, str] = {}

        def visit_Import(self, node: ast.Import) -> None:  # noqa: N802 - ast API
            for item in node.names:
                if item.asname:
                    self.aliases[item.asname] = item.name
                else:
                    root = item.name.split(".", 1)[0]
                    self.aliases.setdefault(root, root)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802 - ast API
            module = node.module or ""
            for item in node.names:
                self.aliases[item.asname or item.name] = f"{module}.{item.name}".strip(".")

        def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802 - ast API
            callable_name = _python_callable_name(node.value, self.aliases)
            if callable_name:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.aliases[target.id] = callable_name
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 - ast API
            nonlocal dynamic
            name = _python_callable_name(node.func, self.aliases).casefold()
            if name in {
                "os.popen",
                "os.system",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "subprocess.popen",
                "subprocess.run",
            }:
                command_node = (
                    node.args[0]
                    if node.args
                    else next(
                        (
                            item.value
                            for item in node.keywords
                            if item.arg in {"args", "command", "cmd"}
                        ),
                        None,
                    )
                )
                literal = None
                if isinstance(command_node, ast.Constant) and isinstance(command_node.value, str):
                    literal = command_node.value
                elif isinstance(command_node, (ast.List, ast.Tuple)) and command_node.elts:
                    first = command_node.elts[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        literal = first.value
                if literal and literal.strip():
                    try:
                        command = shlex.split(literal.strip(), posix=True)[0]
                    except (ValueError, IndexError):
                        command = literal.strip().split()[0]
                    commands.add(command)
                else:
                    dynamic = True
            self.generic_visit(node)

    ProcessVisitor().visit(tree)
    return commands, dynamic


def _observe_capabilities(text: str) -> dict[str, set[str] | bool]:
    reads: set[str] = set()
    writes: set[str] = set()
    environment: set[str] = set()
    process_commands: set[str] = set()
    mcp_tools = set(re.findall(r"\bmcp__[A-Za-z0-9_-]+__[A-Za-z0-9_-]+\b", text))
    for match in re.finditer(
        r"\bopen\s*\(\s*([\"'])(?P<path>[^\"']+)\1"
        r"(?:\s*,\s*([\"'])(?P<mode>[^\"']+)\3)?",
        text,
    ):
        mode = match.group("mode") or "r"
        (writes if any(flag in mode for flag in "wax+") else reads).add(match.group("path"))
    for operation, target in (("read", reads), ("write", writes)):
        for match in re.finditer(
            rf"(?:Path\s*\(\s*|(?:readFile|writeFile|appendFile)(?:Sync)?\s*\(\s*)"
            rf"([\"'])(?P<path>[^\"']+)\1[^\n]{{0,160}}\.?(?:{operation}_?(?:text|bytes)|{operation}File)",
            text,
            re.I,
        ):
            target.add(match.group("path"))
    for operation, target in (("readFile", reads), ("writeFile", writes), ("appendFile", writes)):
        for match in re.finditer(
            rf"\b{operation}(?:Sync)?\s*\(\s*([\"'])(?P<path>[^\"']+)\1",
            text,
        ):
            target.add(match.group("path"))
    for match in re.finditer(r"(?m)^\s*cat\s+([\"']?)([^\s|;&<>]+)\1", text):
        reads.add(match.group(2))
    for match in re.finditer(r"(?m)\btee\s+(?:-[A-Za-z]+\s+)*([\"']?)([^\s|;&]+)\1", text):
        writes.add(match.group(2))
    environment.update(
        first or second
        for first, second in re.findall(
            r"\b(?:os\.getenv|os\.environ\.get|Deno\.env\.get)\s*\(\s*(?:\"([^\"]+)\"|'([^']+)')",
            text,
        )
        if first or second
    )
    environment.update(
        first or second
        for first, second in re.findall(
            r"\bos\.environ\s*\[\s*(?:\"([^\"]+)\"|'([^']+)')\s*\]",
            text,
        )
        if first or second
    )
    environment.update(_javascript_env_names(text))
    environment.update(
        first or second
        for first, second in re.findall(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))", text)
        if _sensitive_env_name(first or second)
    )
    for match in re.finditer(
        r"\b(?:subprocess\.(?:run|Popen|call|check_call|check_output)|"
        r"child_process\.(?:exec|execFile|spawn)|(?:os\.)?(?:system|popen))\s*\(\s*"
        r"(?:\[\s*)?([\"'])(?P<command>[^\"']+)\1",
        text,
        re.I,
    ):
        command = match.group("command").strip().split()[0]
        if command:
            process_commands.add(command)
    python_commands, dynamic_process = _python_process_observations(text)
    process_commands.update(python_commands)
    if dynamic_process:
        process_commands.add("<dynamic>")
    persistent = any(
        re.search(pattern, path, re.I)
        for path in writes
        for pattern in (r"(?:^|/)(?:MEMORY|CLAUDE)\.md$", r"(?:^|/)\.claude/", r"(?:^|/)\.codex/")
    )
    return {
        "filesystem_read": reads,
        "filesystem_write": writes,
        "environment": environment,
        "process_commands": process_commands,
        "mcp_tools": mcp_tools,
        "persistent_state": persistent,
    }


def _filesystem_path_declared(path: str, declared: set[str]) -> bool:
    normalized = path.replace("\\", "/").removeprefix("./")
    if normalized in declared:
        return True
    if "workspace" in declared and not normalized.startswith(("/", "~", ".ssh/", ".aws/")):
        return True
    return any(
        item.endswith("/**") and normalized.startswith(item[:-3].rstrip("/") + "/")
        for item in declared
    )


def _capability_findings(
    manifest: object,
    *,
    path: str | None,
    domains: set[str],
    process_paths: set[str],
    process_commands: set[str],
    filesystem_reads: set[str],
    filesystem_writes: set[str],
    environment_names: set[str],
    mcp_tools: set[str],
    persistent_state: bool,
) -> tuple[bool, list[Finding]]:
    if path is None:
        return False, []
    validation_errors = _validate_capability_manifest(manifest)
    if validation_errors:
        return False, [
            _finding(
                "QINDUN.LOCAL.D7.CAPABILITY_MANIFEST",
                "high",
                "能力声明格式无效",
                "capabilities.json 必须完整遵循 qindun-capabilities/v1 字段类型",
                path,
                "; ".join(validation_errors[:10]),
                dimension="D7",
                disposition="candidate",
            )
        ]
    findings: list[Finding] = []
    network = manifest.get("network") if isinstance(manifest.get("network"), dict) else {}
    declared_domains = {str(value).lower() for value in network.get("domains") or []}
    undeclared = sorted(
        domain for domain in domains if not _domain_declared(domain, declared_domains)
    )
    if undeclared:
        findings.append(
            _finding(
                "QINDUN.LOCAL.D7.UNDECLARED_NETWORK",
                "medium",
                "发现未声明网络目标",
                "静态文本引用了能力声明中没有列出的网络目标",
                path,
                ", ".join(undeclared[:20]),
                dimension="D7",
                disposition="candidate",
            )
        )
    process = manifest.get("process") if isinstance(manifest.get("process"), dict) else {}
    if process_paths and not bool(process.get("spawn")):
        findings.append(
            _finding(
                "QINDUN.LOCAL.D7.UNDECLARED_PROCESS",
                "high",
                "发现未声明进程能力",
                "代码包含进程启动调用，但能力声明没有允许启动进程",
                path,
                ", ".join(sorted(process_paths)[:20]),
                dimension="D7",
                disposition="candidate",
            )
        )
    undeclared_commands = sorted(
        process_commands - set(process.get("commands") or []) - {"<dynamic>"}
    )
    if undeclared_commands:
        findings.append(
            _finding(
                "QINDUN.LOCAL.D7.UNDECLARED_PROCESS_COMMAND",
                "high",
                "发现未声明进程命令",
                "代码启动了能力声明没有列出的进程命令",
                path,
                ", ".join(undeclared_commands[:20]),
                dimension="D7",
                disposition="candidate",
            )
        )
    filesystem = manifest["filesystem"]
    declared_reads = set(filesystem["read"])
    declared_writes = set(filesystem["write"])
    undeclared_reads = sorted(
        value for value in filesystem_reads if not _filesystem_path_declared(value, declared_reads)
    )
    undeclared_writes = sorted(
        value
        for value in filesystem_writes
        if not _filesystem_path_declared(value, declared_writes)
    )
    for rule_id, severity, title, summary, values in (
        (
            "QINDUN.LOCAL.D7.UNDECLARED_FILESYSTEM_READ",
            "medium",
            "发现未声明文件读取",
            "代码读取了能力声明未允许的文件路径",
            undeclared_reads,
        ),
        (
            "QINDUN.LOCAL.D7.UNDECLARED_FILESYSTEM_WRITE",
            "high",
            "发现未声明文件写入",
            "代码写入了能力声明未允许的文件路径",
            undeclared_writes,
        ),
    ):
        if values:
            findings.append(
                _finding(
                    rule_id,
                    severity,
                    title,
                    summary,
                    path,
                    ", ".join(values[:20]),
                    dimension="D7",
                    disposition="candidate",
                )
            )
    declared_variables = set(manifest["environment"]["variables"])
    declared_secrets = set(manifest["environment"]["secrets"])
    declared_environment = declared_variables | declared_secrets
    undeclared_environment = sorted(environment_names - declared_environment)
    if undeclared_environment:
        findings.append(
            _finding(
                "QINDUN.LOCAL.D7.UNDECLARED_ENVIRONMENT",
                "high",
                "发现未声明环境变量",
                "代码读取了能力声明没有列出的环境变量",
                path,
                ", ".join(undeclared_environment[:20]),
                dimension="D7",
                disposition="candidate",
            )
        )
    misdeclared_secrets = sorted(
        name
        for name in environment_names
        if _sensitive_env_name(name) and name not in declared_secrets
    )
    if misdeclared_secrets:
        findings.append(
            _finding(
                "QINDUN.LOCAL.D7.MISDECLARED_ENVIRONMENT_SECRET",
                "high",
                "敏感环境变量未声明为密钥",
                "敏感环境变量必须列入 environment.secrets",
                path,
                ", ".join(misdeclared_secrets[:20]),
                dimension="D7",
                disposition="candidate",
            )
        )
    undeclared_tools = sorted(mcp_tools - set(manifest["mcp_tools"]))
    if undeclared_tools:
        findings.append(
            _finding(
                "QINDUN.LOCAL.D7.UNDECLARED_MCP_TOOL",
                "high",
                "发现未声明 MCP 工具",
                "作品引用了能力声明没有列出的 MCP 工具",
                path,
                ", ".join(undeclared_tools[:20]),
                dimension="D7",
                disposition="candidate",
            )
        )
    if persistent_state and not manifest["persistent_state"]:
        findings.append(
            _finding(
                "QINDUN.LOCAL.D7.UNDECLARED_PERSISTENT_STATE",
                "high",
                "发现未声明持久状态写入",
                "作品会写入跨会话状态，但能力声明未允许",
                path,
                "persistent state write",
                dimension="D7",
                disposition="candidate",
            )
        )
    return True, findings


def scan(
    target: Path,
    *,
    osv: bool = False,
    osv_api_url: str = DEFAULT_OSV_URL,
) -> dict:
    if not target.exists():
        raise ValueError("扫描目标不存在")
    if target.is_symlink():
        raise ValueError("扫描目标不能是符号链接")
    if not target.is_dir() and not target.is_file():
        raise ValueError("扫描目标必须是目录或 ZIP 文件")
    target_kind = "directory" if target.is_dir() else "zip"
    git_metadata_ignored = target_kind == "directory" and (target / ".git").exists()
    if target_kind == "zip" and target.stat().st_size > MAX_SOURCE_ARCHIVE_BYTES:
        raise ValueError("ZIP 原文件超过本地预检大小上限")
    source_sha256 = None if target.is_dir() else _file_sha256(target)
    entries = list(_directory_entries(target) if target.is_dir() else _zip_entries(target))
    instruction_entry_roles: dict[str, str] = {}
    entry_role_conflicts: set[str] = set()
    for entry in entries:
        if entry.data is None:
            continue
        name = PurePosixPath(entry.name).name
        instruction_text = _decode(entry.data)
        if instruction_text is not None and name in {
            "AGENTS.md",
            "CLAUDE.md",
            "SKILL.md",
        }:
            discovered_roles = _instruction_entrypoint_roles(entry.name, instruction_text)
            for entry_path, role in discovered_roles.items():
                if role == CONFLICTING_EXECUTABLE_ROLE or _merge_executable_role(
                    instruction_entry_roles,
                    entry_path,
                    role,
                ):
                    instruction_entry_roles[entry_path] = CONFLICTING_EXECUTABLE_ROLE
                    entry_role_conflicts.add(entry_path)
        if instruction_text is not None and name == "capabilities.json":
            try:
                preflight_capabilities = json.loads(instruction_text)
            except json.JSONDecodeError:
                continue
            discovered_roles = _capability_entrypoint_roles(
                entry.name,
                preflight_capabilities,
            )
            for entry_path, role in discovered_roles.items():
                if role == CONFLICTING_EXECUTABLE_ROLE or _merge_executable_role(
                    instruction_entry_roles,
                    entry_path,
                    role,
                ):
                    instruction_entry_roles[entry_path] = CONFLICTING_EXECUTABLE_ROLE
                    entry_role_conflicts.add(entry_path)
    findings: list[Finding] = []
    domains: set[str] = set()
    endpoints: set[str] = set()
    manifest_entries: list[dict] = []
    collision_paths: dict[str, str] = {}
    rule_counts: dict[str, int] = {}
    package_paths: set[str] = set()
    marker_texts: dict[str, str] = {}
    process_paths: set[str] = set()
    observed_process_commands: set[str] = set()
    capability_manifest: object = None
    capability_path: str | None = None
    capability_paths: list[str] = []
    file_roles: dict[str, str] = {}
    filesystem_reads: set[str] = set()
    filesystem_writes: set[str] = set()
    environment_names: set[str] = set()
    observed_mcp_tools: set[str] = set()
    persistent_state_observed = False
    dependency_files: list[tuple[str, bytes]] = []
    static_reasons: set[str] = set()
    structure_reasons: set[str] = set()
    for entry_path in entry_role_conflicts:
        static_reasons.add(f"入口解释器声明冲突：{entry_path}")
    statistics: dict[str, int | bool] = {
        "discovered_entries": 0,
        "text_files_scanned": 0,
        "structured_code_files": 0,
        "instruction_files": 0,
        "safety_context_files": 0,
        "trusted_internal_files": 0,
        "media_files_skipped": 0,
        "png_text_chunks_scanned": 0,
        "multimodal_files_uninspected": 0,
        "binary_files_uninspected": 0,
        "oversized_files_uninspected": 0,
        "nested_archives_uninspected": 0,
        "findings_truncated": False,
    }
    total_bytes = 0
    manifest_complete = True

    def add(item: Finding) -> None:
        if len(findings) >= MAX_FINDINGS:
            statistics["findings_truncated"] = True
            static_reasons.add("发现数量超过报告上限")
            return
        findings.append(item)

    def inspect_text(
        path: str,
        text: str,
        *,
        raw_data: bytes | None = None,
        primary_file: bool = True,
        mode: int = 0,
        forced_role: str | None = None,
    ) -> None:
        nonlocal capability_manifest, capability_path, persistent_state_observed
        if primary_file:
            statistics["text_files_scanned"] = int(statistics["text_files_scanned"]) + 1
        role, structured_findings, structure_error = _structured_code_findings(
            path,
            text,
            mode=mode,
            forced_role=forced_role or instruction_entry_roles.get(path),
        )
        if primary_file:
            file_roles[path] = role
            if role.removeprefix("safety_") in {
                "python",
                "shell",
                "powershell",
                "javascript",
                "unsupported_executable",
            }:
                statistics["structured_code_files"] = int(statistics["structured_code_files"]) + 1
                if role.startswith("safety_"):
                    statistics["safety_context_files"] = int(statistics["safety_context_files"]) + 1
            elif role == "instructions":
                statistics["instruction_files"] = int(statistics["instruction_files"]) + 1
            elif role == "safety_material":
                statistics["safety_context_files"] = int(statistics["safety_context_files"]) + 1
        if structure_error:
            add(
                _finding(
                    "QINDUN.LOCAL.D3.STRUCTURE_PARSE_FAILURE",
                    "medium",
                    "代码结构分析未完成",
                    "代码仍完成正则候选检查，但无法确认真实调用与数据流",
                    path,
                    structure_error,
                    dimension="D3",
                    disposition="candidate",
                )
            )
            static_reasons.add(structure_error)

        if primary_file:
            marker_name = PurePosixPath(path).name
            if marker_name in {
                "AGENTS.md",
                "CLAUDE.md",
                "SKILL.md",
                "chinmarket.yaml",
                "chinmarket.yml",
                "langgraph.json",
            }:
                marker_texts[path] = text
            if marker_name == "capabilities.json":
                capability_paths.append(path)
                capability_path = path
                try:
                    capability_manifest = json.loads(text)
                except json.JSONDecodeError:
                    capability_manifest = None
            if raw_data is not None and marker_name.casefold() in DEPENDENCY_FILES:
                dependency_files.append((path, raw_data))
            if PROCESS_PATTERN.search(text):
                process_paths.add(path)
            observed = _observe_capabilities(text)
            if observed["process_commands"]:
                process_paths.add(path)
            filesystem_reads.update(observed["filesystem_read"])
            filesystem_writes.update(observed["filesystem_write"])
            environment_names.update(observed["environment"])
            observed_mcp_tools.update(observed["mcp_tools"])
            observed_process_commands.update(observed["process_commands"])
            persistent_state_observed = bool(
                persistent_state_observed or observed["persistent_state"]
            )

        confirmed_rule_ids = {item.rule_id for item in structured_findings}
        for rule in RULES:
            for match in rule.pattern.finditer(text):
                if not _actionable_text_match(rule.rule_id, text, match.start(), match.end(), path):
                    continue
                if rule_counts.get(rule.rule_id, 0) >= MAX_FINDINGS_PER_RULE:
                    statistics["findings_truncated"] = True
                    static_reasons.add("单条规则命中数量超过报告上限")
                    break
                # A text pattern proves that review is needed, not that the text is
                # reachable or executable. Only the structure analyzers below may
                # promote deterministic evidence to confirmed.
                if rule.rule_id in confirmed_rule_ids:
                    continue
                match_line = _line(text, match.start())
                evidence, evidence_digest = _evidence(
                    match.group(0),
                    rule.dimension,
                    rule_id=rule.rule_id,
                    path=path,
                    line=match_line,
                )
                overrides = text_match_overrides(
                    rule.rule_id, text, match.start(), match.end(), path
                )
                add(
                    Finding(
                        rule.rule_id,
                        overrides.get("severity", rule.severity),
                        overrides.get("title", rule.title),
                        overrides.get("summary", rule.summary),
                        path,
                        match_line,
                        evidence,
                        evidence_digest,
                        rule.dimension,
                        rule.version,
                        "candidate",
                    )
                )
                rule_counts[rule.rule_id] = rule_counts.get(rule.rule_id, 0) + 1
        for item in structured_findings:
            add(item)
        for match in URL_PATTERN.finditer(text):
            try:
                host = urlsplit(match.group(0).rstrip(".,;")).hostname
            except ValueError:
                continue
            if host:
                domains.add(host.lower().rstrip("."))
        for match in SOCKET_ENDPOINT_PATTERN.finditer(text):
            host = match.group("host").lower().rstrip(".")
            port = int(match.group("port"))
            if 0 < port <= 65535:
                domains.add(host)
                endpoints.add(f"{host}:{port}")

    for entry in entries:
        statistics["discovered_entries"] = int(statistics["discovered_entries"]) + 1
        if entry.kind == "file_limit" or int(statistics["discovered_entries"]) > MAX_FILES:
            add(
                _finding(
                    "QINDUN.LOCAL.D2.FILE_COUNT",
                    "critical",
                    "文件数量超过本地预检限制",
                    "本地预检未继续读取超出数量上限的文件",
                    entry.name,
                    str(statistics["discovered_entries"]),
                    dimension="D2",
                )
            )
            structure_reasons.add("文件数量超过上限")
            static_reasons.add("文件数量超过上限")
            manifest_complete = False
            break
        total_bytes += max(entry.declared_size, 0)
        manifest_entries.append(
            {
                "name": entry.name,
                "kind": entry.kind,
                "size": entry.declared_size,
                "content_sha256": entry.content_sha256,
                "mode": entry.mode,
            }
        )
        if total_bytes > MAX_TOTAL_BYTES or entry.kind == "total_limit":
            add(
                _finding(
                    "QINDUN.LOCAL.D2.TOTAL_SIZE",
                    "critical",
                    "解包内容超过本地预检限制",
                    "本地预检停止读取超过总大小上限的内容",
                    entry.name,
                    str(total_bytes),
                    dimension="D2",
                )
            )
            structure_reasons.add("展开后总大小超过上限")
            static_reasons.add("展开后总大小超过上限")
            manifest_complete = False
            break
        if not _safe_relative(entry.name) or entry.kind == "unsafe_path":
            add(
                _finding(
                    "QINDUN.LOCAL.D2.PATH_TRAVERSAL",
                    "critical",
                    "发现不安全归档路径",
                    "路径可能逃逸目标目录或使用驱动器绝对路径",
                    entry.name,
                    entry.name,
                    dimension="D2",
                )
            )
            static_reasons.add(f"不安全路径：{entry.name}")
            manifest_complete = False
            continue
        package_paths.add(entry.name)
        collision_key = unicodedata.normalize("NFC", entry.name.replace("\\", "/")).casefold()
        previous = collision_paths.get(collision_key)
        if previous is not None:
            add(
                _finding(
                    "QINDUN.LOCAL.D2.PATH_COLLISION",
                    "critical",
                    "发现冲突归档路径",
                    "ZIP 中存在重复、大小写或 Unicode 规范化后冲突的路径",
                    entry.name,
                    f"{previous} <-> {entry.name}",
                    dimension="D2",
                )
            )
            static_reasons.add(f"冲突路径：{entry.name}")
            continue
        collision_paths[collision_key] = entry.name
        if entry.kind == "unsupported_path_separator":
            add(
                _finding(
                    "QINDUN.LOCAL.D2.UNSUPPORTED_PATH_SEPARATOR",
                    "medium",
                    "归档路径不兼容",
                    "ZIP 路径使用反斜杠分隔符，该条目内容未完成检查",
                    entry.name,
                    entry.name,
                    dimension="D2",
                    disposition="candidate",
                )
            )
            structure_reasons.add(f"不支持的路径分隔符：{entry.name}")
            static_reasons.add(f"不支持的路径分隔符：{entry.name}")
            manifest_complete = False
            continue
        if entry.kind in {"symlink", "special"}:
            add(
                _finding(
                    "QINDUN.LOCAL.D2.UNSAFE_FILE_TYPE",
                    "critical",
                    "发现非常规文件类型",
                    "作品包包含符号链接、设备文件或其他非常规文件",
                    entry.name,
                    entry.kind,
                    dimension="D2",
                )
            )
            static_reasons.add(f"非常规文件：{entry.name}")
            continue
        if entry.kind == "encrypted":
            add(
                _finding(
                    "QINDUN.LOCAL.D2.ENCRYPTED",
                    "critical",
                    "发现无法检查的加密 ZIP 条目",
                    "加密条目会阻止静态安全检查读取真实内容",
                    entry.name,
                    entry.name,
                    dimension="D2",
                )
            )
            static_reasons.add(f"加密条目：{entry.name}")
            manifest_complete = False
            continue
        if entry.kind == "compression_bomb":
            add(
                _finding(
                    "QINDUN.LOCAL.D2.COMPRESSION_RATIO",
                    "critical",
                    "ZIP 条目压缩比异常",
                    "为避免压缩炸弹消耗资源，本地预检拒绝展开该条目",
                    entry.name,
                    str(entry.declared_size),
                    dimension="D2",
                )
            )
            static_reasons.add(f"异常压缩比：{entry.name}")
            manifest_complete = False
            continue
        if entry.kind == "unstable":
            add(
                _finding(
                    "QINDUN.LOCAL.D2.FILE_SIZE",
                    "medium",
                    "文件读取期间发生变化",
                    "无法确认读取内容与属性检查时是同一个稳定普通文件",
                    entry.name,
                    entry.name,
                    dimension="D2",
                    disposition="candidate",
                )
            )
            structure_reasons.add(f"文件无法稳定读取：{entry.name}")
            static_reasons.add(f"文件无法稳定读取：{entry.name}")
            manifest_complete = False
            continue
        if entry.kind != "file":
            continue
        suffix = PurePosixPath(entry.name).suffix.lower()
        if entry.data is not None and entry.data.startswith(EXECUTABLE_MAGICS):
            add(
                _finding(
                    "QINDUN.LOCAL.D3.BINARY_EXECUTABLE",
                    "high",
                    "发现无法静态检查的二进制可执行文件",
                    "基础预检不能分析该原生可执行文件的真实行为",
                    entry.name,
                    entry.name,
                    dimension="D3",
                    disposition="candidate",
                )
            )
            statistics["binary_files_uninspected"] = int(statistics["binary_files_uninspected"]) + 1
            static_reasons.add(f"二进制可执行文件未分析：{entry.name}")
            continue
        if suffix in ARCHIVE_SUFFIXES:
            add(
                _finding(
                    "QINDUN.LOCAL.D2.NESTED_ARCHIVE",
                    "medium",
                    "发现嵌套压缩文件",
                    "本地预检不会递归扫描嵌套压缩文件",
                    entry.name,
                    entry.name,
                    dimension="D2",
                    disposition="candidate",
                )
            )
            statistics["nested_archives_uninspected"] = (
                int(statistics["nested_archives_uninspected"]) + 1
            )
            static_reasons.add(f"未递归扫描嵌套压缩文件：{entry.name}")
            continue
        if entry.data is None:
            add(
                _finding(
                    "QINDUN.LOCAL.D2.FILE_SIZE",
                    "medium",
                    "单文件超过文本检查限制",
                    "文件内容已计入精确摘要，但没有进入静态文本规则检查",
                    entry.name,
                    str(entry.declared_size),
                    dimension="D2",
                    disposition="candidate",
                )
            )
            statistics["oversized_files_uninspected"] = (
                int(statistics["oversized_files_uninspected"]) + 1
            )
            static_reasons.add(f"超大文件未做文本检查：{entry.name}")
            continue
        declared_role = instruction_entry_roles.get(entry.name)
        executable_hint = bool(entry.mode & 0o111) or declared_role is not None
        if entry.content_sha256 in TRUSTED_INTERNAL_DIGESTS:
            statistics["trusted_internal_files"] = int(statistics["trusted_internal_files"]) + 1
            continue
        if suffix in MULTIMODAL_SUFFIXES and not executable_hint:
            statistics["media_files_skipped"] = int(statistics["media_files_skipped"]) + 1
            statistics["multimodal_files_uninspected"] = (
                int(statistics["multimodal_files_uninspected"]) + 1
            )
            if suffix == ".png":
                png_texts, png_errors = _png_text_metadata(entry.data)
                statistics["png_text_chunks_scanned"] = int(
                    statistics["png_text_chunks_scanned"]
                ) + len(png_texts)
                if png_texts:
                    inspect_text(
                        entry.name,
                        "\n".join(png_texts),
                        primary_file=False,
                    )
                for error in png_errors:
                    add(
                        _finding(
                            "QINDUN.LOCAL.D2.PNG_METADATA",
                            "medium",
                            "PNG 文本元数据检查未完成",
                            "PNG 文本数据块损坏或超过本地检查资源上限",
                            entry.name,
                            error,
                            dimension="D2",
                            disposition="candidate",
                        )
                    )
            add(
                _finding(
                    "QINDUN.LOCAL.D2.UNINSPECTED_MULTIMODAL",
                    "medium",
                    "多模态内容未完整分析",
                    "静态预检已检查可读取的文件结构和 PNG 文本元数据，"
                    "但未解释图片像素、音视频内容或 PDF 行为",
                    entry.name,
                    entry.name,
                    dimension="D2",
                    disposition="candidate",
                )
            )
            static_reasons.add(f"多模态内容未完整分析：{entry.name}")
            continue
        if not executable_hint and (
            suffix in INERT_BINARY_SUFFIXES or PurePosixPath(entry.name).name in INERT_BINARY_NAMES
        ):
            statistics["media_files_skipped"] = int(statistics["media_files_skipped"]) + 1
            continue
        text = _decode(entry.data)
        if text is None:
            if entry.data.startswith(EXECUTABLE_MAGICS):
                add(
                    _finding(
                        "QINDUN.LOCAL.D3.BINARY_EXECUTABLE",
                        "high",
                        "发现无法静态检查的二进制可执行文件",
                        "基础预检不能分析该原生可执行文件的真实行为",
                        entry.name,
                        entry.name,
                        dimension="D3",
                        disposition="candidate",
                    )
                )
            statistics["binary_files_uninspected"] = int(statistics["binary_files_uninspected"]) + 1
            static_reasons.add(f"二进制文件未分析：{entry.name}")
            continue
        inspect_text(entry.name, text, raw_data=entry.data, mode=entry.mode)

    if len(capability_paths) > 1:
        capability_manifest = {
            "invalid": "multiple capability manifests",
            "paths": sorted(capability_paths),
        }
    inline_entrypoint = _capability_inline_entrypoint(capability_manifest)
    if inline_entrypoint is not None:
        inline_role, inline_code = inline_entrypoint
        inspect_text(
            f"{capability_path or 'capabilities.json'}#dynamic.entrypoint",
            inline_code,
            primary_file=False,
            forced_role=inline_role,
        )
    declared_entries: set[str] = set(instruction_entry_roles)
    for marker_path, marker_text in marker_texts.items():
        if PurePosixPath(marker_path).name not in {"chinmarket.yaml", "chinmarket.yml"}:
            continue
        entry_match = re.search(r"(?m)^entry\s*:\s*[\"']?([^\s#\"']+)[\"']?\s*$", marker_text)
        if entry_match and _safe_relative(entry_match.group(1)):
            declared_entries.add(
                (PurePosixPath(marker_path).parent / entry_match.group(1)).as_posix()
            )
    if isinstance(capability_manifest, dict):
        dynamic = capability_manifest.get("dynamic")
        if isinstance(dynamic, dict) and isinstance(dynamic.get("entrypoint"), list):
            working_directory = str(dynamic.get("working_directory") or ".")
            entrypoint_items = dynamic["entrypoint"]
            interpreter_role = None
            if entrypoint_items and isinstance(entrypoint_items[0], str):
                interpreter_role = INTERPRETER_ROLES.get(
                    PurePosixPath(entrypoint_items[0]).name.casefold()
                )
            possible_paths = (
                []
                if _capability_inline_entrypoint(capability_manifest) is not None
                else entrypoint_items[1:]
                if interpreter_role is not None
                else entrypoint_items[:1]
            )
            for item in possible_paths:
                if not isinstance(item, str):
                    continue
                candidate = (
                    PurePosixPath(working_directory) / item
                    if working_directory != "."
                    else PurePosixPath(item)
                ).as_posix()
                if _safe_relative(candidate):
                    declared_entries.add(candidate)
                    if interpreter_role is not None:
                        if _merge_executable_role(
                            instruction_entry_roles,
                            candidate,
                            interpreter_role,
                        ):
                            static_reasons.add(f"入口解释器声明冲突：{candidate}")
    for entry_path in sorted(declared_entries):
        role = file_roles.get(entry_path)
        if (
            role is None
            or role in {"data", "instructions", "safety_material"}
            or role.startswith("safety_")
        ):
            add(
                _finding(
                    "QINDUN.LOCAL.D3.UNSUPPORTED_ENTRYPOINT",
                    "high",
                    "作品入口无法完成结构分析",
                    "声明的作品入口缺失、伪装成数据文件或使用了无法确认的执行格式",
                    entry_path,
                    entry_path,
                    dimension="D3",
                    disposition="candidate",
                )
            )
            static_reasons.add(f"作品入口无法结构分析：{entry_path}")

    detected_profile, profile_findings = _structure_findings(package_paths, marker_texts)
    for item in profile_findings:
        add(item)
    capability_valid, declaration_findings = _capability_findings(
        capability_manifest,
        path=capability_path,
        domains=domains,
        process_paths=process_paths,
        process_commands=observed_process_commands,
        filesystem_reads=filesystem_reads,
        filesystem_writes=filesystem_writes,
        environment_names=environment_names,
        mcp_tools=observed_mcp_tools,
        persistent_state=persistent_state_observed,
    )
    for item in declaration_findings:
        add(item)
    network_analysis = [_network_profile(domain) for domain in sorted(domains)]
    for profile in network_analysis:
        if not profile["flags"]:
            continue
        add(
            _finding(
                "QINDUN.LOCAL.D6.NETWORK_REPUTATION",
                "high" if profile["risk"] == "high" else "medium",
                "发现需要复核的网络目标",
                "域名具有隐藏真实目标、临时解析或可疑收集端点等特征",
                "network-observation",
                f"{profile['domain']} ({', '.join(profile['flags'])})",
                dimension="D6",
                disposition="candidate",
            )
        )
    manifest_sha256 = _manifest_digest(manifest_entries, complete=manifest_complete)
    target_sha256 = manifest_sha256 if target_kind == "directory" else source_sha256
    target_digest_complete = manifest_complete if target_kind == "directory" else True
    dependency_inventory = extract(
        dependency_files,
        artifact_sha256=(
            target_sha256 if target_kind == "zip" and target_digest_complete else None
        ),
        content_manifest_sha256=(
            target_sha256 if target_kind == "directory" and target_digest_complete else None
        ),
    )
    for error in dependency_inventory["errors"]:
        add(
            _finding(
                "QINDUN.LOCAL.D4.INCOMPLETE_MANIFEST",
                "high",
                "依赖版本信息不完整",
                "依赖文件存在无法确认的版本或不支持的格式",
                error.split(":", 1)[0],
                error,
                dimension="D4",
                disposition="candidate",
            )
        )
    for script in dependency_inventory["install_scripts"]:
        add(
            _finding(
                "QINDUN.LOCAL.D4.INSTALL_SCRIPT",
                "high",
                "依赖安装阶段会执行脚本",
                "安装依赖时会自动执行作品提供的命令，需要在安装前审查真实用途",
                script["path"],
                f"{script['name']}: {script['command']}",
                dimension="D4",
                disposition="candidate",
            )
        )
    osv_result = (
        query_osv(dependency_inventory["packages"], api_url=osv_api_url)
        if osv
        else {
            "requested": False,
            "complete": False,
            "vulnerabilities": [],
            "error": None,
        }
    )
    for vulnerability in osv_result["vulnerabilities"]:
        dependency = vulnerability["dependency"]
        add(
            _finding(
                "QINDUN.D4.OSV_VULNERABILITY",
                "high",
                "依赖命中公开漏洞库",
                "精确依赖版本在 OSV 公开漏洞库中存在记录",
                "dependency-inventory",
                f"{dependency['ecosystem']}:{dependency['name']}@{dependency['version']} "
                f"{vulnerability['id']}",
                dimension="D4",
                disposition="candidate",
                rule_version="qindun-local-d4-v1",
            )
        )
    if bool(statistics["findings_truncated"]):
        static_reasons.add("报告命中记录已截断")
    structure_status = "partial" if structure_reasons else "completed"
    static_status = "partial" if static_reasons else "completed"
    dependency_status = (
        "not_applicable"
        if not dependency_inventory["manifests"]
        else "completed"
        if dependency_inventory["complete"]
        else "partial"
    )
    controls = [
        {"code": "D2.package_structure", "status": structure_status},
        {"code": "D3.malicious_static", "status": static_status},
        {"code": "D4.dependency_inventory", "status": dependency_status},
        {"code": "D5.secret_scan", "status": static_status},
        {"code": "D6.network_static", "status": static_status},
        {"code": "D7.prompt_static", "status": static_status},
    ]
    if osv:
        controls.append(
            {
                "code": "D4.supply_chain_vulnerability",
                "status": "completed" if osv_result["complete"] else "partial",
            }
        )
    coverage_complete = all(item["status"] in {"completed", "not_applicable"} for item in controls)
    dependency_reasons = set(dependency_inventory["errors"])
    if osv_result["error"]:
        dependency_reasons.add(str(osv_result["error"]))
    scan_status = "completed" if coverage_complete else "partial"
    grade = _local_grade(findings, coverage_complete=coverage_complete)
    return {
        "format": "qindun-local-report/v3",
        "official_certification": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": {"name": "qindun-certify", "version": SCANNER_VERSION},
        "rule_bundle": {
            "version": RULE_BUNDLE_VERSION,
            "digest": RULE_BUNDLE_DIGEST,
            "grade_policy": GRADE_POLICY["format"],
        },
        "target": {
            "name": target.name,
            "kind": target_kind,
            "sha256": target_sha256,
            "sha256_kind": "content_manifest" if target_kind == "directory" else "zip_file",
            "digest_complete": target_digest_complete,
            "content_manifest_sha256": manifest_sha256,
            "content_manifest_complete": manifest_complete,
            "file_count": int(statistics["discovered_entries"]),
            "expanded_bytes": total_bytes,
        },
        "scan_status": scan_status,
        "local_grade_preview": grade,
        "detected_profile": detected_profile,
        "capability_manifest": {
            "present": capability_path is not None,
            "valid": capability_valid if capability_path is not None else None,
            "path": capability_path,
        },
        "observed_capabilities": {
            "filesystem": {
                "read": sorted(filesystem_reads),
                "write": sorted(filesystem_writes),
            },
            "network_domains": sorted(domains),
            "process_paths": sorted(process_paths),
            "process_commands": sorted(observed_process_commands),
            "environment": sorted(environment_names),
            "mcp_tools": sorted(observed_mcp_tools),
            "persistent_state": persistent_state_observed,
        },
        "coverage": {
            "version": "qindun-local-coverage/v3",
            "complete": coverage_complete,
            "controls": controls,
            "incomplete_reasons": sorted(structure_reasons | static_reasons | dependency_reasons),
            "statistics": statistics,
            "not_covered": [
                "D1.platform_identity",
                *(["directory_git_metadata"] if git_metadata_ignored else []),
                *([] if osv else ["D4.supply_chain_vulnerability"]),
                "D6.network_semantic",
                "D7.semantic_consistency",
                "D8.isolated_execution",
                "advanced_dynamic",
                "manual_review",
                "platform_signature",
            ],
        },
        "observed_network_domains": sorted(domains),
        "observed_network_endpoints": sorted(endpoints),
        "network_analysis": network_analysis,
        "observed_process_paths": sorted(process_paths),
        "dependency_inventory": dependency_inventory,
        "osv_audit": {
            **osv_result,
            "provider": "OSV",
            "endpoint": osv_api_url if osv else None,
        },
        "semantic_review": {
            "status": "not_run",
            "affects_local_grade": False,
            "candidate_count": sum(1 for item in findings if item.disposition == "candidate"),
        },
        "findings": [asdict(item) for item in findings],
        "limitations": (
            "本地预检不执行目标代码；OSV 查询仅在明确启用时访问公开漏洞库；"
            "本地智能复核不直接定级，也不调用平台签名服务；"
            "正式等级以秦盾平台扫描为准。"
        ),
    }


def _markdown_text(value: object) -> str:
    rendered = (
        str(value)
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\\", "\\\\")
        .replace("`", "ˋ")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    for character in ("*", "_", "[", "]", "(", ")", "|", "#", "!"):
        rendered = rendered.replace(character, f"\\{character}")
    return rendered


def markdown(report: dict) -> str:
    grade = report["local_grade_preview"] or "未生成（扫描未完整）"
    status = "已完成" if report["scan_status"] == "completed" else "未完整"
    digest = report["target"]["sha256"] or "未生成"
    digest_kind = {
        "zip_file": "ZIP 原文件",
        "content_manifest": "目录内容清单",
    }[report["target"]["sha256_kind"]]
    profile_name = {
        "agent": "Agent（智能体）",
        "skill": "Skill（技能）",
        "workflow": "工作流",
        "unknown": "未识别",
    }[report["detected_profile"]]
    capability = report["capability_manifest"]
    capability_status = (
        "未随包提供"
        if not capability["present"]
        else "格式有效"
        if capability["valid"]
        else "格式无效"
    )
    lines = [
        "# 秦盾本地安全预检报告",
        "",
        "> 非官方认证：本报告不能替代秦盾平台认证或数字签名报告。",
        "",
        "## 扫描结论",
        "",
        f"- 本地等级提示：{grade}",
        f"- 扫描状态：{status}",
        f"- 扫描对象：{_markdown_text(report['target']['name'])}",
        f"- 识别类型：{profile_name}",
        f"- 能力声明：{capability_status}",
        f"- 精确摘要：`{digest}`（{digest_kind}）",
        f"- 扫描器版本：{report['scanner']['version']}",
        f"- 规则包版本：{report['rule_bundle']['version']}",
        f"- 文件数：{report['target']['file_count']}",
        f"- 发现数：{len(report['findings'])}",
        "",
        "## 检查覆盖范围",
        "",
        "| 检查项 | 状态 |",
        "| --- | --- |",
    ]
    source = report.get("source") or {}
    if source.get("kind") == "github":
        lines[lines.index("## 检查覆盖范围") : lines.index("## 检查覆盖范围")] = [
            f"- GitHub 来源：{_markdown_text(source.get('url'))}",
            f"- 实际提交：`{_markdown_text(source.get('resolved_commit'))}`",
            "",
        ]
    control_names = {
        "D2.package_structure": "包结构与解包安全（D2）",
        "D3.malicious_static": "恶意静态行为（D3）",
        "D4.dependency_inventory": "依赖清单（D4）",
        "D4.supply_chain_vulnerability": "公开漏洞库（D4）",
        "D5.secret_scan": "密钥与敏感信息（D5）",
        "D6.network_static": "网络目标（D6）",
        "D7.prompt_static": "提示词安全（D7）",
    }
    for control in report["coverage"]["controls"]:
        control_status = {
            "completed": "完整",
            "partial": "部分完成",
            "not_applicable": "不适用",
        }.get(control["status"], control["status"])
        lines.append(f"| {control_names[control['code']]} | {control_status} |")
    if report["coverage"]["incomplete_reasons"]:
        lines.extend(["", "未完整原因："])
        lines.extend(
            f"- {_markdown_text(reason)}" for reason in report["coverage"]["incomplete_reasons"]
        )
    lines.extend(["", "## 风险发现", ""])
    if not report["findings"]:
        lines.append("当前基础规则未发现中高风险问题；这不代表绝对安全。")
    severity_names = {
        "info": "提示",
        "low": "低",
        "medium": "中",
        "high": "高",
        "critical": "严重",
    }
    disposition_names = {"candidate": "需要复核", "confirmed": "已经确认"}
    for item in report["findings"]:
        location = (
            f"{_markdown_text(item['path'])}:{item['line']}"
            if item["line"]
            else _markdown_text(item["path"])
        )
        lines.extend(
            [
                f"- [{severity_names[item['severity']]}风险 · "
                f"{disposition_names[item['disposition']]}] {_markdown_text(item['title'])}",
                f"  - 位置：{location}",
                f"  - 规则：{item['rule_id']}",
                f"  - 证据：`{_markdown_text(item['evidence'])}`",
                f"  - 修复建议：{_markdown_text(item['remediation'])}",
                f"  - 参考：{_markdown_text(item['help_uri'])}",
            ]
        )
    external = report.get("external_scanners")
    if external:
        external_status_names = {
            "authorization_required": "等待允许源码披露",
            "completed": "已完成",
            "failed": "执行失败",
            "skipped": "已跳过",
            "unavailable": "未安装",
        }
        lines.extend(["", "## 外部扫描器候选证据", ""])
        lines.append(
            f"- 外部证据状态：{'已完成' if external['status'] == 'completed' else '部分完成'}"
        )
        lines.append(
            f"- 是否需要人工复核：{'是' if report.get('manual_review_required') else '否'}"
        )
        for scanner in external["scanners"]:
            lines.append(
                f"- {_markdown_text(scanner['id'])}："
                f"{external_status_names.get(scanner['status'], _markdown_text(scanner['status']))}，"
                f"候选发现 {scanner['finding_count']} 条"
            )
            if scanner.get("error"):
                lines.append(f"  - {_markdown_text(scanner['error'])}")
            for item in scanner.get("findings") or []:
                location = (
                    f"{_markdown_text(item['path'])}:{item['line']}"
                    if item.get("line")
                    else _markdown_text(item["path"])
                )
                lines.append(
                    f"  - [{severity_names[item['severity']]}风险 · 需要复核] "
                    f"{_markdown_text(item['title'])}（{item['dimension']}，{location}）"
                )
        lines.append(f"- 边界：{_markdown_text(external['limitations'])}")
    lines.extend(["", "## 观察到的网络目标", ""])
    network = report["observed_network_endpoints"] or report["observed_network_domains"]
    if network:
        lines.extend(f"- {_markdown_text(item)}" for item in network)
    else:
        lines.append("未从已检查文本中提取到明确网络目标。")
    lines.extend(["", "## 依赖清单", ""])
    dependencies = report["dependency_inventory"]["packages"]
    if dependencies:
        lines.extend(
            f"- {_markdown_text(item['ecosystem'])} · {_markdown_text(item['name'])} · "
            f"{_markdown_text(item['version'])}"
            for item in dependencies[:100]
        )
        if len(dependencies) > 100:
            lines.append(f"- 其余 {len(dependencies) - 100} 项见 JSON 报告中的软件物料清单。")
    else:
        lines.append("未发现受支持的依赖清单。")
    lines.append(f"- 软件物料清单摘要：`{report['dependency_inventory']['sbom_digest']}`")
    if report["osv_audit"]["requested"]:
        osv_status = "已完成" if report["osv_audit"]["complete"] else "未完整"
        lines.append(
            f"- OSV 公开漏洞库：{osv_status}，发现 "
            f"{len(report['osv_audit']['vulnerabilities'])} 条漏洞记录"
        )
    lines.extend(["", "## 能力边界", "", report["limitations"]])
    return "\n".join(lines) + "\n"


def html_report(report: dict) -> str:
    def escape(value: object) -> str:
        return html.escape(str(value), quote=True)

    grade = report["local_grade_preview"] or "—"
    grade_class = f"grade-{grade.lower()}" if grade in {"B", "C", "D"} else "grade-none"
    status = "扫描完整" if report["scan_status"] == "completed" else "扫描未完整"
    control_names = {
        "D2.package_structure": "包结构与解包安全",
        "D3.malicious_static": "恶意静态行为",
        "D4.dependency_inventory": "依赖清单",
        "D4.supply_chain_vulnerability": "公开漏洞库",
        "D5.secret_scan": "密钥与敏感信息",
        "D6.network_static": "网络目标",
        "D7.prompt_static": "提示词安全",
    }
    controls = "".join(
        "<div class='control'><span>"
        f"{escape(control_names.get(item['code'], item['code']))}</span>"
        f"<strong class='status-{escape(item['status'])}'>{escape({'completed': '完整', 'partial': '部分', 'not_applicable': '不适用'}.get(item['status'], item['status']))}</strong></div>"
        for item in report["coverage"]["controls"]
    )
    severity_names = {
        "info": "提示",
        "low": "低风险",
        "medium": "中风险",
        "high": "高风险",
        "critical": "严重风险",
    }
    findings = (
        "".join(
            "<article class='finding'>"
            f"<div><span class='severity severity-{escape(item['severity'])}'>{escape(severity_names[item['severity']])}</span>"
            f"<span class='disposition'>{'需要复核' if item['disposition'] == 'candidate' else '已经确认'}</span></div>"
            f"<h3>{escape(item['title'])}</h3>"
            f"<p>{escape(item['summary'])}</p>"
            f"<dl><dt>位置</dt><dd>{escape(item['path'])}{':' + escape(item['line']) if item['line'] else ''}</dd>"
            f"<dt>规则</dt><dd>{escape(item['rule_id'])}</dd>"
            f"<dt>证据</dt><dd>{escape(item['evidence'])}</dd>"
            f"<dt>修复</dt><dd>{escape(item['remediation'])}</dd>"
            f"<dt>参考</dt><dd><a href='{escape(item['help_uri'])}' rel='noreferrer'>{escape(item['help_uri'])}</a></dd></dl>"
            "</article>"
            for item in report["findings"]
        )
        or "<div class='empty'>当前基础规则未发现中高风险问题，但这不代表绝对安全。</div>"
    )
    network = (
        "".join(
            "<tr>"
            f"<td>{escape(item['domain'])}</td><td>{escape(item['category'])}</td>"
            f"<td>{escape({'low': '常规', 'medium': '注意', 'high': '需复核'}.get(item['risk'], item['risk']))}</td>"
            f"<td>{escape('、'.join(item['flags']) or '—')}</td></tr>"
            for item in report["network_analysis"]
        )
        or "<tr><td colspan='4' class='empty-cell'>未发现明确网络目标</td></tr>"
    )
    packages = report["dependency_inventory"]["packages"]
    dependencies = (
        "".join(
            "<tr>"
            f"<td>{escape(item['ecosystem'])}</td><td>{escape(item['name'])}</td>"
            f"<td>{escape(item['version'])}</td></tr>"
            for item in packages[:100]
        )
        or "<tr><td colspan='3' class='empty-cell'>未发现受支持的依赖清单</td></tr>"
    )
    dependency_note = (
        f"仅展示前 100 项，共 {len(packages)} 项。"
        if len(packages) > 100
        else f"共 {len(packages)} 项。"
    )
    reasons = "".join(
        f"<li>{escape(item)}</li>" for item in report["coverage"]["incomplete_reasons"]
    )
    source = report.get("source") or {}
    source_rows = ""
    if source.get("kind") == "github":
        reputation = source.get("reputation_evidence") or {}
        source_rows = (
            f"<dt>GitHub</dt><dd>{escape(source.get('url'))}</dd>"
            f"<dt>实际提交</dt><dd><code>{escape(source.get('resolved_commit'))}</code></dd>"
            f"<dt>公开来源</dt><dd>{escape('可用' if reputation.get('status') == 'available' else '暂不可用')}，不参与等级</dd>"
        )
    external = report.get("external_scanners")
    external_section = ""
    if external:
        external_status_names = {
            "authorization_required": "等待允许源码披露",
            "completed": "已完成",
            "failed": "执行失败",
            "skipped": "已跳过",
            "unavailable": "未安装",
        }
        scanner_rows = "".join(
            "<tr>"
            f"<td>{escape(item['id'])}</td>"
            f"<td>{escape(external_status_names.get(item['status'], item['status']))}</td>"
            f"<td>{escape(item['finding_count'])}</td>"
            f"<td>{escape(item.get('error') or '—')}</td>"
            "</tr>"
            for item in external["scanners"]
        )
        candidate_rows = (
            "".join(
                "<article class='finding'>"
                f"<div><span class='severity severity-{escape(item['severity'])}'>{escape(severity_names[item['severity']])}</span>"
                "<span class='disposition'>需要复核</span></div>"
                f"<h3>{escape(item['title'])}</h3>"
                f"<p>{escape(item['summary'])}</p>"
                f"<dl><dt>来源</dt><dd>{escape(item['source'])}</dd>"
                f"<dt>维度</dt><dd>{escape(item['dimension'])}</dd>"
                f"<dt>位置</dt><dd>{escape(item['path'])}{':' + escape(item['line']) if item.get('line') else ''}</dd></dl>"
                "</article>"
                for scanner in external["scanners"]
                for item in scanner.get("findings") or []
            )
            or "<div class='empty'>外部扫描器没有返回结构化候选发现。</div>"
        )
        external_section = (
            "<section class='panel'><h2>外部扫描器候选证据</h2>"
            "<table><thead><tr><th>扫描器</th><th>状态</th><th>候选数</th><th>说明</th></tr></thead>"
            f"<tbody>{scanner_rows}</tbody></table>{candidate_rows}"
            f"<p class='note'>{escape(external['limitations'])}</p></section>"
        )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>秦盾本地安全预检报告 · {escape(report["target"]["name"])}</title>
  <style>
    :root{{--ink:#172033;--muted:#697386;--line:#e3e8ef;--paper:#fff;--bg:#f3f6f9;--navy:#102a43;--blue:#1769e0;--green:#16794a;--amber:#a35d00;--red:#b42318}}
    *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}}
    .page{{max-width:1120px;margin:0 auto;padding:42px 24px 72px}} .hero{{display:grid;grid-template-columns:1fr auto;gap:28px;align-items:end;background:linear-gradient(135deg,#0d2238,#173f67);color:#fff;border-radius:22px;padding:34px 38px;box-shadow:0 18px 40px rgba(16,42,67,.16)}}
    .eyebrow{{font-size:12px;letter-spacing:.16em;color:#9fc5ef;font-weight:700}} h1{{font-size:30px;line-height:1.25;margin:8px 0 10px}} .subtitle{{color:#c7d7e7;margin:0}} .grade{{width:118px;height:118px;border-radius:28px;display:grid;place-items:center;font-size:50px;font-weight:800;border:1px solid rgba(255,255,255,.25);background:rgba(255,255,255,.1)}}
    .grade-b{{color:#7cf0b5}}.grade-c{{color:#ffd182}}.grade-d{{color:#ff9b94}}.grade-none{{color:#d3deea}} .meta{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}} .meta article,.panel{{background:var(--paper);border:1px solid var(--line);border-radius:16px;box-shadow:0 5px 18px rgba(31,50,73,.05)}} .meta article{{padding:18px}} .meta small{{display:block;color:var(--muted);margin-bottom:5px}} .meta strong{{font-size:16px;word-break:break-word}}
    .panel{{padding:26px 28px;margin-top:16px}} h2{{font-size:19px;margin:0 0 18px}} .controls{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}} .control{{display:flex;justify-content:space-between;gap:16px;padding:12px 14px;background:#f7f9fb;border-radius:10px}} .control strong{{font-size:13px}} .status-completed{{color:var(--green)}}.status-partial{{color:var(--amber)}}.status-not_applicable{{color:var(--muted)}}
    .finding{{padding:18px 0;border-top:1px solid var(--line)}}.finding:first-of-type{{border-top:0;padding-top:0}} .finding h3{{font-size:16px;margin:8px 0 3px}} .finding p{{color:var(--muted);margin:0 0 9px}} .severity,.disposition{{display:inline-flex;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;margin-right:7px}}.severity-medium{{background:#fff4d6;color:#825100}}.severity-high,.severity-critical{{background:#feeceb;color:var(--red)}}.severity-low,.severity-info{{background:#eaf7f0;color:var(--green)}}.disposition{{background:#edf2f7;color:#52606d}} dl{{display:grid;grid-template-columns:54px 1fr;gap:3px 10px;margin:0;font-size:13px}}dt{{color:var(--muted)}}dd{{margin:0;word-break:break-all}}
    table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}} th{{font-size:12px;color:var(--muted);background:#f7f9fb}} .empty,.empty-cell{{color:var(--muted);text-align:center;padding:28px}} .note{{color:var(--muted);font-size:13px;margin:10px 0 0}} .warning{{border-left:4px solid var(--amber);background:#fff9eb;padding:12px 16px;border-radius:8px}} code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}} footer{{color:var(--muted);font-size:12px;margin-top:18px;text-align:center}}
    @media(max-width:760px){{.hero{{grid-template-columns:1fr;padding:28px}}.grade{{width:86px;height:86px;font-size:38px}}.meta{{grid-template-columns:1fr 1fr}}.controls{{grid-template-columns:1fr}}.panel{{padding:22px 18px}}}}
    @media print{{body{{background:#fff}}.page{{max-width:none;padding:0}}.hero,.meta article,.panel{{box-shadow:none}}}}
  </style>
</head>
<body><main class="page">
  <section class="hero"><div><div class="eyebrow">QINDUN LOCAL PREFLIGHT</div><h1>秦盾本地安全预检报告</h1><p class="subtitle">非官方认证 · {escape(status)} · 结果严格绑定当前扫描对象摘要</p></div><div class="grade {grade_class}">{escape(grade)}</div></section>
  <section class="meta"><article><small>扫描对象</small><strong>{escape(report["target"]["name"])}</strong></article><article><small>作品类型</small><strong>{escape(report["detected_profile"])}</strong></article><article><small>文件数量</small><strong>{escape(report["target"]["file_count"])}</strong></article><article><small>风险发现</small><strong>{len(report["findings"])}</strong></article></section>
  <section class="panel"><h2>检查覆盖范围</h2><div class="controls">{controls}</div>{f'<div class="warning"><strong>未完整原因</strong><ul>{reasons}</ul></div>' if reasons else ""}</section>
  <section class="panel"><h2>风险发现</h2>{findings}</section>
  {external_section}
  <section class="panel"><h2>网络目标</h2><table><thead><tr><th>域名</th><th>类别</th><th>风险提示</th><th>特征</th></tr></thead><tbody>{network}</tbody></table></section>
  <section class="panel"><h2>依赖清单</h2><table><thead><tr><th>生态</th><th>名称</th><th>精确版本</th></tr></thead><tbody>{dependencies}</tbody></table><p class="note">{escape(dependency_note)} 软件物料清单摘要：<code>{escape(report["dependency_inventory"]["sbom_digest"])}</code></p></section>
  <section class="panel"><h2>对象与规则</h2><dl><dt>摘要</dt><dd><code>{escape(report["target"]["sha256"] or "未生成")}</code></dd><dt>扫描器</dt><dd>{escape(report["scanner"]["version"])}</dd><dt>规则包</dt><dd>{escape(report["rule_bundle"]["version"])}</dd>{source_rows}</dl></section>
  <section class="panel"><h2>能力边界</h2><p>{escape(report["limitations"])}</p></section>
  <footer>秦盾本地预检不会执行目标代码。本报告不是秦盾平台签名认证。</footer>
</main></body></html>"""


def _write_output(path: Path, output: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as destination:
            destination.write(output)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _validate_output_location(target: Path, output: Path) -> None:
    target_path = target.resolve()
    output_path = output.resolve(strict=False)
    if output_path == target_path or (target.is_dir() and target_path in output_path.parents):
        raise ValueError("报告输出不能覆盖扫描目标或写入目录扫描目标内部")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="秦盾本地安全预检（非官方认证）")
    parser.add_argument("target", type=Path, help="待检查目录或 ZIP 文件")
    parser.add_argument("--format", choices=("json", "markdown", "html"), default="markdown")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--osv",
        action="store_true",
        help="联网查询 OSV 公开漏洞库；默认只生成离线依赖清单",
    )
    parser.add_argument("--version", action="version", version=f"qindun-certify {SCANNER_VERSION}")
    args = parser.parse_args(argv)
    try:
        if args.output is not None:
            _validate_output_location(args.target, args.output)
        report = scan(args.target, osv=args.osv)
        if args.format == "json":
            output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        elif args.format == "html":
            output = html_report(report)
        else:
            output = markdown(report)
        if args.output:
            _write_output(args.output, output)
        else:
            sys.stdout.write(output)
    except (OSError, ValueError) as error:
        sys.stderr.write(f"秦盾预检失败：{error}\n")
        return EXIT_SCAN_ERROR
    if report["local_grade_preview"] in {"C", "D"}:
        return EXIT_RISK
    if report["scan_status"] != "completed":
        return EXIT_PARTIAL
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
