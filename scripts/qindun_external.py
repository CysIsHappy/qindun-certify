#!/usr/bin/env python3
"""Run explicitly selected third-party scanners and normalize candidate evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable


FORMAT = "qindun-external-evidence/v1"
POLICY_VERSION = "qindun-external-evidence-policy/v1"
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 200
MAX_TEXT = 2_000
DEFAULT_TIMEOUT_SECONDS = 600
MAX_TIMEOUT_SECONDS = 3_600
SKILL_ROOT = Path(__file__).parents[1]
TAXONOMY_MAP_FILE = SKILL_ROOT / "rules" / "external-taxonomy-map-v1.json"
TAXONOMY_MAP_DOCUMENT = json.loads(TAXONOMY_MAP_FILE.read_text(encoding="utf-8"))
if (
    TAXONOMY_MAP_DOCUMENT.get("format") != "qindun-external-taxonomy-map/v1"
    or set(TAXONOMY_MAP_DOCUMENT.get("mappings") or {}) != {f"T0{index}" for index in range(1, 10)}
):
    raise ValueError("秦盾外部分类映射文件无效")
TAXONOMY_MAP = {
    code: (
        value["primary_dimension"],
        list(value["related_dimensions"]),
    )
    for code, value in TAXONOMY_MAP_DOCUMENT["mappings"].items()
}

_POLICY_PAYLOAD = {
    "format": POLICY_VERSION,
    "authority": "candidate_only",
    "clean_result_can_raise_grade": False,
    "external_result_can_issue_d": False,
    "high_or_critical_grade_cap": "C",
    "score_aggregation": "forbidden",
    "taxonomy_map_digest": "sha256:"
    + hashlib.sha256(TAXONOMY_MAP_FILE.read_bytes()).hexdigest(),
}
POLICY_DIGEST = "sha256:" + hashlib.sha256(
    json.dumps(
        _POLICY_PAYLOAD,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()

_BASE_ENV = {
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
}
_AIG_ENV = {
    "LLM_API_KEY",
    "LLM_BASE_URL",
    "LLM_MODEL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
}
_SECRET_PATTERN = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|"
    r"(?i:(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
    r"\s*[:=]\s*[\"']?)[A-Za-z0-9_./+=-]{8,}"
)


def _clean_text(value: object, *, limit: int = MAX_TEXT) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return _SECRET_PATTERN.sub("[已脱敏]", text)[:limit]


def _severity(value: object, *, fallback: str = "medium") -> str:
    normalized = _clean_text(value).casefold().replace("-", "_").replace(" ", "_")
    if normalized in {"critical", "严重", "严重风险", "error_critical"}:
        return "critical"
    if normalized in {"high", "高", "高风险", "error", "malicious", "dangerous"}:
        return "high"
    if normalized in {"medium", "moderate", "中", "中风险", "warning", "suspicious"}:
        return "medium"
    if normalized in {"low", "低", "低风险", "note"}:
        return "low"
    if normalized in {"info", "informational", "提示", "none"}:
        return "info"
    return fallback


def _dimension(rule_id: str, text: str) -> tuple[str, list[str]]:
    taxonomy = re.search(r"(?i)(?:^|[^A-Z0-9])(T0[1-9])(?:[^A-Z0-9]|$)", rule_id)
    if taxonomy:
        primary, dimensions = TAXONOMY_MAP[taxonomy.group(1).upper()]
        return primary, dimensions
    haystack = f"{rule_id} {text}".casefold()
    if any(word in haystack for word in ("dependency", "package confusion", "supply chain", "vulnerab")):
        return "D4", ["D4"]
    if any(word in haystack for word in ("secret", "credential", "token", "private key", "password")):
        return "D5", ["D5"]
    if any(word in haystack for word in ("exfil", "network", "dns", "webhook", "callback")):
        return "D6", ["D6"]
    if any(word in haystack for word in ("prompt", "instruction", "memory", "tool hijack", "tool spoof")):
        return "D7", ["D7"]
    if any(word in haystack for word in ("archive", "path traversal", "symlink", "package structure")):
        return "D2", ["D2"]
    return "D3", ["D3"]


def _location(record: dict) -> tuple[str, int | None]:
    path = record.get("file") or record.get("path") or record.get("filename") or "."
    line = record.get("line") or record.get("line_start") or record.get("start_line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        line = None
    normalized_path = _clean_text(path, limit=500).replace("\\", "/") or "."
    if normalized_path.startswith("/") or re.match(r"^[A-Za-z]:/", normalized_path):
        normalized_path = normalized_path.rstrip("/").rsplit("/", 1)[-1] or "."
    if ".." in normalized_path.split("/"):
        normalized_path = normalized_path.rstrip("/").rsplit("/", 1)[-1] or "."
    return normalized_path, line


def _finding(scanner_id: str, record: dict, *, index: int) -> dict:
    raw_rule_id = (
        record.get("ruleId")
        or record.get("rule_id")
        or record.get("id")
        or record.get("code")
        or record.get("risk_type")
        or record.get("category")
        or f"finding-{index}"
    )
    raw_title = record.get("title") or record.get("name")
    message = record.get("message")
    if isinstance(message, dict):
        message = message.get("text") or message.get("markdown")
    summary = (
        record.get("description")
        or record.get("summary")
        or record.get("detail")
        or message
        or raw_title
        or "外部扫描器返回了需要复核的证据"
    )
    properties = record.get("properties") if isinstance(record.get("properties"), dict) else {}
    severity = _severity(
        record.get("severity")
        or properties.get("severity")
        or record.get("level")
        or record.get("risk")
        or record.get("risk_level")
    )
    rule_id = _clean_text(raw_rule_id, limit=200) or f"finding-{index}"
    dimension, dimensions = _dimension(rule_id, _clean_text(summary))
    path, line = _location(record)
    return {
        "external_rule_id": rule_id,
        "title": _clean_text(raw_title or message or rule_id, limit=500),
        "summary": _clean_text(summary),
        "severity": severity,
        "dimension": dimension,
        "related_dimensions": dimensions,
        "path": path,
        "line": line,
        "disposition": "candidate",
        "source": f"external:{scanner_id}",
        "deterministic": False,
    }


def _sarif_findings(scanner_id: str, document: dict) -> list[dict]:
    findings: list[dict] = []
    for run in document.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for record in run.get("results") or []:
            if not isinstance(record, dict):
                continue
            locations = record.get("locations") or []
            if locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation") or {}
                artifact = physical.get("artifactLocation") or {}
                region = physical.get("region") or {}
                record = {
                    **record,
                    "path": artifact.get("uri") or ".",
                    "line": region.get("startLine"),
                }
            findings.append(_finding(scanner_id, record, index=len(findings) + 1))
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings


_FINDING_KEYS = {
    "alerts",
    "filtered_findings",
    "findings",
    "issues",
    "results",
    "risks",
    "violations",
    "vulnerabilities",
}


def _candidate_records(value: object, *, depth: int = 0) -> list[dict]:
    if depth > 6:
        return []
    records: list[dict] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key.casefold() in _FINDING_KEYS and isinstance(child, list):
                records.extend(item for item in child if isinstance(item, dict))
            elif isinstance(child, (dict, list)):
                records.extend(_candidate_records(child, depth=depth + 1))
            if len(records) > MAX_FINDINGS:
                break
    elif isinstance(value, list):
        for child in value:
            records.extend(_candidate_records(child, depth=depth + 1))
            if len(records) > MAX_FINDINGS:
                break
    return records[: MAX_FINDINGS + 1]


def _verdict_values(value: object, *, depth: int = 0) -> list[str]:
    if depth > 5:
        return []
    values: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key.casefold() in {
                "approved",
                "classification",
                "decision",
                "recommendation",
                "risk",
                "status",
                "verdict",
            } and isinstance(child, (str, bool)):
                values.append(str(child))
            elif isinstance(child, (dict, list)):
                values.extend(_verdict_values(child, depth=depth + 1))
    elif isinstance(value, list):
        for child in value:
            values.extend(_verdict_values(child, depth=depth + 1))
    return values[:100]


def _normalize_document(scanner_id: str, document: dict) -> tuple[list[dict], str]:
    if document.get("version") == "2.1.0" and isinstance(document.get("runs"), list):
        findings = _sarif_findings(scanner_id, document)
    else:
        records = _candidate_records(document)
        findings = [
            _finding(scanner_id, record, index=index)
            for index, record in enumerate(records[:MAX_FINDINGS], start=1)
        ]
    normalized_verdicts = {
        _clean_text(value).casefold().replace("-", "_").replace(" ", "_")
        for value in _verdict_values(document)
    }
    risky = normalized_verdicts & {
        "block",
        "dangerous",
        "do_not_install",
        "false",
        "malicious",
        "reject",
        "suspicious",
        "unsafe",
    }
    clean = normalized_verdicts & {
        "allow",
        "approved",
        "clean",
        "normal",
        "pass",
        "safe",
        "true",
    }
    verdict = "risky" if risky else "clean" if clean and not findings else "unknown"
    if verdict == "risky" and not findings:
        findings.append(
            _finding(
                scanner_id,
                {
                    "rule_id": "EXTERNAL.VERDICT",
                    "title": "外部扫描器给出风险结论",
                    "summary": "外部结果包含风险或不建议安装结论，但没有提供可定位的结构化发现",
                    "severity": "high",
                    "path": ".",
                },
                index=1,
            )
        )
    return findings, verdict


def _tool_version(scanner_id: str, document: dict) -> str | None:
    if document.get("version") == "2.1.0":
        runs = document.get("runs") or []
        if runs and isinstance(runs[0], dict):
            driver = ((runs[0].get("tool") or {}).get("driver") or {})
            return _clean_text(driver.get("version"), limit=100) or None
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    for key in (f"{scanner_id}_version", "version", "scanner_version"):
        value = metadata.get(key) or document.get(key)
        if value:
            return _clean_text(value, limit=100)
    return None


def _read_report(path: Path) -> tuple[bytes, dict]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("外部扫描器报告必须是临时目录中的普通文件")
    size = path.stat().st_size
    if size <= 0:
        raise ValueError("外部扫描器生成了空报告")
    if size > MAX_REPORT_BYTES:
        raise ValueError("外部扫描器报告超过 16 MiB 上限")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("外部扫描器没有生成有效 JSON 报告") from error
    if not isinstance(value, dict):
        raise ValueError("外部扫描器报告必须是 JSON 对象")
    return raw, value


def _environment(scanner_id: str) -> dict[str, str]:
    allowed = set(_BASE_ENV)
    if scanner_id == "aig":
        allowed.update(_AIG_ENV)
    return {key: value for key, value in os.environ.items() if key in allowed}


def _command(
    scanner_id: str,
    target: Path,
    output: Path,
) -> tuple[list[str], bool, str | None]:
    if scanner_id == "aig":
        if not target.is_dir():
            return [], True, "AIG 只接受本地目录目标"
        return [
            "aig-skill-scan",
            "--repo",
            str(target),
            "--language",
            "zh",
            "--output",
            str(output),
        ], True, None
    if scanner_id == "skillspector":
        return [
            "skillspector",
            "scan",
            str(target),
            "--format",
            "json",
            "--output",
            str(output),
            "--no-llm",
        ], False, None
    if scanner_id == "cisco":
        return [
            "skill-scanner",
            "scan",
            str(target),
            "--format",
            "json",
            "--output",
            str(output),
        ], False, None
    raise ValueError(f"不支持的外部扫描器：{scanner_id}")


def _run_one(
    scanner_id: str,
    target: Path,
    *,
    allow_source_disclosure: bool,
    timeout_seconds: int,
    process_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
) -> dict:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=f"qindun-{scanner_id}-") as directory:
        workspace = Path(directory)
        report_path = workspace / "report.json"
        command, discloses_source, skipped_reason = _command(scanner_id, target, report_path)
        if skipped_reason:
            return {
                "id": scanner_id,
                "status": "skipped",
                "source_disclosure": discloses_source,
                "finding_count": 0,
                "findings": [],
                "error": skipped_reason,
                "duration_ms": 0,
            }
        if discloses_source and not allow_source_disclosure:
            return {
                "id": scanner_id,
                "status": "authorization_required",
                "source_disclosure": True,
                "finding_count": 0,
                "findings": [],
                "error": "该扫描器会把源码片段发送给配置的模型服务；请明确增加 --allow-source-disclosure",
                "duration_ms": 0,
            }
        if shutil.which(command[0]) is None:
            return {
                "id": scanner_id,
                "status": "unavailable",
                "source_disclosure": discloses_source,
                "finding_count": 0,
                "findings": [],
                "error": f"没有找到外部命令：{command[0]}",
                "duration_ms": 0,
            }
        try:
            process = process_factory(
                command,
                cwd=workspace,
                env=_environment(scanner_id),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
        except OSError as error:
            return {
                "id": scanner_id,
                "status": "failed",
                "source_disclosure": discloses_source,
                "finding_count": 0,
                "findings": [],
                "error": f"无法启动外部扫描器：{type(error).__name__}",
                "duration_ms": int((time.monotonic() - started) * 1_000),
            }
        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return {
                "id": scanner_id,
                "status": "failed",
                "source_disclosure": discloses_source,
                "finding_count": 0,
                "findings": [],
                "error": f"外部扫描超过 {timeout_seconds} 秒时限",
                "duration_ms": int((time.monotonic() - started) * 1_000),
            }
        try:
            raw, document = _read_report(report_path)
        except (OSError, ValueError) as error:
            return {
                "id": scanner_id,
                "status": "failed",
                "source_disclosure": discloses_source,
                "exit_code": exit_code,
                "finding_count": 0,
                "findings": [],
                "error": str(error),
                "duration_ms": int((time.monotonic() - started) * 1_000),
            }
        findings, verdict = _normalize_document(scanner_id, document)
        return {
            "id": scanner_id,
            "status": "completed",
            "source_disclosure": discloses_source,
            "exit_code": exit_code,
            "tool_version": _tool_version(scanner_id, document),
            "raw_report_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "verdict": verdict,
            "finding_count": len(findings),
            "findings_truncated": (
                sum(
                    len(run.get("results") or [])
                    for run in document.get("runs") or []
                    if isinstance(run, dict)
                )
                > MAX_FINDINGS
                if document.get("version") == "2.1.0"
                else len(_candidate_records(document)) > MAX_FINDINGS
            ),
            "findings": findings,
            "duration_ms": int((time.monotonic() - started) * 1_000),
        }


def run_scanners(
    target: Path,
    scanner_ids: list[str],
    *,
    allow_source_disclosure: bool = False,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    runner: Callable[..., dict] = _run_one,
) -> dict:
    if timeout_seconds < 1 or timeout_seconds > MAX_TIMEOUT_SECONDS:
        raise ValueError(f"外部扫描超时必须在 1-{MAX_TIMEOUT_SECONDS} 秒之间")
    requested = list(dict.fromkeys(scanner_ids))
    invalid = sorted(set(requested) - {"aig", "cisco", "skillspector"})
    if invalid:
        raise ValueError(f"不支持的外部扫描器：{', '.join(invalid)}")
    results = [
        runner(
            scanner_id,
            target,
            allow_source_disclosure=allow_source_disclosure,
            timeout_seconds=timeout_seconds,
        )
        for scanner_id in requested
    ]
    findings = [item for result in results for item in result.get("findings") or []]
    highest = next(
        (
            severity
            for severity in ("critical", "high", "medium", "low", "info")
            if any(item.get("severity") == severity for item in findings)
        ),
        None,
    )
    risky = [
        result["id"]
        for result in results
        if result.get("verdict") == "risky"
        or any(
            item.get("severity") in {"high", "critical"}
            for item in result.get("findings") or []
        )
    ]
    clean = [result["id"] for result in results if result.get("verdict") == "clean"]
    conflict = bool(risky and clean)
    complete = all(result.get("status") == "completed" for result in results)
    return {
        "format": FORMAT,
        "policy": {
            "version": POLICY_VERSION,
            "digest": POLICY_DIGEST,
            "authority": "candidate_only",
            "score_aggregation": "forbidden",
        },
        "status": "completed" if complete else "partial",
        "requested": requested,
        "scanners": results,
        "highest_candidate_severity": highest,
        "conflict_between_external_scanners": conflict,
        "manual_review_required": highest in {"high", "critical"} or conflict,
        "grade_cap": "C" if highest in {"high", "critical"} else None,
        "limitations": (
            "外部结果只作为候选证据；不参与分数平均，不能提高等级，也不能单独签发 D。"
        ),
    }


def merge_report(report: dict, evidence: dict) -> dict:
    report["external_scanners"] = evidence
    native_grade = report.get("local_grade_preview")
    external_cap = evidence.get("grade_cap")
    native_risky = native_grade in {"C", "D"}
    external_clean = any(
        item.get("verdict") == "clean" for item in evidence.get("scanners") or []
    )
    native_external_conflict = bool(native_risky and external_clean) or bool(
        native_grade == "B" and external_cap == "C"
    )
    evidence["conflict_with_qindun"] = native_external_conflict
    report["manual_review_required"] = bool(
        report.get("manual_review_required")
        or evidence.get("manual_review_required")
        or native_external_conflict
    )
    if native_grade == "B" and external_cap == "C":
        report["local_grade_preview"] = "C"
        report["grade_decision_reason"] = "外部扫描器给出高风险候选，按确定性冲突策略进入人工复核"
    if evidence.get("status") != "completed":
        report["limitations"] = (
            report.get("limitations", "")
            + " 已请求的外部扫描没有全部完成；秦盾原生覆盖率与等级仍单独有效。"
        ).strip()
    return report
