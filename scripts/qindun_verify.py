#!/usr/bin/env python3
"""Verify QinDun signed reports without access to any signing private key."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from qindun_trust import (
    DIRECTORY_FORMAT_V2,
    DIRECTORY_FORMAT_V3,
    canonical_json,
    normalize_directory,
    parse_timestamp,
    verify_root_signature,
    verify_trusted_key,
)


SECURITY_GRADES = {"S_PLUS", "S", "A_PLUS", "A", "B", "C", "D"}
SIGNED_FORMAT_V1 = "qindun-signed-report/v1"
SIGNED_FORMAT_V2 = "qindun-signed-report/v2"
PLATFORM_ENVELOPE_V2 = "qindun-report-envelope/v2"
V2_SIGNATURE_DOMAIN = b"QINDUN-SIGNED-REPORT-V2\x00"
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_JSON_BYTES = 8 * 1024 * 1024
V2_REQUIRED_FIELDS = {
    "format",
    "certification_no",
    "report",
    "report_digest",
    "signature_algorithm",
    "signing_key_id",
    "signature",
    "public_key",
}
V2_ALLOWED_FIELDS = V2_REQUIRED_FIELDS | {
    "revoked_at",
    "verification_status",
    "status_checked_at",
}
VERIFICATION_STATUSES = {
    "valid",
    "revoked",
    "expired",
    "unsigned_or_invalid",
    "untrusted_issuer",
    None,
}
RFC3339_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})"
)
GRADE_ORDER = {
    "D": 1,
    "C": 2,
    "B": 3,
    "A": 4,
    "A_PLUS": 5,
    "S": 6,
    "S_PLUS": 7,
}
CONTROL_MINIMUM_GRADES = {
    "D1.identity": "C",
    "D2.package_structure": "C",
    "D3.malicious_static": "C",
    "D5.secret_scan": "C",
    "D6.network_static": "B",
    "D7.declaration_static": "B",
    "D4.supply_chain": "A",
    "D6.domain_reputation": "A",
    "D6.network_semantic": "A_PLUS",
    "D7.declaration_semantic": "A_PLUS",
    "D8.isolated_execution": "S",
    "D8.adversarial_execution": "S_PLUS",
    "D8.independent_replay": "S_PLUS",
    "D1.enhanced_provenance": "S_PLUS",
}
EXECUTABLE_PROFILES = {
    "skill_instruction",
    "skill_with_scripts",
    "agent_runtime",
    "workflow_declarative",
    "workflow_executable",
    "code_heavy_package",
}
PLATFORM_ENVELOPE_FIELDS = {
    "format",
    "certification_no",
    "report",
    "report_digest",
    "signature_algorithm",
    "signing_key_id",
    "signature",
    "public_key",
    "signed_at",
    "expires_at",
    "revoked_at",
    "revocation_reason",
    "report_sequence",
    "previous_report_digest",
    "report_chain_digest",
    "verification_status",
    "status_checked_at",
}


def _report_timestamp(value: object, *, field: str) -> datetime:
    try:
        normalized = str(value or "")
        if normalized.endswith(("Z", "z")):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"{field} 必须是 ISO-8601 时间") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{field} 必须带时区")
    return parsed.astimezone(timezone.utc)


def _unwrap_api_data(value: Any) -> Any:
    if (
        isinstance(value, Mapping)
        and "format" not in value
        and isinstance(value.get("data"), Mapping)
    ):
        return value["data"]
    return value


def _normalize_bundle_input(value: Any) -> Mapping[str, Any]:
    value = _unwrap_api_data(value)
    if not isinstance(value, Mapping):
        raise ValueError("签名报告必须是 JSON 对象")
    if value.get("format") in {
        SIGNED_FORMAT_V1,
        SIGNED_FORMAT_V2,
        PLATFORM_ENVELOPE_V2,
    }:
        return dict(value)
    if isinstance(value.get("public_report"), Mapping):
        return {
            "format": SIGNED_FORMAT_V1,
            "certification_no": value.get("certification_no"),
            "report": value.get("public_report"),
            "report_digest": value.get("report_digest"),
            "signature_algorithm": value.get("signature_algorithm"),
            "signing_key_id": value.get("signing_key_id"),
            "signature": value.get("signature"),
            "public_key": value.get("public_key"),
            "revoked_at": value.get("revoked_at"),
            "verification_status": value.get("verification_status"),
            "status_checked_at": value.get("status_checked_at"),
        }
    return dict(value)


def _validate_v2_envelope_structure(bundle: Mapping[str, Any]) -> str | None:
    missing = V2_REQUIRED_FIELDS - set(bundle)
    if missing:
        return "v2 签名报告缺少必需字段"
    unknown = set(bundle) - V2_ALLOWED_FIELDS
    if unknown:
        return f"v2 签名报告包含未知字段：{', '.join(sorted(map(str, unknown)))}"
    certification_no = bundle.get("certification_no")
    if not isinstance(certification_no, str) or not certification_no:
        return "v2 认证编号必须是非空字符串"
    if not isinstance(bundle.get("report"), Mapping):
        return "v2 报告正文必须是对象"
    report_digest = bundle.get("report_digest")
    if not isinstance(report_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", report_digest
    ):
        return "v2 报告正文摘要格式无效"
    if bundle.get("signature_algorithm") != "Ed25519":
        return "v2 签名算法无效"
    signing_key_id = bundle.get("signing_key_id")
    if (
        not isinstance(signing_key_id, str)
        or not signing_key_id
        or len(signing_key_id) > 80
    ):
        return "v2 签名密钥编号必须是 1-80 个字符的字符串"
    signature = bundle.get("signature")
    if not isinstance(signature, str) or not re.fullmatch(
        r"[A-Za-z0-9+/]{86}==", signature
    ):
        return "v2 签名格式无效"
    public_key = bundle.get("public_key")
    if not isinstance(public_key, str) or not re.fullmatch(
        r"[A-Za-z0-9+/]{43}=", public_key
    ):
        return "v2 签发公钥格式无效"
    verification_status = bundle.get("verification_status")
    if verification_status is not None and (
        not isinstance(verification_status, str)
        or verification_status not in VERIFICATION_STATUSES
    ):
        return "v2 平台认证状态无效"
    for field in ("revoked_at", "status_checked_at"):
        value = bundle.get(field)
        if value is None:
            continue
        if not isinstance(value, str) or RFC3339_TIMESTAMP.fullmatch(value) is None:
            return f"v2 {field} 必须是带时区的时间字符串或空值"
        try:
            _report_timestamp(value, field=field)
        except ValueError as error:
            return str(error)
    return None


def _validate_platform_envelope_structure(bundle: Mapping[str, Any]) -> str | None:
    required = {
        "format",
        "report",
        "report_digest",
        "signature_algorithm",
        "signing_key_id",
        "signature",
        "public_key",
        "signed_at",
        "expires_at",
        "report_sequence",
        "previous_report_digest",
        "report_chain_digest",
    }
    missing = required - set(bundle)
    if missing:
        return "平台 v2 报告封装缺少必需字段"
    unknown = set(bundle) - PLATFORM_ENVELOPE_FIELDS
    if unknown:
        return f"平台 v2 报告封装包含未知字段：{', '.join(sorted(map(str, unknown)))}"
    if not isinstance(bundle.get("report"), Mapping):
        return "平台 v2 报告正文必须是对象"
    if bundle.get("signature_algorithm") != "Ed25519":
        return "平台 v2 签名算法无效"
    if not isinstance(bundle.get("signing_key_id"), str) or not str(
        bundle.get("signing_key_id") or ""
    ):
        return "平台 v2 签名密钥编号无效"
    if not isinstance(bundle.get("report_sequence"), int) or isinstance(
        bundle.get("report_sequence"), bool
    ) or int(bundle["report_sequence"]) < 1:
        return "平台 v2 报告序号无效"
    for field in ("report_digest", "previous_report_digest", "report_chain_digest"):
        value = bundle.get(field)
        if field == "previous_report_digest" and value is None:
            continue
        if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            return f"平台 v2 {field} 摘要格式无效"
    for field in ("signed_at", "expires_at"):
        value = bundle.get(field)
        if not isinstance(value, str) or RFC3339_TIMESTAMP.fullmatch(value) is None:
            return f"平台 v2 {field} 必须是带时区的时间字符串"
    return None


def _validate_policy_claims(report: Mapping[str, Any]) -> str | None:
    if report.get("grade_scheme_version") != "qindun-grade-v2":
        return "报告安全等级规则版本无效"
    plan = report.get("scan_plan")
    coverage = report.get("coverage")
    if not isinstance(plan, Mapping) or plan.get("version") != "qindun-scan-plan/v2":
        return "报告扫描计划版本无效"
    if not isinstance(coverage, Mapping) or coverage.get("version") != "qindun-coverage/v2":
        return "报告检查覆盖版本无效"
    expected_plan_digest = f"sha256:{hashlib.sha256(canonical_json(plan)).hexdigest()}"
    if report.get("scan_plan_digest") != expected_plan_digest:
        return "报告扫描计划摘要不一致"
    if plan.get("scan_mode") != report.get("scan_mode"):
        return "报告扫描计划与扫描模式不一致"
    if plan.get("assurance_profile") != report.get("assurance_profile"):
        return "报告扫描计划与保障方式不一致"
    if report.get("profile") is not None and plan.get("profile") != report.get("profile"):
        return "报告扫描计划与作品执行类型不一致"
    maximum_grade = plan.get("maximum_grade")
    claimed_grade = report.get("security_grade")
    if maximum_grade not in GRADE_ORDER:
        return "报告扫描计划最高等级无效"
    if claimed_grade != "D" and GRADE_ORDER[str(claimed_grade)] > GRADE_ORDER[str(maximum_grade)]:
        return "报告安全等级超过扫描计划上限"
    raw_plan_controls = plan.get("controls")
    raw_coverage_controls = coverage.get("controls")
    if not isinstance(raw_plan_controls, list) or not raw_plan_controls:
        return "报告扫描计划缺少控制项"
    if not isinstance(raw_coverage_controls, list):
        return "报告检查覆盖缺少控制项"
    plan_controls: dict[str, Mapping[str, Any]] = {}
    for item in raw_plan_controls:
        if not isinstance(item, Mapping):
            return "报告扫描计划控制项无效"
        code = item.get("code")
        if not isinstance(code, str) or not code or code in plan_controls:
            return "报告扫描计划控制项编号缺失或重复"
        if item.get("min_grade") not in {"C", "B", "A", "A_PLUS", "S", "S_PLUS"}:
            return f"报告扫描计划控制项最低等级无效：{code}"
        if not isinstance(item.get("required"), bool) or not isinstance(
            item.get("applicable"), bool
        ):
            return f"报告扫描计划控制项适用性无效：{code}"
        plan_controls[code] = item
    if set(plan_controls) != set(CONTROL_MINIMUM_GRADES):
        return "报告扫描计划控制项集合与规则版本不一致"
    for code, minimum_grade in CONTROL_MINIMUM_GRADES.items():
        item = plan_controls[code]
        if item.get("min_grade") != minimum_grade or item.get("dimension") != code.split(
            ".", 1
        )[0]:
            return f"报告扫描计划控制项策略不一致：{code}"
        if item.get("required") is not item.get("applicable"):
            return f"报告扫描计划控制项必做标记不一致：{code}"
    scan_mode = report.get("scan_mode")
    assurance = report.get("assurance_profile")
    executable = report.get("profile") in EXECUTABLE_PROFILES
    isolated_applicable = scan_mode == "dynamic" and executable
    enhanced_applicable = isolated_applicable and assurance == "enhanced"
    for code in (
        "D1.identity",
        "D2.package_structure",
        "D3.malicious_static",
        "D5.secret_scan",
        "D6.network_static",
        "D7.declaration_static",
        "D6.domain_reputation",
        "D6.network_semantic",
        "D7.declaration_semantic",
    ):
        if plan_controls[code].get("applicable") is not True:
            return f"报告扫描计划遗漏固定必做控制项：{code}"
    if plan_controls["D8.isolated_execution"].get("applicable") is not isolated_applicable:
        return "报告隔离执行控制项适用性与扫描模式不一致"
    for code in (
        "D8.adversarial_execution",
        "D8.independent_replay",
        "D1.enhanced_provenance",
    ):
        if plan_controls[code].get("applicable") is not enhanced_applicable:
            return f"报告高级动态控制项适用性与保障方式不一致：{code}"
    expected_maximum_grade = (
        "S_PLUS" if enhanced_applicable else "S" if isolated_applicable else "A_PLUS"
    )
    if maximum_grade != expected_maximum_grade:
        return "报告扫描计划最高等级与扫描模式不一致"
    coverage_controls: dict[str, Mapping[str, Any]] = {}
    for item in raw_coverage_controls:
        if not isinstance(item, Mapping):
            return "报告检查覆盖控制项无效"
        code = item.get("code")
        if not isinstance(code, str) or not code or code in coverage_controls:
            return "报告检查覆盖控制项编号缺失或重复"
        if code not in plan_controls:
            return f"报告检查覆盖包含计划外控制项：{code}"
        planned = plan_controls[code]
        for field in ("dimension", "min_grade", "required", "applicable"):
            if item.get(field) != planned.get(field):
                return f"报告检查覆盖与扫描计划不一致：{code}"
        status = item.get("status")
        if status not in {"passed", "failed", "partial", "missing", "not_applicable"}:
            return f"报告检查覆盖状态无效：{code}"
        if planned.get("applicable") is False and status != "not_applicable":
            return f"不适用控制项状态无效：{code}"
        if planned.get("applicable") is True and status == "not_applicable":
            return f"适用控制项被错误标记为不适用：{code}"
        evidence_digest = item.get("evidence_digest")
        if status in {"passed", "failed"} and (
            not isinstance(evidence_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", evidence_digest) is None
        ):
            return f"已完成控制项缺少证据摘要：{code}"
        coverage_controls[code] = item
    if set(coverage_controls) != set(plan_controls):
        return "报告检查覆盖没有完整对应扫描计划控制项"

    def completed(item: Mapping[str, Any]) -> bool:
        return item.get("status") in {"passed", "failed"} and isinstance(
            item.get("evidence_digest"), str
        )

    expected_complete = all(
        not bool(plan_item.get("applicable"))
        or not bool(plan_item.get("required"))
        or completed(coverage_controls[code])
        for code, plan_item in plan_controls.items()
    )
    if coverage.get("complete") is not expected_complete:
        return "报告检查覆盖完整状态与控制项证据不一致"
    if claimed_grade != "D":
        claimed_rank = GRADE_ORDER[str(claimed_grade)]
        required_for_grade = [
            code
            for code, item in plan_controls.items()
            if item.get("applicable") is True
            and GRADE_ORDER[str(item["min_grade"])] <= claimed_rank
        ]
        if not required_for_grade or any(
            not completed(coverage_controls[code]) for code in required_for_grade
        ):
            return "报告安全等级缺少对应的必做检查证据"
    identity = report.get("execution_identity")
    if not isinstance(identity, Mapping):
        return "报告缺少扫描器与安全策略身份"
    for field in ("security_policy_hash", "scanner_bundle_digest"):
        value = identity.get(field)
        if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            return f"报告扫描策略身份无效：{field}"
    return None


def _validate_report_structure(
    report: Mapping[str, Any], *, reference_time: datetime, strict_types: bool = False
) -> str | None:
    required = {
        "report_version",
        "certification_no",
        "subject",
        "security_grade",
        "coverage",
        "signed_at",
        "expires_at",
    }
    if not required.issubset(report):
        return "报告正文缺少必需字段"
    if report.get("report_version") != "qindun-report/v2":
        return "不支持的报告正文版本"
    certification_no = report.get("certification_no")
    if strict_types and (
        not isinstance(certification_no, str) or not certification_no
    ):
        return "v2 报告正文认证编号必须是非空字符串"
    if not strict_types and not str(certification_no or "").strip():
        return "报告正文缺少认证编号"
    security_grade = report.get("security_grade")
    if not isinstance(security_grade, str) or security_grade not in SECURITY_GRADES:
        return "报告安全等级无效"
    coverage = report.get("coverage")
    if not isinstance(coverage, Mapping) or not isinstance(coverage.get("complete"), bool):
        return "报告检查覆盖信息无效"
    grade = security_grade
    if grade != "D" and coverage.get("complete") is not True:
        return "D 以外的安全等级必须具有完整检查覆盖"
    if grade == "D":
        public_findings = report.get("public_findings")
        has_confirmed_critical = isinstance(public_findings, list) and any(
            isinstance(item, Mapping)
            and item.get("severity") == "critical"
            and item.get("disposition") == "confirmed"
            for item in public_findings
        )
        if not has_confirmed_critical:
            return "D 级报告缺少已确认的严重危险公开发现"
    if strict_types:
        public_findings = report.get("public_findings")
        if public_findings is not None:
            if not isinstance(public_findings, list):
                return "v2 公开风险发现必须是数组"
            for item in public_findings:
                if not isinstance(item, Mapping):
                    return "v2 公开风险发现条目必须是对象"
                severity = item.get("severity")
                if severity is not None and (
                    not isinstance(severity, str)
                    or severity
                    not in {"info", "low", "medium", "high", "critical"}
                ):
                    return "v2 公开风险程度无效"
                disposition = item.get("disposition")
                if disposition is not None and (
                    not isinstance(disposition, str)
                    or disposition not in {"candidate", "confirmed", "resolved"}
                ):
                    return "v2 公开风险处置状态无效"
    subject = report.get("subject")
    if not isinstance(subject, Mapping):
        return "报告绑定对象缺失"
    version_id = subject.get("artifact_bag_version_id")
    if not isinstance(version_id, int) or isinstance(version_id, bool) or version_id < 1:
        return "报告绑定的作品包版本无效"
    server_sha256_value = subject.get("server_sha256")
    if strict_types and not isinstance(server_sha256_value, str):
        return "v2 报告绑定的作品包摘要必须是字符串"
    server_sha256 = str(server_sha256_value or "")
    if not re.fullmatch(r"[0-9a-f]{64}", server_sha256):
        return "报告绑定的作品包摘要无效"
    if strict_types:
        for field in ("signed_at", "expires_at"):
            value = report.get(field)
            if not isinstance(value, str) or RFC3339_TIMESTAMP.fullmatch(value) is None:
                return f"v2 {field} 必须是带时区的时间字符串"
        if "scan_mode" in report:
            scan_mode = report.get("scan_mode")
            if not isinstance(scan_mode, str) or scan_mode not in {"basic", "dynamic"}:
                return "v2 扫描模式无效"
        if "assurance_profile" in report:
            assurance_profile = report.get("assurance_profile")
            if not isinstance(assurance_profile, str) or assurance_profile not in {
                "basic",
                "standard",
                "enhanced",
            }:
                return "v2 保障方式无效"
        approval = report.get("manual_approval")
        if approval is not None:
            if not isinstance(approval, Mapping):
                return "v2 人工复核记录必须是对象或空值"
            if "review_no" in approval and (
                not isinstance(approval.get("review_no"), str)
                or not approval.get("review_no")
            ):
                return "v2 人工复核编号必须是非空字符串"
            if "approved_grade" in approval and approval.get(
                "approved_grade"
            ) != "S_PLUS":
                return "v2 人工批准等级无效"
    try:
        signed_at = _report_timestamp(report.get("signed_at"), field="signed_at")
        expires_at = _report_timestamp(report.get("expires_at"), field="expires_at")
    except ValueError as error:
        return str(error)
    if signed_at > reference_time + MAX_CLOCK_SKEW:
        return "报告签发时间晚于当前时间"
    if expires_at <= signed_at:
        return "报告有效期必须晚于签发时间"
    if grade in {"S", "S_PLUS"} and report.get("scan_mode") != "dynamic":
        return "S 或 S+ 报告必须来自动态扫描"
    if grade == "S_PLUS":
        approval = report.get("manual_approval")
        if report.get("assurance_profile") != "enhanced":
            return "S+ 报告必须来自高级动态扫描"
        if (
            not isinstance(approval, Mapping)
            or not isinstance(approval.get("review_no"), str)
            or not approval["review_no"].strip()
            or approval.get("approved_grade") != "S_PLUS"
        ):
            return "S+ 报告缺少有效的人工复核记录"
        if coverage.get("complete") is not True:
            return "S+ 报告的检查覆盖必须完整"
    if strict_types:
        policy_error = _validate_policy_claims(report)
        if policy_error:
            return policy_error
    return None


def _ed25519_verify(public_key: bytes, signature: bytes, payload: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise RuntimeError(
            "验签需要 cryptography；请先运行 python3 -m pip install cryptography"
        ) from error
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (ValueError, InvalidSignature) as error:
        raise ValueError("Ed25519 签名无效") from error


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _v2_protected_payload(bundle: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "format": SIGNED_FORMAT_V2,
        "certification_no": bundle.get("certification_no"),
        "report": bundle.get("report"),
        "report_digest": bundle.get("report_digest"),
        "signature_algorithm": bundle.get("signature_algorithm"),
        "signing_key_id": bundle.get("signing_key_id"),
    }


def signature_payload(bundle: Mapping[str, Any]) -> tuple[bytes, str]:
    if bundle.get("format") == SIGNED_FORMAT_V2:
        return V2_SIGNATURE_DOMAIN + canonical_json(_v2_protected_payload(bundle)), "protected_v2"
    if bundle.get("format") == PLATFORM_ENVELOPE_V2:
        return canonical_json(bundle.get("report")), "platform_report_envelope_v2"
    return canonical_json(bundle.get("report")), "legacy_report_only"


def _result() -> dict[str, Any]:
    return {
        "valid": False,
        "integrity_valid": False,
        "signature_valid": False,
        "issuer_trusted": False,
        "key_in_directory": False,
        "trust_directory_pinned": False,
        "trust_directory_current": None,
        "trust_directory_sequence": None,
        "trust_directory_digest": None,
        "trust_anchor_type": None,
        "trust_status_as_of": None,
        "offline_snapshot_valid": False,
        "revocation_status": "unknown",
        "current_status_confirmed": False,
        "source_verification_status": None,
        "source_revoked_at": None,
        "source_status_checked_at": None,
        "target_matches": None,
        "trusted_certification_valid": False,
        "overall_status": "invalid",
        "signature_scope": None,
        "certification_no": None,
        "message": "报告无效",
    }


def verify_bundle(
    bundle: Mapping[str, Any],
    *,
    trusted_directory: Mapping[str, Any] | None = None,
    allow_embedded_key: bool = False,
    expected_trust_digest: str | None = None,
    allow_unpinned_trust_store: bool = False,
    trusted_root_public_key: str | None = None,
    minimum_trust_sequence: int | None = None,
    expected_previous_trust_digest: str | None = None,
    max_trust_age_days: int | None = None,
    target: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    result = _result()
    bundle_format = bundle.get("format")
    if not isinstance(bundle_format, str) or bundle_format not in {
        SIGNED_FORMAT_V1,
        SIGNED_FORMAT_V2,
        PLATFORM_ENVELOPE_V2,
    }:
        result["message"] = "不支持的秦盾签名报告格式"
        return result
    if bundle_format == SIGNED_FORMAT_V2:
        envelope_error = _validate_v2_envelope_structure(bundle)
        if envelope_error:
            result["message"] = envelope_error
            return result
    if bundle_format == PLATFORM_ENVELOPE_V2:
        envelope_error = _validate_platform_envelope_structure(bundle)
        if envelope_error:
            result["message"] = envelope_error
            return result
    result.update(
        source_verification_status=bundle.get("verification_status"),
        source_revoked_at=bundle.get("revoked_at"),
        source_status_checked_at=bundle.get("status_checked_at"),
    )
    if bundle.get("signature_algorithm") != "Ed25519":
        result["message"] = "签名算法缺失或不受支持"
        return result
    report = bundle.get("report")
    if not isinstance(report, Mapping):
        result["message"] = "报告正文缺失"
        return result
    reference_time = now or datetime.now(timezone.utc)
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)
    else:
        reference_time = reference_time.astimezone(timezone.utc)
    structure_error = _validate_report_structure(
        report,
        reference_time=reference_time,
        strict_types=bundle_format in {SIGNED_FORMAT_V2, PLATFORM_ENVELOPE_V2},
    )
    if structure_error:
        result["message"] = structure_error
        return result
    result["certification_no"] = report.get("certification_no")
    report_payload = canonical_json(report)
    expected_digest = f"sha256:{hashlib.sha256(report_payload).hexdigest()}"
    if bundle.get("report_digest") != expected_digest:
        result["message"] = "报告正文摘要不一致"
        return result
    envelope_certification_no = bundle.get("certification_no")
    if bundle_format == PLATFORM_ENVELOPE_V2 and envelope_certification_no in (None, ""):
        envelope_certification_no = report.get("certification_no")
    if envelope_certification_no != report.get("certification_no"):
        result["message"] = "认证编号不一致"
        return result
    try:
        public_key = base64.b64decode(str(bundle.get("public_key") or ""), validate=True)
        signature = base64.b64decode(str(bundle.get("signature") or ""), validate=True)
        if len(public_key) != 32 or len(signature) != 64:
            raise ValueError("签名材料长度无效")
        signed_payload, signature_scope = signature_payload(bundle)
        _ed25519_verify(public_key, signature, signed_payload)
    except RuntimeError:
        raise
    except ValueError as error:
        result["message"] = str(error)
        return result
    result.update(
        integrity_valid=True,
        signature_valid=True,
        signature_scope=signature_scope,
    )

    if bundle_format != PLATFORM_ENVELOPE_V2:
        source_status = str(bundle.get("verification_status") or "").strip().lower()
        if bundle.get("revoked_at") not in (None, "") or source_status == "revoked":
            result.update(
                revocation_status="revoked",
                overall_status="revoked",
                message="认证已经撤销",
            )
            return result
        if source_status in {"unsigned_or_invalid", "expired", "untrusted_issuer"}:
            result.update(
                overall_status="source_status_invalid",
                message="平台接口返回的认证状态无效",
            )
            return result
        if source_status == "valid":
            result["revocation_status"] = "not_revoked_at_source"
        elif source_status:
            result.update(
                overall_status="source_status_unknown",
                message="平台接口返回了不支持的认证状态",
            )
            return result
        if bundle.get("status_checked_at") not in (None, ""):
            try:
                status_checked_at = _report_timestamp(
                    bundle.get("status_checked_at"), field="status_checked_at"
                )
            except ValueError as error:
                result["message"] = str(error)
                return result
            if status_checked_at > reference_time + MAX_CLOCK_SKEW:
                result["message"] = "平台离线状态快照时间晚于当前时间"
                return result

    if trusted_directory is None:
        if not allow_embedded_key:
            result["message"] = "必须提供可信公钥目录"
            return result
        result.update(
            overall_status="integrity_only",
            message="签名完整性通过，但没有验证秦盾可信签发方",
        )
        return result

    if (
        expected_trust_digest is None
        and trusted_root_public_key is None
        and not allow_unpinned_trust_store
    ):
        result["message"] = (
            "可信公钥目录没有可信锚点；请固定目录摘要、提供根公钥，"
            "或明确接受未固定目录"
        )
        return result
    if trusted_root_public_key is not None and minimum_trust_sequence is None:
        result["message"] = "使用根公钥时必须提供可信目录最低序号以防止回退"
        return result
    if expected_trust_digest and not re.fullmatch(
        r"sha256:[0-9a-f]{64}", expected_trust_digest
    ):
        result["message"] = "固定的可信公钥目录摘要格式无效"
        return result
    if expected_previous_trust_digest and not re.fullmatch(
        r"sha256:[0-9a-f]{64}", expected_previous_trust_digest
    ):
        result["message"] = "上一版可信公钥目录摘要格式无效"
        return result
    if minimum_trust_sequence is not None and minimum_trust_sequence < 1:
        result["message"] = "可信公钥目录最低序号必须是正整数"
        return result
    if max_trust_age_days is not None and max_trust_age_days < 1:
        result["message"] = "可信公钥目录最大时效必须是正整数天"
        return result
    try:
        normalized = normalize_directory(trusted_directory)
        if trusted_root_public_key is not None:
            if normalized.get("format") != DIRECTORY_FORMAT_V3:
                raise ValueError("根公钥只用于统一的 v3 可信公钥目录")
            normalized = verify_root_signature(
                normalized,
                trusted_root_public_key=trusted_root_public_key,
            )
    except (RuntimeError, ValueError) as error:
        result["message"] = f"可信公钥目录无效：{error}"
        return result
    generated_at = parse_timestamp(normalized["generated_at"], field="generated_at")
    result["trust_directory_sequence"] = int(normalized["sequence"])
    result["trust_directory_digest"] = normalized["directory_digest"]
    result["trust_status_as_of"] = normalized["generated_at"]
    if generated_at > reference_time + MAX_CLOCK_SKEW:
        result["message"] = "可信公钥目录生成时间晚于当前时间"
        return result
    directory_current: bool | None = None
    if normalized.get("format") in {DIRECTORY_FORMAT_V2, DIRECTORY_FORMAT_V3}:
        directory_expiry = parse_timestamp(normalized.get("expires_at"), field="expires_at")
        directory_current = directory_expiry > reference_time
        result["trust_directory_current"] = directory_current
    if max_trust_age_days is not None:
        current = reference_time - generated_at <= timedelta(days=max_trust_age_days)
        directory_current = current if directory_current is None else directory_current and current
        result["trust_directory_current"] = directory_current
    if expected_trust_digest and normalized["directory_digest"] != expected_trust_digest:
        result["message"] = "可信公钥目录摘要与固定值不一致"
        return result
    if expected_previous_trust_digest and (
        normalized.get("previous_directory_digest") != expected_previous_trust_digest
    ):
        result["message"] = "可信公钥目录没有衔接指定的上一版摘要"
        return result
    if minimum_trust_sequence is not None and int(normalized["sequence"]) < minimum_trust_sequence:
        result["message"] = "可信公钥目录版本早于最低要求"
        return result
    trusted_key, message = verify_trusted_key(
        normalized,
        key_id=bundle.get("signing_key_id"),
        public_key=bundle.get("public_key"),
        signed_at=report.get("signed_at"),
    )
    if not trusted_key:
        result["message"] = message
        return result
    result["key_in_directory"] = True
    anchored_by_digest = expected_trust_digest is not None
    anchored_by_root = trusted_root_public_key is not None
    result["trust_directory_pinned"] = anchored_by_digest or anchored_by_root
    result["trust_anchor_type"] = (
        "root_public_key_and_digest"
        if anchored_by_digest and anchored_by_root
        else "root_public_key"
        if anchored_by_root
        else "directory_digest"
        if anchored_by_digest
        else None
    )
    if not (anchored_by_digest or anchored_by_root):
        result.update(
            overall_status="unpinned_trust_directory",
            message="签名完整性通过且公钥在用户接受的目录中，但目录未固定，不能证明秦盾签发身份",
        )
        return result
    result["issuer_trusted"] = True
    result["offline_snapshot_valid"] = True

    report_expiry = _report_timestamp(report.get("expires_at"), field="expires_at")
    if report_expiry <= reference_time:
        result.update(overall_status="expired", message="认证已经过期")
        return result
    if target is not None:
        if not target.is_file():
            result["message"] = "作品包比对只接受原始作品包文件"
            return result
        expected_target = str((report.get("subject") or {}).get("server_sha256") or "")
        result["target_matches"] = _file_sha256(target) == expected_target
        if not result["target_matches"]:
            result.update(overall_status="target_mismatch", message="本地作品包与报告绑定摘要不一致")
            return result

    if directory_current is False:
        result.update(
            overall_status="historical_signature_valid_stale_trust_directory",
            message="历史签名和签发方验证通过，但可信公钥目录已经过期或超过允许时效，不能确认认证当前有效",
        )
        return result

    if bundle_format == PLATFORM_ENVELOPE_V2:
        result.update(
            offline_snapshot_valid=False,
            revocation_status="unknown",
            overall_status="historical_platform_signature_valid_unsigned_status",
            message=(
                "报告历史签名与签发方验证通过，但单文件封装中的"
                "撤销和状态快照未受签名保护；必须验证完整企业离线包"
                "或在线查询当前状态"
            ),
        )
        return result

    result.update(
        valid=True,
        trusted_certification_valid=True,
        overall_status="trusted_valid_offline_snapshot",
        message="离线可信验证通过；状态只确认到离线快照时间，当前平台撤销状态未在线确认",
    )
    return result


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"JSON 包含重复字段：{key}")
        value[key] = item
    return value


def _read_json(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON 文件超过大小上限")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="离线验证秦盾平台签名报告")
    parser.add_argument("bundle", type=Path, help="平台导出的 .qindun.json 文件")
    trust = parser.add_mutually_exclusive_group(required=True)
    trust.add_argument("--trust-store", type=Path, help="秦盾可信公钥目录 JSON 文件")
    trust.add_argument(
        "--allow-embedded-key",
        action="store_true",
        help="只检查报告完整性；该模式不会返回可信认证有效",
    )
    parser.add_argument("--expected-trust-digest", help="固定可信公钥目录摘要")
    parser.add_argument(
        "--trusted-root-public-key-file",
        type=Path,
        help="通过独立可信渠道保存的秦盾 Ed25519 根公钥文件（仅适用于 v3 目录）",
    )
    parser.add_argument(
        "--accept-unpinned-trust-store",
        action="store_true",
        help="仅检查公钥是否在用户目录中；该模式不会返回可信认证有效",
    )
    parser.add_argument("--minimum-trust-sequence", type=int, help="可信目录最低序号")
    parser.add_argument("--expected-previous-trust-digest", help="要求目录衔接的上一版摘要")
    parser.add_argument("--max-trust-age-days", type=int, help="可信目录允许的最大生成天数")
    parser.add_argument("--target", type=Path, help="同时核对原始作品包文件 SHA-256")
    parser.add_argument("--json", action="store_true", help="输出结构化验证结果")
    args = parser.parse_args(argv)
    if args.trust_store and not (
        args.expected_trust_digest
        or args.trusted_root_public_key_file
        or args.accept_unpinned_trust_store
    ):
        parser.error(
            "--trust-store 必须同时固定目录摘要或根公钥，"
            "或明确使用 --accept-unpinned-trust-store"
        )
    if args.trusted_root_public_key_file and not args.trust_store:
        parser.error("--trusted-root-public-key-file 必须与 --trust-store 一起使用")
    if args.trusted_root_public_key_file and args.minimum_trust_sequence is None:
        parser.error("使用根公钥时必须提供 --minimum-trust-sequence 以防止目录回退")
    if args.allow_embedded_key and (
        args.expected_trust_digest
        or args.minimum_trust_sequence is not None
        or args.expected_previous_trust_digest
        or args.max_trust_age_days is not None
        or args.accept_unpinned_trust_store
        or args.trusted_root_public_key_file
    ):
        parser.error("仅检查报告内公钥时不能使用可信目录参数")
    try:
        bundle = _normalize_bundle_input(_read_json(args.bundle))
        trusted = None
        trusted_root_public_key = None
        if args.trust_store:
            trusted_value = _unwrap_api_data(_read_json(args.trust_store))
            if not isinstance(trusted_value, Mapping):
                raise ValueError("可信公钥目录必须是 JSON 对象")
            trusted = trusted_value
        if args.trusted_root_public_key_file:
            trusted_root_public_key = args.trusted_root_public_key_file.read_text(
                encoding="ascii"
            ).strip()
        result = verify_bundle(
            bundle,
            trusted_directory=trusted,
            allow_embedded_key=args.allow_embedded_key,
            expected_trust_digest=args.expected_trust_digest,
            allow_unpinned_trust_store=args.accept_unpinned_trust_store,
            trusted_root_public_key=trusted_root_public_key,
            minimum_trust_sequence=args.minimum_trust_sequence,
            expected_previous_trust_digest=args.expected_previous_trust_digest,
            max_trust_age_days=args.max_trust_age_days,
            target=args.target,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError, ValueError) as error:
        if args.json:
            print(json.dumps({"valid": False, "message": str(error)}, ensure_ascii=False))
        else:
            print(f"无法验证：{error}")
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(("验证通过：" if result["valid"] else "验证未通过：") + result["message"])
    return 0 if result["trusted_certification_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
