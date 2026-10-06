#!/usr/bin/env python3
"""Render a QinDun local report as SARIF 2.1.0."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import quote


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _uri(path: object) -> str:
    normalized = str(path or "unknown").replace("\\", "/").lstrip("/")
    return quote(normalized or "unknown", safe="/._-")


def _fingerprint(finding: dict) -> str:
    identity = "\x00".join(
        str(finding.get(field) or "")
        for field in ("rule_id", "path", "line", "evidence_digest")
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def render(report: dict) -> str:
    """Return a stable, source-relative SARIF document for one local report."""
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id") or "QINDUN.UNKNOWN")
        severity = str(finding.get("severity") or "medium")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": str(finding.get("title") or rule_id),
                "shortDescription": {
                    "text": str(finding.get("title") or "秦盾安全发现")
                },
                "fullDescription": {
                    "text": str(finding.get("summary") or "秦盾本地预检发现")
                },
                "help": {
                    "text": str(
                        finding.get("remediation")
                        or "根据秦盾证据修正问题后重新扫描。"
                    )
                },
                "helpUri": str(finding.get("help_uri") or "https://cwe.mitre.org/"),
                "defaultConfiguration": {"level": LEVELS.get(severity, "warning")},
                "properties": {
                    "dimension": finding.get("dimension"),
                    "ruleVersion": finding.get("rule_version"),
                    "disposition": finding.get("disposition"),
                    "tags": ["security", "qindun", str(finding.get("dimension") or "")],
                },
            },
        )
        location: dict = {
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(finding.get("path"))},
            }
        }
        line = finding.get("line")
        if isinstance(line, int) and line > 0:
            location["physicalLocation"]["region"] = {"startLine": line}
        results.append(
            {
                "ruleId": rule_id,
                "level": LEVELS.get(severity, "warning"),
                "kind": "fail" if finding.get("disposition") == "confirmed" else "review",
                "message": {
                    "text": str(finding.get("summary") or finding.get("title") or rule_id)
                },
                "locations": [location],
                "partialFingerprints": {
                    "qindunFinding/v1": _fingerprint(finding)
                },
                "properties": {
                    "severity": severity,
                    "dimension": finding.get("dimension"),
                    "disposition": finding.get("disposition"),
                    "evidence": finding.get("evidence"),
                    "remediation": finding.get("remediation"),
                    "helpUri": finding.get("help_uri"),
                    "deterministic": finding.get("deterministic"),
                },
            }
        )

    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    notifications = []
    if not coverage.get("complete", False):
        reasons = coverage.get("incomplete_reasons") or []
        notifications.append(
            {
                "level": "warning",
                "descriptor": {"id": "QINDUN.SCAN.PARTIAL"},
                "message": {
                    "text": "扫描覆盖不完整：" + "；".join(str(item) for item in reasons[:20])
                },
            }
        )

    scanner = report.get("scanner") if isinstance(report.get("scanner"), dict) else {}
    run = {
        "tool": {
            "driver": {
                "name": str(scanner.get("name") or "qindun-certify"),
                "version": str(scanner.get("version") or "unknown"),
                "rules": [rules[key] for key in sorted(rules)],
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": notifications,
                "properties": {
                    "officialCertification": False,
                    "scanStatus": report.get("scan_status"),
                    "localGradePreview": report.get("local_grade_preview"),
                    "coverageComplete": bool(coverage.get("complete")),
                    "targetSha256": (report.get("target") or {}).get("sha256"),
                    "ruleBundleDigest": (report.get("rule_bundle") or {}).get("digest"),
                },
            }
        ],
        "properties": {
            "qindunReportFormat": report.get("format"),
            "officialCertification": False,
        },
    }
    payload = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
