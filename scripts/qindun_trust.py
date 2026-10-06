#!/usr/bin/env python3
"""Portable QinDun public-key trust-directory validation."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping


try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - verification reports the missing dependency
    InvalidSignature = ValueError  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]


DIRECTORY_FORMAT_V1 = "qindun-trusted-key-directory/v1"
DIRECTORY_FORMAT_V2 = "qindun-trusted-key-directory/v2"
DIRECTORY_FORMAT_V3 = "qindun-trusted-key-directory/v3"
DIRECTORY_FORMAT = DIRECTORY_FORMAT_V3
DIRECTORY_FORMATS = {DIRECTORY_FORMAT_V1, DIRECTORY_FORMAT_V2, DIRECTORY_FORMAT_V3}
V3_ROOT_SIGNATURE_DOMAIN = b"QINDUN-TRUSTED-KEY-DIRECTORY-V3\x00"
KEY_STATUSES = {"active", "retired", "revoked"}
V2_DIRECTORY_FIELDS = {
    "format",
    "issuer",
    "sequence",
    "previous_directory_digest",
    "generated_at",
    "expires_at",
    "keys",
    "directory_digest",
}
V2_KEY_FIELDS = {
    "key_id",
    "public_key",
    "public_key_sha256",
    "status",
    "valid_from",
    "valid_until",
    "retired_at",
    "revoked_at",
    "reason",
}
V3_DIRECTORY_FIELDS = V2_DIRECTORY_FIELDS | {
    "root_signature_algorithm",
    "root_signature",
}
V3_KEY_FIELDS = V2_KEY_FIELDS


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def parse_timestamp(
    value: object, *, field: str, require_timezone: bool = False
) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"{field} 必须是 ISO-8601 时间") from error
    else:
        raise ValueError(f"{field} 必须是 ISO-8601 时间")
    if parsed.tzinfo is None and require_timezone:
        raise ValueError(f"{field} 必须带时区")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def optional_timestamp(
    value: object, *, field: str, require_timezone: bool = False
) -> datetime | None:
    return (
        None
        if value in (None, "")
        else parse_timestamp(value, field=field, require_timezone=require_timezone)
    )


def _format_timestamp(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _directory_core(directory: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "format": directory.get("format"),
        "issuer": directory.get("issuer"),
        "sequence": directory.get("sequence"),
        "previous_directory_digest": directory.get("previous_directory_digest"),
        "generated_at": directory.get("generated_at"),
        "expires_at": directory.get("expires_at"),
        "keys": directory.get("keys"),
    }


def directory_digest(directory: Mapping[str, Any]) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(_directory_core(directory))).hexdigest()}"


def root_signature_payload(directory: Mapping[str, Any]) -> bytes:
    core = _directory_core(directory)
    protected = {
        "directory": core,
        "directory_digest": directory_digest(core),
        "root_signature_algorithm": "Ed25519",
    }
    return V3_ROOT_SIGNATURE_DOMAIN + canonical_json(protected)


def normalize_directory(value: Mapping[str, Any]) -> dict[str, Any]:
    directory_format = str(value.get("format") or "")
    if directory_format not in DIRECTORY_FORMATS:
        raise ValueError("不支持的可信公钥目录格式")
    if directory_format in {DIRECTORY_FORMAT_V2, DIRECTORY_FORMAT_V3}:
        allowed_fields = (
            V3_DIRECTORY_FIELDS
            if directory_format == DIRECTORY_FORMAT_V3
            else V2_DIRECTORY_FIELDS
        )
        unknown_fields = [str(field) for field in value if field not in allowed_fields]
        if unknown_fields:
            version = "v3" if directory_format == DIRECTORY_FORMAT_V3 else "v2"
            raise ValueError(f"{version} 可信公钥目录包含未知字段：{unknown_fields[0]}")
    issuer = str(value.get("issuer") or "").strip()
    if not issuer:
        raise ValueError("可信公钥目录缺少签发方")
    generated_at = parse_timestamp(
        value.get("generated_at"),
        field="generated_at",
        require_timezone=directory_format in {DIRECTORY_FORMAT_V2, DIRECTORY_FORMAT_V3},
    )
    expires_at = optional_timestamp(
        value.get("expires_at"),
        field="expires_at",
        require_timezone=directory_format in {DIRECTORY_FORMAT_V2, DIRECTORY_FORMAT_V3},
    )
    if directory_format in {DIRECTORY_FORMAT_V2, DIRECTORY_FORMAT_V3} and expires_at is None:
        version = "v3" if directory_format == DIRECTORY_FORMAT_V3 else "v2"
        raise ValueError(f"{version} 可信公钥目录缺少 expires_at")
    if expires_at is not None and expires_at <= generated_at:
        raise ValueError("可信公钥目录有效期必须晚于生成时间")
    raw_sequence = 1 if "sequence" not in value else value.get("sequence")
    if isinstance(raw_sequence, bool):
        raise ValueError("可信公钥目录序号必须是正整数")
    if isinstance(raw_sequence, int):
        sequence = raw_sequence
    elif (
        directory_format == DIRECTORY_FORMAT_V1
        and isinstance(raw_sequence, str)
        and re.fullmatch(r"[1-9][0-9]*", raw_sequence.strip())
    ):
        sequence = int(raw_sequence)
    else:
        raise ValueError("可信公钥目录序号必须是正整数")
    if sequence < 1:
        raise ValueError("可信公钥目录序号必须是正整数")
    previous_digest = value.get("previous_directory_digest")
    if previous_digest not in (None, "") and not re.fullmatch(
        r"sha256:[0-9a-f]{64}", str(previous_digest)
    ):
        raise ValueError("上一版可信公钥目录摘要无效")
    raw_keys = value.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise ValueError("可信公钥目录至少需要一把公钥")

    keys: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_fingerprints: set[str] = set()
    for raw in raw_keys:
        if not isinstance(raw, Mapping):
            raise ValueError("可信公钥条目必须是对象")
        if directory_format in {DIRECTORY_FORMAT_V2, DIRECTORY_FORMAT_V3}:
            allowed_key_fields = (
                V3_KEY_FIELDS if directory_format == DIRECTORY_FORMAT_V3 else V2_KEY_FIELDS
            )
            unknown_fields = [str(field) for field in raw if field not in allowed_key_fields]
            if unknown_fields:
                version = "v3" if directory_format == DIRECTORY_FORMAT_V3 else "v2"
                raise ValueError(f"{version} 可信公钥条目包含未知字段：{unknown_fields[0]}")
        key_id = str(raw.get("key_id") or "").strip()
        if not key_id or len(key_id) > 80 or key_id in seen:
            raise ValueError("可信公钥编号缺失、重复或过长")
        seen.add(key_id)
        public_key = str(raw.get("public_key") or "").strip()
        try:
            public_raw = base64.b64decode(public_key, validate=True)
        except ValueError as error:
            raise ValueError(f"公钥不是有效 Base64：{key_id}") from error
        if len(public_raw) != 32:
            raise ValueError(f"Ed25519 公钥必须是 32 字节：{key_id}")
        status = str(raw.get("status") or "").strip()
        if status not in KEY_STATUSES:
            raise ValueError(f"公钥状态无效：{key_id}")
        require_key_timezone = directory_format in {
            DIRECTORY_FORMAT_V2,
            DIRECTORY_FORMAT_V3,
        }
        valid_from = optional_timestamp(
            raw.get("valid_from"), field="valid_from", require_timezone=require_key_timezone
        )
        valid_until = optional_timestamp(
            raw.get("valid_until"), field="valid_until", require_timezone=require_key_timezone
        )
        retired_at = optional_timestamp(
            raw.get("retired_at"), field="retired_at", require_timezone=require_key_timezone
        )
        revoked_at = optional_timestamp(
            raw.get("revoked_at"), field="revoked_at", require_timezone=require_key_timezone
        )
        if valid_from and valid_until and valid_until < valid_from:
            raise ValueError(f"公钥失效时间早于生效时间：{key_id}")
        if status == "active" and (retired_at is not None or revoked_at is not None):
            raise ValueError(f"有效公钥不能带停用或撤销时间：{key_id}")
        if status == "retired":
            if retired_at is None:
                raise ValueError(f"已停用公钥缺少停用时间：{key_id}")
            if revoked_at is not None:
                raise ValueError(f"已停用公钥不能带撤销时间：{key_id}")
        if status == "revoked" and revoked_at is None:
            raise ValueError(f"已撤销公钥缺少撤销时间：{key_id}")
        if valid_from and retired_at and retired_at < valid_from:
            raise ValueError(f"公钥停用时间早于生效时间：{key_id}")
        if valid_from and revoked_at and revoked_at < valid_from:
            raise ValueError(f"公钥撤销时间早于生效时间：{key_id}")
        if retired_at and revoked_at and revoked_at < retired_at:
            raise ValueError(f"公钥撤销时间早于停用时间：{key_id}")
        fingerprint = hashlib.sha256(public_raw).hexdigest()
        supplied_fingerprint = raw.get("public_key_sha256")
        if supplied_fingerprint not in (None, "") and supplied_fingerprint != fingerprint:
            raise ValueError(f"公钥指纹与公钥内容不一致：{key_id}")
        if fingerprint in seen_fingerprints:
            raise ValueError("可信公钥目录不能用多个编号重复登记同一公钥")
        seen_fingerprints.add(fingerprint)
        keys.append(
            {
                "key_id": key_id,
                "public_key": public_key,
                "public_key_sha256": fingerprint,
                "status": status,
                "valid_from": _format_timestamp(valid_from),
                "valid_until": _format_timestamp(valid_until),
                "retired_at": _format_timestamp(retired_at),
                "revoked_at": _format_timestamp(revoked_at),
                "reason": str(raw.get("reason") or "").strip() or None,
            }
        )
    directory = {
        "format": directory_format,
        "issuer": issuer,
        "sequence": sequence,
        "previous_directory_digest": previous_digest or None,
        "generated_at": _format_timestamp(generated_at),
        "keys": sorted(keys, key=lambda item: item["key_id"]),
    }
    if directory_format in {DIRECTORY_FORMAT_V2, DIRECTORY_FORMAT_V3}:
        directory["expires_at"] = _format_timestamp(expires_at)
    directory["directory_digest"] = directory_digest(directory)
    supplied_digest = value.get("directory_digest")
    if supplied_digest not in (None, "") and supplied_digest != directory["directory_digest"]:
        raise ValueError("可信公钥目录自身摘要不一致")
    if directory_format == DIRECTORY_FORMAT_V3:
        if supplied_digest in (None, ""):
            raise ValueError("v3 可信公钥目录缺少 directory_digest")
        if value.get("root_signature_algorithm") != "Ed25519":
            raise ValueError("v3 可信公钥目录缺少 Ed25519 根签名算法")
        root_signature = str(value.get("root_signature") or "")
        try:
            signature_raw = base64.b64decode(root_signature, validate=True)
        except ValueError as error:
            raise ValueError("v3 可信公钥目录根签名不是有效 Base64") from error
        if len(signature_raw) != 64:
            raise ValueError("v3 可信公钥目录根签名必须是 64 字节")
        directory["root_signature_algorithm"] = "Ed25519"
        directory["root_signature"] = root_signature
    return directory


def verify_root_signature(
    directory: Mapping[str, Any], *, trusted_root_public_key: str
) -> dict[str, Any]:
    normalized = normalize_directory(directory)
    if normalized["format"] != DIRECTORY_FORMAT_V3:
        raise ValueError("只有 v3 可信公钥目录支持统一根签名验证")
    if Ed25519PublicKey is None:
        raise RuntimeError("验证可信公钥目录根签名需要 cryptography")
    try:
        public_raw = base64.b64decode(trusted_root_public_key.strip(), validate=True)
        signature_raw = base64.b64decode(normalized["root_signature"], validate=True)
        if len(public_raw) != 32:
            raise ValueError("根公钥必须是 32 字节")
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature_raw,
            root_signature_payload(normalized),
        )
    except (ValueError, InvalidSignature) as error:
        raise ValueError("可信公钥目录根签名无效") from error
    return normalized


def verify_trusted_key(
    directory: Mapping[str, Any],
    *,
    key_id: object,
    public_key: object,
    signed_at: object,
) -> tuple[bool, str]:
    normalized = normalize_directory(directory)
    entry = next(
        (item for item in normalized["keys"] if item["key_id"] == str(key_id or "")),
        None,
    )
    if entry is None:
        return False, "签名公钥不在可信目录中"
    if entry["public_key"] != str(public_key or ""):
        return False, "报告内公钥与可信目录不一致"
    try:
        signed_time = parse_timestamp(signed_at, field="signed_at")
    except ValueError:
        return False, "报告签发时间缺失或无效"
    if normalized["format"] in {DIRECTORY_FORMAT_V2, DIRECTORY_FORMAT_V3}:
        generated_at = parse_timestamp(normalized["generated_at"], field="generated_at")
        expires_at = parse_timestamp(normalized["expires_at"], field="expires_at")
        if signed_time < generated_at:
            return False, "报告早于可信公钥目录生效时间"
        if signed_time > expires_at:
            return False, "报告晚于可信公钥目录有效时间"
    valid_from = optional_timestamp(entry.get("valid_from"), field="valid_from")
    valid_until = optional_timestamp(entry.get("valid_until"), field="valid_until")
    if valid_from and signed_time < valid_from:
        return False, "报告早于公钥生效时间"
    if valid_until and signed_time > valid_until:
        return False, "报告晚于公钥有效时间"
    if entry["status"] == "revoked":
        return False, "签名公钥已经撤销"
    if entry["status"] == "retired":
        retired_at = optional_timestamp(entry.get("retired_at"), field="retired_at")
        if retired_at is None or signed_time > retired_at:
            return False, "报告签发时公钥已经停用"
    return True, "签名有效且签发方可信"
