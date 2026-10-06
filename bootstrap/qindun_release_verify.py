#!/usr/bin/env python3
"""Independently verify and safely extract a signed QinDun release archive.

Distribute this bootstrap verifier and its digest through a channel independent
from the release archive. It deliberately imports no code from that archive.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile


RELEASE_SIGNATURE_DOMAIN = b"QINDUN-RELEASE-MANIFEST-V1\x00"
MAX_RELEASE_JSON_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_FILES = 20_000
MAX_ARCHIVE_FILE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000
SAFE_RELEASE_MODES = {"0644", "0755"}
ROOT_PREFIX = "qindun-certify/"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"发布 JSON 包含重复字段：{key}")
        value[key] = item
    return value


def _read_json(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > MAX_RELEASE_JSON_BYTES:
        raise ValueError(f"发布 JSON 超过大小上限：{path.name}")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"发布 JSON 无效：{path.name}") from error
    if not isinstance(value, dict):
        raise ValueError(f"发布 JSON 必须是对象：{path.name}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _require_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{label}字段集合无效")


def _expected_mode(relative: str) -> str:
    return "0755" if relative == "qindun" or relative.endswith(".py") else "0644"


def _validate_manifest(manifest: dict, archive_path: Path) -> dict[str, dict]:
    _require_keys(
        manifest,
        {"format", "skill_version", "source_commit", "archive", "files"},
        "发布清单",
    )
    if manifest.get("format") != "qindun-release-manifest/v1":
        raise ValueError("不支持的发布清单格式")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(manifest.get("skill_version") or "")):
        raise ValueError("发布清单版本号无效")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("source_commit") or "")):
        raise ValueError("发布清单缺少有效来源提交号")
    archive = manifest.get("archive")
    if not isinstance(archive, dict):
        raise ValueError("发布清单缺少归档信息")
    _require_keys(archive, {"name", "size", "sha256"}, "归档信息")
    if (
        archive.get("name") != archive_path.name
        or archive.get("size") != archive_path.stat().st_size
        or archive.get("sha256") != _sha256(archive_path)
    ):
        raise ValueError("原始 ZIP 与发布清单不一致")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_ARCHIVE_FILES:
        raise ValueError("发布清单文件列表无效")
    expected: dict[str, dict] = {}
    total = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("发布清单文件条目无效")
        _require_keys(entry, {"path", "size", "sha256", "mode"}, "发布文件条目")
        relative = str(entry.get("path") or "")
        pure = PurePosixPath(relative)
        if (
            not relative
            or pure.is_absolute()
            or ".." in pure.parts
            or "\\" in relative
            or relative in expected
        ):
            raise ValueError("发布清单包含不安全或重复路径")
        size = entry.get("size")
        digest = entry.get("sha256")
        mode = entry.get("mode")
        if not isinstance(size, int) or size < 0 or size > MAX_ARCHIVE_FILE_BYTES:
            raise ValueError(f"发布文件大小无效：{relative}")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"发布文件摘要无效：{relative}")
        if mode not in SAFE_RELEASE_MODES or mode != _expected_mode(relative):
            raise ValueError(f"发布文件权限无效：{relative}")
        total += size
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise ValueError("发布包展开总大小超过上限")
        expected[relative] = entry
    return expected


def _verify_signature(manifest: dict, signature: dict, expected_public_key: str) -> str:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise RuntimeError("验证发布签名需要 cryptography") from error
    _require_keys(
        signature,
        {
            "format",
            "signature_algorithm",
            "signing_key_id",
            "manifest_sha256",
            "public_key",
            "signature",
        },
        "发布签名",
    )
    if signature.get("format") != "qindun-release-signature/v1":
        raise ValueError("不支持的发布签名格式")
    if signature.get("signature_algorithm") != "Ed25519":
        raise ValueError("发布签名算法无效")
    key_id = str(signature.get("signing_key_id") or "").strip()
    if not key_id or len(key_id) > 80:
        raise ValueError("发布签名密钥编号无效")
    manifest_digest = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    if signature.get("manifest_sha256") != manifest_digest:
        raise ValueError("发布清单摘要不一致")
    embedded_public_key = str(signature.get("public_key") or "")
    if embedded_public_key != expected_public_key.strip():
        raise ValueError("发布签名公钥与固定公钥不一致")
    try:
        public_raw = base64.b64decode(embedded_public_key, validate=True)
        signature_raw = base64.b64decode(str(signature.get("signature") or ""), validate=True)
        if len(public_raw) != 32 or len(signature_raw) != 64:
            raise ValueError("发布签名材料长度无效")
        protected = {
            "format": signature["format"],
            "signature_algorithm": signature["signature_algorithm"],
            "signing_key_id": key_id,
            "manifest_sha256": manifest_digest,
            "public_key": embedded_public_key,
            "manifest": manifest,
        }
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature_raw,
            RELEASE_SIGNATURE_DOMAIN + _canonical_json(protected),
        )
    except (ValueError, InvalidSignature) as error:
        raise ValueError("发布清单签名无效") from error
    return hashlib.sha256(public_raw).hexdigest()


def _archive_members(archive_path: Path, expected: dict[str, dict]) -> dict[str, object]:
    try:
        archive = ZipFile(archive_path)
    except (BadZipFile, OSError) as error:
        raise ValueError("发布归档不是有效 ZIP") from error
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_FILES:
            raise ValueError("发布归档文件数量无效")
        members: dict[str, object] = {}
        total = 0
        for info in infos:
            if info.is_dir():
                raise ValueError("发布归档不接受目录占位条目")
            name = info.filename
            if not name.startswith(ROOT_PREFIX):
                raise ValueError("发布归档必须只有 qindun-certify 根目录")
            relative = name[len(ROOT_PREFIX) :]
            pure = PurePosixPath(relative)
            if (
                not relative
                or pure.is_absolute()
                or ".." in pure.parts
                or "\\" in relative
                or relative in members
            ):
                raise ValueError("发布归档包含不安全或重复路径")
            if info.flag_bits & 0x1:
                raise ValueError(f"发布归档不接受加密文件：{relative}")
            entry = expected.get(relative)
            if entry is None:
                raise ValueError(f"发布归档包含清单外文件：{relative}")
            mode_value = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode_value)
            if file_type not in {0, stat.S_IFREG}:
                raise ValueError(f"发布归档包含非普通文件：{relative}")
            actual_mode = f"{stat.S_IMODE(mode_value):04o}"
            if actual_mode != entry["mode"]:
                raise ValueError(f"发布归档文件权限与清单不一致：{relative}")
            if info.file_size != entry["size"] or info.file_size > MAX_ARCHIVE_FILE_BYTES:
                raise ValueError(f"发布归档文件大小与清单不一致：{relative}")
            if info.compress_size == 0 and info.file_size > 0:
                raise ValueError(f"发布归档压缩信息无效：{relative}")
            if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise ValueError(f"发布归档文件压缩比超过上限：{relative}")
            total += info.file_size
            if total > MAX_ARCHIVE_TOTAL_BYTES:
                raise ValueError("发布归档展开总大小超过上限")
            digest = hashlib.sha256()
            read_total = 0
            try:
                with archive.open(info, "r") as source:
                    while chunk := source.read(1024 * 1024):
                        read_total += len(chunk)
                        if read_total > entry["size"]:
                            raise ValueError(f"发布归档文件读取超限：{relative}")
                        digest.update(chunk)
            except (BadZipFile, RuntimeError, OSError) as error:
                raise ValueError(f"发布归档文件读取失败：{relative}") from error
            if read_total != entry["size"] or digest.hexdigest() != entry["sha256"]:
                raise ValueError(f"发布归档文件摘要与清单不一致：{relative}")
            members[relative] = info
        if set(members) != set(expected):
            raise ValueError("发布归档缺少清单声明文件")
        return members


def verify_release(
    archive_path: Path,
    *,
    manifest_path: Path,
    signature_path: Path,
    public_key_path: Path,
) -> tuple[dict, dict[str, object], str]:
    archive_path = archive_path.expanduser().resolve(strict=True)
    manifest = _read_json(manifest_path.expanduser().resolve(strict=True))
    signature = _read_json(signature_path.expanduser().resolve(strict=True))
    expected_public_key = public_key_path.expanduser().resolve(strict=True).read_text(
        encoding="utf-8"
    )
    expected = _validate_manifest(manifest, archive_path)
    key_fingerprint = _verify_signature(manifest, signature, expected_public_key)
    members = _archive_members(archive_path, expected)
    return manifest, members, key_fingerprint


def extract_verified(
    archive_path: Path,
    destination: Path,
    members: dict[str, object],
    manifest: dict,
) -> Path:
    expected = _validate_manifest(manifest, archive_path)
    current_members = _archive_members(archive_path, expected)
    if set(current_members) != set(members):
        raise ValueError("发布归档在验证后发生变化")
    members = current_members
    destination = destination.expanduser().resolve()
    if destination.exists():
        raise ValueError(f"解压目标已存在：{destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".qindun-verified-", dir=destination.parent))
    root = temporary / "qindun-certify"
    root.mkdir()
    entries = {str(item["path"]): item for item in manifest["files"]}
    try:
        with ZipFile(archive_path) as archive:
            for relative in sorted(members):
                target = root.joinpath(*PurePosixPath(relative).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(members[relative], "r") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                if (
                    target.stat().st_size != entries[relative]["size"]
                    or _sha256(target) != entries[relative]["sha256"]
                ):
                    raise ValueError(f"解压文件与发布清单不一致：{relative}")
                target.chmod(int(entries[relative]["mode"], 8))
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination / "qindun-certify"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="独立验证秦盾正式发布 ZIP，并可在验证后安全解压"
    )
    parser.add_argument("archive", type=Path, help="原始秦盾发布 ZIP")
    parser.add_argument("--manifest", type=Path, required=True, help="发布清单 JSON")
    parser.add_argument("--signature", type=Path, required=True, help="发布签名 JSON")
    parser.add_argument(
        "--public-key-file", type=Path, required=True, help="通过独立可信渠道固定的发布公钥"
    )
    parser.add_argument("--extract-to", type=Path, help="验证后安全解压到尚不存在的目录")
    args = parser.parse_args(argv)
    try:
        manifest, members, fingerprint = verify_release(
            args.archive,
            manifest_path=args.manifest,
            signature_path=args.signature,
            public_key_path=args.public_key_file,
        )
        extracted = (
            extract_verified(args.archive, args.extract_to, members, manifest)
            if args.extract_to
            else None
        )
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(3, f"秦盾发布验证失败：{error}\n")
    print("秦盾正式发布签名和原始 ZIP 验证通过")
    print(f"版本：{manifest['skill_version']}")
    print(f"来源提交：{manifest['source_commit']}")
    print(f"发布公钥指纹（SHA-256）：{fingerprint}")
    if extracted:
        print(f"已安全解压到：{extracted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
