#!/usr/bin/env python3
"""Install QinDun into a SKILL.md-compatible local skills directory."""

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
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).parents[1]
EXCLUDED_NAMES = {
    "__pycache__",
    "bootstrap",
    "dist",
    "tests",
    "package_release.py",
}
RELEASE_SIGNATURE_DOMAIN = b"QINDUN-RELEASE-MANIFEST-V1\x00"
MAX_RELEASE_JSON_BYTES = 8 * 1024 * 1024
SAFE_RELEASE_MODES = {"0644", "0755"}


def _default_root(platform: str) -> Path:
    return Path.home() / (".codex/skills" if platform == "codex" else ".claude/skills")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_release_mode(relative: str) -> str:
    return "0755" if relative == "qindun" or relative.endswith(".py") else "0644"


def _validate_source_tree(root: Path) -> None:
    for path in root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"安装源不接受符号链接：{path.relative_to(root)}")
        if not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"安装源不接受特殊文件：{path.relative_to(root)}")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"发布 JSON 包含重复字段：{key}")
        value[key] = item
    return value


def _read_release_json(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > MAX_RELEASE_JSON_BYTES:
        raise ValueError("发布 JSON 超过大小上限")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    if not isinstance(value, dict):
        raise ValueError("发布 JSON 必须是对象")
    return value


def verify_release(
    *,
    root: Path,
    manifest_path: Path,
    signature_path: Path,
    expected_public_key: str,
    archive_path: Path | None = None,
) -> dict:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise RuntimeError("验证发布签名需要 cryptography") from error
    _validate_source_tree(root)
    manifest = _read_release_json(manifest_path)
    signature = _read_release_json(signature_path)
    if manifest.get("format") != "qindun-release-manifest/v1":
        raise ValueError("不支持的发布清单格式")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(manifest.get("skill_version") or "")):
        raise ValueError("发布清单版本号无效")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("source_commit") or "")):
        raise ValueError("发布清单缺少有效来源提交号")
    if signature.get("format") != "qindun-release-signature/v1":
        raise ValueError("不支持的发布签名格式")
    if signature.get("signature_algorithm") != "Ed25519":
        raise ValueError("发布签名算法无效")
    signing_key_id = str(signature.get("signing_key_id") or "").strip()
    if not signing_key_id or len(signing_key_id) > 80:
        raise ValueError("发布签名密钥编号无效")
    manifest_payload = _canonical_json(manifest)
    if signature.get("manifest_sha256") != hashlib.sha256(manifest_payload).hexdigest():
        raise ValueError("发布清单摘要不一致")
    embedded_public_key = str(signature.get("public_key") or "")
    if embedded_public_key != expected_public_key.strip():
        raise ValueError("发布签名公钥与固定公钥不一致")
    try:
        public_raw = base64.b64decode(embedded_public_key, validate=True)
        signature_raw = base64.b64decode(str(signature.get("signature") or ""), validate=True)
        if len(public_raw) != 32 or len(signature_raw) != 64:
            raise ValueError("发布签名材料长度无效")
        protected_payload = {
            "format": signature.get("format"),
            "signature_algorithm": signature.get("signature_algorithm"),
            "signing_key_id": signing_key_id,
            "manifest_sha256": signature.get("manifest_sha256"),
            "public_key": embedded_public_key,
            "manifest": manifest,
        }
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature_raw, RELEASE_SIGNATURE_DOMAIN + _canonical_json(protected_payload)
        )
    except (ValueError, InvalidSignature) as error:
        raise ValueError("发布清单签名无效") from error
    if archive_path is not None:
        archive = manifest.get("archive")
        if not isinstance(archive, dict):
            raise ValueError("发布清单缺少归档信息")
        if (
            archive.get("name") != archive_path.name
            or archive.get("size") != archive_path.stat().st_size
            or archive.get("sha256") != _sha256(archive_path)
        ):
            raise ValueError("发布归档与签名清单不一致")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("发布清单缺少文件列表")
    expected_paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("发布清单文件条目无效")
        relative = str(entry.get("path") or "")
        pure = Path(relative)
        if not relative or pure.is_absolute() or ".." in pure.parts or relative in expected_paths:
            raise ValueError("发布清单包含不安全或重复路径")
        expected_paths.add(relative)
        path = root / pure
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"发布文件缺失或类型无效：{relative}")
        declared_mode = entry.get("mode")
        expected_mode = _expected_release_mode(relative)
        if declared_mode not in SAFE_RELEASE_MODES or declared_mode != expected_mode:
            raise ValueError(f"发布清单文件权限无效：{relative}")
        actual_mode = f"{stat.S_IMODE(path.stat().st_mode):04o}"
        if actual_mode != declared_mode:
            raise ValueError(f"发布文件权限与签名清单不一致：{relative}")
        if path.stat().st_size != entry.get("size") or _sha256(path) != entry.get("sha256"):
            raise ValueError(f"发布文件与签名清单不一致：{relative}")
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    if actual_paths != expected_paths:
        raise ValueError("安装源包含清单之外的文件或缺少已声明文件")
    return manifest


def install(
    destination_root: Path,
    *,
    replace: bool = False,
    release_manifest: Path | None = None,
    release_signature: Path | None = None,
    release_public_key: str | None = None,
    release_archive: Path | None = None,
    allow_unverified_source: bool = False,
) -> tuple[Path, Path | None]:
    _validate_source_tree(ROOT)
    required_verification_values = (
        release_manifest,
        release_signature,
        release_public_key,
        release_archive,
    )
    verification_requested = any(value is not None for value in required_verification_values)
    if verification_requested and allow_unverified_source:
        raise ValueError("签名发布安装和未验证源码安装不能同时启用")
    if verification_requested:
        if not all(value is not None for value in required_verification_values):
            raise ValueError("发布验证必须同时提供原始 ZIP、清单、签名和固定公钥")
    elif not allow_unverified_source:
        raise ValueError(
            "安装正式发布必须先验证签名；从已审查源码安装请明确增加 "
            "--allow-unverified-source"
        )
    destination_root = destination_root.expanduser().resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    target = destination_root / "qindun-certify"
    if target.exists() and not replace:
        raise ValueError(f"目标已存在：{target}；如需升级请明确增加 --replace")
    backup = None
    temporary = Path(tempfile.mkdtemp(prefix=".qindun-certify-", dir=destination_root))
    staged = temporary / "qindun-certify"
    try:
        shutil.copytree(
            ROOT,
            staged,
            ignore=lambda _directory, names: [name for name in names if name in EXCLUDED_NAMES],
        )
        if not (staged / "SKILL.md").is_file() or not (staged / "VERSION").is_file():
            raise ValueError("安装源缺少 SKILL.md 或 VERSION")
        if verification_requested:
            verify_release(
                root=staged,
                manifest_path=release_manifest,
                signature_path=release_signature,
                expected_public_key=release_public_key,
                archive_path=release_archive,
            )
        if target.exists():
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = destination_root / f"qindun-certify.backup-{stamp}"
            if backup.exists():
                raise ValueError(f"备份目录已存在：{backup}")
            os.replace(target, backup)
        os.replace(staged, target)
    except Exception:
        if backup is not None and backup.exists() and not target.exists():
            os.replace(backup, target)
        raise
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    return target, backup


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="安装或升级秦盾本地预检 Skill")
    parser.add_argument("--platform", choices=("codex", "claude"), default="codex")
    parser.add_argument("--destination", type=Path, help="自定义技能根目录")
    parser.add_argument("--replace", action="store_true", help="备份并替换已有安装")
    parser.add_argument("--release-manifest", type=Path, help="发布清单 JSON")
    parser.add_argument("--release-signature", type=Path, help="发布清单签名 JSON")
    parser.add_argument("--release-public-key-file", type=Path, help="已固定的发布公钥文件")
    parser.add_argument("--release-archive", type=Path, help="必须核对的下载原始 ZIP")
    parser.add_argument(
        "--allow-unverified-source",
        action="store_true",
        help="仅从已审查源码开发安装；明确跳过正式发布签名验证",
    )
    args = parser.parse_args(argv)
    destination = args.destination or _default_root(args.platform)
    try:
        release_public_key = (
            args.release_public_key_file.read_text(encoding="utf-8").strip()
            if args.release_public_key_file
            else None
        )
        target, backup = install(
            destination,
            replace=args.replace,
            release_manifest=args.release_manifest,
            release_signature=args.release_signature,
            release_public_key=release_public_key,
            release_archive=args.release_archive,
            allow_unverified_source=args.allow_unverified_source,
        )
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(3, f"秦盾安装失败：{error}\n")
    print(f"秦盾已安装到：{target}")
    if backup:
        print(f"原版本备份：{backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
