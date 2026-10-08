#!/usr/bin/env python3
"""Build a deterministic, checksummed QinDun skill release archive."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import stat
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile, ZipInfo


ROOT = Path(__file__).parents[1]
FIXED_TIMESTAMP = (2026, 1, 1, 0, 0, 0)
INCLUDED_PATHS = (
    "LICENSE",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "README.md",
    "SECURITY.md",
    "SKILL.md",
    "VERSION",
    "action.yml",
    "agents",
    "integrations",
    "qindun",
    "references",
    "rules/current.json",
    "rules/qindun-rule-bundle-v1.schema.json",
    "rules/qindun-rule-corpus-v1.schema.json",
    "rules/external-taxonomy-map-v1.json",
    "rules/rule-corpus-2026.10.5.json",
    "rules/rules-2026.10.5.json",
    "scripts/install.py",
    "scripts/qindun.py",
    "scripts/qindun_benchmark.py",
    "scripts/qindun_certify.py",
    "scripts/qindun_dependencies.py",
    "scripts/qindun_external.py",
    "scripts/qindun_review.py",
    "scripts/qindun_sarif.py",
    "scripts/qindun_source_context.py",
    "scripts/qindun_trust.py",
    "scripts/qindun_verify.py",
)
RELEASE_MANIFEST_FORMAT = "qindun-release-manifest/v1"
RELEASE_SIGNATURE_FORMAT = "qindun-release-signature/v1"
RELEASE_SIGNATURE_DOMAIN = b"QINDUN-RELEASE-MANIFEST-V1\x00"


def _release_mode(relative: str) -> str:
    return "0755" if relative == "qindun" or relative.endswith(".py") else "0644"


def release_files() -> list[Path]:
    files: list[Path] = []
    root = ROOT.resolve(strict=True)
    for name in INCLUDED_PATHS:
        path = ROOT / name
        try:
            metadata = path.lstat()
        except FileNotFoundError as error:
            raise ValueError(f"发布包缺少必需路径：{name}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"发布包不接受符号链接：{name}")
        if stat.S_ISREG(metadata.st_mode):
            _validate_release_file(path, root)
            files.append(path)
        elif stat.S_ISDIR(metadata.st_mode):
            for item in path.rglob("*"):
                relative = item.relative_to(ROOT).as_posix()
                item_metadata = item.lstat()
                if stat.S_ISLNK(item_metadata.st_mode):
                    raise ValueError(f"发布包不接受符号链接：{relative}")
                if stat.S_ISDIR(item_metadata.st_mode):
                    continue
                if not stat.S_ISREG(item_metadata.st_mode):
                    raise ValueError(f"发布包不接受特殊文件：{relative}")
                if "__pycache__" in item.parts:
                    continue
                _validate_release_file(item, root)
                files.append(item)
        else:
            raise ValueError(f"发布包不接受特殊文件：{name}")
    return sorted(files, key=lambda item: item.relative_to(ROOT).as_posix())


def _validate_release_file(path: Path, root: Path) -> None:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"发布文件越出技能目录：{path}") from error


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _release_manifest(
    archive_path: Path, files: list[Path], *, version: str, source_commit: str | None
) -> dict:
    if source_commit is not None and re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("发布来源提交号必须是 40 位小写 Git 提交号")
    return {
        "format": RELEASE_MANIFEST_FORMAT,
        "skill_version": version,
        "source_commit": source_commit,
        "archive": {
            "name": archive_path.name,
            "size": archive_path.stat().st_size,
            "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        },
        "files": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "size": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "mode": _release_mode(path.relative_to(ROOT).as_posix()),
            }
            for path in files
        ],
    }


def _sign_manifest(manifest: dict, *, private_key_value: str, key_id: str) -> dict:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as error:
        raise RuntimeError("签署发布清单需要 cryptography") from error
    normalized = private_key_value.strip()
    if normalized.startswith("-----BEGIN"):
        private_key = serialization.load_pem_private_key(normalized.encode("utf-8"), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("发布签名私钥必须是 Ed25519")
    else:
        try:
            raw = base64.b64decode(normalized, validate=True)
        except ValueError as error:
            raise ValueError("发布签名私钥格式无效") from error
        if len(raw) != 32:
            raise ValueError("Ed25519 发布签名私钥必须是 32 字节")
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
    normalized_key_id = key_id.strip()
    if not normalized_key_id or len(normalized_key_id) > 80:
        raise ValueError("发布签名密钥编号必须包含 1-80 个字符")
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signature_metadata = {
        "format": RELEASE_SIGNATURE_FORMAT,
        "signature_algorithm": "Ed25519",
        "signing_key_id": normalized_key_id,
        "manifest_sha256": hashlib.sha256(_canonical_json(manifest)).hexdigest(),
        "public_key": base64.b64encode(public_raw).decode("ascii"),
    }
    payload = RELEASE_SIGNATURE_DOMAIN + _canonical_json(
        {**signature_metadata, "manifest": manifest}
    )
    return {
        **signature_metadata,
        "signature": base64.b64encode(private_key.sign(payload)).decode("ascii"),
    }


def build(
    output_dir: Path,
    *,
    source_commit: str | None = None,
    signing_private_key: str | None = None,
    signing_key_id: str | None = None,
) -> tuple[Path, Path]:
    if (signing_private_key is None) != (signing_key_id is None):
        raise ValueError("发布签名私钥和密钥编号必须同时提供")
    if signing_private_key is not None and source_commit is None:
        raise ValueError("签署发布清单必须提供来源提交号")
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise ValueError("VERSION 不能为空")
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"qindun-certify-{version}.zip"
    files = release_files()
    # ZIP_STORED avoids zlib-version-dependent bytes and makes cross-runner
    # reproducibility depend only on the fixed metadata and file contents.
    with ZipFile(archive_path, "w", compression=ZIP_STORED) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            info = ZipInfo(f"qindun-certify/{relative}", FIXED_TIMESTAMP)
            info.compress_type = ZIP_STORED
            info.external_attr = int(_release_mode(relative), 8) << 16
            archive.writestr(info, path.read_bytes())
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = archive_path.with_suffix(".zip.sha256")
    checksum_path.write_text(
        f"{digest}  {archive_path.name}\n",
        encoding="utf-8",
    )
    manifest = _release_manifest(archive_path, files, version=version, source_commit=source_commit)
    manifest_path = archive_path.with_suffix(".zip.manifest.json")
    manifest_path.write_bytes(_canonical_json(manifest) + b"\n")
    signature_path = archive_path.with_suffix(".zip.manifest.sig.json")
    if signing_private_key is not None:
        assert signing_key_id is not None
        signature = _sign_manifest(
            manifest,
            private_key_value=signing_private_key,
            key_id=signing_key_id,
        )
        signature_path.write_bytes(_canonical_json(signature) + b"\n")
    else:
        signature_path.unlink(missing_ok=True)
    return archive_path, checksum_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="构建秦盾预检技能发布包")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--source-commit", help="写入清单的 40 位来源提交号")
    parser.add_argument("--signing-key-file", type=Path, help="可选 Ed25519 发布私钥文件")
    parser.add_argument("--signing-key-id", help="发布签名密钥编号")
    parser.add_argument(
        "--unsigned-development-build",
        action="store_true",
        help="仅构建未签名开发包；不得作为正式发布",
    )
    args = parser.parse_args(argv)
    if (args.signing_key_file is None) != (args.signing_key_id is None):
        parser.error("发布签名私钥和密钥编号必须同时提供")
    if args.signing_key_file is None and not args.unsigned_development_build:
        parser.error("正式发布必须签名；测试源码构建请明确增加 --unsigned-development-build")
    if args.signing_key_file is not None and args.unsigned_development_build:
        parser.error("签名发布不能同时标记为未签名开发包")
    private_key = (
        args.signing_key_file.read_text(encoding="utf-8") if args.signing_key_file else None
    )
    archive_path, checksum_path = build(
        args.output_dir,
        source_commit=args.source_commit,
        signing_private_key=private_key,
        signing_key_id=args.signing_key_id,
    )
    print(archive_path)
    print(checksum_path)
    print(archive_path.with_suffix(".zip.manifest.json"))
    signature_path = archive_path.with_suffix(".zip.manifest.sig.json")
    if signature_path.exists():
        print(signature_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
