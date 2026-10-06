#!/usr/bin/env python3
"""User-facing QinDun runner for local, GitHub, and batch preflight scans."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import qindun_certify as engine  # noqa: E402 - 支持脚本在任意工作目录独立运行
import qindun_external  # noqa: E402 - 外部扫描器只提供候选证据
import qindun_sarif  # noqa: E402 - 与统一入口一起发布
import qindun_verify  # noqa: E402 - 与统一入口一起发布


GITHUB_HOST = "github.com"
SAFE_REF = re.compile(r"[A-Za-z0-9._/-]{1,200}")
FORMAT_SUFFIX = {
    "json": ".json",
    "markdown": ".md",
    "html": ".html",
    "sarif": ".sarif",
}
MAX_GITHUB_METADATA_BYTES = 1024 * 1024
MAX_GITHUB_ARCHIVE_BYTES = 128 * 1024 * 1024
GITHUB_TIMEOUT_SECONDS = 30
MAX_GITHUB_DOWNLOAD_SECONDS = 120
GITHUB_TOKEN_ENV = "QINDUN_GITHUB_TOKEN"


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "qindun-certify",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get(GITHUB_TOKEN_ENV, "").strip()
    if token:
        if len(token) > 512 or any(ord(character) < 0x20 for character in token):
            raise ValueError(f"{GITHUB_TOKEN_ENV} 格式无效")
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() != GITHUB_HOST:
        return None
    if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        return None
    owner, repository = parts
    repository = repository.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+", repository
    ):
        return None
    return urlunsplit(("https", GITHUB_HOST, f"/{owner}/{repository}.git", "", ""))


def _validated_ref(value: str) -> str:
    if (
        SAFE_REF.fullmatch(value) is None
        or value.startswith(("-", "/"))
        or ".." in value
        or "//" in value
        or "@{" in value
    ):
        raise ValueError("Git 引用名称不安全或格式无效")
    return value


def _github_json(api_url: str) -> dict:
    request = Request(
        api_url,
        headers=_github_headers(),
    )
    try:
        with urlopen(request, timeout=GITHUB_TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_GITHUB_METADATA_BYTES + 1)
    except HTTPError as error:
        if error.code in {403, 429}:
            retry_after = error.headers.get("Retry-After") if error.headers else None
            rate_reset = error.headers.get("X-RateLimit-Reset") if error.headers else None
            retry_hint = retry_after or rate_reset
            suffix = f"；建议在 {retry_hint} 后重试" if retry_hint else "；请稍后重试"
            raise ValueError(
                "GitHub 接口已限流"
                + suffix
                + f"；也可通过 {GITHUB_TOKEN_ENV} 提供只读令牌提高额度"
            ) from error
        if error.code == 401:
            raise ValueError(f"GitHub 只读令牌无效；请检查 {GITHUB_TOKEN_ENV}") from error
        raise ValueError(f"GitHub 接口返回 HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise ValueError(f"GitHub 接口不可用：{type(error).__name__}") from error
    if len(raw) > MAX_GITHUB_METADATA_BYTES:
        raise ValueError("GitHub 元数据响应超过大小上限")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("GitHub 返回了无效元数据") from error
    if not isinstance(payload, dict):
        raise ValueError("GitHub 元数据不是对象")
    return payload


def _github_reputation_evidence(url: str) -> dict:
    path = urlsplit(url).path.removesuffix(".git").strip("/")
    try:
        payload = _github_json(f"https://api.github.com/repos/{path}")
    except ValueError as error:
        return {
            "status": "unavailable",
            "affects_local_grade": False,
            "error": f"GitHub 来源元数据不可用：{error}",
        }
    owner = payload.get("owner") if isinstance(payload.get("owner"), dict) else {}
    return {
        "status": "available",
        "affects_local_grade": False,
        "repository_created_at": payload.get("created_at"),
        "repository_updated_at": payload.get("updated_at"),
        "stars": payload.get("stargazers_count"),
        "forks": payload.get("forks_count"),
        "archived": bool(payload.get("archived")),
        "disabled": bool(payload.get("disabled")),
        "owner_type": owner.get("type"),
    }


def _resolve_github_commit(url: str, requested_ref: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{40}", requested_ref):
        return requested_ref.lower()
    path = urlsplit(url).path.removesuffix(".git").strip("/")
    resolved_ref = requested_ref
    if requested_ref == "HEAD":
        repository = _github_json(f"https://api.github.com/repos/{path}")
        resolved_ref = str(repository.get("default_branch") or "").strip()
        if not resolved_ref:
            raise ValueError("GitHub 仓库没有可解析的默认分支")
    commit = _github_json(
        f"https://api.github.com/repos/{path}/commits/{quote(resolved_ref, safe='')}"
    )
    sha = str(commit.get("sha") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("GitHub 没有返回完整提交号")
    return sha


def _download_github_archive(url: str, commit: str, destination: Path) -> str:
    repository_path = urlsplit(url).path.removesuffix(".git").strip("/")
    archive_url = f"https://codeload.github.com/{repository_path}/zip/{commit}"
    request = Request(
        archive_url,
        headers={"Accept": "application/zip", "User-Agent": "qindun-certify"},
    )
    digest = hashlib.sha256()
    total = 0
    started_at = time.monotonic()
    try:
        with urlopen(request, timeout=GITHUB_TIMEOUT_SECONDS) as response:
            final_host = (urlsplit(response.geturl()).hostname or "").lower()
            if final_host != "codeload.github.com":
                raise ValueError("GitHub 归档下载跳转到了非预期主机")
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > MAX_GITHUB_ARCHIVE_BYTES:
                raise ValueError("GitHub 归档超过下载大小上限")
            with destination.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    if time.monotonic() - started_at > MAX_GITHUB_DOWNLOAD_SECONDS:
                        raise ValueError("GitHub 归档下载超过总时限")
                    total += len(chunk)
                    if total > MAX_GITHUB_ARCHIVE_BYTES:
                        raise ValueError("GitHub 归档超过下载大小上限")
                    output.write(chunk)
                    digest.update(chunk)
    except HTTPError as error:
        if error.code in {401, 403, 404}:
            raise ValueError(
                "GitHub 归档无法匿名下载；当前只支持可公开下载的仓库"
            ) from error
        raise ValueError(f"GitHub 归档获取失败：HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise ValueError(f"GitHub 归档获取失败：{type(error).__name__}") from error
    if total == 0:
        raise ValueError("GitHub 归档为空")
    return digest.hexdigest()


def _external_git_objects(archive_path: Path) -> list[dict[str, str]]:
    external: list[dict[str, str]] = []
    try:
        archive = ZipFile(archive_path)
    except (BadZipFile, OSError) as error:
        raise ValueError("GitHub 返回的不是有效 ZIP 归档") from error
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            source_parts = parts[1:] if len(parts) > 1 else parts
            if source_parts == (".gitmodules",):
                external.append({"kind": "git_submodule", "path": name})
                continue
            if info.file_size > 2048 or info.flag_bits & 0x1:
                continue
            try:
                raw = archive.read(info)
            except (BadZipFile, OSError, RuntimeError, NotImplementedError):
                continue
            if (
                raw.startswith(b"version https://git-lfs.github.com/spec/v1\n")
                and b"\noid sha256:" in raw
                and b"\nsize " in raw
            ):
                external.append({"kind": "git_lfs", "path": name})
            if len(external) >= 100:
                external.append(
                    {"kind": "truncated", "path": "外部 Git 对象列表超过 100 项"}
                )
                break
    return external


def _mark_source_partial(report: dict, external: list[dict[str, str]]) -> None:
    if not external:
        return
    labels = {
        "git_submodule": "Git 子模块",
        "git_lfs": "Git LFS 原文件",
        "truncated": "更多外部 Git 对象",
    }
    reasons = {
        f"未取得{labels.get(item['kind'], '外部 Git 对象')}：{item['path']}"
        for item in external
    }
    coverage = report["coverage"]
    coverage["complete"] = False
    coverage["incomplete_reasons"] = sorted(
        set(coverage.get("incomplete_reasons") or []) | reasons
    )
    controls = coverage.get("controls") or []
    source_control = next(
        (item for item in controls if item.get("code") == "D2.source_materialization"),
        None,
    )
    if source_control is None:
        controls.append({"code": "D2.source_materialization", "status": "partial"})
    else:
        source_control["status"] = "partial"
    report["scan_status"] = "partial"
    if report.get("local_grade_preview") != "D":
        report["local_grade_preview"] = None


def _scan_github(
    url: str,
    *,
    ref: str,
    osv: bool,
    external_scanners: list[str] | None = None,
    allow_source_disclosure: bool = False,
    external_timeout: int = qindun_external.DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    normalized = _github_url(url)
    if normalized is None:
        raise ValueError("只支持不含账号凭据、查询参数或子目录的 GitHub HTTPS 仓库地址")
    requested_ref = _validated_ref(ref)
    reputation_evidence = _github_reputation_evidence(normalized)
    commit = _resolve_github_commit(normalized, requested_ref)
    with tempfile.TemporaryDirectory(prefix="qindun-github-") as directory:
        archive_path = Path(directory) / "source.zip"
        archive_sha256 = _download_github_archive(normalized, commit, archive_path)
        external = _external_git_objects(archive_path)
        report = engine.scan(archive_path, osv=osv)
        _mark_source_partial(report, external)
        if external_scanners:
            evidence = qindun_external.run_scanners(
                archive_path,
                external_scanners,
                allow_source_disclosure=allow_source_disclosure,
                timeout_seconds=external_timeout,
            )
            qindun_external.merge_report(report, evidence)
    report["target"]["name"] = urlsplit(normalized).path.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    report["source"] = {
        "kind": "github",
        "url": normalized.removesuffix(".git"),
        "requested_ref": requested_ref,
        "resolved_commit": commit,
        "fetch_method": "github_commit_archive",
        "archive_sha256": archive_sha256,
        "materialization_complete": not external,
        "external_objects": external,
        "reputation_evidence": reputation_evidence,
        "reputation_affects_grade": False,
    }
    return report


def scan_target(
    value: str,
    *,
    ref: str,
    osv: bool,
    external_scanners: list[str] | None = None,
    allow_source_disclosure: bool = False,
    external_timeout: int = qindun_external.DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    if value.startswith(("http://", "https://")):
        return _scan_github(
            value,
            ref=ref,
            osv=osv,
            external_scanners=external_scanners,
            allow_source_disclosure=allow_source_disclosure,
            external_timeout=external_timeout,
        )
    target = Path(value).expanduser()
    report = engine.scan(target, osv=osv)
    if external_scanners:
        evidence = qindun_external.run_scanners(
            target,
            external_scanners,
            allow_source_disclosure=allow_source_disclosure,
            timeout_seconds=external_timeout,
        )
        qindun_external.merge_report(report, evidence)
    report["source"] = {"kind": "local"}
    return report


def _render(report: dict, format_name: str) -> str:
    if format_name == "json":
        return json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if format_name == "html":
        return engine.html_report(report)
    if format_name == "sarif":
        return qindun_sarif.render(report)
    return engine.markdown(report)


def _slug(value: str) -> str:
    if _github_url(value):
        value = urlsplit(value).path.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    else:
        value = Path(value).name or "target"
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")[:60] or "target"


def _exit_code(report: dict) -> int:
    if report["local_grade_preview"] in {"C", "D"}:
        return engine.EXIT_RISK
    if report["scan_status"] != "completed" or (
        report.get("external_scanners", {}).get("status") not in {None, "completed"}
    ):
        return engine.EXIT_PARTIAL
    return engine.EXIT_OK


def _validate_output_location(output_dir: Path, targets: list[str]) -> None:
    output = output_dir.expanduser().resolve()
    for value in targets:
        if value.startswith(("http://", "https://")):
            continue
        target = Path(value).expanduser()
        try:
            resolved_target = target.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved_target.is_dir():
            continue
        try:
            output.relative_to(resolved_target)
        except ValueError:
            continue
        raise ValueError(
            f"报告目录不能位于扫描目标内部：{output}；请改用目标目录之外的位置"
        )


def _print_top_help() -> None:
    print(
        """usage: qindun <command> [options]

秦盾本地安全预检和签名报告验证。

commands:
  scan    扫描本地目录、ZIP 或 GitHub 仓库（可省略 scan）
  verify  验证秦盾平台签名报告
  benchmark 运行内置语料或通过 ClawScan 运行公开基准

examples:
  qindun scan ./my-skill
  qindun benchmark corpus
  qindun verify report.qindun.json --help

使用 `qindun scan --help`、`qindun benchmark --help` 或
`qindun verify --help` 查看子命令参数。"""
    )


def _clawscan_adapter(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="供 ClawScan 调用的秦盾 JSON 适配入口"
    )
    parser.add_argument("target", help="ClawScan 提供的本地目标")
    args = parser.parse_args(arguments)
    try:
        report = scan_target(args.target, ref="HEAD", osv=False)
    except (OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "format": "qindun-clawscan-adapter/v1",
                    "status": "failed",
                    "error": str(error),
                },
                ensure_ascii=False,
            )
        )
        return engine.EXIT_SCAN_ERROR
    report["qindun_exit_code"] = _exit_code(report)
    sys.stdout.write(json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n")
    # ClawScan must retain valid C、D and partial JSON as evidence. Its profile
    # applies warning policy to report fields instead of treating them as a tool crash.
    return engine.EXIT_OK


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] in {"-h", "--help"}:
        _print_top_help()
        return engine.EXIT_OK
    if arguments and arguments[0] == "verify":
        return qindun_verify.main(arguments[1:])
    if arguments and arguments[0] == "benchmark":
        import qindun_benchmark

        return qindun_benchmark.main(arguments[1:])
    if arguments and arguments[0] == "clawscan-adapter":
        return _clawscan_adapter(arguments[1:])
    if arguments and arguments[0] == "scan":
        arguments = arguments[1:]
    parser = argparse.ArgumentParser(
        description="秦盾本地预检：支持本地目录、ZIP、GitHub 仓库和批量报告"
    )
    parser.add_argument("targets", nargs="+", help="一个或多个本地目标或 GitHub HTTPS 地址")
    parser.add_argument("--ref", default="HEAD", help="GitHub 分支、标签或提交，默认 HEAD")
    parser.add_argument("--osv", action="store_true", help="联网查询 OSV 公开漏洞库")
    parser.add_argument(
        "--external-scanner",
        action="append",
        choices=("aig", "cisco", "skillspector"),
        default=[],
        help="运行一个外部扫描器并作为候选证据；可重复指定",
    )
    parser.add_argument(
        "--allow-source-disclosure",
        action="store_true",
        help="明确允许所选外部扫描器把源码片段发送给其模型服务",
    )
    parser.add_argument(
        "--external-timeout",
        type=int,
        default=qindun_external.DEFAULT_TIMEOUT_SECONDS,
        help="每个外部扫描器的秒级时限，默认 600",
    )
    parser.add_argument(
        "--format",
        action="append",
        choices=("json", "markdown", "html", "sarif"),
        dest="formats",
        help="输出格式；批量模式可重复指定，默认输出三种格式",
    )
    parser.add_argument("--output-dir", type=Path, help="批量报告目录")
    parser.add_argument("--version", action="version", version=f"qindun-certify {engine.SCANNER_VERSION}")
    args = parser.parse_args(arguments)
    batch = len(args.targets) > 1
    if batch and args.output_dir is None:
        parser.error("批量扫描必须提供 --output-dir")
    formats = args.formats or (["json", "markdown", "html"] if batch else ["markdown"])
    if not batch and args.output_dir is None and len(formats) > 1:
        parser.error("同一目标输出多种格式时必须提供 --output-dir")
    if args.output_dir:
        try:
            _validate_output_location(args.output_dir, args.targets)
        except ValueError as error:
            parser.error(str(error))
        args.output_dir.mkdir(parents=True, exist_ok=True)
    summary: list[dict] = []
    codes: list[int] = []
    for index, target in enumerate(args.targets, start=1):
        try:
            report = scan_target(
                target,
                ref=args.ref,
                osv=args.osv,
                external_scanners=args.external_scanner,
                allow_source_disclosure=args.allow_source_disclosure,
                external_timeout=args.external_timeout,
            )
            code = _exit_code(report)
            outputs: list[str] = []
            for format_name in formats:
                rendered = _render(report, format_name)
                if args.output_dir:
                    path = args.output_dir / (
                        f"{index:03d}-{_slug(target)}{FORMAT_SUFFIX[format_name]}"
                    )
                    engine._write_output(path, rendered)
                    outputs.append(str(path))
                else:
                    sys.stdout.write(rendered)
            summary.append(
                {
                    "target": target,
                    "status": report["scan_status"],
                    "grade": report["local_grade_preview"],
                    "exit_code": code,
                    "outputs": outputs,
                    "source": report.get("source"),
                    "external_status": (report.get("external_scanners") or {}).get("status"),
                }
            )
            codes.append(code)
        except (OSError, ValueError) as error:
            print(f"秦盾扫描失败：{target}：{error}", file=sys.stderr)
            summary.append(
                {
                    "target": target,
                    "status": "failed",
                    "grade": None,
                    "exit_code": engine.EXIT_SCAN_ERROR,
                    "error": str(error),
                    "outputs": [],
                }
            )
            codes.append(engine.EXIT_SCAN_ERROR)
    if args.output_dir:
        engine._write_output(
            args.output_dir / "summary.json",
            json.dumps({"format": "qindun-batch-summary/v1", "items": summary}, ensure_ascii=False, indent=2)
            + "\n",
        )
        sys.stdout.write(f"秦盾报告已保存到：{args.output_dir}\n")
    if engine.EXIT_SCAN_ERROR in codes:
        return engine.EXIT_SCAN_ERROR
    if engine.EXIT_RISK in codes:
        return engine.EXIT_RISK
    if engine.EXIT_PARTIAL in codes:
        return engine.EXIT_PARTIAL
    return engine.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
