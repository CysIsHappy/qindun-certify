#!/usr/bin/env python3
"""Deterministic dependency inventory and optional OSV lookup for QinDun."""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
import xml.etree.ElementTree as ElementTree
from pathlib import Path, PurePosixPath
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


class _DependencyFileNames(frozenset):
    def __contains__(self, value: object) -> bool:
        return super().__contains__(value) or (
            isinstance(value, str) and value.casefold().endswith(".gemspec")
        )


DEPENDENCY_FILES = _DependencyFileNames(
    {
        ".flattened-pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "build.rs",
        "cargo.toml",
        "cargo.lock",
        "composer.json",
        "composer.lock",
        "gemfile",
        "gemfile.lock",
        "go.mod",
        "go.sum",
        "gradle.lockfile",
        "npm-shrinkwrap.json",
        "package.json",
        "package-lock.json",
        "packages.lock.json",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "pom.xml",
        "requirements.txt",
        "settings.gradle",
        "settings.gradle.kts",
        "setup.py",
        "uv.lock",
        "yarn.lock",
    }
)
MAX_DEPENDENCIES = 5_000
MAX_DEPENDENCY_FILE_BYTES = 5 * 1024 * 1024
MAX_OSV_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_OSV_BATCH_SIZE = 100
MAX_OSV_RETRIES = 2
OSV_RETRY_DELAY_SECONDS = 0.25
MAX_OSV_TOTAL_SECONDS = 120.0
MAX_OSV_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024
DEFAULT_OSV_URL = "https://api.osv.dev/v1/querybatch"

PROVENANCE_PRIORITY = {
    "public": 0,
    "unknown": 1,
    "vcs": 2,
    "private": 3,
    "local": 4,
}


def _add(
    target: dict[tuple[str, str, str], dict[str, str]],
    ecosystem: str,
    name: str,
    version: str,
    *,
    provenance: str = "unknown",
) -> None:
    if provenance not in PROVENANCE_PRIORITY:
        provenance = "unknown"
    normalized = (ecosystem, name.strip(), version.strip())
    if normalized[1] and normalized[2]:
        existing = target.get(normalized)
        if (
            existing is not None
            and PROVENANCE_PRIORITY[existing["provenance"]] >= PROVENANCE_PRIORITY[provenance]
        ):
            return
        target[normalized] = {
            "ecosystem": normalized[0],
            "name": normalized[1],
            "version": normalized[2],
            "provenance": provenance,
        }


def _url_provenance(value: object, *, public_hosts: tuple[str, ...]) -> str:
    rendered = str(value or "").strip().casefold()
    if not rendered:
        return "unknown"
    if rendered.startswith(("file:", "link:", "workspace:", "path:", "./", "../", "/")):
        return "local"
    if (
        rendered.startswith(("git+", "git://", "ssh://", "git@"))
        or rendered.endswith(".git")
    ):
        return "vcs"
    parsed = urlsplit(rendered)
    if parsed.hostname in public_hosts:
        return "public"
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return "private"
    return "unknown"


def _python_source_provenance(source_value: str) -> str:
    normalized = source_value.casefold()
    if any(
        marker in normalized
        for marker in ("directory", "editable", "path", "virtual", "workspace")
    ):
        return "local"
    if "git" in normalized:
        return "vcs"
    urls = re.findall(r"https?://[^\s\"',}]+", normalized)
    if urls:
        provenances = {
            _url_provenance(
                value,
                public_hosts=("pypi.org", "files.pythonhosted.org"),
            )
            for value in urls
        }
        return "public" if provenances == {"public"} else "private"
    return "private" if normalized else "unknown"


def _npm_lock(raw: bytes, target: dict) -> bool:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    packages = payload.get("packages") if isinstance(payload, dict) else None
    if not isinstance(packages, dict):
        return False
    for path, item in packages.items():
        if not path or not isinstance(item, dict) or not item.get("version"):
            continue
        name = item.get("name") or str(path).split("node_modules/")[-1]
        resolved = item.get("resolved")
        provenance = (
            "local"
            if item.get("link") is True
            else _url_provenance(
                resolved,
                public_hosts=("registry.npmjs.org", "registry.yarnpkg.com"),
            )
            if resolved
            else "unknown"
        )
        _add(
            target,
            "npm",
            str(name),
            str(item["version"]),
            provenance=provenance,
        )
    return True


def _requirements(raw: bytes, target: dict) -> bool:
    complete = True
    indexes: list[str] = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        index = re.match(
            r"^--(?:extra-)?index-url(?:\s+|=)(\S+)",
            stripped,
            re.IGNORECASE,
        )
        if index:
            indexes.append(index.group(1))
            continue
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)\s*(?:#.*)?$", line)
        if match:
            provenances = {
                _url_provenance(
                    value,
                    public_hosts=("pypi.org", "files.pythonhosted.org"),
                )
                for value in indexes
            }
            provenance = (
                "public"
                if provenances == {"public"}
                else "private"
                if "private" in provenances
                else "unknown"
            )
            _add(
                target,
                "PyPI",
                match.group(1),
                match.group(2),
                provenance=provenance,
            )
        else:
            complete = False
    return complete


def _python_toml_lock(raw: bytes, target: dict) -> bool:
    text = raw.decode("utf-8", errors="replace")
    sections = re.split(r"(?m)^\s*\[\[package\]\]\s*$", text)[1:]
    if not sections:
        return False
    complete = True
    for section in sections:
        name = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', section)
        version = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', section)
        if name is None or version is None:
            complete = False
            continue
        source = re.search(r"(?m)^\s*source\s*=\s*\{([^}]*)\}", section)
        source_table = re.search(
            r"(?ms)^\s*\[package\.source\]\s*$\n(.*?)(?=^\s*\[|\Z)",
            section,
        )
        provenance = "unknown"
        if source:
            source_value = source.group(1).casefold()
        elif source_table:
            source_value = source_table.group(1).casefold()
        else:
            source_value = ""
        if source_value:
            provenance = _python_source_provenance(source_value)
        _add(
            target,
            "PyPI",
            name.group(1),
            version.group(1),
            provenance=provenance,
        )
    return complete


def _pipfile_lock(raw: bytes, target: dict) -> bool:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    meta = payload.get("_meta") if isinstance(payload, dict) else None
    raw_sources = meta.get("sources") if isinstance(meta, dict) else None
    sources: dict[str, str] = {}
    if isinstance(raw_sources, list):
        for source in raw_sources:
            if not isinstance(source, dict) or not source.get("name"):
                continue
            sources[str(source["name"]).casefold()] = _url_provenance(
                source.get("url"),
                public_hosts=("pypi.org", "files.pythonhosted.org"),
            )
    found = False
    complete = True
    for section in ("default", "develop"):
        packages = payload.get(section) if isinstance(payload, dict) else None
        if not isinstance(packages, dict):
            continue
        for name, item in packages.items():
            found = True
            version = item.get("version") if isinstance(item, dict) else None
            match = re.fullmatch(r"==([^;\s]+)", str(version or ""))
            if match:
                provenance = "unknown"
                if isinstance(item, dict):
                    if item.get("path") or item.get("file"):
                        provenance = "local"
                    elif item.get("git"):
                        provenance = "vcs"
                    elif item.get("index"):
                        provenance = sources.get(str(item["index"]).casefold(), "unknown")
                    elif len(sources) == 1:
                        provenance = next(iter(sources.values()))
                _add(
                    target,
                    "PyPI",
                    str(name),
                    match.group(1),
                    provenance=provenance,
                )
            else:
                complete = False
    return found and complete


def _pyproject(raw: bytes, target: dict) -> bool:
    text = raw.decode("utf-8", errors="replace")
    values: list[str] = []
    for block in re.findall(r"(?ms)^\s*(?:dependencies|[A-Za-z0-9_.-]+)\s*=\s*\[(.*?)\]", text):
        values.extend(match[1] for match in re.findall(r'(["\'])(.*?)(?<!\\)\1', block))
    poetry = re.search(r"(?ms)^\s*\[tool\.poetry\.dependencies\]\s*$\n(.*?)(?=^\s*\[|\Z)", text)
    if poetry:
        for name, value in re.findall(
            r'(?m)^\s*([A-Za-z0-9_.-]+)\s*=\s*["\']([^"\']+)["\']', poetry.group(1)
        ):
            if name.lower() != "python":
                values.append(f"{name}=={value.removeprefix('==')}")
    complete = True
    for value in values:
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([^;\s]+)", value)
        if match:
            _add(target, "PyPI", match.group(1), match.group(2))
        else:
            complete = False
    return complete if values else True


def _pnpm_lock(raw: bytes, target: dict) -> bool:
    matches = re.findall(
        r"(?m)^\s{2,6}['\"]?/?((?:@[^/\s:'\"]+/)?[^@/\s:'\"]+)@([^\s:'\"(]+)(?:\([^\n]+\))?['\"]?:\s*$",
        raw.decode("utf-8", errors="replace"),
    )
    for name, version in matches:
        _add(target, "npm", name, version, provenance="unknown")
    return bool(matches)


def _yarn_lock(raw: bytes, target: dict) -> bool:
    current_names: list[str] = []
    found = False
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if line and not line.startswith((" ", "#")) and line.endswith(":"):
            current_names = []
            for selector in line[:-1].split(","):
                match = re.match(r"^(@[^/]+/[^@]+|[^@]+)@", selector.strip().strip("\"'"))
                if match:
                    current_names.append(match.group(1))
        version = re.match(r"^\s{2,}version\s+[\"']?([^\"'\s]+)", line)
        if version and current_names:
            for name in current_names:
                _add(target, "npm", name, version.group(1), provenance="unknown")
                found = True
            current_names = []
    return found


def _go_sum(raw: bytes, target: dict) -> bool:
    found = False
    complete = True
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3 or not parts[1].startswith("v"):
            complete = False
            continue
        _add(
            target,
            "Go",
            parts[0],
            parts[1].removesuffix("/go.mod"),
            provenance="unknown",
        )
        found = True
    return found and complete


def _cargo_lock(raw: bytes, target: dict) -> bool:
    text = raw.decode("utf-8", errors="replace")
    sections = re.split(r"(?m)^\s*\[\[package\]\]\s*$", text)[1:]
    if not sections:
        return False
    complete = True
    for section in sections:
        name = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', section)
        version = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', section)
        if name is None or version is None:
            complete = False
            continue
        source = re.search(r'(?m)^\s*source\s*=\s*["\']([^"\']+)["\']', section)
        source_value = source.group(1) if source else ""
        normalized_source = source_value.casefold().rstrip("/")
        provenance = (
            "local"
            if not normalized_source
            else "public"
            if normalized_source
            in {
                "registry+https://github.com/rust-lang/crates.io-index",
                "sparse+https://index.crates.io",
            }
            else "vcs"
            if normalized_source.startswith("git+")
            else "private"
        )
        _add(
            target,
            "crates.io",
            name.group(1),
            version.group(1),
            provenance=provenance,
        )
    return complete


def _composer_lock(raw: bytes, target: dict) -> bool:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    found = False
    complete = True
    for section in ("packages", "packages-dev"):
        packages = payload.get(section) if isinstance(payload, dict) else None
        if not isinstance(packages, list):
            continue
        for item in packages:
            if not isinstance(item, dict) or not item.get("name") or not item.get("version"):
                complete = False
                continue
            dist = item.get("dist") if isinstance(item.get("dist"), dict) else {}
            source = item.get("source") if isinstance(item.get("source"), dict) else {}
            location = dist.get("url") or source.get("url")
            notification_url = item.get("notification-url")
            notification_provenance = _url_provenance(
                notification_url,
                public_hosts=("packagist.org", "repo.packagist.org"),
            )
            if str(dist.get("type") or "").casefold() == "path":
                provenance = "local"
            elif str(source.get("type") or "").casefold() in {"git", "hg", "svn", "fossil"}:
                provenance = "vcs"
            elif notification_provenance == "public":
                provenance = "public"
            elif location:
                provenance = _url_provenance(
                    location,
                    public_hosts=("packagist.org", "repo.packagist.org"),
                )
            else:
                provenance = "unknown"
            _add(
                target,
                "Packagist",
                str(item["name"]),
                str(item["version"]).lstrip("v"),
                provenance=provenance,
            )
            found = True
    return found and complete


def _nuget_lock(raw: bytes, target: dict) -> bool:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    dependencies = payload.get("dependencies") if isinstance(payload, dict) else None
    if not isinstance(dependencies, dict):
        return False
    found = False
    complete = True
    for framework in dependencies.values():
        if not isinstance(framework, dict):
            complete = False
            continue
        for name, item in framework.items():
            version = item.get("resolved") if isinstance(item, dict) else None
            if version:
                _add(
                    target,
                    "NuGet",
                    str(name),
                    str(version),
                    provenance="unknown",
                )
                found = True
            else:
                complete = False
    return found and complete


def _gemfile_lock(raw: bytes, target: dict) -> bool:
    section = ""
    provenance = "unknown"
    in_specs = False
    found = False
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if line and not line.startswith(" "):
            section = line.strip().upper()
            in_specs = False
            provenance = (
                "vcs"
                if section == "GIT"
                else "local"
                if section == "PATH"
                else "unknown"
            )
            continue
        remote = re.match(r"^\s{2}remote:\s*(\S+)", line)
        if remote and section == "GEM":
            provenance = _url_provenance(
                remote.group(1),
                public_hosts=("rubygems.org",),
            )
        if line == "  specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith("    "):
            in_specs = False
        if in_specs:
            match = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^ )]+)", line)
            if match:
                _add(
                    target,
                    "RubyGems",
                    match.group(1),
                    match.group(2),
                    provenance=provenance,
                )
                found = True
    return found


def _gradle_lock(raw: bytes, target: dict) -> bool:
    found = False
    complete = True
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("empty="):
            continue
        parts = stripped.split("=", 1)[0].split(":")
        if len(parts) == 3 and all(parts):
            _add(
                target,
                "Maven",
                f"{parts[0]}:{parts[1]}",
                parts[2],
                provenance="unknown",
            )
            found = True
        else:
            complete = False
    return found and complete


def _maven_pom(raw: bytes, target: dict) -> bool:
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return False
    found = False
    complete = True
    for dependency in root.findall(".//{*}dependency"):
        group = dependency.findtext("{*}groupId")
        artifact = dependency.findtext("{*}artifactId")
        version = dependency.findtext("{*}version")
        if group and artifact and version and "${" not in version:
            _add(
                target,
                "Maven",
                f"{group}:{artifact}",
                version,
                provenance="unknown",
            )
            found = True
        elif group and artifact:
            complete = False
    return found and complete


READERS = {
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "requirements.txt": _requirements,
    "poetry.lock": _python_toml_lock,
    "uv.lock": _python_toml_lock,
    "pipfile.lock": _pipfile_lock,
    "pyproject.toml": _pyproject,
    "pnpm-lock.yaml": _pnpm_lock,
    "yarn.lock": _yarn_lock,
    "go.sum": _go_sum,
    "cargo.lock": _cargo_lock,
    "composer.lock": _composer_lock,
    "packages.lock.json": _nuget_lock,
    "gemfile.lock": _gemfile_lock,
    "gradle.lockfile": _gradle_lock,
    ".flattened-pom.xml": _maven_pom,
}

DECLARATION_LOCKS = {
    "package.json": {"npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"},
    "cargo.toml": {"cargo.lock"},
    "composer.json": {"composer.lock"},
    "gemfile": {"gemfile.lock"},
    "go.mod": {"go.sum"},
    "pom.xml": {".flattened-pom.xml"},
    "pyproject.toml": {"poetry.lock", "uv.lock"},
    "setup.py": set(),
    "build.gradle": {"gradle.lockfile"},
    "build.gradle.kts": {"gradle.lockfile"},
}

DECLARATION_ECOSYSTEMS = {
    "package.json": "npm",
    "cargo.toml": "crates.io",
    "composer.json": "Packagist",
    "gemfile": "RubyGems",
    "go.mod": "Go",
    "pom.xml": "Maven",
    "pyproject.toml": "PyPI",
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
}


def _normalized_path(path: str) -> str:
    return PurePosixPath(path.replace("\\", "/")).as_posix().removeprefix("./")


def _parent(path: str) -> str:
    value = PurePosixPath(path).parent.as_posix()
    return "" if value == "." else value


def _toml_section(text: str, section: str) -> str:
    match = re.search(
        rf"(?ms)^\s*\[{re.escape(section)}\]\s*$\n(.*?)(?=^\s*\[|\Z)",
        text,
    )
    return match.group(1) if match else ""


def _toml_array(section: str, key: str) -> list[str]:
    match = re.search(rf"(?ms)^\s*{re.escape(key)}\s*=\s*\[(.*?)\]", section)
    if match is None:
        return []
    return [item[1] for item in re.findall(r'(["\'])(.*?)(?<!\\)\1', match.group(1))]


def _workspace_patterns(manifest_name: str, raw: bytes) -> list[str]:
    values: list[str] = []
    excluded_values: list[str] = []
    if manifest_name == "package.json":
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return []
        workspaces = payload.get("workspaces") if isinstance(payload, dict) else None
        if isinstance(workspaces, list):
            values = [str(item) for item in workspaces]
        elif isinstance(workspaces, dict) and isinstance(workspaces.get("packages"), list):
            values = [str(item) for item in workspaces["packages"]]
    elif manifest_name == "cargo.toml":
        section = _toml_section(
            raw.decode("utf-8", errors="replace"),
            "workspace",
        )
        values = _toml_array(section, "members")
        excluded_values = _toml_array(section, "exclude")
    elif manifest_name == "pyproject.toml":
        section = _toml_section(
            raw.decode("utf-8", errors="replace"),
            "tool.uv.workspace",
        )
        values = _toml_array(section, "members")
        excluded_values = _toml_array(section, "exclude")
    elif manifest_name in {"settings.gradle", "settings.gradle.kts"}:
        text = raw.decode("utf-8", errors="replace")
        for match in re.finditer(
            r"(?m)^\s*include(?:\s*\(([^)]*)\)|\s+([^\n]+))",
            text,
        ):
            arguments = match.group(1) or match.group(2) or ""
            for _quote, value in re.findall(r'(["\'])(.*?)(?<!\\)\1', arguments):
                normalized = value.removeprefix(":").replace(":", "/")
                if normalized:
                    values.append(normalized)
    patterns = []
    for value in [*values, *(f"!{item}" for item in excluded_values)]:
        negative = value.startswith("!")
        candidate = value[1:] if negative else value
        normalized = candidate.replace("\\", "/").removeprefix("./").rstrip("/")
        if (
            normalized
            and not normalized.startswith("/")
            and ".." not in PurePosixPath(normalized).parts
        ):
            patterns.append(f"!{normalized}" if negative else normalized)
    return patterns


def _is_workspace_member(relative_directory: str, patterns: list[str]) -> bool:
    included = False
    for pattern in patterns:
        if pattern.startswith("!"):
            if PurePosixPath(relative_directory).match(pattern[1:]):
                included = False
            continue
        if PurePosixPath(relative_directory).match(pattern):
            included = True
    return included


def _project_lock_locations(
    *,
    path: str,
    name: str,
    raw_by_location: dict[tuple[str, str], bytes],
) -> list[tuple[str, str]]:
    directory = _parent(path)
    lock_names = DECLARATION_LOCKS[name]
    locations = [
        (directory, lock_name)
        for lock_name in sorted(lock_names)
        if (directory, lock_name) in raw_by_location
    ]
    if locations:
        return locations
    workspace_names = (
        ("settings.gradle", "settings.gradle.kts")
        if name in {"build.gradle", "build.gradle.kts"}
        else (name,)
    )
    parts = PurePosixPath(directory).parts if directory else ()
    for length in range(len(parts) - 1, -1, -1):
        ancestor = PurePosixPath(*parts[:length]).as_posix() if length else ""
        if not any((ancestor, lock_name) in raw_by_location for lock_name in lock_names):
            continue
        relative = directory[len(ancestor) :].lstrip("/") if ancestor else directory
        for workspace_name in workspace_names:
            workspace_raw = raw_by_location.get((ancestor, workspace_name))
            if (
                workspace_raw is not None
                and relative
                and _is_workspace_member(
                    relative,
                    _workspace_patterns(workspace_name, workspace_raw),
                )
            ):
                locations.extend(
                    (ancestor, lock_name)
                    for lock_name in sorted(lock_names)
                    if (ancestor, lock_name) in raw_by_location
                )
                return locations
    return []


def _normalized_package_name(name: str, *, ecosystem: str) -> str:
    normalized = name.strip().casefold()
    return re.sub(r"[-_.]+", "-", normalized) if ecosystem == "PyPI" else normalized


def _declared_dependency_names(name: str, raw: bytes) -> set[str] | None:
    if name == "package.json":
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        names: set[str] = set()
        for section_name in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            section = payload.get(section_name)
            if isinstance(section, dict):
                names.update(
                    _normalized_package_name(str(item), ecosystem="npm") for item in section
                )
        return names
    text = raw.decode("utf-8", errors="replace")
    if name == "pyproject.toml":
        values = _toml_array(_toml_section(text, "project"), "dependencies")
        optional = _toml_section(text, "project.optional-dependencies")
        for block in re.findall(r"(?ms)^\s*[A-Za-z0-9_.-]+\s*=\s*\[(.*?)\]", optional):
            values.extend(item[1] for item in re.findall(r'(["\'])(.*?)(?<!\\)\1', block))
        names = set()
        for value in values:
            match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)", value)
            if match is None or re.search(
                r"@\s*(?:file:|\.\.?/|/)",
                value,
                re.IGNORECASE,
            ):
                continue
            names.add(_normalized_package_name(match.group(1), ecosystem="PyPI"))
        for section in re.findall(
            r"(?ms)^\s*\[tool\.poetry(?:\.group\.[^.]+)?\.dependencies\]\s*$"
            r"\n(.*?)(?=^\s*\[|\Z)",
            text,
        ):
            for match in re.finditer(
                r'(?m)^\s*["\']?([A-Za-z0-9][A-Za-z0-9_.-]*)["\']?\s*=\s*([^#\n]+)',
                section,
            ):
                if (
                    match.group(1).casefold() != "python"
                    and not re.search(r"\bpath\s*=", match.group(2))
                ):
                    names.add(_normalized_package_name(match.group(1), ecosystem="PyPI"))
        return names
    if name == "cargo.toml":
        names: set[str] = set()
        for section in re.findall(
            r"(?ms)^\s*\[(?:(?:workspace|target\.[^]]+)\.)?"
            r"(?:dev-|build-)?dependencies\]\s*$\n(.*?)(?=^\s*\[|\Z)",
            text,
        ):
            for match in re.finditer(
                r'(?m)^\s*["\']?([A-Za-z0-9][A-Za-z0-9_-]*)["\']?\s*=\s*([^#\n]+)',
                section,
            ):
                alias, value = match.groups()
                package = re.search(r'\bpackage\s*=\s*["\']([^"\']+)["\']', value)
                names.add((package.group(1) if package else alias).casefold())
        return names
    if name == "composer.json":
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        names = set()
        for section_name in ("require", "require-dev"):
            section = payload.get(section_name)
            if isinstance(section, dict):
                names.update(
                    str(item).casefold()
                    for item in section
                    if "/" in str(item) and not str(item).startswith(("ext-", "lib-"))
                )
        return names
    if name == "gemfile":
        if re.search(r"(?m)^\s*(?:gemspec|eval_gemfile)\b", text):
            return None
        return {
            match.group(1).casefold()
            for match in re.finditer(r'(?m)^\s*gem\s*(?:\(|\s)\s*["\']([^"\']+)["\']', text)
        }
    if name == "go.mod":
        names = {
            match.group(1).casefold()
            for match in re.finditer(r"(?m)^\s*require\s+([^\s()]+)\s+v[^\s]+", text)
        }
        for block in re.findall(r"(?ms)^\s*require\s*\((.*?)^\s*\)", text):
            names.update(
                match.group(1).casefold()
                for match in re.finditer(r"(?m)^\s*([^\s/][^\s]*)\s+v[^\s]+", block)
            )
        local_replacements = {
            match.group(1).casefold()
            for match in re.finditer(
                r"(?m)^\s*replace\s+([^\s]+)(?:\s+v[^\s]+)?\s+=>\s+(?:\./|\.\./|/)",
                text,
            )
        }
        for block in re.findall(r"(?ms)^\s*replace\s*\((.*?)^\s*\)", text):
            local_replacements.update(
                match.group(1).casefold()
                for match in re.finditer(
                    r"(?m)^\s*([^\s]+)(?:\s+v[^\s]+)?\s+=>\s+(?:\./|\.\./|/)",
                    block,
                )
            )
        names.difference_update(local_replacements)
        return names
    if name == "pom.xml":
        try:
            root = ElementTree.fromstring(raw)
        except ElementTree.ParseError:
            return None
        names = set()
        dependencies = root.find("{*}dependencies")
        if dependencies is None:
            return names
        for dependency in dependencies.findall("{*}dependency"):
            group = dependency.findtext("{*}groupId")
            artifact = dependency.findtext("{*}artifactId")
            if group and artifact:
                names.add(f"{group}:{artifact}".casefold())
        return names
    if name in {"build.gradle", "build.gradle.kts"}:
        names = {
            f"{match.group(1)}:{match.group(2)}".casefold()
            for match in re.finditer(r'["\']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):[^"\']+["\']', text)
        }
        if re.search(r"\b(?:implementation|api|compileOnly|runtimeOnly)\s*\(?\s*libs\.", text):
            return None
        return names
    return None


def _locked_dependency_names(
    locations: list[tuple[str, str]],
    raw_by_location: dict[tuple[str, str], bytes],
) -> set[str]:
    dependencies: dict[tuple[str, str, str], dict[str, str]] = {}
    for location in locations:
        reader = READERS.get(location[1])
        if reader is not None:
            reader(raw_by_location[location], dependencies)
    return {
        _normalized_package_name(item["name"], ecosystem=item["ecosystem"])
        for item in dependencies.values()
    }


def _append_install_script(
    target: list[dict[str, str]],
    *,
    path: str,
    name: str,
    command: str,
) -> None:
    normalized = " ".join(command.split())[:500]
    if not normalized:
        return
    item = {"path": path, "name": name, "command": normalized}
    if item not in target:
        target.append(item)


def _install_hooks(path: str, name: str, raw: bytes) -> list[dict[str, str]]:
    hooks: list[dict[str, str]] = []
    text = raw.decode("utf-8", errors="replace")
    if name == "package.json":
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return hooks
        scripts = payload.get("scripts") if isinstance(payload, dict) else None
        if isinstance(scripts, dict):
            for script_name in ("preinstall", "install", "postinstall", "prepare"):
                value = scripts.get(script_name)
                if isinstance(value, str):
                    _append_install_script(
                        hooks,
                        path=path,
                        name=f"npm-{script_name}",
                        command=value,
                    )
    elif name == "pyproject.toml":
        section = _toml_section(text, "build-system")
        backend = re.search(r'(?m)^\s*build-backend\s*=\s*["\']([^"\']+)["\']', section)
        backend_paths = _toml_array(section, "backend-path")
        build_requires = _toml_array(section, "requires")
        if backend:
            command = backend.group(1)
            if backend_paths:
                command += f" (backend-path: {', '.join(backend_paths)})"
            if build_requires:
                command += f" (requires: {', '.join(build_requires)})"
            _append_install_script(
                hooks,
                path=path,
                name="python-build-backend",
                command=command,
            )
    elif name == "setup.py":
        _append_install_script(
            hooks,
            path=path,
            name="python-legacy-build",
            command="setup.py is executable during legacy Python package build",
        )
    elif name == "cargo.toml":
        section = _toml_section(text, "package")
        build = re.search(r'(?m)^\s*build\s*=\s*["\']([^"\']+)["\']', section)
        if build:
            _append_install_script(
                hooks,
                path=path,
                name="cargo-package-build",
                command=build.group(1),
            )
    elif name == "build.rs":
        _append_install_script(
            hooks,
            path=path,
            name="cargo-build-script",
            command="Cargo executes build.rs during package build",
        )
    elif name == "pom.xml":
        try:
            root = ElementTree.fromstring(raw)
        except ElementTree.ParseError:
            return hooks
        for plugin in root.findall(".//{*}build/{*}plugins/{*}plugin"):
            group = plugin.findtext("{*}groupId") or "org.apache.maven.plugins"
            artifact = plugin.findtext("{*}artifactId") or "unknown-plugin"
            version = plugin.findtext("{*}version") or "unversioned"
            goals = [item.text for item in plugin.findall(".//{*}goal") if item.text]
            command = f"{group}:{artifact}@{version}"
            if goals:
                command += f" goals={','.join(goals)}"
            _append_install_script(
                hooks,
                path=path,
                name="maven-plugin",
                command=command,
            )
    elif name in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}:
        _append_install_script(
            hooks,
            path=path,
            name="gradle-build-script",
            command=f"Gradle evaluates {name} during build configuration",
        )
    elif name == "composer.json":
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return hooks
        scripts = payload.get("scripts") if isinstance(payload, dict) else None
        if isinstance(scripts, dict):
            for script_name, value in sorted(scripts.items()):
                commands = (
                    [value] if isinstance(value, str) else value if isinstance(value, list) else []
                )
                for command in commands:
                    if isinstance(command, str):
                        _append_install_script(
                            hooks,
                            path=path,
                            name=f"composer-{script_name}",
                            command=command,
                        )
        config = payload.get("config") if isinstance(payload, dict) else None
        allowed = config.get("allow-plugins") if isinstance(config, dict) else None
        if isinstance(allowed, dict):
            for plugin, enabled in sorted(allowed.items()):
                if enabled is True:
                    _append_install_script(
                        hooks,
                        path=path,
                        name="composer-plugin",
                        command=str(plugin),
                    )
    elif name == "gemfile":
        for match in re.finditer(r"(?m)^\s*(gemspec|eval_gemfile)\b([^#\n]*)", text):
            _append_install_script(
                hooks,
                path=path,
                name=f"ruby-{match.group(1).replace('_', '-')}",
                command=match.group(0),
            )
    elif name.endswith(".gemspec"):
        _append_install_script(
            hooks,
            path=path,
            name="ruby-gemspec-file",
            command=f"RubyGems evaluates {name} during package build",
        )
        extension = re.search(
            r"(?m)^\s*(?:[A-Za-z_][\w]*\.)?extensions\s*=\s*([^#\n]+)",
            text,
        )
        if extension:
            _append_install_script(
                hooks,
                path=path,
                name="ruby-native-extension",
                command=extension.group(0),
            )
    return hooks


def _manifest_identity(files: list[tuple[str, bytes]]) -> tuple[str | None, str | None]:
    candidates = sorted(
        files,
        key=lambda item: (len(PurePosixPath(item[0]).parts), item[0]),
    )
    for path, raw in candidates:
        name = PurePosixPath(path).name.casefold()
        text = raw.decode("utf-8", errors="replace")
        if name in {"package.json", "composer.json"}:
            try:
                payload = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and payload.get("name"):
                return str(payload["name"]), str(payload.get("version") or "") or None
        elif name == "pyproject.toml":
            section = _toml_section(text, "project")
            project_name = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', section)
            version = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', section)
            if project_name:
                return project_name.group(1), version.group(1) if version else None
        elif name == "cargo.toml":
            section = _toml_section(text, "package")
            package_name = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', section)
            version = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', section)
            if package_name:
                return package_name.group(1), version.group(1) if version else None
        elif name == "go.mod":
            module = re.search(r"(?m)^\s*module\s+([^\s]+)", text)
            if module:
                return module.group(1), None
        elif name == "pom.xml":
            try:
                root = ElementTree.fromstring(raw)
            except ElementTree.ParseError:
                continue
            artifact = root.findtext("{*}artifactId")
            version = root.findtext("{*}version")
            if artifact:
                return artifact, version
    return None, None


def _root_component(
    files: list[tuple[str, bytes]],
    *,
    artifact_sha256: str | None = None,
    content_manifest_sha256: str | None = None,
) -> dict:
    evidence = [
        {"path": path, "sha256": hashlib.sha256(raw).hexdigest()} for path, raw in sorted(files)
    ]
    evidence_digest = hashlib.sha256(_canonical(evidence)).hexdigest()
    artifact_digest = (
        artifact_sha256
        if isinstance(artifact_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)
        else None
    )
    content_manifest_digest = (
        content_manifest_sha256
        if isinstance(content_manifest_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", content_manifest_sha256)
        else None
    )
    digest = artifact_digest or content_manifest_digest or evidence_digest
    identity_kind = (
        "artifact"
        if artifact_digest
        else "content-manifest"
        if content_manifest_digest
        else "dependency-evidence"
    )
    name, version = _manifest_identity(files)
    component = {
        "type": "application",
        "bom-ref": f"urn:qindun:{identity_kind}:{digest}",
        "name": name or "qindun-scanned-artifact",
        "properties": [
            {"name": "qindun:dependency-evidence-count", "value": str(len(evidence))},
            {"name": "qindun:dependency-evidence-sha256", "value": evidence_digest},
            {
                "name": "qindun:artifact-sha256",
                "value": artifact_digest or "unavailable",
            },
            {
                "name": "qindun:content-manifest-sha256",
                "value": content_manifest_digest or "unavailable",
            },
            {
                "name": "qindun:dependency-graph",
                "value": "direct-declarations-only",
            },
        ],
    }
    if version:
        component["version"] = version
    return component


def extract(
    files: Iterable[tuple[str, bytes]],
    *,
    artifact_sha256: str | None = None,
    content_manifest_sha256: str | None = None,
) -> dict:
    normalized_files = [(_normalized_path(path), raw) for path, raw in files]
    dependencies: dict[tuple[str, str, str], dict[str, str]] = {}
    manifests: list[str] = []
    errors: list[str] = []
    install_scripts: list[dict[str, str]] = []
    direct_dependencies: set[tuple[str, str]] = set()
    raw_by_location = {
        (_parent(path), PurePosixPath(path).name.casefold()): raw
        for path, raw in normalized_files
        if len(raw) <= MAX_DEPENDENCY_FILE_BYTES
    }
    for path, raw in normalized_files:
        name = PurePosixPath(path).name.casefold()
        if name in DEPENDENCY_FILES and len(raw) > MAX_DEPENDENCY_FILE_BYTES:
            manifests.append(path)
            errors.append(f"{path}: 依赖文件超过 5 MiB 分析上限")
            continue
        install_scripts.extend(_install_hooks(path, name, raw))
        reader = READERS.get(name)
        if name.endswith(".gemspec"):
            manifests.append(path)
            if (_parent(path), "gemfile.lock") not in raw_by_location:
                errors.append(f"{path}: 没有找到同项目的 gemfile.lock 精确版本锁文件")
            continue
        if name in DECLARATION_LOCKS:
            manifests.append(path)
            if name == "setup.py":
                errors.append(f"{path}: setup.py 可能动态声明依赖，无法生成精确依赖清单")
                continue
            declared_names = _declared_dependency_names(name, raw)
            lock_locations = _project_lock_locations(
                path=path,
                name=name,
                raw_by_location=raw_by_location,
            )
            if declared_names:
                ecosystem = DECLARATION_ECOSYSTEMS.get(name)
                if ecosystem:
                    direct_dependencies.update((ecosystem, item) for item in declared_names)
            if declared_names is None:
                errors.append(f"{path}: 依赖声明包含无法静态确定的来源或格式")
            if declared_names is None or declared_names:
                if not lock_locations:
                    errors.append(f"{path}: 没有找到同项目或已声明工作区的精确版本锁文件")
            if declared_names is not None and lock_locations:
                missing = sorted(
                    declared_names - _locked_dependency_names(lock_locations, raw_by_location)
                )
                if missing:
                    errors.append(f"{path}: 声明依赖未在适用锁文件中找到：{', '.join(missing)}")
            if name == "pyproject.toml" and not lock_locations and declared_names:
                if reader is not None and not reader(raw, dependencies):
                    errors.append(f"{path}: 依赖版本不完整或格式无效")
            continue
        if reader is None:
            continue
        manifests.append(path)
        if not reader(raw, dependencies):
            errors.append(f"{path}: 依赖版本不完整或格式无效")
        elif name == "requirements.txt":
            direct: dict[tuple[str, str, str], dict[str, str]] = {}
            reader(raw, direct)
            direct_dependencies.update(
                ("PyPI", _normalized_package_name(item["name"], ecosystem="PyPI"))
                for item in direct.values()
                if item["ecosystem"] == "PyPI"
            )
    packages = [dependencies[key] for key in sorted(dependencies)]
    if len(packages) > MAX_DEPENDENCIES:
        errors.append(f"依赖数量 {len(packages)} 超过上限 {MAX_DEPENDENCIES}")
        packages = packages[:MAX_DEPENDENCIES]
    direct_refs = {
        _component(item)["bom-ref"]
        for item in packages
        if (
            item["ecosystem"],
            _normalized_package_name(item["name"], ecosystem=item["ecosystem"]),
        )
        in direct_dependencies
    }
    sbom = build_sbom(
        packages,
        root_component=_root_component(
            normalized_files,
            artifact_sha256=artifact_sha256,
            content_manifest_sha256=content_manifest_sha256,
        ),
        direct_dependency_refs=direct_refs,
    )
    return {
        "manifests": sorted(manifests),
        "packages": packages,
        "package_count": len(packages),
        "complete": not errors,
        "errors": errors,
        "install_scripts": sorted(
            install_scripts,
            key=lambda item: (item["path"], item["name"], item["command"]),
        ),
        "sbom_format": "CycloneDX 1.6",
        "direct_dependency_refs": sorted(direct_refs),
        "sbom_digest": f"sha256:{hashlib.sha256(_canonical(sbom)).hexdigest()}",
        "sbom": sbom,
    }


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _scanner_version() -> str:
    try:
        version = (Path(__file__).parents[1] / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    return version or "unknown"


def _component(dependency: dict[str, str]) -> dict:
    purl_type = {
        "PyPI": "pypi",
        "npm": "npm",
        "Go": "golang",
        "crates.io": "cargo",
        "Maven": "maven",
        "RubyGems": "gem",
        "Packagist": "composer",
        "NuGet": "nuget",
    }.get(dependency["ecosystem"], dependency["ecosystem"].lower())
    namespace = ""
    component_name = dependency["name"]
    if purl_type == "maven" and ":" in component_name:
        namespace, component_name = component_name.split(":", 1)
    elif purl_type == "npm" and component_name.startswith("@") and "/" in component_name:
        namespace, component_name = component_name.split("/", 1)
    elif purl_type in {"composer", "golang"} and "/" in component_name:
        namespace, component_name = component_name.rsplit("/", 1)
    encoded_namespace = "/".join(quote(part, safe="") for part in namespace.split("/") if part)
    purl_path = "/".join(
        value
        for value in (
            encoded_namespace,
            quote(component_name, safe=""),
        )
        if value
    )
    version = quote(dependency["version"], safe=".-_~")
    purl = f"pkg:{purl_type}/{purl_path}@{version}"
    provenance = dependency.get("provenance", "unknown")
    bom_ref = purl
    if provenance != "public":
        identity = {
            "ecosystem": dependency["ecosystem"],
            "name": dependency["name"],
            "version": dependency["version"],
            "provenance": provenance,
        }
        bom_ref = f"urn:qindun:dependency:{hashlib.sha256(_canonical(identity)).hexdigest()}"
    component = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": component_name,
        "version": dependency["version"],
        "properties": [
            {"name": "qindun:osv-ecosystem", "value": dependency["ecosystem"]},
            {"name": "qindun:source-name", "value": dependency["name"]},
            {
                "name": "qindun:provenance",
                "value": provenance,
            },
        ],
    }
    if provenance == "public":
        component["purl"] = purl
    if namespace:
        component["group"] = namespace
    return component


def build_sbom(
    dependencies: list[dict[str, str]],
    *,
    root_component: dict | None = None,
    direct_dependency_refs: set[str] | None = None,
) -> dict:
    components = []
    for dependency in sorted(
        dependencies, key=lambda item: (item["ecosystem"], item["name"], item["version"])
    ):
        components.append(_component(dependency))
    if root_component is None:
        digest = hashlib.sha256(_canonical(components)).hexdigest()
        root_component = {
            "type": "application",
            "bom-ref": f"urn:qindun:artifact:{digest}",
            "name": "qindun-scanned-artifact",
        }
    tool_component = {
        "type": "application",
        "name": "qindun-certify",
        "version": _scanner_version(),
    }
    serial_seed = hashlib.sha256(
        _canonical(
            {
                "component": root_component,
                "components": components,
                "tool": tool_component,
            }
        )
    ).hexdigest()
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"qindun-sbom:{serial_seed}")
    component_refs = sorted(item["bom-ref"] for item in components)
    direct_refs = (
        component_refs
        if direct_dependency_refs is None
        else sorted(set(component_refs) & direct_dependency_refs)
    )
    dependency_graph = [
        {"ref": root_component["bom-ref"], "dependsOn": direct_refs},
        *({"ref": reference, "dependsOn": []} for reference in component_refs),
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": {"components": [tool_component]},
            "component": root_component,
        },
        "components": components,
        "dependencies": dependency_graph,
    }


def _query_osv_batch(
    dependencies: list[dict[str, str]],
    *,
    api_url: str,
    timeout_seconds: float,
    deadline_monotonic: float,
    response_budget_bytes: int,
) -> tuple[list[dict] | None, str | None, int]:
    payload = {
        "queries": [
            {
                "package": {"name": item["name"], "ecosystem": item["ecosystem"]},
                "version": item["version"],
            }
            for item in dependencies
        ]
    }
    raw = b""
    bytes_read = 0
    for attempt in range(MAX_OSV_RETRIES + 1):
        retry_after_seconds: float | None = None
        remaining_seconds = deadline_monotonic - time.monotonic()
        if remaining_seconds <= 0:
            return None, "OSV 查询超过整次扫描总时限", bytes_read
        if response_budget_bytes <= 0:
            return None, "OSV 响应超过整次扫描总大小上限", bytes_read
        request = Request(
            api_url,
            data=_canonical(payload),
            headers={"Content-Type": "application/json", "User-Agent": "qindun-certify"},
            method="POST",
        )
        try:
            with urlopen(
                request,
                timeout=min(timeout_seconds, remaining_seconds),
            ) as response:
                response_limit = min(
                    MAX_OSV_RESPONSE_BYTES,
                    response_budget_bytes,
                )
                raw = response.read(response_limit + 1)
                bytes_read += len(raw)
            break
        except HTTPError as error:
            retryable = error.code in {408, 429, 500, 502, 503, 504}
            if not retryable or attempt >= MAX_OSV_RETRIES:
                return None, f"OSV 查询失败：HTTP {error.code}", bytes_read
            if error.headers is not None:
                retry_after = error.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    retry_after_seconds = min(float(retry_after), 5.0)
        except (URLError, TimeoutError, OSError) as error:
            if attempt >= MAX_OSV_RETRIES:
                return None, f"OSV 查询失败：{type(error).__name__}", bytes_read
        delay = retry_after_seconds or OSV_RETRY_DELAY_SECONDS * (attempt + 1)
        remaining_seconds = deadline_monotonic - time.monotonic()
        if remaining_seconds <= delay:
            return None, "OSV 查询超过整次扫描总时限", bytes_read
        time.sleep(delay)
    if len(raw) > MAX_OSV_RESPONSE_BYTES:
        return None, "OSV 响应超过单批大小上限", bytes_read
    if len(raw) > response_budget_bytes:
        return None, "OSV 响应超过整次扫描总大小上限", bytes_read
    try:
        body = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        body = None
    results = body.get("results") if isinstance(body, dict) else None
    if not isinstance(results, list) or len(results) != len(dependencies):
        return None, "OSV 响应没有覆盖全部依赖", bytes_read
    for result in results:
        vulnerabilities = result.get("vulns", []) if isinstance(result, dict) else None
        if not isinstance(vulnerabilities, list) or not all(
            isinstance(item, dict) for item in vulnerabilities
        ):
            return None, "OSV 响应中的漏洞记录格式无效", bytes_read
    return results, None, bytes_read


def query_osv(
    dependencies: list[dict[str, str]],
    *,
    api_url: str = DEFAULT_OSV_URL,
    timeout_seconds: float = 15.0,
    overall_timeout_seconds: float = MAX_OSV_TOTAL_SECONDS,
    max_total_response_bytes: int = MAX_OSV_TOTAL_RESPONSE_BYTES,
) -> dict:
    queryable = [item for item in dependencies if item.get("provenance", "unknown") == "public"]
    skipped = [
        {
            "ecosystem": item.get("ecosystem"),
            "name": item.get("name"),
            "version": item.get("version"),
            "provenance": item.get("provenance", "unknown"),
            "reason": "不是已确认的公开仓库依赖，未发送给 OSV",
        }
        for item in dependencies
        if item.get("provenance", "unknown") != "public"
    ]
    batches = [
        queryable[index : index + MAX_OSV_BATCH_SIZE]
        for index in range(0, len(queryable), MAX_OSV_BATCH_SIZE)
    ]
    vulnerabilities = []
    errors = []
    failed_batches = []
    completed_queries = 0
    completed_batches = 0
    total_response_bytes = 0
    started = time.monotonic()
    deadline = started + max(0.001, overall_timeout_seconds)
    for batch_number, batch in enumerate(batches, start=1):
        if time.monotonic() >= deadline or total_response_bytes >= max_total_response_bytes:
            failed_batches.extend(range(batch_number, len(batches) + 1))
            errors.append("OSV 查询达到整次扫描总时限或总响应大小上限，剩余批次未发送")
            break
        results, error, response_bytes = _query_osv_batch(
            batch,
            api_url=api_url,
            timeout_seconds=timeout_seconds,
            deadline_monotonic=deadline,
            response_budget_bytes=max_total_response_bytes - total_response_bytes,
        )
        total_response_bytes += response_bytes
        if results is None:
            failed_batches.append(batch_number)
            errors.append(f"批次 {batch_number}/{len(batches)}：{error}")
            continue
        completed_batches += 1
        completed_queries += len(batch)
        for dependency, result in zip(batch, results):
            entries = result.get("vulns") if isinstance(result, dict) else []
            for vulnerability in entries or []:
                vulnerability_id = str(vulnerability.get("id") or "unknown")
                raw_aliases = vulnerability.get("aliases")
                aliases = (
                    [str(item) for item in raw_aliases][:20]
                    if isinstance(raw_aliases, list)
                    else []
                )
                vulnerabilities.append(
                    {
                        "dependency": dependency,
                        "id": vulnerability_id,
                        "aliases": aliases,
                    }
                )
    return {
        "requested": True,
        "complete": not failed_batches,
        "vulnerabilities": vulnerabilities,
        "error": "; ".join(errors) if errors else None,
        "batch_count": len(batches),
        "completed_batches": completed_batches,
        "failed_batches": failed_batches,
        "completed_queries": completed_queries,
        "total_queries": len(queryable),
        "input_dependency_count": len(dependencies),
        "skipped_dependencies": skipped,
        "total_response_bytes": total_response_bytes,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "overall_timeout_seconds": overall_timeout_seconds,
        "max_total_response_bytes": max_total_response_bytes,
    }
