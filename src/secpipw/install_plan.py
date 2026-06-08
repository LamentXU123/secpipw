from __future__ import annotations

import json
import os
import subprocess
import sys

class _FrozenRecord:
    __slots__ = ()
    _field_names: tuple[str, ...] = ()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __repr__(self) -> str:
        values = ", ".join(
            f"{name}={getattr(self, name)!r}" for name in self._field_names
        )
        return f"{type(self).__name__}({values})"

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return False
        return all(
            getattr(self, name) == getattr(other, name) for name in self._field_names
        )

    def __hash__(self) -> int:
        return hash(tuple(getattr(self, name) for name in self._field_names))


class ResolvedPackage(_FrozenRecord):
    __slots__ = (
        "name",
        "version",
        "requested",
        "is_direct",
        "download_url",
        "artifact_name",
        "archive_hash",
        "requires_dist",
        "metadata",
        "yanked",
        "yanked_reason",
    )
    _field_names = __slots__

    def __init__(
        self,
        *,
        name: str,
        version: str,
        requested: bool,
        is_direct: bool,
        download_url: str | None,
        artifact_name: str | None,
        archive_hash: str | None,
        requires_dist: tuple[str, ...],
        metadata: dict,
        yanked: bool = False,
        yanked_reason: str | None = None,
    ) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "requested", requested)
        object.__setattr__(self, "is_direct", is_direct)
        object.__setattr__(self, "download_url", download_url)
        object.__setattr__(self, "artifact_name", artifact_name)
        object.__setattr__(self, "archive_hash", archive_hash)
        object.__setattr__(self, "requires_dist", requires_dist)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "yanked", yanked)
        object.__setattr__(self, "yanked_reason", yanked_reason)

    name: str
    version: str
    requested: bool
    is_direct: bool
    download_url: str | None
    artifact_name: str | None
    archive_hash: str | None
    requires_dist: tuple[str, ...]
    metadata: dict
    yanked: bool
    yanked_reason: str | None


class InstallPlan(_FrozenRecord):
    __slots__ = ("packages", "raw_report")
    _field_names = __slots__

    def __init__(self, packages: tuple[ResolvedPackage, ...], raw_report: dict) -> None:
        object.__setattr__(self, "packages", packages)
        object.__setattr__(self, "raw_report", raw_report)

    packages: tuple[ResolvedPackage, ...]
    raw_report: dict


class InstallPlanError(RuntimeError):
    def __init__(self, returncode: int, stderr: str, stdout: str) -> None:
        super().__init__("failed to resolve install plan")
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


def resolve_install_plan(pip_args: list[str]) -> InstallPlan:
    command = _build_pip_command(
        [
            "install",
            "--dry-run",
            "--quiet",
            "--report",
            "-",
            *_strip_conflicting_report_args(pip_args),
        ]
    )
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        env=_pip_report_env(),
    )
    if completed.returncode != 0:
        raise InstallPlanError(
            returncode=completed.returncode,
            stderr=completed.stderr,
            stdout=completed.stdout,
        )

    return install_plan_from_report(json.loads(completed.stdout))


def install_plan_from_report(report: dict) -> InstallPlan:
    packages = tuple(
        package
        for item in report.get("install", [])
        if (package := _package_from_report_item(item)) is not None
    )
    return InstallPlan(packages=packages, raw_report=report)


def render_install_plan(plan: InstallPlan) -> str:
    from secpipw.severity import Severity
    from secpipw.terminal import colorize

    lines = [
        colorize(
            f"[INFO] resolved packages to download ({len(plan.packages)}):",
            Severity.INFO,
        )
    ]
    for package in plan.packages:
        suffix = " [requested]" if package.requested else ""
        lines.append(
            colorize(f"  - {package.name}=={package.version}{suffix}", Severity.INFO)
        )
    return "\n".join(lines)


def _package_from_report_item(item: dict) -> ResolvedPackage | None:
    metadata = item.get("metadata") or {}
    name = metadata.get("name")
    version = metadata.get("version")
    if not name or not version:
        return None

    download_info = item.get("download_info") or {}
    download_url = download_info.get("url")
    archive_hash = _archive_hash_from_download_info(download_info)
    requires_dist = tuple(metadata.get("requires_dist") or ())
    return ResolvedPackage(
        name=name,
        version=version,
        requested=bool(item.get("requested")),
        is_direct=bool(item.get("is_direct")),
        download_url=download_url,
        artifact_name=_artifact_name_from_url(download_url),
        archive_hash=archive_hash,
        requires_dist=requires_dist,
        metadata=dict(metadata),
        yanked=bool(item.get("is_yanked")),
        yanked_reason=_yanked_reason_from_report_item(item),
    )


def _artifact_name_from_url(download_url: str | None) -> str | None:
    from pathlib import PurePosixPath
    from urllib.parse import unquote, urlparse

    if not download_url:
        return None
    parsed = urlparse(download_url)
    if not parsed.path:
        return None
    return unquote(PurePosixPath(parsed.path).name) or None


def _archive_hash_from_download_info(download_info: dict) -> str | None:
    archive_info = download_info.get("archive_info") or {}
    value = archive_info.get("hash")
    if isinstance(value, str) and value:
        return value
    hashes = archive_info.get("hashes") or {}
    if isinstance(hashes, dict):
        sha256 = hashes.get("sha256")
        if isinstance(sha256, str) and sha256:
            return f"sha256={sha256}"
        for algorithm, digest in hashes.items():
            if isinstance(algorithm, str) and isinstance(digest, str) and digest:
                return f"{algorithm}={digest}"
    return None


def _yanked_reason_from_report_item(item: dict) -> str | None:
    value = item.get("yanked_reason")
    if isinstance(value, str) and value.strip():
        return value.strip()
    download_info = item.get("download_info") or {}
    value = download_info.get("yanked_reason")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _strip_conflicting_report_args(args: list[str]) -> list[str]:
    result: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--report":
            skip_next = True
            continue
        if arg.startswith("--report="):
            continue
        result.append(arg)
    return result


def _pip_report_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    return env


def _build_pip_command(argv: list[str]) -> list[str]:
    return [sys.executable, "-m", "pip", *argv]
