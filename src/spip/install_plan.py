from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse

from spip.pip_bridge import build_pip_command
from spip.severity import Severity
from spip.terminal import colorize


@dataclass(frozen=True)
class ResolvedPackage:
    name: str
    version: str
    requested: bool
    is_direct: bool
    download_url: str | None
    artifact_name: str | None
    requires_dist: tuple[str, ...]


@dataclass(frozen=True)
class InstallPlan:
    packages: tuple[ResolvedPackage, ...]
    raw_report: dict


class InstallPlanError(RuntimeError):
    def __init__(self, returncode: int, stderr: str, stdout: str) -> None:
        super().__init__("failed to resolve install plan")
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


def resolve_install_plan(pip_args: list[str]) -> InstallPlan:
    command = build_pip_command(
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

    payload = json.loads(completed.stdout)
    packages = tuple(
        package
        for item in payload.get("install", [])
        if (package := _package_from_report_item(item)) is not None
    )
    return InstallPlan(packages=packages, raw_report=payload)


def render_install_plan(plan: InstallPlan) -> str:
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
    requires_dist = tuple(metadata.get("requires_dist") or ())
    return ResolvedPackage(
        name=name,
        version=version,
        requested=bool(item.get("requested")),
        is_direct=bool(item.get("is_direct")),
        download_url=download_url,
        artifact_name=_artifact_name_from_url(download_url),
        requires_dist=requires_dist,
    )


def _artifact_name_from_url(download_url: str | None) -> str | None:
    if not download_url:
        return None
    parsed = urlparse(download_url)
    if not parsed.path:
        return None
    return unquote(PurePosixPath(parsed.path).name) or None


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
