from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

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


DEFAULT_INSTALL_PLAN_CACHE_TTL_SECONDS = 900
INSTALL_PLAN_CACHE_VERSION = 1
_PLAN_CACHE_ENV_KEYS = (
    "PIP_CONFIG_FILE",
    "PIP_EXTRA_INDEX_URL",
    "PIP_FIND_LINKS",
    "PIP_INDEX_URL",
    "PIP_NO_INDEX",
    "PIP_TRUSTED_HOST",
)
_CACHE_KEY_IGNORED_VALUE_OPTIONS = {
    "-t",
    "--target",
    "--prefix",
    "--progress-bar",
    "--root",
    "--timeout",
}
_CACHE_KEY_IGNORED_FLAGS = {"--disable-pip-version-check"}


def resolve_install_plan(
    pip_args: list[str],
    *,
    ignore_installed: bool = False,
    use_cache: bool = False,
) -> InstallPlan:
    effective_args = _normalized_plan_args(
        pip_args,
        ignore_installed=ignore_installed,
    )
    if use_cache:
        cached_report = _load_cached_install_plan_report(effective_args)
        if cached_report is not None:
            return install_plan_from_report(cached_report)

    command = _build_pip_command(
        [
            "install",
            "--disable-pip-version-check",
            "--dry-run",
            "--quiet",
            "--report",
            "-",
            *effective_args,
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

    report = json.loads(completed.stdout)
    if use_cache:
        _store_cached_install_plan_report(effective_args, report)
    return install_plan_from_report(report)


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


def _normalized_plan_args(
    pip_args: list[str],
    *,
    ignore_installed: bool,
) -> list[str]:
    normalized = _strip_conflicting_report_args(pip_args)
    if ignore_installed and "--ignore-installed" not in normalized:
        normalized = ["--ignore-installed", *normalized]
    return normalized


def _pip_report_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    return env


def _build_pip_command(argv: list[str]) -> list[str]:
    return [sys.executable, "-m", "pip", *argv]


def _load_cached_install_plan_report(pip_args: list[str]) -> dict | None:
    ttl_seconds = _install_plan_cache_ttl_seconds()
    if ttl_seconds <= 0 or not _install_plan_cacheable(pip_args):
        return None

    cache_path = _install_plan_cache_path(pip_args)
    if not cache_path.exists():
        return None

    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    if payload.get("version") != INSTALL_PLAN_CACHE_VERSION:
        return None

    created_at = payload.get("created_at")
    if not isinstance(created_at, (int, float)):
        return None
    if (time.time() - float(created_at)) > ttl_seconds:
        return None

    report = payload.get("report")
    return report if isinstance(report, dict) else None


def _store_cached_install_plan_report(pip_args: list[str], report: dict) -> None:
    ttl_seconds = _install_plan_cache_ttl_seconds()
    if ttl_seconds <= 0 or not _install_plan_cacheable(pip_args):
        return

    cache_path = _install_plan_cache_path(pip_args)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = cache_path.with_name(
        f".{cache_path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    )
    payload = {
        "version": INSTALL_PLAN_CACHE_VERSION,
        "created_at": time.time(),
        "report": report,
    }
    try:
        temporary_path.write_text(
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
        os.replace(temporary_path, cache_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _install_plan_cacheable(pip_args: list[str]) -> bool:
    value_options = {
        "-c",
        "--constraint",
        "-e",
        "--editable",
        "-f",
        "--find-links",
        "-r",
        "--requirement",
        "--report",
    }
    i = 0
    while i < len(pip_args):
        arg = pip_args[i]
        option_name = arg.split("=", 1)[0]
        if arg == "--":
            return all(not _is_direct_or_local_target(value) for value in pip_args[i + 1 :])
        if option_name in value_options:
            return False
        if arg.startswith("-"):
            i += 2 if "=" not in arg and _option_expects_value(option_name) else 1
            continue
        if _is_direct_or_local_target(arg):
            return False
        i += 1
    return True


def _option_expects_value(option_name: str) -> bool:
    return option_name in {
        "-c",
        "--constraint",
        "-e",
        "--editable",
        "-f",
        "--find-links",
        "-r",
        "--requirement",
        "-t",
        "--target",
        "--prefix",
        "--python",
        "--index-url",
        "--extra-index-url",
        "--progress-bar",
        "--root",
        "--timeout",
        "--trusted-host",
    }


def _is_direct_or_local_target(value: str) -> bool:
    from packaging.requirements import InvalidRequirement, Requirement
    from urllib.parse import urlparse

    try:
        requirement = Requirement(value)
    except InvalidRequirement:
        requirement = None

    if requirement is not None:
        if requirement.url:
            return True
        return False

    parsed = urlparse(value)
    if parsed.scheme:
        return parsed.scheme != "https" and parsed.scheme != "http"

    if value in {".", ".."}:
        return True
    if value.startswith(("./", "../", ".\\", "..\\")):
        return True

    path = Path(value)
    if path.is_absolute() or path.exists():
        return True

    suffixes = path.suffixes
    if suffixes[-1:] == [".whl"]:
        return True
    if suffixes[-2:] == [".tar", ".gz"] or suffixes[-1:] == [".zip"]:
        return True
    return False


def _install_plan_cache_path(pip_args: list[str]) -> Path:
    payload = {
        "argv": _cache_key_plan_args(pip_args),
        "config_signatures": _pip_config_signatures(os.environ),
        "cwd": str(Path.cwd()),
        "env": {
            key: value
            for key in _PLAN_CACHE_ENV_KEYS
            if (value := os.environ.get(key))
        },
        "python": {
            "executable": sys.executable,
            "version": list(sys.version_info[:3]),
        },
        "version": INSTALL_PLAN_CACHE_VERSION,
    }
    digest = hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return _install_plan_cache_root() / digest[:2] / f"{digest}.json"


def _cache_key_plan_args(pip_args: list[str]) -> list[str]:
    normalized: list[str] = []
    i = 0
    while i < len(pip_args):
        arg = pip_args[i]
        option_name = arg.split("=", 1)[0]
        if option_name in _CACHE_KEY_IGNORED_VALUE_OPTIONS:
            i += 1 if "=" in arg else 2
            continue
        if arg in _CACHE_KEY_IGNORED_FLAGS:
            i += 1
            continue
        normalized.append(arg)
        if (
            "=" not in arg
            and arg.startswith("-")
            and _option_expects_value(option_name)
            and i + 1 < len(pip_args)
        ):
            normalized.append(pip_args[i + 1])
            i += 2
            continue
        i += 1
    return normalized


def _install_plan_cache_root() -> Path:
    configured = os.environ.get("SPIP_CACHE_DIR")
    if configured:
        return Path(configured).expanduser() / "install-plans"

    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if local_app_data:
            return Path(local_app_data) / "spip" / "cache" / "install-plans"

    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        return Path(xdg_cache_home) / "spip" / "install-plans"
    return Path.home() / ".cache" / "spip" / "install-plans"


def _install_plan_cache_ttl_seconds() -> int:
    configured = os.environ.get("SPIP_INSTALL_PLAN_CACHE_TTL_SECONDS")
    if configured is None:
        return DEFAULT_INSTALL_PLAN_CACHE_TTL_SECONDS
    try:
        return max(0, int(configured))
    except ValueError:
        return DEFAULT_INSTALL_PLAN_CACHE_TTL_SECONDS


def _pip_config_signatures(env: dict[str, str]) -> list[tuple[str, int, int]]:
    signatures: list[tuple[str, int, int]] = []
    for path in _pip_config_paths(env):
        try:
            stat = path.stat()
        except OSError:
            continue
        signatures.append((str(path.resolve()), stat.st_mtime_ns, stat.st_size))
    return signatures


def _pip_config_paths(env: dict[str, str]) -> list[Path]:
    paths: list[Path] = []
    home = Path(env.get("HOME") or env.get("USERPROFILE") or Path.home())
    virtual_env = env.get("VIRTUAL_ENV")
    appdata = env.get("APPDATA")
    programdata = env.get("PROGRAMDATA")
    xdg_config_home = env.get("XDG_CONFIG_HOME")
    configured = env.get("PIP_CONFIG_FILE")

    if configured:
        paths.append(Path(configured))
    if programdata:
        paths.append(Path(programdata) / "pip" / "pip.ini")
    paths.append(Path("/etc/pip.conf"))
    if appdata:
        paths.append(Path(appdata) / "pip" / "pip.ini")
    if xdg_config_home:
        paths.append(Path(xdg_config_home) / "pip" / "pip.conf")
    else:
        paths.append(home / ".config" / "pip" / "pip.conf")
    paths.append(home / "pip" / "pip.ini")
    paths.append(home / ".pip" / "pip.conf")
    if virtual_env:
        paths.append(Path(virtual_env) / "pip.ini")
        paths.append(Path(virtual_env) / "pip.conf")

    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped
