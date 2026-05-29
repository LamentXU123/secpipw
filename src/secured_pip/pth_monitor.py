from __future__ import annotations

import hashlib
import configparser
import csv
import json
import re
import site
import subprocess
import sys
import sysconfig
import tarfile
import zipfile
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from pathlib import PurePosixPath
from typing import Callable, Iterable, Iterator, TextIO

from packaging.utils import canonicalize_name

from secured_pip.severity import Severity
from secured_pip.terminal import colorize
from secured_pip.warning_gate import GateDecision
from secured_pip.warning_gate import enforce_warning_policy

IMPORT_LINE_RE = re.compile(r"^\s*import\b")
PIP_OPTIONS_WITH_VALUE = {
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--python",
}


@dataclass(frozen=True)
class SuspiciousPthAlert:
    severity: Severity
    path: Path
    import_lines: tuple[str, ...]
    message: str
    remediation: str


@dataclass(frozen=True)
class PthSnapshotEntry:
    mtime_ns: int
    size: int
    digest: str


@dataclass(frozen=True)
class PackageArtifactHistoryAlert:
    severity: Severity
    package_name: str
    previous_version: str | None
    current_version: str | None
    change_type: str
    message: str


@dataclass(frozen=True)
class PthMonitor:
    directories: tuple[Path, ...]
    snapshot: dict[Path, PthSnapshotEntry]

    @classmethod
    def from_install_args(cls, pip_args: list[str]) -> "PthMonitor":
        directories = tuple(resolve_watch_directories(pip_args))
        snapshot = snapshot_pth_files(directories)
        return cls(directories=directories, snapshot=snapshot)

    def inspect(self) -> list[SuspiciousPthAlert]:
        after = snapshot_pth_files(self.directories, previous_snapshot=self.snapshot)
        alerts: list[SuspiciousPthAlert] = []
        for path, entry in after.items():
            if self.snapshot.get(path) == entry:
                continue
            import_lines = tuple(find_import_lines(path))
            if not import_lines:
                continue
            alerts.append(
                SuspiciousPthAlert(
                    severity=Severity.MEDIUM,
                    path=path,
                    import_lines=import_lines,
                    message=f"'{path}' contains executable import statements in a .pth file",
                    remediation="review and delete the .pth file if it is not expected",
                )
            )
        return alerts


def inspect_install_artifacts(
    requirements: Iterable[object],
) -> list[SuspiciousPthAlert]:
    alerts: list[SuspiciousPthAlert] = []
    seen_paths: set[Path] = set()
    for req in requirements:
        for local_file_path in (
            getattr(req, "_spip_prebuild_local_file_path", None),
            getattr(req, "local_file_path", None),
        ):
            if not local_file_path:
                continue
            artifact_path = Path(local_file_path).resolve()
            if artifact_path in seen_paths:
                continue
            seen_paths.add(artifact_path)
            if artifact_path.suffix.lower() == ".whl":
                alerts.extend(inspect_wheel_for_suspicious_pth(artifact_path))
                continue
            if _is_supported_sdist_path(artifact_path):
                alerts.extend(inspect_source_artifact_for_suspicious_pth(artifact_path))
    return alerts


def gate_suspicious_pth_alerts(
    alerts: Iterable[SuspiciousPthAlert],
    *,
    ignore_warning: bool,
    sensitivity: Severity,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
    is_tty: Callable[[], bool] | None = None,
) -> GateDecision:
    alert_list = list(alerts)
    stderr = sys.stderr if stderr is None else stderr
    if not alert_list:
        return GateDecision(allow_install=True, exit_code=0)

    stderr.write(render_suspicious_pth_alerts(alert_list) + "\n")
    return enforce_warning_policy(
        alert_list,
        ignore_warning=ignore_warning,
        sensitivity=sensitivity,
        stdin=stdin,
        stderr=stderr,
        is_tty=is_tty,
    )


def inspect_wheel_for_suspicious_pth(path: Path) -> list[SuspiciousPthAlert]:
    with zipfile.ZipFile(path) as archive:
        return _inspect_zip_archive_for_suspicious_pth(
            archive,
            archive_path=path,
            remediation=(
                "review the package artifact before installation, or rerun "
                "with --ignore-warning if this .pth file is expected"
            )
        )


def inspect_source_artifact_for_suspicious_pth(path: Path) -> list[SuspiciousPthAlert]:
    if path.suffix.lower() == ".zip":
        return inspect_zip_sdist_for_suspicious_pth(path)
    return inspect_sdist_for_suspicious_pth(path)


def inspect_sdist_for_suspicious_pth(path: Path) -> list[SuspiciousPthAlert]:
    alerts: list[SuspiciousPthAlert] = []
    with tarfile.open(path) as archive:
        for member_name, content in _iter_sdist_pth_files(archive):
            import_lines = tuple(_import_lines_from_text(content))
            if not import_lines:
                continue
            alert_path = path / member_name
            alerts.append(
                SuspiciousPthAlert(
                    severity=Severity.MEDIUM,
                    path=alert_path,
                    import_lines=import_lines,
                    message=(
                        f"'{member_name}' inside '{path.name}' contains executable "
                        "import statements in a .pth file"
                    ),
                    remediation=(
                        "review the source artifact before installation, or rerun "
                        "with --ignore-warning if this .pth file is expected"
                    ),
                )
            )
    return alerts


def inspect_zip_sdist_for_suspicious_pth(path: Path) -> list[SuspiciousPthAlert]:
    with zipfile.ZipFile(path) as archive:
        return _inspect_zip_archive_for_suspicious_pth(
            archive,
            archive_path=path,
            remediation=(
                "review the source artifact before installation, or rerun "
                "with --ignore-warning if this .pth file is expected"
            )
        )


def handle_suspicious_pth_alerts(
    alerts: Iterable[SuspiciousPthAlert],
    *,
    ignore_warning: bool,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
    is_tty: Callable[[], bool] | None = None,
) -> GateDecision:
    alert_list = list(alerts)
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    is_tty = (lambda: sys.stdin.isatty()) if is_tty is None else is_tty

    if not alert_list:
        return GateDecision(allow_install=True, exit_code=0)

    stderr.write(render_suspicious_pth_alerts(alert_list) + "\n")
    if ignore_warning:
        return GateDecision(allow_install=True, exit_code=0)

    if not is_tty():
        stderr.write(
            colorize(
                "installation completed, but suspicious .pth files were found.\n",
                Severity.MEDIUM,
            )
        )
        stderr.write(
            colorize(
                "run interactively to choose deletion, or rerun with --ignore-warning "
                "to ignore this warning.\n",
                Severity.MEDIUM,
            )
        )
        return GateDecision(allow_install=False, exit_code=2)

    stderr.write(
        colorize(
            "delete suspicious .pth file(s)? enter y/n [y/N] "
            "(rerun with --ignore-warning to ignore this warning): ",
            Severity.MEDIUM,
        )
    )
    stderr.flush()
    answer = stdin.readline().strip().lower()
    if answer in {"y", "yes"}:
        deleted = delete_pth_files(alert_list)
        if deleted:
            stderr.write(
                colorize(
                    f"deleted {deleted} suspicious .pth file(s).\n",
                    Severity.MEDIUM,
                )
            )
        return GateDecision(allow_install=True, exit_code=0)

    stderr.write(colorize("keeping suspicious .pth file(s).\n", Severity.MEDIUM))
    return GateDecision(allow_install=True, exit_code=0)


def render_suspicious_pth_alerts(alerts: Iterable[SuspiciousPthAlert]) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] suspicious-pth: {alert.message}",
                alert.severity,
            )
        )
        lines.append(colorize(f"  path: {alert.path}", alert.severity))
        for import_line in alert.import_lines:
            lines.append(colorize(f"  import line: {import_line}", alert.severity))
        lines.append(colorize(f"  suggestion: {alert.remediation}", alert.severity))
    return "\n".join(lines)


def delete_pth_files(alerts: Iterable[SuspiciousPthAlert]) -> int:
    count = 0
    for alert in alerts:
        if alert.path.exists():
            alert.path.unlink()
            count += 1
    return count


def inspect_package_artifact_history(
    packages: Iterable[object],
    install_directories: Iterable[Path],
    *,
    pip_args: list[str] | None = None,
    history_path: Path | None = None,
    update_history: bool = True,
) -> list[PackageArtifactHistoryAlert]:
    package_list = tuple(packages)
    if not package_list:
        return []

    script_directories = resolve_script_directories(pip_args or [])
    records = collect_package_artifact_records(
        package_list,
        install_directories,
        script_directories=script_directories,
    )
    if not records:
        return []

    path = package_artifact_history_path() if history_path is None else history_path
    history = load_package_artifact_history(path)
    previous_packages = history.get("packages", {})
    alerts: list[PackageArtifactHistoryAlert] = []

    for package_name, record in records.items():
        previous = previous_packages.get(package_name)
        if isinstance(previous, dict):
            alerts.extend(compare_package_artifact_record(previous, record))

    if update_history:
        updated_packages = {
            name: value
            for name, value in previous_packages.items()
            if isinstance(name, str) and isinstance(value, dict)
        }
        updated_packages.update(records)
        store_package_artifact_history({"version": 1, "packages": updated_packages}, path)

    return alerts


def handle_package_artifact_history_alerts(
    alerts: Iterable[PackageArtifactHistoryAlert],
    *,
    ignore_warning: bool,
    sensitivity: Severity,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
    is_tty: Callable[[], bool] | None = None,
) -> GateDecision:
    alert_list = list(alerts)
    stderr = sys.stderr if stderr is None else stderr
    if not alert_list:
        return GateDecision(allow_install=True, exit_code=0)

    stderr.write(render_package_artifact_history_alerts(alert_list) + "\n")
    return enforce_warning_policy(
        alert_list,
        ignore_warning=ignore_warning,
        sensitivity=sensitivity,
        stdin=stdin,
        stderr=stderr,
        is_tty=is_tty,
    )


def render_package_artifact_history_alerts(
    alerts: Iterable[PackageArtifactHistoryAlert],
) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] artifact-history: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def collect_package_artifact_records(
    packages: Iterable[object],
    install_directories: Iterable[Path],
    *,
    script_directories: Iterable[Path] = (),
) -> dict[str, dict]:
    requested = {
        canonicalize_name(str(package.name)): str(package.version)
        for package in packages
        if getattr(package, "name", None) and getattr(package, "version", None)
    }
    if not requested:
        return {}

    script_roots = _dedupe_paths(script_directories)
    records: dict[str, dict] = {}

    for site_dir in install_directories:
        if not site_dir.exists() or not site_dir.is_dir():
            continue
        for dist_info in site_dir.glob("*.dist-info"):
            metadata = _read_distribution_metadata(dist_info)
            name = metadata.get("name") or _name_from_dist_info_dir(dist_info)
            if not name:
                continue
            canonical_name = canonicalize_name(name)
            if canonical_name not in requested:
                continue
            version = metadata.get("version") or requested[canonical_name]
            records[canonical_name] = _package_artifact_record(
                name=name,
                version=version,
                dist_info=dist_info,
                site_dir=site_dir,
                script_roots=script_roots,
            )

    return records


def compare_package_artifact_record(
    previous: dict,
    current: dict,
) -> list[PackageArtifactHistoryAlert]:
    package_name = str(current.get("name") or "")
    previous_version = _optional_str(previous.get("version"))
    current_version = _optional_str(current.get("version"))
    alerts: list[PackageArtifactHistoryAlert] = []

    pth_changes = _changed_keys(
        previous.get("pth_files"),
        current.get("pth_files"),
        compare_values=True,
    )
    if pth_changes:
        alerts.append(
            PackageArtifactHistoryAlert(
                severity=Severity.MEDIUM,
                package_name=package_name,
                previous_version=previous_version,
                current_version=current_version,
                change_type="pth",
                message=_history_message(
                    package_name,
                    previous_version,
                    current_version,
                    "installed .pth files changed from the previous spip baseline",
                    pth_changes,
                ),
            )
        )

    entry_changes = _changed_sequence(
        previous.get("entry_points"),
        current.get("entry_points"),
    )
    script_changes = _changed_keys(
        previous.get("script_files"),
        current.get("script_files"),
        compare_values=False,
    )
    combined_entry_changes = [*entry_changes, *script_changes]
    if combined_entry_changes:
        alerts.append(
            PackageArtifactHistoryAlert(
                severity=Severity.LOW,
                package_name=package_name,
                previous_version=previous_version,
                current_version=current_version,
                change_type="entry",
                message=_history_message(
                    package_name,
                    previous_version,
                    current_version,
                    "entry points or script files changed from the previous spip baseline",
                    combined_entry_changes,
                ),
            )
        )

    return alerts


def package_artifact_history_path() -> Path:
    from secured_pip.pypi_api import _default_cache_root

    return _default_cache_root() / "installed-artifacts.json"


def load_package_artifact_history(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "packages": {}}
    if not isinstance(payload, dict):
        return {"version": 1, "packages": {}}
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        payload["packages"] = {}
    return payload


def store_package_artifact_history(payload: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def resolve_watch_directories(pip_args: list[str]) -> list[Path]:
    target = _option_value(pip_args, "-t", "--target")
    if target is not None:
        return [Path(target).resolve()]

    python_executable = _option_value(pip_args, "--python")
    root = _option_value(pip_args, "--root")
    prefix = _option_value(pip_args, "--prefix")
    user = "--user" in pip_args

    install_dirs = query_install_directories(
        python_executable=python_executable,
        user=user,
        prefix=prefix,
    )
    if root is None:
        return install_dirs
    return [_apply_root(Path(root).resolve(), path) for path in install_dirs]


def resolve_script_directories(pip_args: list[str]) -> list[Path]:
    target = _option_value(pip_args, "-t", "--target")
    if target is not None:
        target_path = Path(target).resolve()
        return _dedupe_paths([target_path / "bin", target_path / "Scripts"])

    python_executable = _option_value(pip_args, "--python")
    root = _option_value(pip_args, "--root")
    prefix = _option_value(pip_args, "--prefix")
    user = "--user" in pip_args

    script_dirs = query_script_directories(
        python_executable=python_executable,
        user=user,
        prefix=prefix,
    )
    if root is None:
        return script_dirs
    return [_apply_root(Path(root).resolve(), path) for path in script_dirs]


def snapshot_pth_files(
    directories: Iterable[Path],
    *,
    previous_snapshot: dict[Path, PthSnapshotEntry] | None = None,
) -> dict[Path, PthSnapshotEntry]:
    snapshot: dict[Path, PthSnapshotEntry] = {}
    for directory in directories:
        if not directory.exists() or not directory.is_dir():
            continue
        for path in directory.glob("*.pth"):
            resolved = path.resolve()
            try:
                stat = path.stat()
            except OSError:
                continue
            previous = (
                previous_snapshot.get(resolved) if previous_snapshot is not None else None
            )
            if (
                previous is not None
                and previous.mtime_ns == stat.st_mtime_ns
                and previous.size == stat.st_size
            ):
                snapshot[resolved] = previous
                continue
            snapshot[resolved] = PthSnapshotEntry(
                mtime_ns=stat.st_mtime_ns,
                size=stat.st_size,
                digest=_file_digest(path),
            )
    return snapshot


def find_import_lines(path: Path) -> list[str]:
    return list(
        _import_lines_from_text(path.read_text(encoding="utf-8", errors="ignore"))
    )


def query_install_directories(
    *,
    python_executable: str | None,
    user: bool,
    prefix: str | None,
) -> list[Path]:
    if python_executable is None:
        return _local_install_directories(user=user, prefix=prefix)
    return _remote_install_directories(
        python_executable=python_executable, user=user, prefix=prefix
    )


def query_script_directories(
    *,
    python_executable: str | None,
    user: bool,
    prefix: str | None,
) -> list[Path]:
    if python_executable is None:
        return _local_script_directories(user=user, prefix=prefix)
    return _remote_script_directories(
        python_executable=python_executable, user=user, prefix=prefix
    )


def _local_install_directories(*, user: bool, prefix: str | None) -> list[Path]:
    if user:
        return _dedupe_paths([Path(site.getusersitepackages())])

    if prefix is None:
        paths = sysconfig.get_paths()
        return _dedupe_paths([Path(paths["purelib"]), Path(paths["platlib"])])

    vars_map = {"base": prefix, "platbase": prefix}
    return _dedupe_paths(
        [
            Path(sysconfig.get_path("purelib", vars=vars_map)),
            Path(sysconfig.get_path("platlib", vars=vars_map)),
        ]
    )


def _local_script_directories(*, user: bool, prefix: str | None) -> list[Path]:
    if user:
        return _dedupe_paths([Path(site.getuserbase()) / "Scripts", Path(site.getuserbase()) / "bin"])

    if prefix is None:
        return _dedupe_paths([Path(sysconfig.get_path("scripts"))])

    vars_map = {"base": prefix, "platbase": prefix}
    return _dedupe_paths([Path(sysconfig.get_path("scripts", vars=vars_map))])


def _remote_install_directories(
    *,
    python_executable: str,
    user: bool,
    prefix: str | None,
) -> list[Path]:
    script = (
        "import json, site, sysconfig; "
        f"user={json.dumps(user)}; "
        f"prefix={json.dumps(prefix)}; "
        "paths=[]; "
        "if user: "
        " paths=[site.getusersitepackages()]; "
        "elif prefix is None: "
        " p=sysconfig.get_paths(); paths=[p['purelib'], p['platlib']]; "
        "else: "
        " vars_map={'base': prefix, 'platbase': prefix}; "
        " paths=[sysconfig.get_path('purelib', vars=vars_map), sysconfig.get_path('platlib', vars=vars_map)]; "
        "print(json.dumps(paths))"
    )
    completed = subprocess.run(
        [python_executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip() or "failed to query install directories"
        )
    return _dedupe_paths(Path(item) for item in json.loads(completed.stdout))


def _remote_script_directories(
    *,
    python_executable: str,
    user: bool,
    prefix: str | None,
) -> list[Path]:
    script = (
        "import json, site, sysconfig; "
        f"user={json.dumps(user)}; "
        f"prefix={json.dumps(prefix)}; "
        "if user: "
        " paths=[site.getuserbase() + '/Scripts', site.getuserbase() + '/bin']; "
        "elif prefix is None: "
        " paths=[sysconfig.get_path('scripts')]; "
        "else: "
        " vars_map={'base': prefix, 'platbase': prefix}; "
        " paths=[sysconfig.get_path('scripts', vars=vars_map)]; "
        "print(json.dumps(paths))"
    )
    completed = subprocess.run(
        [python_executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip() or "failed to query script directories"
        )
    return _dedupe_paths(Path(item) for item in json.loads(completed.stdout))


def _option_value(args: list[str], *names: str) -> str | None:
    for name in names:
        prefix = f"{name}="
        for index, arg in enumerate(args):
            if arg == name and index + 1 < len(args):
                return args[index + 1]
            if arg.startswith(prefix):
                return arg.split("=", 1)[1]
    return None


def _apply_root(root: Path, path: Path) -> Path:
    drive = path.drive.rstrip(":")
    parts = [part for part in path.parts if part not in {path.anchor, path.drive, "\\"}]
    if drive:
        return root.joinpath(drive, *parts)
    return root.joinpath(*parts)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_artifact_record(
    *,
    name: str,
    version: str,
    dist_info: Path,
    site_dir: Path,
    script_roots: list[Path],
) -> dict:
    pth_files: dict[str, dict] = {}
    script_files: dict[str, dict] = {}

    for installed_path in _record_paths(dist_info):
        if installed_path.suffix.lower() == ".pth" and installed_path.exists():
            key = _relative_artifact_key(installed_path, [site_dir], prefix="site")
            pth_files[key] = {
                "digest": _file_digest(installed_path),
                "import_lines": find_import_lines(installed_path),
                "size": installed_path.stat().st_size,
            }
            continue
        if _is_under_any(installed_path, script_roots) and installed_path.is_file():
            key = _relative_artifact_key(installed_path, script_roots, prefix="scripts")
            script_files[key] = {
                "digest": _file_digest(installed_path),
                "size": installed_path.stat().st_size,
            }

    return {
        "name": name,
        "version": version,
        "pth_files": pth_files,
        "entry_points": _entry_points_from_dist_info(dist_info),
        "script_files": script_files,
    }


def _record_paths(dist_info: Path) -> Iterator[Path]:
    record_path = dist_info / "RECORD"
    try:
        text = record_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    for row in csv.reader(StringIO(text)):
        if not row:
            continue
        installed = _installed_path_from_record(dist_info, row[0])
        if installed is not None:
            yield installed


def _installed_path_from_record(dist_info: Path, value: str) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path.resolve()
    parts = PurePosixPath(value).parts
    return dist_info.parent.joinpath(*parts).resolve()


def _entry_points_from_dist_info(dist_info: Path) -> list[str]:
    entry_points_path = dist_info / "entry_points.txt"
    try:
        text = entry_points_path.read_text(encoding="utf-8")
    except OSError:
        return []

    parser = configparser.ConfigParser()
    parser.optionxform = str
    try:
        parser.read_string(text)
    except configparser.Error:
        return []

    entries: list[str] = []
    for section in sorted(parser.sections()):
        for name, value in sorted(parser.items(section)):
            entries.append(f"{section}:{name}={value.strip()}")
    return entries


def _read_distribution_metadata(dist_info: Path) -> dict[str, str]:
    metadata_path = dist_info / "METADATA"
    result: dict[str, str] = {}
    try:
        lines = metadata_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return result
    for line in lines:
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower()
        if normalized_key in {"name", "version"}:
            result[normalized_key] = value.strip()
    return result


def _name_from_dist_info_dir(path: Path) -> str | None:
    name = path.name
    if not name.endswith(".dist-info"):
        return None
    stem = name[: -len(".dist-info")]
    if "-" not in stem:
        return stem or None
    return stem.rsplit("-", 1)[0] or None


def _changed_keys(
    previous: object,
    current: object,
    *,
    compare_values: bool,
) -> list[str]:
    previous_items = previous if isinstance(previous, dict) else {}
    current_items = current if isinstance(current, dict) else {}

    changes: list[str] = []
    previous_keys = set(previous_items)
    current_keys = set(current_items)
    changes.extend(f"added {key}" for key in sorted(current_keys - previous_keys))
    changes.extend(f"removed {key}" for key in sorted(previous_keys - current_keys))
    if compare_values:
        changes.extend(
            f"changed {key}"
            for key in sorted(previous_keys & current_keys)
            if previous_items.get(key) != current_items.get(key)
        )
    return changes


def _changed_sequence(previous: object, current: object) -> list[str]:
    previous_items = set(previous if isinstance(previous, list) else [])
    current_items = set(current if isinstance(current, list) else [])
    changes: list[str] = []
    changes.extend(f"added {item}" for item in sorted(current_items - previous_items))
    changes.extend(f"removed {item}" for item in sorted(previous_items - current_items))
    return changes


def _history_message(
    package_name: str,
    previous_version: str | None,
    current_version: str | None,
    summary: str,
    changes: list[str],
) -> str:
    version_text = ""
    if previous_version or current_version:
        version_text = f" ({previous_version or '?'} -> {current_version or '?'})"
    detail = "; ".join(changes[:6])
    if len(changes) > 6:
        detail += f"; and {len(changes) - 6} more"
    return f"'{package_name}'{version_text} {summary}: {detail}"


def _relative_artifact_key(path: Path, roots: Iterable[Path], *, prefix: str) -> str:
    for root in roots:
        try:
            return f"{prefix}/{path.relative_to(root)}".replace("\\", "/")
        except ValueError:
            continue
    return f"{prefix}/{path.name}"


def _is_under_any(path: Path, roots: Iterable[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
        except ValueError:
            continue
        return True
    return False


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        result.append(resolved)
    return result


def _import_lines_from_text(text: str) -> Iterator[str]:
    for line in text.splitlines():
        if IMPORT_LINE_RE.match(line):
            yield line.strip()


def _iter_sdist_pth_files(archive: tarfile.TarFile) -> Iterator[tuple[str, str]]:
    for member in archive:
        if not member.isfile() or not member.name.lower().endswith(".pth"):
            continue
        handle = archive.extractfile(member)
        if handle is None:
            continue
        yield member.name, handle.read().decode("utf-8", errors="ignore")


def _inspect_zip_archive_for_suspicious_pth(
    archive: zipfile.ZipFile,
    *,
    archive_path: Path,
    remediation: str,
) -> list[SuspiciousPthAlert]:
    alerts: list[SuspiciousPthAlert] = []
    pth_members = [
        info
        for info in archive.infolist()
        if not info.is_dir() and info.filename.lower().endswith(".pth")
    ]
    if not pth_members:
        return alerts

    for member in pth_members:
        member_name = member.filename
        import_lines = tuple(
            _import_lines_from_text(
                archive.read(member).decode("utf-8", errors="ignore")
            )
        )
        if not import_lines:
            continue
        alert_path = archive_path / member_name
        alerts.append(
            SuspiciousPthAlert(
                severity=Severity.MEDIUM,
                path=alert_path,
                import_lines=import_lines,
                message=(
                    f"'{member_name}' inside '{archive_path.name}' contains "
                    "executable import statements in a .pth file"
                ),
                remediation=remediation,
            )
        )
    return alerts


def _is_supported_sdist_path(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".zip"))
