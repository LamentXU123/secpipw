from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, Iterator, TextIO

if TYPE_CHECKING:
    from secpipw.severity import Severity
    from secpipw.warning_gate import GateDecision

PYTHON_DIRECTORY_QUERY_TIMEOUT_SECONDS = 10
PIP_OPTIONS_WITH_VALUE = {
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--python",
}


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


class SuspiciousPthAlert(_FrozenRecord):
    __slots__ = ("severity", "path", "import_lines", "message", "remediation")
    _field_names = __slots__

    def __init__(
        self,
        severity: Severity,
        path: Path,
        import_lines: tuple[str, ...],
        message: str,
        remediation: str,
    ) -> None:
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "import_lines", import_lines)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "remediation", remediation)

    severity: Severity
    path: Path
    import_lines: tuple[str, ...]
    message: str
    remediation: str


class PthSnapshotEntry(_FrozenRecord):
    __slots__ = ("mtime_ns", "size", "digest")
    _field_names = __slots__

    def __init__(self, mtime_ns: int, size: int, digest: str) -> None:
        object.__setattr__(self, "mtime_ns", mtime_ns)
        object.__setattr__(self, "size", size)
        object.__setattr__(self, "digest", digest)

    mtime_ns: int
    size: int
    digest: str


class PackageArtifactHistoryAlert(_FrozenRecord):
    __slots__ = (
        "severity",
        "package_name",
        "previous_version",
        "current_version",
        "change_type",
        "message",
    )
    _field_names = __slots__

    def __init__(
        self,
        severity: Severity,
        package_name: str,
        previous_version: str | None,
        current_version: str | None,
        change_type: str,
        message: str,
    ) -> None:
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "package_name", package_name)
        object.__setattr__(self, "previous_version", previous_version)
        object.__setattr__(self, "current_version", current_version)
        object.__setattr__(self, "change_type", change_type)
        object.__setattr__(self, "message", message)

    severity: Severity
    package_name: str
    previous_version: str | None
    current_version: str | None
    change_type: str
    message: str


class PthMonitor(_FrozenRecord):
    __slots__ = ("directories", "snapshot")
    _field_names = __slots__

    def __init__(
        self,
        directories: tuple[Path, ...],
        snapshot: dict[Path, PthSnapshotEntry],
    ) -> None:
        object.__setattr__(self, "directories", directories)
        object.__setattr__(self, "snapshot", snapshot)

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
                    severity=_severity_medium(),
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
            artifact_path = _absolute_path(Path(local_file_path))
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
    ignore_severity: Severity | None = None,
    sensitivity: Severity,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
    is_tty: Callable[[], bool] | None = None,
) -> GateDecision:
    from secpipw.warning_gate import (
        GateDecision,
        enforce_warning_policy,
        filter_ignored_warnings,
    )

    alert_list = filter_ignored_warnings(alerts, ignore_severity)
    stderr = sys.stderr if stderr is None else stderr
    if not alert_list:
        return GateDecision(allow_install=True, exit_code=0)

    stderr.write(render_suspicious_pth_alerts(alert_list) + "\n")
    return enforce_warning_policy(
        alert_list,
        ignore_warning=ignore_warning,
        ignore_severity=ignore_severity,
        sensitivity=sensitivity,
        stdin=stdin,
        stderr=stderr,
        is_tty=is_tty,
    )


def inspect_wheel_for_suspicious_pth(path: Path) -> list[SuspiciousPthAlert]:
    import zipfile

    with zipfile.ZipFile(path) as archive:
        return _inspect_zip_archive_for_suspicious_pth(
            archive,
            archive_path=path,
            remediation=(
                "review the package artifact before installation, or rerun "
                "with --spip-ignore-warning if this .pth file is expected"
            ),
        )


def inspect_source_artifact_for_suspicious_pth(path: Path) -> list[SuspiciousPthAlert]:
    if path.suffix.lower() == ".zip":
        return inspect_zip_sdist_for_suspicious_pth(path)
    return inspect_sdist_for_suspicious_pth(path)


def remote_zip_artifact_contains_pth(
    download_url: str,
    *,
    initial_tail_bytes: int = 131072,
    max_tail_bytes: int = 1048576,
    timeout: float = 15.0,
) -> bool | None:
    from urllib.parse import urlparse

    parsed = urlparse(download_url)
    if parsed.scheme not in {"http", "https"}:
        return None

    tail_bytes = max(initial_tail_bytes, 4096)
    while tail_bytes <= max_tail_bytes:
        try:
            response = _fetch_http_suffix_range(
                download_url,
                tail_bytes=tail_bytes,
                timeout=timeout,
            )
        except Exception:
            return None
        if response is None:
            return None

        if not response.partial:
            return _zip_bytes_contain_pth(response.payload)

        contains_pth = _zip_tail_contains_pth(
            response.payload,
            total_size=response.total_size,
        )
        if contains_pth is not None:
            return contains_pth
        if response.total_size <= len(response.payload):
            return _zip_bytes_contain_pth(response.payload)
        tail_bytes *= 2
    return None


class _SuffixRangeResponse(_FrozenRecord):
    __slots__ = ("payload", "partial", "total_size")
    _field_names = __slots__

    def __init__(self, payload: bytes, partial: bool, total_size: int) -> None:
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "partial", partial)
        object.__setattr__(self, "total_size", total_size)

    payload: bytes
    partial: bool
    total_size: int


def inspect_sdist_for_suspicious_pth(path: Path) -> list[SuspiciousPthAlert]:
    import tarfile

    alerts: list[SuspiciousPthAlert] = []
    with tarfile.open(path) as archive:
        for member_name, content in _iter_sdist_pth_files(archive):
            import_lines = tuple(_import_lines_from_text(content))
            if not import_lines:
                continue
            alert_path = path / member_name
            alerts.append(
                SuspiciousPthAlert(
                    severity=_severity_medium(),
                    path=alert_path,
                    import_lines=import_lines,
                    message=(
                        f"'{member_name}' inside '{path.name}' contains executable "
                        "import statements in a .pth file"
                    ),
                    remediation=(
                        "review the source artifact before installation, or rerun "
                        "with --spip-ignore-warning if this .pth file is expected"
                    ),
                )
            )
    return alerts


def inspect_zip_sdist_for_suspicious_pth(path: Path) -> list[SuspiciousPthAlert]:
    import zipfile

    with zipfile.ZipFile(path) as archive:
        return _inspect_zip_archive_for_suspicious_pth(
            archive,
            archive_path=path,
            remediation=(
                "review the source artifact before installation, or rerun "
                "with --spip-ignore-warning if this .pth file is expected"
            ),
        )


def handle_suspicious_pth_alerts(
    alerts: Iterable[SuspiciousPthAlert],
    *,
    ignore_warning: bool,
    ignore_severity: Severity | None = None,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
    is_tty: Callable[[], bool] | None = None,
) -> GateDecision:
    from secpipw.terminal import colorize
    from secpipw.warning_gate import GateDecision, filter_ignored_warnings

    alert_list = filter_ignored_warnings(alerts, ignore_severity)
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
                _severity_medium(),
            )
        )
        stderr.write(
            colorize(
                "run interactively to choose deletion, or rerun with --spip-ignore-warning "
                "to ignore this warning.\n",
                _severity_medium(),
            )
        )
        return GateDecision(allow_install=False, exit_code=2)

    stderr.write(
        colorize(
            "delete suspicious .pth file(s)? enter y/n [y/N] "
            "(rerun with --spip-ignore-warning to ignore this warning): ",
            _severity_medium(),
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
                    _severity_medium(),
                )
            )
        return GateDecision(allow_install=True, exit_code=0)

    stderr.write(colorize("keeping suspicious .pth file(s).\n", _severity_medium()))
    return GateDecision(allow_install=True, exit_code=0)


def render_suspicious_pth_alerts(alerts: Iterable[SuspiciousPthAlert]) -> str:
    from secpipw.terminal import colorize

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
        store_package_artifact_history(
            {"version": 1, "packages": updated_packages}, path
        )

    return alerts


def handle_package_artifact_history_alerts(
    alerts: Iterable[PackageArtifactHistoryAlert],
    *,
    ignore_warning: bool,
    ignore_severity: Severity | None = None,
    sensitivity: Severity,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
    is_tty: Callable[[], bool] | None = None,
) -> GateDecision:
    from secpipw.warning_gate import (
        GateDecision,
        enforce_warning_policy,
        filter_ignored_warnings,
    )

    alert_list = filter_ignored_warnings(alerts, ignore_severity)
    stderr = sys.stderr if stderr is None else stderr
    if not alert_list:
        return GateDecision(allow_install=True, exit_code=0)

    stderr.write(render_package_artifact_history_alerts(alert_list) + "\n")
    return enforce_warning_policy(
        alert_list,
        ignore_warning=ignore_warning,
        ignore_severity=ignore_severity,
        sensitivity=sensitivity,
        stdin=stdin,
        stderr=stderr,
        is_tty=is_tty,
    )


def render_package_artifact_history_alerts(
    alerts: Iterable[PackageArtifactHistoryAlert],
) -> str:
    from secpipw.terminal import colorize

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
    from packaging.utils import canonicalize_name

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
        site_has_pth = any(site_dir.glob("*.pth"))
        script_roots_exist = any(root.exists() for root in script_roots)
        found: set[str] = set()
        visited: set[Path] = set()
        for canonical_name, version, dist_info in _candidate_dist_info_dirs(
            site_dir,
            requested,
        ):
            resolved_dist_info = _absolute_path(dist_info)
            if resolved_dist_info in visited:
                continue
            visited.add(resolved_dist_info)
            collected = _collect_package_artifact_record_from_dist_info(
                dist_info,
                requested,
                site_dir=site_dir,
                script_roots=script_roots,
                site_has_pth=site_has_pth,
                script_roots_exist=script_roots_exist,
                known_canonical_name=canonical_name,
                known_version=version,
            )
            if collected is None:
                continue
            canonical_name, record = collected
            records[canonical_name] = record
            found.add(canonical_name)

        if found == set(requested):
            continue

        for dist_info in site_dir.glob("*.dist-info"):
            resolved_dist_info = _absolute_path(dist_info)
            if resolved_dist_info in visited:
                continue
            collected = _collect_package_artifact_record_from_dist_info(
                dist_info=dist_info,
                requested=requested,
                site_dir=site_dir,
                script_roots=script_roots,
                site_has_pth=site_has_pth,
                script_roots_exist=script_roots_exist,
            )
            if collected is None:
                continue
            canonical_name, record = collected
            records[canonical_name] = record
            found.add(canonical_name)
            if found == set(requested):
                break

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
        _normalized_pth_files(previous.get("pth_files")),
        _normalized_pth_files(current.get("pth_files")),
        compare_values=True,
    )
    if pth_changes:
        alerts.append(
            PackageArtifactHistoryAlert(
                severity=_severity_medium(),
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
    script_changes = _changed_sequence(
        previous.get("script_files"),
        current.get("script_files"),
    )
    combined_entry_changes = [*entry_changes, *script_changes]
    if combined_entry_changes:
        alerts.append(
            PackageArtifactHistoryAlert(
                severity=_severity_low(),
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


def _candidate_dist_info_dirs(
    site_dir: Path,
    requested: dict[str, str],
) -> Iterator[tuple[str, str, Path]]:
    for canonical_name, version in requested.items():
        names = _dist_info_name_variants(canonical_name)
        versions = _dist_info_version_variants(version)
        for name in names:
            for version_text in versions:
                candidate = site_dir / f"{name}-{version_text}.dist-info"
                if candidate.is_dir():
                    yield canonical_name, version, candidate


def _dist_info_name_variants(canonical_name: str) -> tuple[str, ...]:
    variants = {
        canonical_name,
        canonical_name.replace("-", "_"),
        canonical_name.replace("_", "-"),
    }
    return tuple(sorted(value for value in variants if value))


def _dist_info_version_variants(version: str) -> tuple[str, ...]:
    normalized = str(version).strip()
    if not normalized:
        return ()
    variants = {normalized, normalized.replace("-", "_")}
    return tuple(sorted(value for value in variants if value))


def _collect_package_artifact_record_from_dist_info(
    dist_info: Path,
    requested: dict[str, str],
    *,
    site_dir: Path,
    script_roots: list[Path],
    site_has_pth: bool,
    script_roots_exist: bool,
    known_canonical_name: str | None = None,
    known_version: str | None = None,
) -> tuple[str, dict] | None:
    if known_canonical_name is None:
        from packaging.utils import canonicalize_name

        metadata = _read_distribution_metadata(dist_info)
        name = metadata.get("name") or _name_from_dist_info_dir(dist_info)
        if not name:
            return None
        canonical_name = canonicalize_name(name)
        if canonical_name not in requested:
            return None
        version = metadata.get("version") or requested[canonical_name]
    else:
        canonical_name = known_canonical_name
        if canonical_name not in requested:
            return None
        name = _name_from_dist_info_dir(dist_info) or canonical_name
        version = known_version or requested[canonical_name]
    return canonical_name, _package_artifact_record(
        name=name,
        version=version,
        dist_info=dist_info,
        site_dir=site_dir,
        script_roots=script_roots,
        site_has_pth=site_has_pth,
        script_roots_exist=script_roots_exist,
    )


def package_artifact_history_path() -> Path:
    from secpipw.pypi_api import _default_cache_root

    return _default_cache_root() / "installed-artifacts.json"


def load_package_artifact_history(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "packages": {}}
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
    path.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )


def resolve_watch_directories(pip_args: list[str]) -> list[Path]:
    target = _option_value(pip_args, "-t", "--target")
    if target is not None:
        return [_absolute_path(Path(target))]

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
    return [_apply_root(_absolute_path(Path(root)), path) for path in install_dirs]


def resolve_script_directories(pip_args: list[str]) -> list[Path]:
    target = _option_value(pip_args, "-t", "--target")
    if target is not None:
        target_path = _absolute_path(Path(target))
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
    return [_apply_root(_absolute_path(Path(root)), path) for path in script_dirs]


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
            resolved = _absolute_path(path)
            try:
                stat = path.stat()
            except OSError:
                continue
            previous = (
                previous_snapshot.get(resolved)
                if previous_snapshot is not None
                else None
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
    import site
    import sysconfig

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
    import site
    import sysconfig

    if user:
        return _dedupe_paths(
            [Path(site.getuserbase()) / "Scripts", Path(site.getuserbase()) / "bin"]
        )

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
    import subprocess

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
        timeout=PYTHON_DIRECTORY_QUERY_TIMEOUT_SECONDS,
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
    import subprocess

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
        timeout=PYTHON_DIRECTORY_QUERY_TIMEOUT_SECONDS,
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
    import hashlib

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
    site_has_pth: bool,
    script_roots_exist: bool,
) -> dict:
    if _artifact_record_is_empty(
        dist_info,
        site_has_pth=site_has_pth,
        script_roots_exist=script_roots_exist,
    ):
        return {
            "name": name,
            "version": version,
            "pth_files": {},
            "entry_points": [],
            "script_files": [],
        }

    pth_files: dict[str, dict] = {}
    script_files: list[str] = []

    for installed_path in _record_paths(dist_info):
        if installed_path.suffix.lower() == ".pth" and installed_path.exists():
            key = _relative_artifact_key(installed_path, [site_dir], prefix="site")
            pth_files[key] = {
                "digest": _file_digest(installed_path),
                "import_lines": find_import_lines(installed_path),
            }
            continue
        if _is_under_any(installed_path, script_roots) and installed_path.is_file():
            key = _relative_artifact_key(installed_path, script_roots, prefix="scripts")
            script_files.append(key)

    return {
        "name": name,
        "version": version,
        "pth_files": pth_files,
        "entry_points": _entry_points_from_dist_info(dist_info),
        "script_files": sorted(set(script_files)),
    }


def _artifact_record_is_empty(
    dist_info: Path,
    *,
    site_has_pth: bool,
    script_roots_exist: bool,
) -> bool:
    if (dist_info / "entry_points.txt").exists():
        return False
    if site_has_pth:
        return False
    return not script_roots_exist


def _record_paths(dist_info: Path) -> Iterator[Path]:
    import csv
    from io import StringIO

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
    from pathlib import PurePosixPath

    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return _absolute_path(path)
    parts = PurePosixPath(value).parts
    return _absolute_path(dist_info.parent.joinpath(*parts))


def _entry_points_from_dist_info(dist_info: Path) -> list[str]:
    import configparser

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
    previous_items = set(_artifact_sequence_items(previous))
    current_items = set(_artifact_sequence_items(current))
    changes: list[str] = []
    changes.extend(f"added {item}" for item in sorted(current_items - previous_items))
    changes.extend(f"removed {item}" for item in sorted(previous_items - current_items))
    return changes


def _artifact_sequence_items(value: object) -> tuple[str, ...]:
    if isinstance(value, dict):
        return tuple(str(item) for item in value)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return ()


def _normalized_pth_files(value: object) -> dict[str, dict]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, dict] = {}
    for path, metadata in value.items():
        if not isinstance(path, str) or not isinstance(metadata, dict):
            continue
        normalized[path] = {
            "digest": metadata.get("digest"),
            "import_lines": (
                metadata.get("import_lines")
                if isinstance(metadata.get("import_lines"), list)
                else []
            ),
        }
    return normalized


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


def _severity_low() -> Severity:
    from secpipw.severity import Severity

    return Severity.LOW


def _severity_medium() -> Severity:
    from secpipw.severity import Severity

    return Severity.MEDIUM


def _dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = _absolute_path(path)
        if resolved in seen:
            continue
        seen.add(resolved)
        result.append(resolved)
    return result


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(str(path)))


def _import_lines_from_text(text: str) -> Iterator[str]:
    for line in text.splitlines():
        if _looks_like_import_line(line):
            yield line.strip()


def _looks_like_import_line(line: str) -> bool:
    stripped = line.lstrip()
    if not stripped.startswith("import"):
        return False
    if len(stripped) == len("import"):
        return True
    return not (stripped[len("import")].isalnum() or stripped[len("import")] == "_")


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
                severity=_severity_medium(),
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


def _fetch_http_suffix_range(
    download_url: str,
    *,
    tail_bytes: int,
    timeout: float,
) -> _SuffixRangeResponse | None:
    from urllib.request import Request, urlopen

    request = Request(
        download_url,
        headers={"Range": f"bytes=-{tail_bytes}"},
    )
    with urlopen(request, timeout=timeout) as response:
        payload = response.read()
        content_range = response.headers.get("Content-Range", "")
        total_size = _content_range_total_size(content_range)
        partial = bool(content_range) or getattr(response, "status", None) == 206
        if total_size is None:
            total_length = response.headers.get("Content-Length")
            if total_length and total_length.isdigit():
                total_size = int(total_length)
            else:
                total_size = len(payload)
        return _SuffixRangeResponse(
            payload=payload,
            partial=partial,
            total_size=total_size,
        )


def _content_range_total_size(value: str) -> int | None:
    normalized = value.strip()
    if "/" not in normalized:
        return None
    total = normalized.rsplit("/", 1)[1]
    if not total.isdigit():
        return None
    return int(total)


def _zip_bytes_contain_pth(payload: bytes) -> bool | None:
    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            return any(
                not info.is_dir() and info.filename.lower().endswith(".pth")
                for info in archive.infolist()
            )
    except Exception:
        return None


def _zip_tail_contains_pth(payload: bytes, *, total_size: int) -> bool | None:
    import struct

    eocd_offset = payload.rfind(b"PK\x05\x06")
    if eocd_offset < 0 or len(payload) - eocd_offset < 22:
        return None

    (
        _signature,
        _disk_number,
        _start_disk_number,
        _disk_entries,
        total_entries,
        central_directory_size,
        central_directory_offset,
        comment_length,
    ) = struct.unpack_from("<4s4H2LH", payload, eocd_offset)

    if comment_length < 0 or eocd_offset + 22 + comment_length > len(payload):
        return None
    if total_entries == 0xFFFF:
        return None
    if (
        central_directory_size == 0xFFFFFFFF
        or central_directory_offset == 0xFFFFFFFF
    ):
        return None
    if central_directory_offset + central_directory_size > total_size:
        return None

    tail_start = total_size - len(payload)
    if central_directory_offset < tail_start:
        return None

    directory_start = central_directory_offset - tail_start
    directory_end = directory_start + central_directory_size
    if directory_end > len(payload):
        return None

    return _central_directory_contains_pth(
        payload[directory_start:directory_end],
        expected_entries=total_entries,
    )


def _central_directory_contains_pth(
    payload: bytes,
    *,
    expected_entries: int,
) -> bool | None:
    import struct

    offset = 0
    seen_entries = 0
    while offset < len(payload):
        if len(payload) - offset < 46:
            return None
        (
            signature,
            _version_made_by,
            _version_needed,
            _flags,
            _compression,
            _modified_time,
            _modified_date,
            _crc32,
            _compressed_size,
            _uncompressed_size,
            filename_length,
            extra_length,
            comment_length,
            _disk_start,
            _internal_attributes,
            _external_attributes,
            _local_header_offset,
        ) = struct.unpack_from("<4s6H3L5H2L", payload, offset)
        if signature != b"PK\x01\x02":
            return None

        record_end = offset + 46 + filename_length + extra_length + comment_length
        if record_end > len(payload):
            return None

        filename_bytes = payload[offset + 46 : offset + 46 + filename_length]
        filename = filename_bytes.decode("utf-8", errors="ignore").lower()
        if filename.endswith(".pth"):
            return True

        seen_entries += 1
        offset = record_end

    if seen_entries != expected_entries:
        return None
    return False


def _is_supported_sdist_path(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".zip"))
