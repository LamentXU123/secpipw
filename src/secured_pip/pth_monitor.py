from __future__ import annotations

import hashlib
import json
import re
import site
import subprocess
import sys
import sysconfig
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, TextIO

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
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
