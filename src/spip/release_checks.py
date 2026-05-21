from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Protocol
from urllib.error import URLError

from packaging.version import InvalidVersion, Version

from spip.pypi_api import OfficialPyPIClient
from spip.severity import Severity
from spip.terminal import colorize

RECENT_RELEASE_THRESHOLD = timedelta(days=2)
_RELEASE_LOOKUP_CACHE: dict[tuple[str, str], "_ReleaseLookupResult"] = {}


class PackageLike(Protocol):
    name: str
    version: str
    download_url: str | None
    artifact_name: str | None
    requested: bool


@dataclass(frozen=True)
class ReleaseAgeAlert:
    severity: Severity
    package_name: str
    version: str
    published_at: datetime | None
    age: timedelta | None
    message: str


@dataclass(frozen=True)
class VersionAlert:
    severity: Severity
    package_name: str
    version: str
    message: str


@dataclass(frozen=True)
class _ReleaseLookupResult:
    timed_out: bool
    published_at: datetime | None


def detect_recent_release_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    now: datetime | None = None,
) -> list[ReleaseAgeAlert]:
    client = client or OfficialPyPIClient()
    now = datetime.now(timezone.utc) if now is None else now
    alerts: list[ReleaseAgeAlert] = []

    for package in _unique_packages_for_recent_release_check(packages):
        if not _looks_like_pypi_download(package.download_url):
            continue
        lookup = _fetch_release_lookup_result(package, client)
        if lookup.timed_out:
            alerts.append(
                ReleaseAgeAlert(
                    severity=Severity.LOW,
                    package_name=package.name,
                    version=package.version,
                    published_at=None,
                    age=None,
                    message=(
                        f"could not check whether '{package.name}=={package.version}' "
                        "was published recently because PyPI timed out"
                    ),
                )
            )
            continue
        published_at = lookup.published_at
        if published_at is None:
            continue
        age = now - published_at
        if age >= RECENT_RELEASE_THRESHOLD:
            continue
        alerts.append(
            ReleaseAgeAlert(
                severity=Severity.MEDIUM,
                package_name=package.name,
                version=package.version,
                published_at=published_at,
                age=age,
                message=(
                    f"'{package.name}=={package.version}' was published "
                    f"{_format_age(age)} ago on PyPI"
                ),
            )
        )
    return alerts


def detect_zero_version_alerts(
    packages: Iterable[PackageLike],
) -> list[VersionAlert]:
    alerts: list[VersionAlert] = []

    for package in packages:
        if not _is_zero_version(package.version):
            continue
        alerts.append(
            VersionAlert(
                severity=Severity.LOW,
                package_name=package.name,
                version=package.version,
                message=(
                    f"'{package.name}=={package.version}' uses a zero release version"
                ),
            )
        )
    return alerts


def render_release_age_alerts(alerts: Iterable[ReleaseAgeAlert]) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] recent-release: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def render_version_alerts(alerts: Iterable[VersionAlert]) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] zero-version: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def _looks_like_pypi_download(download_url: str | None) -> bool:
    if not download_url:
        return False
    return "pythonhosted.org" in download_url or "/packages/" in download_url


def _unique_packages_for_recent_release_check(
    packages: Iterable[PackageLike],
) -> list[PackageLike]:
    selected: list[PackageLike] = []
    seen: set[tuple[str, str]] = set()

    for package in packages:
        key = (package.name.lower(), package.version)
        if key in seen:
            continue
        seen.add(key)
        selected.append(package)
    return selected


def _fetch_release_lookup_result(
    package: PackageLike,
    client: OfficialPyPIClient,
) -> _ReleaseLookupResult:
    key = (package.name.lower(), package.version)
    cached = _RELEASE_LOOKUP_CACHE.get(key)
    if cached is not None:
        return cached

    try:
        published_at = client.fetch_release_upload_time(
            package.name,
            package.version,
            download_url=package.download_url,
            filename=package.artifact_name,
        )
    except Exception as exc:
        if _is_timeout_error(exc):
            result = _ReleaseLookupResult(timed_out=True, published_at=None)
        else:
            result = _ReleaseLookupResult(timed_out=False, published_at=None)
    else:
        result = _ReleaseLookupResult(timed_out=False, published_at=published_at)

    _RELEASE_LOOKUP_CACHE[key] = result
    return result


def _is_timeout_error(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    if isinstance(exc, URLError):
        reason = getattr(exc, "reason", None)
        return isinstance(reason, (TimeoutError, socket.timeout))
    return False


def _is_zero_version(version: str) -> bool:
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    release = parsed.release
    return len(release) >= 2 and all(component == 0 for component in release)


def _format_age(age: timedelta) -> str:
    total_seconds = int(max(age.total_seconds(), 0))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
