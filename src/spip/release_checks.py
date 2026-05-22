from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from typing import Iterable, Protocol
from urllib.error import URLError

from packaging.version import InvalidVersion, Version

from spip.pypi_api import OfficialPyPIClient, load_disposable_email_domains
from spip.severity import Severity
from spip.terminal import colorize

RECENT_RELEASE_THRESHOLD = timedelta(days=2)
RECENT_RELEASE_MAX_WORKERS = 8
_RELEASE_LOOKUP_CACHE: dict[tuple[str, str, str, str, str], "_ReleaseLookupResult"] = {}
_DISPOSABLE_EMAIL_LOOKUP_CACHE: dict[tuple[str, str, str], "_DisposableEmailLookupResult"] = {}


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
class DisposableEmailAlert:
    severity: Severity
    package_name: str
    version: str
    email: str
    message: str


@dataclass(frozen=True)
class _ReleaseLookupResult:
    timed_out: bool
    published_at: datetime | None


@dataclass(frozen=True)
class _DisposableEmailLookupResult:
    timed_out: bool
    matched_emails: tuple[str, ...]


def detect_recent_release_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    now: datetime | None = None,
) -> list[ReleaseAgeAlert]:
    client = client or OfficialPyPIClient()
    now = datetime.now(timezone.utc) if now is None else now
    alerts: list[ReleaseAgeAlert] = []
    candidates = [
        package
        for package in _unique_packages_for_recent_release_check(packages)
        if _looks_like_pypi_download(package.download_url)
    ]

    if not candidates:
        return alerts

    max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        lookups = list(
            executor.map(lambda package: _fetch_release_lookup_result(package, client), candidates)
        )

    for package, lookup in zip(candidates, lookups):
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


def detect_disposable_email_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    disposable_domains: set[str] | None = None,
) -> list[DisposableEmailAlert]:
    client = client or OfficialPyPIClient()
    disposable_domains = (
        load_disposable_email_domains()
        if disposable_domains is None
        else {domain.lower() for domain in disposable_domains}
    )
    alerts: list[DisposableEmailAlert] = []
    candidates = _unique_packages_for_recent_release_check(packages)

    if not candidates:
        return alerts

    max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        lookups = list(
            executor.map(
                lambda package: _fetch_disposable_email_lookup_result(
                    package,
                    client,
                    disposable_domains=disposable_domains,
                ),
                candidates,
            )
        )

    for package, lookup in zip(candidates, lookups):
        if lookup.timed_out:
            alerts.append(
                DisposableEmailAlert(
                    severity=Severity.LOW,
                    package_name=package.name,
                    version=package.version,
                    email="",
                    message=(
                        f"could not verify whether '{package.name}=={package.version}' "
                        "uses a disposable maintainer email because PyPI timed out"
                    ),
                )
            )
            continue
        for email in lookup.matched_emails:
            alerts.append(
                DisposableEmailAlert(
                    severity=Severity.LOW,
                    package_name=package.name,
                    version=package.version,
                    email=email,
                    message=(
                        f"'{package.name}=={package.version}' publishes metadata with "
                        f"disposable email '{email}'"
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


def render_disposable_email_alerts(alerts: Iterable[DisposableEmailAlert]) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] disposable-email: {alert.message}",
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
    key = (
        client.base_url.rstrip("/").lower(),
        package.name.lower(),
        package.version,
        package.download_url or "",
        package.artifact_name or "",
    )
    cached = _RELEASE_LOOKUP_CACHE.get(key)
    if cached is not None:
        return cached

    cached_hit, cached_published_at = client.load_cached_release_upload_time(
        package.name,
        package.version,
        download_url=package.download_url,
        filename=package.artifact_name,
    )
    if cached_hit:
        result = _ReleaseLookupResult(
            timed_out=False,
            published_at=cached_published_at,
        )
        _RELEASE_LOOKUP_CACHE[key] = result
        return result

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
        client.store_cached_release_upload_time(
            package.name,
            package.version,
            published_at,
            download_url=package.download_url,
            filename=package.artifact_name,
        )

    _RELEASE_LOOKUP_CACHE[key] = result
    return result


def _fetch_disposable_email_lookup_result(
    package: PackageLike,
    client: OfficialPyPIClient,
    *,
    disposable_domains: set[str],
) -> _DisposableEmailLookupResult:
    key = (
        client.base_url.rstrip("/").lower(),
        package.name.lower(),
        package.version,
    )
    cached = _DISPOSABLE_EMAIL_LOOKUP_CACHE.get(key)
    if cached is not None:
        return cached

    try:
        emails = client.fetch_release_contact_emails(package.name, package.version)
    except Exception as exc:
        if _is_timeout_error(exc):
            result = _DisposableEmailLookupResult(timed_out=True, matched_emails=())
        else:
            result = _DisposableEmailLookupResult(timed_out=False, matched_emails=())
    else:
        matched_emails = tuple(
            email
            for email in emails
            if _email_uses_disposable_domain(email, disposable_domains)
        )
        result = _DisposableEmailLookupResult(
            timed_out=False,
            matched_emails=matched_emails,
        )

    _DISPOSABLE_EMAIL_LOOKUP_CACHE[key] = result
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


def _email_uses_disposable_domain(email: str, disposable_domains: set[str]) -> bool:
    _, address = parseaddr(email)
    if "@" not in address:
        return False
    domain = address.rsplit("@", 1)[1].strip().lower()
    parts = domain.split(".")
    for index in range(len(parts) - 1):
        if ".".join(parts[index:]) in disposable_domains:
            return True
    return False


def _format_age(age: timedelta) -> str:
    total_seconds = int(max(age.total_seconds(), 0))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
