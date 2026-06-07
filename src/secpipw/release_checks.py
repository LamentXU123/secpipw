from __future__ import annotations

import socket
from collections.abc import Iterable as IterableABC
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import getaddresses, parseaddr
from difflib import SequenceMatcher
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from secpipw.pypi_api import OfficialPyPIClient
from secpipw.severity import Severity
from secpipw.terminal import colorize
from secpipw.typo import PIP_OPTIONS_WITH_VALUE

RECENT_RELEASE_MEDIUM_THRESHOLD = timedelta(hours=8)
RECENT_RELEASE_LOW_THRESHOLD = timedelta(hours=48)
RECENT_RELEASE_MAX_WORKERS = 8
_RELEASE_LOOKUP_CACHE: dict[tuple[str, str, str, str, str], "_ReleaseLookupResult"] = {}
_DESCRIPTION_LOOKUP_CACHE: dict[tuple[str, str, str], "_DescriptionLookupResult"] = {}
_SUSPICIOUS_URL_LOOKUP_CACHE: dict[
    tuple[str, str, str], "_SuspiciousUrlLookupResult"
] = {}
_REPOSITORY_MISMATCH_LOOKUP_CACHE: dict[
    tuple[str, str, str], "_RepositoryMismatchLookupResult"
] = {}
_NO_PREFETCHED_METADATA = object()

VCS_URL_PREFIXES = ("git+", "hg+", "svn+", "bzr+")
SHORTENER_DOMAINS = {
    "bit.ly",
    "bitly.com",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "s.id",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}
SUSPICIOUS_TLDS = {
    "cf",
    "click",
    "ga",
    "gq",
    "ml",
    "mov",
    "tk",
    "top",
    "work",
    "xyz",
    "zip",
}
REPOSITORY_LABEL_TOKENS = ("source", "repo", "repository", "code", "github", "gitlab")


class PackageLike(Protocol):
    name: str
    version: str
    download_url: str | None
    artifact_name: str | None
    archive_hash: str | None
    requested: bool
    requires_dist: tuple[str, ...]
    metadata: dict


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
class EmptyDescriptionAlert:
    severity: Severity
    package_name: str
    version: str
    message: str


@dataclass(frozen=True)
class DirectUrlAlert:
    severity: Severity
    package_name: str | None
    version: str | None
    requirement: str
    message: str


@dataclass(frozen=True)
class MetadataUrlAlert:
    severity: Severity
    package_name: str
    version: str
    url: str
    reason: str
    message: str


@dataclass(frozen=True)
class RepositoryMismatchAlert:
    severity: Severity
    package_name: str
    version: str
    url: str
    repository_name: str
    message: str


@dataclass(frozen=True)
class EmailDomainDriftAlert:
    severity: Severity
    package_name: str
    version: str
    previous_domains: tuple[str, ...]
    current_domains: tuple[str, ...]
    message: str


@dataclass(frozen=True)
class YankedReleaseAlert:
    severity: Severity
    package_name: str
    version: str
    reason: str | None
    message: str


@dataclass(frozen=True)
class ArchiveHashMismatchAlert:
    severity: Severity
    package_name: str
    version: str
    filename: str | None
    algorithm: str
    expected_digest: str
    actual_digest: str
    message: str


@dataclass(frozen=True)
class _ReleaseLookupResult:
    timed_out: bool
    published_at: datetime | None


@dataclass(frozen=True)
class _DescriptionLookupResult:
    has_empty_description: bool


@dataclass(frozen=True)
class _SuspiciousUrlLookupResult:
    findings: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _RepositoryMismatchLookupResult:
    findings: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _RegistryMetadataLookupResult:
    timed_out: bool
    metadata: dict | None


RegistryMetadataLookup = Mapping[
    tuple[str, str, str],
    _RegistryMetadataLookupResult,
]


def prefetch_release_metadata(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
) -> dict[tuple[str, str, str], _RegistryMetadataLookupResult]:
    client = client or OfficialPyPIClient()
    candidates = [
        package
        for package in _packages_with_registry_metadata(packages)
        if _package_report_metadata(package) is None
    ]
    if not candidates:
        return {}

    if not getattr(client, "network_enabled", True):
        return {
            _registry_metadata_cache_key(
                package, client
            ): _RegistryMetadataLookupResult(
                timed_out=False,
                metadata=None,
            )
            for package in candidates
        }

    max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        lookups = list(
            executor.map(
                lambda package: _fetch_registry_metadata_lookup(package, client),
                candidates,
            )
        )

    return {
        _registry_metadata_cache_key(package, client): lookup
        for package, lookup in zip(candidates, lookups)
    }


def detect_recent_release_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    now: datetime | None = None,
    report_metadata_available: bool | None = None,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> list[ReleaseAgeAlert]:
    client = client or OfficialPyPIClient()
    now = datetime.now(timezone.utc) if now is None else now
    alerts: list[ReleaseAgeAlert] = []
    candidates = _packages_with_registry_metadata(packages)

    if not candidates:
        return alerts

    max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        lookups = list(
            executor.map(
                lambda package: _fetch_release_lookup_result(
                    package,
                    client,
                    registry_metadata=registry_metadata,
                ),
                candidates,
            )
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
        if age < RECENT_RELEASE_MEDIUM_THRESHOLD:
            severity = Severity.MEDIUM
        elif age < RECENT_RELEASE_LOW_THRESHOLD:
            severity = Severity.LOW
        else:
            continue
        alerts.append(
            ReleaseAgeAlert(
                severity=severity,
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


def detect_empty_description_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    report_metadata_available: bool | None = None,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> list[EmptyDescriptionAlert]:
    client = client or OfficialPyPIClient()
    alerts: list[EmptyDescriptionAlert] = []
    candidates = _packages_with_registry_metadata(packages)

    if not candidates:
        return alerts

    if _report_metadata_available(candidates, report_metadata_available):
        lookups = [
            _fetch_description_lookup_result(
                package,
                client,
                registry_metadata=registry_metadata,
            )
            for package in candidates
        ]
    else:
        max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            lookups = list(
                executor.map(
                    lambda package: _fetch_description_lookup_result(
                        package,
                        client,
                        registry_metadata=registry_metadata,
                    ),
                    candidates,
                )
            )

    for package, lookup in zip(candidates, lookups):
        if not lookup.has_empty_description:
            continue
        alerts.append(
            EmptyDescriptionAlert(
                severity=Severity.LOW,
                package_name=package.name,
                version=package.version,
                message=(
                    f"'{package.name}=={package.version}' publishes metadata with "
                    "an empty description"
                ),
            )
        )
    return alerts


def detect_direct_url_alerts(
    pip_args: Iterable[str],
    packages: Iterable[PackageLike],
) -> list[DirectUrlAlert]:
    alerts: list[DirectUrlAlert] = []
    seen: set[tuple[str | None, str | None, str]] = set()

    for requirement in _extract_direct_url_inputs(list(pip_args)):
        key = (None, None, requirement)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            DirectUrlAlert(
                severity=Severity.MEDIUM,
                package_name=None,
                version=None,
                requirement=requirement,
                message=f"install target uses direct URL or VCS reference '{requirement}'",
            )
        )

    for package in packages:
        for requirement in getattr(package, "requires_dist", ()):
            if not _requirement_uses_direct_url(requirement):
                continue
            key = (package.name, package.version, requirement)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(
                DirectUrlAlert(
                    severity=Severity.MEDIUM,
                    package_name=package.name,
                    version=package.version,
                    requirement=requirement,
                    message=(
                        f"'{package.name}=={package.version}' declares direct URL "
                        f"dependency '{requirement}'"
                    ),
                )
            )
    return alerts


def detect_suspicious_metadata_url_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    report_metadata_available: bool | None = None,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> list[MetadataUrlAlert]:
    client = client or OfficialPyPIClient()
    alerts: list[MetadataUrlAlert] = []
    candidates = _packages_with_registry_metadata(packages)

    if not candidates:
        return alerts

    if _report_metadata_available(candidates, report_metadata_available):
        lookups = [
            _fetch_suspicious_url_lookup_result(
                package,
                client,
                registry_metadata=registry_metadata,
            )
            for package in candidates
        ]
    else:
        max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            lookups = list(
                executor.map(
                    lambda package: _fetch_suspicious_url_lookup_result(
                        package,
                        client,
                        registry_metadata=registry_metadata,
                    ),
                    candidates,
                )
            )

    for package, lookup in zip(candidates, lookups):
        for url, reason in lookup.findings:
            alerts.append(
                MetadataUrlAlert(
                    severity=Severity.LOW,
                    package_name=package.name,
                    version=package.version,
                    url=url,
                    reason=reason,
                    message=(
                        f"'{package.name}=={package.version}' metadata links to "
                        f"suspicious URL '{url}' ({reason})"
                    ),
                )
            )
    return alerts


def detect_repository_mismatch_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    report_metadata_available: bool | None = None,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> list[RepositoryMismatchAlert]:
    client = client or OfficialPyPIClient()
    alerts: list[RepositoryMismatchAlert] = []
    candidates = _packages_with_registry_metadata(packages)

    if not candidates:
        return alerts

    if _report_metadata_available(candidates, report_metadata_available):
        lookups = [
            _fetch_repository_mismatch_lookup_result(
                package,
                client,
                registry_metadata=registry_metadata,
            )
            for package in candidates
        ]
    else:
        max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            lookups = list(
                executor.map(
                    lambda package: _fetch_repository_mismatch_lookup_result(
                        package,
                        client,
                        registry_metadata=registry_metadata,
                    ),
                    candidates,
                )
            )

    for package, lookup in zip(candidates, lookups):
        for url, repository_name in lookup.findings:
            alerts.append(
                RepositoryMismatchAlert(
                    severity=Severity.LOW,
                    package_name=package.name,
                    version=package.version,
                    url=url,
                    repository_name=repository_name,
                    message=(
                        f"'{package.name}=={package.version}' metadata repository "
                        f"'{repository_name}' appears unrelated to the package name"
                    ),
                )
            )
    return alerts


def detect_email_domain_drift_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    update_history: bool = True,
    report_metadata_available: bool | None = None,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> list[EmailDomainDriftAlert]:
    client = client or OfficialPyPIClient()
    alerts: list[EmailDomainDriftAlert] = []
    candidates = _packages_with_registry_metadata(packages)

    if not candidates:
        return alerts

    history = client.load_email_domain_history()
    updated_history = dict(history)

    if _report_metadata_available(candidates, report_metadata_available):
        current_domains = [
            _fetch_contact_email_domains(
                package,
                client,
                registry_metadata=registry_metadata,
            )
            for package in candidates
        ]
    else:
        max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            current_domains = list(
                executor.map(
                    lambda package: _fetch_contact_email_domains(
                        package,
                        client,
                        registry_metadata=registry_metadata,
                    ),
                    candidates,
                )
            )

    for package, domains in zip(candidates, current_domains):
        if not domains:
            continue
        project_key = canonicalize_name(package.name)
        previous = tuple(history.get(project_key, ()))
        if previous and set(previous).isdisjoint(domains):
            alerts.append(
                EmailDomainDriftAlert(
                    severity=Severity.LOW,
                    package_name=package.name,
                    version=package.version,
                    previous_domains=previous,
                    current_domains=domains,
                    message=(
                        f"'{package.name}=={package.version}' maintainer email domain "
                        f"changed from {', '.join(previous)} to {', '.join(domains)}"
                    ),
                )
            )
        updated_history[project_key] = domains

    if update_history and updated_history != history:
        client.store_email_domain_history(updated_history)
    return alerts


def detect_yanked_release_alerts(
    packages: Iterable[PackageLike],
) -> list[YankedReleaseAlert]:
    alerts: list[YankedReleaseAlert] = []
    seen: set[tuple[str, str]] = set()

    for package in packages:
        if not getattr(package, "yanked", False):
            continue
        key = (package.name.lower(), package.version)
        if key in seen:
            continue
        seen.add(key)
        reason = getattr(package, "yanked_reason", None)
        if not isinstance(reason, str) or not reason.strip():
            reason = None
        message = f"'{package.name}=={package.version}' is marked as yanked"
        if reason is not None:
            message = f"{message}: {reason.strip()}"
        alerts.append(
            YankedReleaseAlert(
                severity=Severity.MEDIUM,
                package_name=package.name,
                version=package.version,
                reason=reason.strip() if reason is not None else None,
                message=message,
            )
        )
    return alerts


def detect_archive_hash_mismatch_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> list[ArchiveHashMismatchAlert]:
    client = client or OfficialPyPIClient()
    alerts: list[ArchiveHashMismatchAlert] = []
    seen: set[tuple[str, str, str, str | None]] = set()

    for package in _packages_with_registry_metadata(packages):
        parsed_hash = _parse_archive_hash(getattr(package, "archive_hash", None))
        if parsed_hash is None:
            continue
        algorithm, actual_digest = parsed_hash
        metadata = _release_metadata_without_fetch(
            package,
            client,
            registry_metadata=registry_metadata,
        )
        if metadata is None:
            continue
        selected_file = _selected_release_file_from_metadata(
            metadata,
            download_url=package.download_url,
            filename=package.artifact_name,
        )
        if selected_file is None:
            continue
        expected_digest = _digest_from_release_file(selected_file, algorithm)
        if expected_digest is None or expected_digest == actual_digest:
            continue
        key = (package.name.lower(), package.version, algorithm, package.artifact_name)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(
            ArchiveHashMismatchAlert(
                severity=Severity.HIGH,
                package_name=package.name,
                version=package.version,
                filename=package.artifact_name,
                algorithm=algorithm,
                expected_digest=expected_digest,
                actual_digest=actual_digest,
                message=(
                    f"'{package.name}=={package.version}' archive hash "
                    f"{algorithm}={actual_digest} does not match PyPI metadata "
                    f"digest {algorithm}={expected_digest}"
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


def render_empty_description_alerts(alerts: Iterable[EmptyDescriptionAlert]) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] empty-description: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def render_direct_url_alerts(alerts: Iterable[DirectUrlAlert]) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] direct-url: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def render_suspicious_metadata_url_alerts(
    alerts: Iterable[MetadataUrlAlert],
) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] suspicious-url: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def render_repository_mismatch_alerts(
    alerts: Iterable[RepositoryMismatchAlert],
) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] repository-mismatch: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def render_email_domain_drift_alerts(
    alerts: Iterable[EmailDomainDriftAlert],
) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] email-domain-drift: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def render_yanked_release_alerts(alerts: Iterable[YankedReleaseAlert]) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] yanked-release: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def render_archive_hash_mismatch_alerts(
    alerts: Iterable[ArchiveHashMismatchAlert],
) -> str:
    lines = []
    for alert in alerts:
        lines.append(
            colorize(
                f"[{alert.severity.label.upper()}] archive-hash: {alert.message}",
                alert.severity,
            )
        )
    return "\n".join(lines)


def _packages_with_registry_metadata(
    packages: Iterable[PackageLike],
) -> list[PackageLike]:
    return [
        package
        for package in _unique_packages_for_recent_release_check(packages)
        if _package_can_use_registry_metadata(package)
    ]


def _package_can_use_registry_metadata(package: PackageLike) -> bool:
    # Direct and editable installs do not map reliably to registry release metadata.
    if getattr(package, "is_direct", False):
        return False
    return bool(package.name and package.version)


def _all_packages_have_report_metadata(packages: Iterable[PackageLike]) -> bool:
    return all(_package_report_metadata(package) is not None for package in packages)


def _report_metadata_available(
    packages: Iterable[PackageLike],
    available: bool | None,
) -> bool:
    if available is not None:
        return available
    return _all_packages_have_report_metadata(packages)


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


def _registry_metadata_cache_key(
    package: PackageLike,
    client: OfficialPyPIClient,
) -> tuple[str, str, str]:
    return (
        client.base_url.rstrip("/").lower(),
        package.name.lower(),
        package.version,
    )


def _fetch_registry_metadata_lookup(
    package: PackageLike,
    client: OfficialPyPIClient,
) -> _RegistryMetadataLookupResult:
    try:
        metadata = client.fetch_release_metadata(package.name, package.version)
    except Exception as exc:
        return _RegistryMetadataLookupResult(
            timed_out=_is_timeout_error(exc),
            metadata=None,
        )
    return _RegistryMetadataLookupResult(timed_out=False, metadata=metadata)


def _lookup_prefetched_registry_metadata(
    package: PackageLike,
    client: OfficialPyPIClient,
    registry_metadata: RegistryMetadataLookup | None,
) -> _RegistryMetadataLookupResult | object:
    if registry_metadata is None:
        return _NO_PREFETCHED_METADATA
    return registry_metadata.get(
        _registry_metadata_cache_key(package, client),
        _NO_PREFETCHED_METADATA,
    )


def _fetch_release_lookup_result(
    package: PackageLike,
    client: OfficialPyPIClient,
    *,
    registry_metadata: RegistryMetadataLookup | None = None,
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

    prefetched = _lookup_prefetched_registry_metadata(
        package,
        client,
        registry_metadata,
    )
    if prefetched is not _NO_PREFETCHED_METADATA:
        assert isinstance(prefetched, _RegistryMetadataLookupResult)
        published_at = (
            _upload_time_from_release_metadata(
                prefetched.metadata,
                download_url=package.download_url,
                filename=package.artifact_name,
            )
            if prefetched.metadata is not None
            else None
        )
        result = _ReleaseLookupResult(
            timed_out=prefetched.timed_out,
            published_at=published_at,
        )
        if prefetched.metadata is not None:
            client.store_cached_release_upload_time(
                package.name,
                package.version,
                published_at,
                download_url=package.download_url,
                filename=package.artifact_name,
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
            if _is_not_found_error(exc):
                client.store_cached_release_upload_time(
                    package.name,
                    package.version,
                    None,
                    download_url=package.download_url,
                    filename=package.artifact_name,
                )
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


def _fetch_description_lookup_result(
    package: PackageLike,
    client: OfficialPyPIClient,
    *,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> _DescriptionLookupResult:
    key = (
        client.base_url.rstrip("/").lower(),
        package.name.lower(),
        package.version,
    )
    cached = _DESCRIPTION_LOOKUP_CACHE.get(key)
    if cached is not None:
        return cached

    metadata = _package_report_metadata(package)
    if metadata is not None:
        summary, description = _description_fields_from_metadata(metadata)
    else:
        prefetched = _lookup_prefetched_registry_metadata(
            package,
            client,
            registry_metadata,
        )
        if prefetched is not _NO_PREFETCHED_METADATA:
            assert isinstance(prefetched, _RegistryMetadataLookupResult)
            if prefetched.metadata is None:
                result = _DescriptionLookupResult(has_empty_description=False)
                _DESCRIPTION_LOOKUP_CACHE[key] = result
                return result
            summary, description = _description_fields_from_metadata(
                prefetched.metadata
            )
        else:
            try:
                summary, description = client.fetch_release_description_fields(
                    package.name,
                    package.version,
                )
            except Exception:
                result = _DescriptionLookupResult(has_empty_description=False)
                _DESCRIPTION_LOOKUP_CACHE[key] = result
                return result

    result = _DescriptionLookupResult(
        has_empty_description=(
            _is_empty_metadata_text(summary) and _is_empty_metadata_text(description)
        ),
    )

    _DESCRIPTION_LOOKUP_CACHE[key] = result
    return result


def _fetch_suspicious_url_lookup_result(
    package: PackageLike,
    client: OfficialPyPIClient,
    *,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> _SuspiciousUrlLookupResult:
    key = (
        client.base_url.rstrip("/").lower(),
        package.name.lower(),
        package.version,
    )
    cached = _SUSPICIOUS_URL_LOOKUP_CACHE.get(key)
    if cached is not None:
        return cached

    metadata = _package_report_metadata(package)
    if metadata is None:
        prefetched = _lookup_prefetched_registry_metadata(
            package,
            client,
            registry_metadata,
        )
        if prefetched is not _NO_PREFETCHED_METADATA:
            assert isinstance(prefetched, _RegistryMetadataLookupResult)
            if prefetched.metadata is None:
                result = _SuspiciousUrlLookupResult(findings=())
                _SUSPICIOUS_URL_LOOKUP_CACHE[key] = result
                return result
            metadata = prefetched.metadata
        else:
            try:
                metadata = client.fetch_release_metadata(package.name, package.version)
            except Exception:
                result = _SuspiciousUrlLookupResult(findings=())
                _SUSPICIOUS_URL_LOOKUP_CACHE[key] = result
                return result

    findings = tuple(
        (url, reason)
        for _, url in _metadata_urls(metadata)
        if (reason := _suspicious_url_reason(url)) is not None
    )
    result = _SuspiciousUrlLookupResult(findings=findings)

    _SUSPICIOUS_URL_LOOKUP_CACHE[key] = result
    return result


def _fetch_repository_mismatch_lookup_result(
    package: PackageLike,
    client: OfficialPyPIClient,
    *,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> _RepositoryMismatchLookupResult:
    key = (
        client.base_url.rstrip("/").lower(),
        package.name.lower(),
        package.version,
    )
    cached = _REPOSITORY_MISMATCH_LOOKUP_CACHE.get(key)
    if cached is not None:
        return cached

    metadata = _package_report_metadata(package)
    if metadata is None:
        prefetched = _lookup_prefetched_registry_metadata(
            package,
            client,
            registry_metadata,
        )
        if prefetched is not _NO_PREFETCHED_METADATA:
            assert isinstance(prefetched, _RegistryMetadataLookupResult)
            if prefetched.metadata is None:
                result = _RepositoryMismatchLookupResult(findings=())
                _REPOSITORY_MISMATCH_LOOKUP_CACHE[key] = result
                return result
            metadata = prefetched.metadata
        else:
            try:
                metadata = client.fetch_release_metadata(package.name, package.version)
            except Exception:
                result = _RepositoryMismatchLookupResult(findings=())
                _REPOSITORY_MISMATCH_LOOKUP_CACHE[key] = result
                return result

    findings = tuple(
        (url, repository_name)
        for label, url in _metadata_urls(metadata)
        if _label_looks_like_repository(label)
        for repository_name in [_repository_name_from_url(url)]
        if repository_name is not None
        and _repository_looks_unrelated(package.name, repository_name)
    )
    result = _RepositoryMismatchLookupResult(findings=findings)

    _REPOSITORY_MISMATCH_LOOKUP_CACHE[key] = result
    return result


def _fetch_contact_email_domains(
    package: PackageLike,
    client: OfficialPyPIClient,
    *,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> tuple[str, ...]:
    metadata = _package_report_metadata(package)
    if metadata is not None:
        emails = _contact_emails_from_metadata(metadata)
    else:
        prefetched = _lookup_prefetched_registry_metadata(
            package,
            client,
            registry_metadata,
        )
        if prefetched is not _NO_PREFETCHED_METADATA:
            assert isinstance(prefetched, _RegistryMetadataLookupResult)
            if prefetched.metadata is None:
                return ()
            emails = _contact_emails_from_metadata(prefetched.metadata)
        else:
            try:
                emails = client.fetch_release_contact_emails(
                    package.name, package.version
                )
            except Exception:
                return ()
    return tuple(
        sorted(
            {
                domain
                for email in emails
                if (domain := _domain_from_email(email)) is not None
            }
        )
    )


def _upload_time_from_release_metadata(
    metadata: dict,
    *,
    download_url: str | None = None,
    filename: str | None = None,
) -> datetime | None:
    urls = _release_files_from_metadata(metadata)
    selected = _selected_release_file_from_metadata(
        metadata,
        download_url=download_url,
        filename=filename,
    )

    if selected is None and urls:
        selected = max(
            urls,
            key=lambda item: _parse_upload_time(item.get("upload_time_iso_8601"))
            or datetime.min.replace(tzinfo=timezone.utc),
        )

    if selected is None:
        return None
    return _parse_upload_time(selected.get("upload_time_iso_8601"))


def _release_metadata_without_fetch(
    package: PackageLike,
    client: OfficialPyPIClient,
    *,
    registry_metadata: RegistryMetadataLookup | None = None,
) -> dict | None:
    metadata = _package_report_metadata(package)
    if metadata is not None and _release_files_from_metadata(metadata):
        return metadata

    prefetched = _lookup_prefetched_registry_metadata(
        package,
        client,
        registry_metadata,
    )
    if prefetched is _NO_PREFETCHED_METADATA:
        return None
    assert isinstance(prefetched, _RegistryMetadataLookupResult)
    return prefetched.metadata


def _release_files_from_metadata(metadata: dict) -> list[dict]:
    urls = metadata.get("urls")
    if isinstance(urls, list):
        return [item for item in urls if isinstance(item, dict)]
    return []


def _selected_release_file_from_metadata(
    metadata: dict,
    *,
    download_url: str | None = None,
    filename: str | None = None,
) -> dict | None:
    selected = None
    for item in _release_files_from_metadata(metadata):
        if download_url and item.get("url") == download_url:
            selected = item
            break
        if filename and item.get("filename") == filename:
            selected = item
            break
    return selected


def _parse_archive_hash(value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    normalized = value.strip()
    if "=" in normalized:
        algorithm, digest = normalized.split("=", 1)
    elif ":" in normalized:
        algorithm, digest = normalized.split(":", 1)
    else:
        return None
    algorithm = algorithm.strip().lower()
    digest = digest.strip().lower()
    if not algorithm or not digest:
        return None
    return algorithm, digest


def _digest_from_release_file(file_info: dict, algorithm: str) -> str | None:
    digests = file_info.get("digests")
    if isinstance(digests, dict):
        value = digests.get(algorithm)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    value = file_info.get(f"{algorithm}_digest")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return None


def _parse_upload_time(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def _is_timeout_error(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    if isinstance(exc, URLError):
        reason = getattr(exc, "reason", None)
        return isinstance(reason, (TimeoutError, socket.timeout))
    return False


def _is_not_found_error(exc: Exception) -> bool:
    return isinstance(exc, HTTPError) and exc.code == 404


def _is_zero_version(version: str) -> bool:
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    release = parsed.release
    return len(release) >= 2 and all(component == 0 for component in release)


def _domain_from_email(email: str) -> str | None:
    _, address = parseaddr(email)
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().lower()
    return domain or None


def _is_empty_metadata_text(value: str) -> bool:
    normalized = value.strip()
    return normalized == "" or normalized.upper() == "UNKNOWN"


def _extract_direct_url_inputs(pip_args: list[str]) -> list[str]:
    direct_urls: list[str] = []
    requirement_files: list[Path] = []
    i = 0

    while i < len(pip_args):
        arg = pip_args[i]
        if arg == "--":
            direct_urls.extend(
                value for value in pip_args[i + 1 :] if _input_uses_direct_url(value)
            )
            break
        if arg.startswith("--requirement="):
            requirement_files.append(Path(arg.split("=", 1)[1]))
        elif arg in {"-r", "--requirement"}:
            if i + 1 < len(pip_args):
                requirement_files.append(Path(pip_args[i + 1]))
            i += 1
        elif arg in {"-e", "--editable"}:
            if i + 1 < len(pip_args) and _input_uses_direct_url(pip_args[i + 1]):
                direct_urls.append(pip_args[i + 1])
            i += 1
        elif arg.startswith("--editable="):
            value = arg.split("=", 1)[1]
            if _input_uses_direct_url(value):
                direct_urls.append(value)
        elif _starts_with_known_option_prefix(arg):
            pass
        elif arg in PIP_OPTIONS_WITH_VALUE:
            i += 1
        elif not arg.startswith("-") and _input_uses_direct_url(arg):
            direct_urls.append(arg)
        i += 1

    for path in requirement_files:
        direct_urls.extend(
            _extract_direct_urls_from_requirement_file(path.resolve(), set())
        )
    return direct_urls


def _extract_direct_urls_from_requirement_file(
    path: Path, visited: set[Path]
) -> list[str]:
    if path in visited or not path.exists():
        return []
    visited.add(path)

    direct_urls: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = _strip_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("--requirement="):
            nested = line.split("=", 1)[1]
            direct_urls.extend(
                _extract_direct_urls_from_requirement_file(
                    (path.parent / nested).resolve(), visited
                )
            )
            continue
        if line.startswith(("-r ", "--requirement ")):
            nested = line.split(maxsplit=1)[1]
            direct_urls.extend(
                _extract_direct_urls_from_requirement_file(
                    (path.parent / nested).resolve(), visited
                )
            )
            continue
        if line.startswith(("-e ", "--editable ")):
            value = line.split(maxsplit=1)[1]
            if _input_uses_direct_url(value):
                direct_urls.append(value)
            continue
        if line.startswith("--editable="):
            value = line.split("=", 1)[1]
            if _input_uses_direct_url(value):
                direct_urls.append(value)
            continue
        if line.startswith("-"):
            continue
        if _input_uses_direct_url(line):
            direct_urls.append(line)
    return direct_urls


def _input_uses_direct_url(value: str) -> bool:
    if value.startswith(VCS_URL_PREFIXES):
        return True
    if _requirement_uses_direct_url(value):
        return True
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"}


def _requirement_uses_direct_url(requirement: str) -> bool:
    try:
        parsed = Requirement(requirement)
    except InvalidRequirement:
        return requirement.startswith(VCS_URL_PREFIXES)
    return bool(parsed.url)


def _strip_comment(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    if " #" in line and "://" not in line:
        return line.split(" #", 1)[0]
    return line


def _starts_with_known_option_prefix(arg: str) -> bool:
    if not arg.startswith("--") or "=" not in arg:
        return False
    return arg.split("=", 1)[0] in PIP_OPTIONS_WITH_VALUE


def _package_report_metadata(package: PackageLike) -> dict | None:
    metadata = getattr(package, "metadata", None)
    if not isinstance(metadata, dict) or not metadata:
        return None
    return metadata


def _metadata_info(metadata: dict) -> dict:
    info = metadata.get("info")
    if isinstance(info, dict):
        return info
    return metadata


def _contact_emails_from_metadata(metadata: dict) -> tuple[str, ...]:
    info = _metadata_info(metadata)
    raw_values = [
        str(info.get("author_email") or ""),
        str(info.get("maintainer_email") or ""),
    ]
    emails: list[str] = []
    seen: set[str] = set()
    for _, address in getaddresses(raw_values):
        normalized = address.strip().lower()
        if not normalized or "@" not in normalized or normalized in seen:
            continue
        seen.add(normalized)
        emails.append(normalized)
    return tuple(emails)


def _description_fields_from_metadata(metadata: dict) -> tuple[str, str]:
    info = _metadata_info(metadata)
    return (
        str(info.get("summary") or ""),
        str(info.get("description") or ""),
    )


def _metadata_urls(metadata: dict) -> tuple[tuple[str, str], ...]:
    info = _metadata_info(metadata)
    urls: list[tuple[str, str]] = []
    for key in ("home_page", "download_url"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            urls.append((key, value.strip()))
    project_urls = info.get("project_urls") or {}
    if isinstance(project_urls, dict):
        for label, value in project_urls.items():
            if isinstance(label, str) and isinstance(value, str) and value.strip():
                urls.append((label, value.strip()))
    project_url_entries = info.get("project_url") or ()
    if isinstance(project_url_entries, str):
        project_url_entries = (project_url_entries,)
    if isinstance(project_url_entries, IterableABC):
        for entry in project_url_entries:
            if not isinstance(entry, str):
                continue
            label, separator, value = entry.partition(",")
            if separator and label.strip() and value.strip():
                urls.append((label.strip(), value.strip()))
    return tuple(urls)


def _suspicious_url_reason(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return f"non-http URL scheme '{parsed.scheme}'"
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        return None
    if parsed.username or parsed.password:
        return "URL includes embedded credentials"
    try:
        ip_address(hostname)
    except ValueError:
        pass
    else:
        return "URL uses a raw IP address"
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return "URL points to localhost"
    if _host_matches_any_suffix(hostname, SHORTENER_DOMAINS):
        return "URL uses a known shortener domain"
    if hostname.startswith("xn--") or ".xn--" in hostname:
        return "URL uses an internationalized domain"
    tld = hostname.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        return f"URL uses suspicious TLD '.{tld}'"
    return None


def _host_matches_any_suffix(hostname: str, suffixes: set[str]) -> bool:
    return any(
        hostname == suffix or hostname.endswith(f".{suffix}") for suffix in suffixes
    )


def _label_looks_like_repository(label: str) -> bool:
    normalized = label.strip().lower()
    return any(token in normalized for token in REPOSITORY_LABEL_TOKENS)


def _repository_name_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if hostname not in {"github.com", "www.github.com", "gitlab.com", "www.gitlab.com"}:
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    repository = parts[1]
    if repository.endswith(".git"):
        repository = repository[:-4]
    return repository or None


def _repository_looks_unrelated(package_name: str, repository_name: str) -> bool:
    package = canonicalize_name(package_name)
    repository = canonicalize_name(repository_name)
    if not package or not repository:
        return False
    if package == repository or package in repository or repository in package:
        return False
    package_tokens = {token for token in package.split("-") if len(token) >= 4}
    repository_tokens = {token for token in repository.split("-") if len(token) >= 4}
    if package_tokens.intersection(repository_tokens):
        return False
    return _similarity_below_threshold(package, repository, 0.72)


def _similarity_below_threshold(a: str, b: str, threshold: float) -> bool:
    if a == b:
        return False
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return True
    # SequenceMatcher's ratio cannot exceed this length-only upper bound.
    if (2 * min(la, lb) / (la + lb)) < threshold:
        return True
    return SequenceMatcher(None, a, b).ratio() < threshold


def _format_age(age: timedelta) -> str:
    total_seconds = int(max(age.total_seconds(), 0))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
