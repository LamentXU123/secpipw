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
from typing import Iterable, Protocol
from urllib.error import URLError
from urllib.parse import urlparse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from secured_pip.pypi_api import OfficialPyPIClient, load_disposable_email_domains
from secured_pip.severity import Severity
from secured_pip.terminal import colorize
from secured_pip.typo import PIP_OPTIONS_WITH_VALUE

RECENT_RELEASE_THRESHOLD = timedelta(days=2)
RECENT_RELEASE_MAX_WORKERS = 8
_RELEASE_LOOKUP_CACHE: dict[tuple[str, str, str, str, str], "_ReleaseLookupResult"] = {}
_DISPOSABLE_EMAIL_LOOKUP_CACHE: dict[
    tuple[str, str, str], "_DisposableEmailLookupResult"
] = {}
_DESCRIPTION_LOOKUP_CACHE: dict[tuple[str, str, str], "_DescriptionLookupResult"] = {}
_SUSPICIOUS_URL_LOOKUP_CACHE: dict[
    tuple[str, str, str], "_SuspiciousUrlLookupResult"
] = {}
_REPOSITORY_MISMATCH_LOOKUP_CACHE: dict[
    tuple[str, str, str], "_RepositoryMismatchLookupResult"
] = {}

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
class DisposableEmailAlert:
    severity: Severity
    package_name: str
    version: str
    email: str
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
class _ReleaseLookupResult:
    timed_out: bool
    published_at: datetime | None


@dataclass(frozen=True)
class _DisposableEmailLookupResult:
    timed_out: bool
    matched_emails: tuple[str, ...]


@dataclass(frozen=True)
class _DescriptionLookupResult:
    has_empty_description: bool


@dataclass(frozen=True)
class _SuspiciousUrlLookupResult:
    findings: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _RepositoryMismatchLookupResult:
    findings: tuple[tuple[str, str], ...]


def detect_recent_release_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
    now: datetime | None = None,
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
                lambda package: _fetch_release_lookup_result(package, client),
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
    candidates = _packages_with_registry_metadata(packages)

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


def detect_empty_description_alerts(
    packages: Iterable[PackageLike],
    *,
    client: OfficialPyPIClient | None = None,
) -> list[EmptyDescriptionAlert]:
    client = client or OfficialPyPIClient()
    alerts: list[EmptyDescriptionAlert] = []
    candidates = _packages_with_registry_metadata(packages)

    if not candidates:
        return alerts

    max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        lookups = list(
            executor.map(
                lambda package: _fetch_description_lookup_result(package, client),
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
) -> list[MetadataUrlAlert]:
    client = client or OfficialPyPIClient()
    alerts: list[MetadataUrlAlert] = []
    candidates = _packages_with_registry_metadata(packages)

    if not candidates:
        return alerts

    max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        lookups = list(
            executor.map(
                lambda package: _fetch_suspicious_url_lookup_result(package, client),
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
) -> list[RepositoryMismatchAlert]:
    client = client or OfficialPyPIClient()
    alerts: list[RepositoryMismatchAlert] = []
    candidates = _packages_with_registry_metadata(packages)

    if not candidates:
        return alerts

    max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        lookups = list(
            executor.map(
                lambda package: _fetch_repository_mismatch_lookup_result(
                    package,
                    client,
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
) -> list[EmailDomainDriftAlert]:
    client = client or OfficialPyPIClient()
    alerts: list[EmailDomainDriftAlert] = []
    candidates = _packages_with_registry_metadata(packages)

    if not candidates:
        return alerts

    history = client.load_email_domain_history()
    updated_history = dict(history)

    max_workers = min(RECENT_RELEASE_MAX_WORKERS, len(candidates))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        current_domains = list(
            executor.map(
                lambda package: _fetch_contact_email_domains(package, client),
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

    metadata = _package_report_metadata(package)
    if metadata is not None:
        emails = _contact_emails_from_metadata(metadata)
    else:
        try:
            emails = client.fetch_release_contact_emails(package.name, package.version)
        except Exception as exc:
            if _is_timeout_error(exc):
                result = _DisposableEmailLookupResult(timed_out=True, matched_emails=())
            else:
                result = _DisposableEmailLookupResult(
                    timed_out=False,
                    matched_emails=(),
                )
            _DISPOSABLE_EMAIL_LOOKUP_CACHE[key] = result
            return result

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


def _fetch_description_lookup_result(
    package: PackageLike,
    client: OfficialPyPIClient,
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
) -> tuple[str, ...]:
    metadata = _package_report_metadata(package)
    if metadata is not None:
        emails = _contact_emails_from_metadata(metadata)
    else:
        try:
            emails = client.fetch_release_contact_emails(package.name, package.version)
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
    domain = _domain_from_email(email)
    if domain is None:
        return False
    parts = domain.split(".")
    for index in range(len(parts) - 1):
        if ".".join(parts[index:]) in disposable_domains:
            return True
    return False


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
    return SequenceMatcher(None, package, repository).ratio() < 0.72


def _format_age(age: timedelta) -> str:
    total_seconds = int(max(age.total_seconds(), 0))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
