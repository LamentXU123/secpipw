from __future__ import annotations

import sys
from functools import lru_cache
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Iterable, Protocol

from secpipw.severity import Severity
from secpipw.warning_gate import (
    GateDecision,
    enforce_warning_policy,
    filter_ignored_warnings,
    severity_is_ignored,
)

MAX_TYPO_SEVERITY = Severity.MEDIUM
MAX_DIRECT_URL_SEVERITY = Severity.MEDIUM
MAX_RECENT_RELEASE_SEVERITY = Severity.MEDIUM
MAX_EMPTY_DESCRIPTION_SEVERITY = Severity.LOW
MAX_SUSPICIOUS_METADATA_URL_SEVERITY = Severity.LOW
MAX_REPOSITORY_MISMATCH_SEVERITY = Severity.LOW
MAX_EMAIL_DOMAIN_DRIFT_SEVERITY = Severity.LOW
MAX_ZERO_VERSION_SEVERITY = Severity.LOW
MAX_YANKED_RELEASE_SEVERITY = Severity.MEDIUM
MAX_ARCHIVE_HASH_MISMATCH_SEVERITY = Severity.HIGH
CHECK_FIELDS = (
    "typo_alerts",
    "direct_url_alerts",
    "recent_release_alerts",
    "empty_description_alerts",
    "suspicious_metadata_url_alerts",
    "repository_mismatch_alerts",
    "email_domain_drift_alerts",
    "zero_version_alerts",
    "yanked_release_alerts",
    "archive_hash_mismatch_alerts",
)
_BOOTSTRAP_PROJECT_NAME_SET: frozenset[str] | None = None

if TYPE_CHECKING:
    from secpipw.install_plan import InstallPlan


class WarningLike(Protocol):
    severity: Severity
    message: str


def render_install_plan(*args, **kwargs):
    from secpipw.install_plan import render_install_plan as impl

    return impl(*args, **kwargs)


def client_from_pip_args(*args, **kwargs):
    from secpipw.pypi_api import client_from_pip_args as impl

    return impl(*args, **kwargs)


@lru_cache(maxsize=1)
def _release_checks_module():
    from secpipw import release_checks

    return release_checks


def _all_packages_have_report_metadata(*args, **kwargs):
    return _release_checks_module()._all_packages_have_report_metadata(
        *args,
        **kwargs,
    )


def _packages_with_registry_metadata(*args, **kwargs):
    return _release_checks_module()._packages_with_registry_metadata(*args, **kwargs)


def detect_direct_url_alerts(*args, **kwargs):
    return _release_checks_module().detect_direct_url_alerts(*args, **kwargs)


def detect_archive_hash_mismatch_alerts(*args, **kwargs):
    return _release_checks_module().detect_archive_hash_mismatch_alerts(
        *args,
        **kwargs,
    )


def detect_email_domain_drift_alerts(*args, **kwargs):
    return _release_checks_module().detect_email_domain_drift_alerts(*args, **kwargs)


def detect_empty_description_alerts(*args, **kwargs):
    return _release_checks_module().detect_empty_description_alerts(*args, **kwargs)


def detect_recent_release_alerts(*args, **kwargs):
    return _release_checks_module().detect_recent_release_alerts(*args, **kwargs)


def detect_repository_mismatch_alerts(*args, **kwargs):
    return _release_checks_module().detect_repository_mismatch_alerts(*args, **kwargs)


def detect_suspicious_metadata_url_alerts(*args, **kwargs):
    return _release_checks_module().detect_suspicious_metadata_url_alerts(
        *args,
        **kwargs,
    )


def detect_zero_version_alerts(*args, **kwargs):
    return _release_checks_module().detect_zero_version_alerts(*args, **kwargs)


def detect_yanked_release_alerts(*args, **kwargs):
    return _release_checks_module().detect_yanked_release_alerts(*args, **kwargs)


def prefetch_release_metadata(*args, **kwargs):
    return _release_checks_module().prefetch_release_metadata(*args, **kwargs)


def render_direct_url_alerts(*args, **kwargs):
    return _release_checks_module().render_direct_url_alerts(*args, **kwargs)


def render_archive_hash_mismatch_alerts(*args, **kwargs):
    return _release_checks_module().render_archive_hash_mismatch_alerts(
        *args,
        **kwargs,
    )


def render_email_domain_drift_alerts(*args, **kwargs):
    return _release_checks_module().render_email_domain_drift_alerts(*args, **kwargs)


def render_empty_description_alerts(*args, **kwargs):
    return _release_checks_module().render_empty_description_alerts(*args, **kwargs)


def render_release_age_alerts(*args, **kwargs):
    return _release_checks_module().render_release_age_alerts(*args, **kwargs)


def render_repository_mismatch_alerts(*args, **kwargs):
    return _release_checks_module().render_repository_mismatch_alerts(*args, **kwargs)


def render_suspicious_metadata_url_alerts(*args, **kwargs):
    return _release_checks_module().render_suspicious_metadata_url_alerts(
        *args,
        **kwargs,
    )


def render_version_alerts(*args, **kwargs):
    return _release_checks_module().render_version_alerts(*args, **kwargs)


def render_yanked_release_alerts(*args, **kwargs):
    return _release_checks_module().render_yanked_release_alerts(*args, **kwargs)


def detect_typos_in_resolved_packages(*args, **kwargs):
    from secpipw.typo import detect_typos_in_resolved_packages as impl

    return impl(*args, **kwargs)


def render_alerts(*args, **kwargs):
    from secpipw.typo import render_alerts as impl

    return impl(*args, **kwargs)


@dataclass(frozen=True)
class InstallAlerts:
    typo_alerts: tuple[WarningLike, ...]
    direct_url_alerts: tuple[WarningLike, ...]
    recent_release_alerts: tuple[WarningLike, ...]
    empty_description_alerts: tuple[WarningLike, ...]
    suspicious_metadata_url_alerts: tuple[WarningLike, ...]
    repository_mismatch_alerts: tuple[WarningLike, ...]
    email_domain_drift_alerts: tuple[WarningLike, ...]
    zero_version_alerts: tuple[WarningLike, ...]
    yanked_release_alerts: tuple[WarningLike, ...]
    archive_hash_mismatch_alerts: tuple[WarningLike, ...]

    @property
    def all_alerts(self) -> tuple[WarningLike, ...]:
        return tuple(
            alert for field in CHECK_FIELDS for alert in getattr(self, field)
        )

    def without_ignored(self, ignore_severity: Severity | None) -> "InstallAlerts":
        return _install_alerts_from_mapping(
            {
                field: filter_ignored_warnings(getattr(self, field), ignore_severity)
                for field in CHECK_FIELDS
            }
        )


@dataclass(frozen=True)
class _InstallCheck:
    field: str
    max_severity: Severity
    needs_registry_metadata: bool
    prefetch_registry_metadata: bool
    detect: Callable[[InstallPlan, list[str], "_ReleaseCheckContext"], tuple[Any, ...]]


@dataclass(frozen=True)
class _ReleaseCheckContext:
    client: object | None
    registry_packages: list[object]
    report_metadata_available: bool
    prefetched_metadata: dict


def run_install_checks(
    plan: InstallPlan,
    pip_args: list[str],
    *,
    ignore_warning: bool,
    ignore_severity: Severity | None = None,
    sensitivity: Severity,
    debug: bool,
) -> GateDecision:
    if debug:
        sys.stderr.write(render_install_plan(plan) + "\n")

    alerts = detect_install_alerts(
        plan,
        pip_args,
        ignore_severity=ignore_severity,
    )
    visible_alerts = (
        alerts if ignore_severity is None else alerts.without_ignored(ignore_severity)
    )
    if not visible_alerts.all_alerts:
        return GateDecision(allow_install=True, exit_code=0)

    rendered = render_install_alerts(visible_alerts)
    if rendered:
        sys.stderr.write(rendered + "\n")
    return enforce_warning_policy(
        visible_alerts.all_alerts,
        ignore_warning=ignore_warning,
        ignore_severity=ignore_severity,
        sensitivity=sensitivity,
    )


def detect_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    *,
    ignore_severity: Severity | None = None,
) -> InstallAlerts:
    checks = _enabled_install_checks(ignore_severity)
    if not checks:
        return _empty_install_alerts()

    context = _release_check_context(plan, pip_args, checks)
    return _install_alerts_from_mapping(
        {
            check.field: check.detect(plan, pip_args, context)
            for check in checks
        }
    )


def _enabled_install_checks(
    ignore_severity: Severity | None,
) -> tuple[_InstallCheck, ...]:
    if ignore_severity is None:
        return _INSTALL_CHECKS
    return tuple(
        check
        for check in _INSTALL_CHECKS
        if not severity_is_ignored(ignore_severity, check.max_severity)
    )


def _release_check_context(
    plan: InstallPlan,
    pip_args: list[str],
    checks: tuple[_InstallCheck, ...],
) -> _ReleaseCheckContext:
    if not any(check.needs_registry_metadata for check in checks):
        return _ReleaseCheckContext(
            client=None,
            registry_packages=[],
            report_metadata_available=True,
            prefetched_metadata={},
        )

    release_client = client_from_pip_args(pip_args)
    registry_packages = _packages_with_registry_metadata(plan.packages)
    report_metadata_available = _all_packages_have_report_metadata(registry_packages)
    should_prefetch_metadata = any(
        check.prefetch_registry_metadata for check in checks
    )
    prefetched_metadata = (
        {}
        if report_metadata_available or not should_prefetch_metadata
        else prefetch_release_metadata(
            registry_packages,
            client=release_client,
        )
    )
    return _ReleaseCheckContext(
        client=release_client,
        registry_packages=registry_packages,
        report_metadata_available=report_metadata_available,
        prefetched_metadata=prefetched_metadata,
    )


def _detect_typo_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    if _all_package_names_in_bootstrap(plan.packages):
        return ()
    return tuple(detect_typos_in_resolved_packages(plan.packages))


def _detect_direct_url_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    return tuple(detect_direct_url_alerts(pip_args, plan.packages))


def _detect_recent_release_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    return tuple(
        detect_recent_release_alerts(
            context.registry_packages,
            client=context.client,
            registry_metadata=context.prefetched_metadata,
        )
    )


def _detect_empty_description_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    return tuple(
        detect_empty_description_alerts(
            context.registry_packages,
            client=context.client,
            report_metadata_available=context.report_metadata_available,
            registry_metadata=context.prefetched_metadata,
        )
    )


def _detect_suspicious_metadata_url_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    return tuple(
        detect_suspicious_metadata_url_alerts(
            context.registry_packages,
            client=context.client,
            report_metadata_available=context.report_metadata_available,
            registry_metadata=context.prefetched_metadata,
        )
    )


def _detect_repository_mismatch_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    return tuple(
        detect_repository_mismatch_alerts(
            context.registry_packages,
            client=context.client,
            report_metadata_available=context.report_metadata_available,
            registry_metadata=context.prefetched_metadata,
        )
    )


def _detect_email_domain_drift_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    return tuple(
        detect_email_domain_drift_alerts(
            context.registry_packages,
            client=context.client,
            report_metadata_available=context.report_metadata_available,
            registry_metadata=context.prefetched_metadata,
        )
    )


def _detect_zero_version_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    return tuple(detect_zero_version_alerts(plan.packages))


def _detect_yanked_release_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    return tuple(detect_yanked_release_alerts(plan.packages))


def _detect_archive_hash_mismatch_install_alerts(
    plan: InstallPlan,
    pip_args: list[str],
    context: _ReleaseCheckContext,
) -> tuple[WarningLike, ...]:
    return _detect_archive_hash_mismatch_alerts_if_metadata_available(
        plan.packages,
        client=context.client,
        registry_metadata=context.prefetched_metadata,
    )


_INSTALL_CHECKS: tuple[_InstallCheck, ...] = (
    _InstallCheck(
        "typo_alerts",
        MAX_TYPO_SEVERITY,
        False,
        False,
        _detect_typo_alerts,
    ),
    _InstallCheck(
        "direct_url_alerts",
        MAX_DIRECT_URL_SEVERITY,
        False,
        False,
        _detect_direct_url_install_alerts,
    ),
    _InstallCheck(
        "recent_release_alerts",
        MAX_RECENT_RELEASE_SEVERITY,
        True,
        False,
        _detect_recent_release_install_alerts,
    ),
    _InstallCheck(
        "empty_description_alerts",
        MAX_EMPTY_DESCRIPTION_SEVERITY,
        True,
        True,
        _detect_empty_description_install_alerts,
    ),
    _InstallCheck(
        "suspicious_metadata_url_alerts",
        MAX_SUSPICIOUS_METADATA_URL_SEVERITY,
        True,
        True,
        _detect_suspicious_metadata_url_install_alerts,
    ),
    _InstallCheck(
        "repository_mismatch_alerts",
        MAX_REPOSITORY_MISMATCH_SEVERITY,
        True,
        True,
        _detect_repository_mismatch_install_alerts,
    ),
    _InstallCheck(
        "email_domain_drift_alerts",
        MAX_EMAIL_DOMAIN_DRIFT_SEVERITY,
        True,
        True,
        _detect_email_domain_drift_install_alerts,
    ),
    _InstallCheck(
        "zero_version_alerts",
        MAX_ZERO_VERSION_SEVERITY,
        False,
        False,
        _detect_zero_version_install_alerts,
    ),
    _InstallCheck(
        "yanked_release_alerts",
        MAX_YANKED_RELEASE_SEVERITY,
        False,
        False,
        _detect_yanked_release_install_alerts,
    ),
    _InstallCheck(
        "archive_hash_mismatch_alerts",
        MAX_ARCHIVE_HASH_MISMATCH_SEVERITY,
        False,
        False,
        _detect_archive_hash_mismatch_install_alerts,
    ),
)


def _empty_install_alerts() -> InstallAlerts:
    return _install_alerts_from_mapping({})


def _all_package_names_in_bootstrap(packages: Iterable[object]) -> bool:
    bootstrap_names = _bootstrap_project_name_set()
    for package in packages:
        name = getattr(package, "name", None)
        if not name or _canonicalize_name(str(name)) not in bootstrap_names:
            return False
    return True


def _bootstrap_project_name_set() -> frozenset[str]:
    global _BOOTSTRAP_PROJECT_NAME_SET
    if _BOOTSTRAP_PROJECT_NAME_SET is None:
        from secpipw.pypi_api import BOOTSTRAP_PROJECT_NAMES

        # BOOTSTRAP_PROJECT_NAMES is already stored in canonical normalized form.
        _BOOTSTRAP_PROJECT_NAME_SET = frozenset(BOOTSTRAP_PROJECT_NAMES)
    return _BOOTSTRAP_PROJECT_NAME_SET


def _canonicalize_name(name: str) -> str:
    normalized: list[str] = []
    previous_was_separator = False
    for char in name.strip().lower():
        is_separator = char in "-_."
        if is_separator:
            if previous_was_separator:
                continue
            normalized.append("-")
        else:
            normalized.append(char)
        previous_was_separator = is_separator
    return "".join(normalized)


def _install_alerts_from_mapping(alerts: dict[str, Iterable]) -> InstallAlerts:
    return InstallAlerts(
        **{
            field: tuple(alerts.get(field, ()))
            for field in CHECK_FIELDS
        }
    )


def _detect_archive_hash_mismatch_alerts_if_metadata_available(
    packages,
    *,
    client,
    registry_metadata,
) -> tuple[WarningLike, ...]:
    if not registry_metadata and not _has_release_file_metadata(packages):
        return ()
    return tuple(
        detect_archive_hash_mismatch_alerts(
            packages,
            client=client,
            registry_metadata=registry_metadata,
        )
    )


def _has_release_file_metadata(packages) -> bool:
    for package in packages:
        if getattr(package, "is_direct", False):
            continue
        if not getattr(package, "archive_hash", None):
            continue
        metadata = getattr(package, "metadata", None)
        if not isinstance(metadata, dict):
            continue
        urls = metadata.get("urls")
        if isinstance(urls, list) and any(isinstance(item, dict) for item in urls):
            return True
    return False


def render_install_alerts(alerts: InstallAlerts) -> str:
    rendered: list[str] = []
    _append_rendered(rendered, render_alerts(alerts.typo_alerts))
    _append_rendered(rendered, render_direct_url_alerts(alerts.direct_url_alerts))
    _append_rendered(rendered, render_release_age_alerts(alerts.recent_release_alerts))
    _append_rendered(
        rendered,
        render_empty_description_alerts(alerts.empty_description_alerts),
    )
    _append_rendered(
        rendered,
        render_suspicious_metadata_url_alerts(alerts.suspicious_metadata_url_alerts),
    )
    _append_rendered(
        rendered,
        render_repository_mismatch_alerts(alerts.repository_mismatch_alerts),
    )
    _append_rendered(
        rendered,
        render_email_domain_drift_alerts(alerts.email_domain_drift_alerts),
    )
    _append_rendered(rendered, render_version_alerts(alerts.zero_version_alerts))
    _append_rendered(
        rendered,
        render_yanked_release_alerts(alerts.yanked_release_alerts),
    )
    _append_rendered(
        rendered,
        render_archive_hash_mismatch_alerts(alerts.archive_hash_mismatch_alerts),
    )
    return "\n".join(rendered)


def _append_rendered(rendered: list[str], text: str) -> None:
    if text:
        rendered.append(text)
