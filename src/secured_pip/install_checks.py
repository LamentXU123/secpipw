from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Iterable, Protocol

from secured_pip.install_plan import InstallPlan, render_install_plan
from secured_pip.pypi_api import client_from_pip_args
from secured_pip.release_checks import (
    _all_packages_have_report_metadata,
    _packages_with_registry_metadata,
    detect_direct_url_alerts,
    detect_email_domain_drift_alerts,
    detect_empty_description_alerts,
    detect_recent_release_alerts,
    detect_repository_mismatch_alerts,
    detect_suspicious_metadata_url_alerts,
    detect_zero_version_alerts,
    render_direct_url_alerts,
    render_email_domain_drift_alerts,
    render_empty_description_alerts,
    render_release_age_alerts,
    render_repository_mismatch_alerts,
    render_suspicious_metadata_url_alerts,
    render_version_alerts,
)
from secured_pip.severity import Severity
from secured_pip.typo import detect_typos_in_resolved_packages, render_alerts
from secured_pip.warning_gate import GateDecision, enforce_warning_policy


class WarningLike(Protocol):
    severity: Severity
    message: str


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

    @property
    def all_alerts(self) -> tuple[WarningLike, ...]:
        return (
            *self.typo_alerts,
            *self.direct_url_alerts,
            *self.recent_release_alerts,
            *self.empty_description_alerts,
            *self.suspicious_metadata_url_alerts,
            *self.repository_mismatch_alerts,
            *self.email_domain_drift_alerts,
            *self.zero_version_alerts,
        )


def run_install_checks(
    plan: InstallPlan,
    pip_args: list[str],
    *,
    ignore_warning: bool,
    sensitivity: Severity,
    debug: bool,
) -> GateDecision:
    if debug:
        sys.stderr.write(render_install_plan(plan) + "\n")

    alerts = detect_install_alerts(plan, pip_args)
    if not alerts.all_alerts:
        return GateDecision(allow_install=True, exit_code=0)

    rendered = render_install_alerts(alerts)
    if rendered:
        sys.stderr.write(rendered + "\n")
    return enforce_warning_policy(
        alerts.all_alerts,
        ignore_warning=ignore_warning,
        sensitivity=sensitivity,
    )


def detect_install_alerts(plan: InstallPlan, pip_args: list[str]) -> InstallAlerts:
    release_client = client_from_pip_args(pip_args)
    registry_metadata_packages = _packages_with_registry_metadata(plan.packages)
    report_metadata_available = _all_packages_have_report_metadata(
        registry_metadata_packages
    )
    typo_alerts = tuple(detect_typos_in_resolved_packages(plan.packages))
    direct_url_alerts = tuple(detect_direct_url_alerts(pip_args, plan.packages))
    recent_release_alerts = tuple(
        detect_recent_release_alerts(
            registry_metadata_packages,
            client=release_client,
        )
    )
    empty_description_alerts = tuple(
        detect_empty_description_alerts(
            registry_metadata_packages,
            client=release_client,
            report_metadata_available=report_metadata_available,
        )
    )
    suspicious_metadata_url_alerts = tuple(
        detect_suspicious_metadata_url_alerts(
            registry_metadata_packages,
            client=release_client,
            report_metadata_available=report_metadata_available,
        )
    )
    repository_mismatch_alerts = tuple(
        detect_repository_mismatch_alerts(
            registry_metadata_packages,
            client=release_client,
            report_metadata_available=report_metadata_available,
        )
    )
    email_domain_drift_alerts = tuple(
        detect_email_domain_drift_alerts(
            registry_metadata_packages,
            client=release_client,
            report_metadata_available=report_metadata_available,
        )
    )
    zero_version_alerts = tuple(detect_zero_version_alerts(plan.packages))
    return InstallAlerts(
        typo_alerts=typo_alerts,
        direct_url_alerts=direct_url_alerts,
        recent_release_alerts=recent_release_alerts,
        empty_description_alerts=empty_description_alerts,
        suspicious_metadata_url_alerts=suspicious_metadata_url_alerts,
        repository_mismatch_alerts=repository_mismatch_alerts,
        email_domain_drift_alerts=email_domain_drift_alerts,
        zero_version_alerts=zero_version_alerts,
    )


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
    return "\n".join(rendered)


def _append_rendered(rendered: list[str], text: str) -> None:
    if text:
        rendered.append(text)
