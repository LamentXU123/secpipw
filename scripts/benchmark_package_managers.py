from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "manager-benchmark-results.json"
DEFAULT_RUNS = 3
DEFAULT_PACKAGES = ("ruff", "httpie", "uvicorn")


@dataclass(frozen=True)
class Scenario:
    key: str
    wrapper: str
    guarded_entry: str
    packages: tuple[str, ...]


SCENARIOS = (
    Scenario("pip", "pip", "spip", DEFAULT_PACKAGES),
    Scenario("uv", "uv", "suv", DEFAULT_PACKAGES),
    Scenario("pipx", "pipx", "spipx", DEFAULT_PACKAGES),
    Scenario("poetry", "poetry", "spoetry", DEFAULT_PACKAGES),
)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    env = _benchmark_env()
    records: list[dict] = []

    for scenario in args.scenarios:
        packages = args.packages or scenario.packages
        for package in packages:
            for run in range(args.runs):
                records.append(_run_scenario(scenario, package, run, env))

    payload = _payload(records, args)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    _print_summary(payload, args.output)
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark original wrapper commands versus guarded secpipw entrypoints."
    )
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS, help="runs per package")
    parser.add_argument(
        "--scenario",
        dest="scenario_keys",
        action="append",
        choices=[scenario.key for scenario in SCENARIOS],
        help="scenario to run; may be provided multiple times",
    )
    parser.add_argument(
        "--json",
        dest="output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="JSON output path",
    )
    parser.add_argument(
        "--package",
        dest="packages",
        action="append",
        default=None,
        help="override package set; may be provided multiple times",
    )
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    selected = args.scenario_keys or [scenario.key for scenario in SCENARIOS]
    args.scenarios = tuple(scenario for scenario in SCENARIOS if scenario.key in selected)
    args.packages = tuple(args.packages or ())
    return args


def _benchmark_env() -> dict[str, str]:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    pythonpath_entries = [str(ROOT / "src")]
    if existing_pythonpath:
        pythonpath_entries.append(existing_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def _run_scenario(scenario: Scenario, package: str, run: int, env: dict[str, str]) -> dict:
    work_dir = Path(tempfile.mkdtemp(prefix=f"manager-bench-{scenario.key}-"))
    try:
        scenario_env = _scenario_env(env, scenario, work_dir)
        original_command = _original_command(scenario, package, work_dir)
        guarded_command = _guarded_command(scenario, package, work_dir)
        original_duration, original_completed = _run_command(original_command, scenario_env, work_dir)
        guarded_duration, guarded_completed = _run_command(guarded_command, scenario_env, work_dir)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    if original_completed.returncode != 0:
        _print_failure(scenario, package, "original", original_command, original_completed)
        raise SystemExit(original_completed.returncode)
    if guarded_completed.returncode != 0:
        _print_failure(scenario, package, "guarded", guarded_command, guarded_completed)
        raise SystemExit(guarded_completed.returncode)

    return {
        "scenario": scenario.key,
        "wrapper": scenario.wrapper,
        "guarded_entry": scenario.guarded_entry,
        "package": package,
        "run": run,
        "original_duration_seconds": original_duration,
        "guarded_duration_seconds": guarded_duration,
    }


def _scenario_env(
    base_env: dict[str, str],
    scenario: Scenario,
    work_dir: Path,
) -> dict[str, str]:
    env = dict(base_env)
    if scenario.key == "pipx":
        env["PIPX_HOME"] = str(work_dir / "pipx-home")
        env["PIPX_BIN_DIR"] = str(work_dir / "pipx-bin")
        env["PIPX_DEFAULT_BACKEND"] = "pip"
    if scenario.key == "poetry":
        env["POETRY_VIRTUALENVS_IN_PROJECT"] = "true"
        env["POETRY_CACHE_DIR"] = str(work_dir / "poetry-cache")
    return env


def _original_command(scenario: Scenario, package: str, work_dir: Path) -> list[str]:
    if scenario.key == "pip":
        return [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "--target",
            str(work_dir / "pip-target"),
            package,
        ]
    if scenario.key == "uv":
        return [
            "uv",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(work_dir / "uv-target"),
            package,
        ]
    if scenario.key == "pipx":
        return [
            "pipx",
            "install",
            "--force",
            "--pip-args=--disable-pip-version-check",
            package,
        ]
    _ensure_poetry_project(work_dir)
    return ["poetry", "add", package]


def _guarded_command(scenario: Scenario, package: str, work_dir: Path) -> list[str]:
    if scenario.key == "pip":
        return [
            sys.executable,
            "-m",
            "secpipw",
            "install",
            "--spip-ignore-warning",
            "--disable-pip-version-check",
            "--no-deps",
            "--target",
            str(work_dir / "spip-target"),
            package,
        ]
    if scenario.key == "uv":
        return [
            "suv",
            "--spip-ignore-warning",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(work_dir / "suv-target"),
            package,
        ]
    if scenario.key == "pipx":
        return [
            "spipx",
            "--spip-ignore-warning",
            "install",
            "--force",
            "--pip-args=--disable-pip-version-check",
            package,
        ]
    _ensure_poetry_project(work_dir)
    return ["spoetry", "--spip-ignore-warning", "add", package]


def _ensure_poetry_project(work_dir: Path) -> None:
    pyproject = work_dir / "pyproject.toml"
    if pyproject.exists():
        return
    python_version = f">={sys.version_info.major}.{sys.version_info.minor},<{sys.version_info.major}.{sys.version_info.minor + 1}"
    pyproject.write_text(
        "\n".join(
            [
                "[tool.poetry]",
                'name = "manager-benchmark"',
                'version = "0.1.0"',
                'description = "benchmark"',
                'authors = ["benchmark <benchmark@example.com>"]',
                "",
                "[tool.poetry.dependencies]",
                f'python = "{python_version}"',
                "",
                "[build-system]",
                'requires = ["poetry-core>=1.0.0"]',
                'build-backend = "poetry.core.masonry.api"',
            ]
        ),
        encoding="utf-8",
    )


def _run_command(
    command: list[str],
    env: dict[str, str],
    cwd: Path,
) -> tuple[float, subprocess.CompletedProcess[str]]:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=cwd,
        check=False,
    )
    return time.perf_counter() - started, completed


def _payload(records: list[dict], args: argparse.Namespace) -> dict:
    summaries = []
    for scenario in args.scenarios:
        scenario_records = [
            record for record in records if record["scenario"] == scenario.key
        ]
        original_durations = [
            record["original_duration_seconds"] for record in scenario_records
        ]
        guarded_durations = [
            record["guarded_duration_seconds"] for record in scenario_records
        ]
        original_stats = _stats(original_durations)
        guarded_stats = _stats(guarded_durations)
        ratio_avg = guarded_stats["avg"] / original_stats["avg"] if original_stats["avg"] else 0.0
        summaries.append(
            {
                "scenario": scenario.key,
                "wrapper": scenario.wrapper,
                "guarded_entry": scenario.guarded_entry,
                "packages": sorted({record["package"] for record in scenario_records}),
                "original": original_stats,
                "guarded": guarded_stats,
                "ratio": {
                    "avg": ratio_avg,
                    "avg_label": f"x{ratio_avg:.4f}",
                },
            }
        )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "runs": args.runs,
        "mode": "guarded package-manager wall-clock benchmark",
        "summaries": summaries,
        "records": records,
    }
    source = _github_actions_source()
    if source:
        payload["source"] = source
        benchmark_url = source.get("job_url") or source.get("run_url")
        if benchmark_url:
            payload["benchmark_url"] = benchmark_url
    return payload


def _stats(values: list[float]) -> dict[str, float]:
    return {
        "avg": statistics.fmean(values),
        "min": min(values),
        "max": max(values),
    }


def _github_actions_source() -> dict[str, str] | None:
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    run_url = os.environ.get("BENCHMARK_RUN_URL")
    if not run_url and repository and run_id:
        run_url = f"{server_url}/{repository}/actions/runs/{run_id}"

    job_url = os.environ.get("BENCHMARK_JOB_URL")
    if not run_url and not job_url:
        return None

    source: dict[str, str] = {}
    if repository:
        source["repository"] = repository
    if run_id:
        source["run_id"] = run_id
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
    if run_attempt:
        source["run_attempt"] = run_attempt
    job_name = os.environ.get("GITHUB_JOB")
    if job_name:
        source["job_name"] = job_name
    if run_url:
        source["run_url"] = run_url
    if job_url:
        source["job_url"] = job_url
    return source


def _print_failure(
    scenario: Scenario,
    package: str,
    label: str,
    command: list[str],
    completed: subprocess.CompletedProcess[str],
) -> None:
    print(f"\n{scenario.key}:{package} {label} failed with exit code {completed.returncode}")
    print("command:", " ".join(command))
    if completed.stdout:
        print("\nstdout:\n" + _safe_console_text(completed.stdout))
    if completed.stderr:
        print("\nstderr:\n" + _safe_console_text(completed.stderr))


def _print_summary(payload: dict, output: Path) -> None:
    print("\nPackage-manager benchmark")
    for summary in payload["summaries"]:
        print(
            f"{summary['wrapper']} vs {summary['guarded_entry']} "
            f"({', '.join(summary['packages'])}): original avg {summary['original']['avg']:.4f}s, "
            f"guarded avg {summary['guarded']['avg']:.4f}s, ratio {summary['ratio']['avg_label']}"
        )
    print(f"\nwrote JSON results to {output}")


def _safe_console_text(value: str) -> str:
    encoding = sys.stdout.encoding or "utf-8"
    return value.encode(encoding, errors="replace").decode(encoding, errors="replace")


if __name__ == "__main__":
    raise SystemExit(main())
