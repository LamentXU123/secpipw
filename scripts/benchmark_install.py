from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORK_DIR = ROOT / ".tmp-benchmark"
DEFAULT_REQUIREMENTS = ("opencv-python", "scipy", "uv")
BENCHMARK_MODE = (
    "local wheelhouse install, --no-index, --no-deps, fresh --target per run"
)


@dataclass(frozen=True)
class RunResult:
    label: str
    scenario: str
    pair: str
    requirement: str
    command: list[str]
    duration_seconds: float
    returncode: int
    stdout: str
    stderr: str
    trace_file: str | None = None


@dataclass(frozen=True)
class ToolScenario:
    key: str
    label: str
    module: str
    spip_options: tuple[str, ...] = ()


PIP_SCENARIO = ToolScenario("pip", "pip", "pip")
SPIP_SCENARIO = ToolScenario("spip", "spip", "secpipw", ("--spip-ignore-warning",))


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    work_dir = args.work_dir.resolve()

    if work_dir.exists() and not args.keep_work_dir:
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    env = _benchmark_env(work_dir)
    wheelhouse = work_dir / "wheelhouse"
    _prepare_wheelhouse(args.requirements, wheelhouse, env)
    records: list[RunResult] = []

    for index in range(args.warmups):
        _run_cases(
            index=index,
            phase="warmup",
            args=args,
            wheelhouse=wheelhouse,
            work_dir=work_dir,
            env=env,
            records=None,
        )

    for index in range(args.runs):
        _run_cases(
            index=index,
            phase="run",
            args=args,
            wheelhouse=wheelhouse,
            work_dir=work_dir,
            env=env,
            records=records,
        )

    _print_summary(records, args.requirements)
    if args.json_output:
        payload = _json_payload(records, args)
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        print(f"\nwrote JSON results to {args.json_output}")

    if not args.keep_work_dir:
        shutil.rmtree(work_dir, ignore_errors=True)
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark pip install versus default spip install from a local "
            "wheelhouse."
        )
    )
    parser.add_argument("--runs", type=int, default=12, help="measured runs per tool")
    parser.add_argument("--warmups", type=int, default=1, help="warmup runs per tool")
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=DEFAULT_WORK_DIR,
        help="temporary benchmark workspace",
    )
    parser.add_argument(
        "--requirement",
        dest="requirements",
        action="append",
        default=None,
        help="requirement to benchmark; may be provided multiple times",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        type=Path,
        default=None,
        help="optional JSON output path",
    )
    parser.add_argument(
        "--keep-work-dir",
        action="store_true",
        help="keep temporary target directories",
    )
    parser.add_argument(
        "--viztracer",
        action="store_true",
        help="generate VizTracer HTML reports for measured runs",
    )
    parser.add_argument(
        "--viztracer-dir",
        type=Path,
        default=None,
        help="directory for VizTracer reports; defaults to WORK_DIR/viztracer",
    )
    parser.add_argument(
        "--viztracer-min-duration",
        type=float,
        default=0.02,
        help="VizTracer --min_duration value in seconds",
    )
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.warmups < 0:
        parser.error("--warmups must be at least 0")
    args.requirements = tuple(args.requirements or DEFAULT_REQUIREMENTS)
    if any(not requirement.strip() for requirement in args.requirements):
        parser.error("--requirement values must not be empty")
    return args


def _run_cases(
    *,
    index: int,
    phase: str,
    args: argparse.Namespace,
    wheelhouse: Path,
    work_dir: Path,
    env: dict[str, str],
    records: list[RunResult] | None,
) -> None:
    requirements = list(args.requirements)
    offset = index % len(requirements)
    requirements = requirements[offset:] + requirements[:offset]

    for case_index, requirement in enumerate(requirements):
        tools = [PIP_SCENARIO, SPIP_SCENARIO]
        if (index + case_index) % 2 == 1:
            tools.reverse()
        for tool in tools:
            result = _run_scenario(
                tool,
                requirement=requirement,
                index=index,
                phase=phase,
                args=args,
                wheelhouse=wheelhouse,
                work_dir=work_dir,
                env=env,
            )
            if result.returncode != 0:
                _print_failure(result)
                raise SystemExit(result.returncode)
            if records is not None:
                records.append(result)


def _run_scenario(
    scenario: ToolScenario,
    *,
    requirement: str,
    index: int,
    phase: str,
    args: argparse.Namespace,
    wheelhouse: Path,
    work_dir: Path,
    env: dict[str, str],
) -> RunResult:
    case_key = _case_key(requirement)
    target = work_dir / f"{phase}-{index}-{case_key}-{scenario.key}-target"
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    command = [
        sys.executable,
        "-m",
        scenario.module,
        "install",
    ]
    command.extend(scenario.spip_options)
    command.extend(
        [
            "--disable-pip-version-check",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--no-deps",
            "--progress-bar",
            "off",
            "--timeout",
            "120",
            "--target",
            str(target),
            requirement,
        ]
    )
    trace_file = None
    if args.viztracer and phase == "run":
        trace_dir = args.viztracer_dir or (work_dir / "viztracer")
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_file = trace_dir / f"{phase}-{index}-{case_key}-{scenario.key}.html"
        command = _viztracer_command(
            command,
            trace_file=trace_file,
            min_duration=args.viztracer_min_duration,
        )
    return _run_timed(scenario, requirement, command, env, trace_file=trace_file)


def _viztracer_command(
    command: list[str],
    *,
    trace_file: Path,
    min_duration: float,
) -> list[str]:
    if len(command) < 4 or command[0] != sys.executable or command[1] != "-m":
        raise ValueError("VizTracer benchmark only supports python -m commands")
    return [
        sys.executable,
        "-m",
        "viztracer",
        "--quiet",
        "--min_duration",
        str(min_duration),
        "-o",
        str(trace_file),
        "--module",
        command[2],
        *command[3:],
    ]


def _prepare_wheelhouse(
    requirements: tuple[str, ...],
    wheelhouse: Path,
    env: dict[str, str],
) -> None:
    wheelhouse.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--only-binary",
        ":all:",
        "--no-deps",
        "--disable-pip-version-check",
        "--dest",
        str(wheelhouse),
        *requirements,
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        print("\nfailed to prepare benchmark wheelhouse")
        print("command:", " ".join(command))
        if completed.stdout:
            print("\nstdout:\n" + completed.stdout)
        if completed.stderr:
            print("\nstderr:\n" + completed.stderr)
        raise SystemExit(completed.returncode)


def _run_timed(
    scenario: ToolScenario,
    requirement: str,
    command: list[str],
    env: dict[str, str],
    *,
    trace_file: Path | None = None,
) -> RunResult:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    duration = time.perf_counter() - started
    case_key = _case_key(requirement)
    return RunResult(
        label=scenario.label,
        scenario=f"{scenario.key}:{case_key}",
        pair=case_key,
        requirement=requirement,
        command=command,
        duration_seconds=duration,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        trace_file=str(trace_file) if trace_file is not None else None,
    )


def _benchmark_env(work_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    pythonpath_entries = [str(ROOT / "src")]
    if existing_pythonpath:
        pythonpath_entries.append(existing_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["SPIP_CACHE_DIR"] = str(work_dir / "spip-cache")
    return env


def _print_failure(result: RunResult) -> None:
    print(f"\n{result.label} failed with exit code {result.returncode}")
    print("command:", " ".join(result.command))
    if result.stdout:
        print("\nstdout:\n" + result.stdout)
    if result.stderr:
        print("\nstderr:\n" + result.stderr)


def _print_summary(records: list[RunResult], requirements: tuple[str, ...]) -> None:
    grouped = _group_durations(records)

    print("\nInstall benchmark")
    print(f"requirements: {', '.join(requirements)}")
    print(f"mode: {BENCHMARK_MODE}")
    print("")
    for requirement in requirements:
        key = _case_key(requirement)
        pip_stats = _stats(grouped[_scenario_key("pip", requirement)])
        spip_stats = _stats(grouped[_scenario_key("spip", requirement)])
        metrics = _comparison_metrics(pip_stats, spip_stats)
        print(f"case: {requirement}")
        _print_stats("  pip ", pip_stats)
        _print_stats("  spip", spip_stats)
        print(
            f"  overhead: avg {metrics['overhead']['avg_seconds']:+.4f}s "
            f"({metrics['overhead']['avg_percent']:+.2f}%), "
            f"median {metrics['overhead']['median_seconds']:+.4f}s "
            f"({metrics['overhead']['median_percent']:+.2f}%)"
        )
        print(
            f"  ratio: median {metrics['ratio']['median_label']}, "
            f"avg {metrics['ratio']['avg_label']}"
        )


def _print_stats(label: str, stats: dict[str, float]) -> None:
    print(
        f"{label}: avg {stats['avg']:.4f}s, median {stats['median']:.4f}s, "
        f"min {stats['min']:.4f}s, max {stats['max']:.4f}s"
    )


def _group_durations(records: list[RunResult]) -> dict[str, list[float]]:
    grouped: dict[str, list[float]] = {}
    for record in records:
        grouped.setdefault(record.scenario, []).append(record.duration_seconds)
    return grouped


def _scenario_key(tool: str, requirement: str) -> str:
    return f"{tool}:{_case_key(requirement)}"


def _case_key(requirement: str) -> str:
    return (
        requirement.strip()
        .lower()
        .replace("/", "-")
        .replace("\\", "-")
        .replace(" ", "-")
        .replace("=", "-")
        .replace(":", "-")
    )


def _stats(values: list[float]) -> dict[str, float]:
    return {
        "avg": statistics.fmean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def _comparison_metrics(
    pip_stats: dict[str, float], spip_stats: dict[str, float]
) -> dict[str, dict[str, float | str]]:
    avg_ratio = spip_stats["avg"] / pip_stats["avg"] if pip_stats["avg"] else 0.0
    median_ratio = (
        spip_stats["median"] / pip_stats["median"] if pip_stats["median"] else 0.0
    )
    avg_overhead = spip_stats["avg"] - pip_stats["avg"]
    median_overhead = spip_stats["median"] - pip_stats["median"]
    return {
        "ratio": {
            "avg": avg_ratio,
            "median": median_ratio,
            "avg_label": f"x{avg_ratio:.4f}",
            "median_label": f"x{median_ratio:.4f}",
        },
        "overhead": {
            "avg_seconds": avg_overhead,
            "median_seconds": median_overhead,
            "avg_percent": (
                (avg_overhead / pip_stats["avg"]) * 100 if pip_stats["avg"] else 0.0
            ),
            "median_percent": (
                (median_overhead / pip_stats["median"]) * 100
                if pip_stats["median"]
                else 0.0
            ),
        },
    }


def _json_payload(records: list[RunResult], args: argparse.Namespace) -> dict:
    grouped = _group_durations(records)
    scenario_summaries = []
    for requirement in args.requirements:
        pip_stats = _stats(grouped[_scenario_key("pip", requirement)])
        spip_stats = _stats(grouped[_scenario_key("spip", requirement)])
        scenario_summaries.append(
            {
                "key": _case_key(requirement),
                "label": requirement,
                "requirement": requirement,
                "pip": pip_stats,
                "spip": spip_stats,
                **_comparison_metrics(pip_stats, spip_stats),
            }
        )
    default_summary = scenario_summaries[0]
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "primary_metric": "median",
        "requirement": args.requirements[0],
        "requirements": list(args.requirements),
        "runs": args.runs,
        "warmups": args.warmups,
        "mode": BENCHMARK_MODE,
        "summary": default_summary,
        "scenarios": scenario_summaries,
        "records": [
            {
                "label": record.label,
                "scenario": record.scenario,
                "pair": record.pair,
                "requirement": record.requirement,
                "duration_seconds": record.duration_seconds,
                "returncode": record.returncode,
                "command": record.command,
                "trace_file": record.trace_file,
            }
            for record in records
        ],
    }
    source = _github_actions_source()
    if source:
        payload["source"] = source
        benchmark_url = source.get("job_url") or source.get("run_url")
        if benchmark_url:
            payload["benchmark_url"] = benchmark_url
    return payload


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


if __name__ == "__main__":
    raise SystemExit(main())
