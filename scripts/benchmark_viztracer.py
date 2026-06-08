from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / ".tmp-viztracer-benchmark"


@dataclass(frozen=True)
class Scenario:
    key: str
    label: str
    code: str


SCENARIOS = {
    "package-import": Scenario(
        key="package-import",
        label="import secpipw",
        code="import secpipw",
    ),
    "cli-import": Scenario(
        key="cli-import",
        label="import secpipw.cli",
        code="import secpipw.cli",
    ),
    "tool-passthrough-pipx-list": Scenario(
        key="tool-passthrough-pipx-list",
        label="pipx list wrapper passthrough",
        code=(
            "import secpipw.cli as c; "
            "c.run_tool=lambda *args, **kwargs: 0; "
            "raise SystemExit(c.pipx_main(['list']))"
        ),
    ),
    "tool-passthrough-poetry-show": Scenario(
        key="tool-passthrough-poetry-show",
        label="poetry show wrapper passthrough",
        code=(
            "import secpipw.cli as c; "
            "c.run_tool=lambda *args, **kwargs: 0; "
            "raise SystemExit(c.poetry_main(['show']))"
        ),
    ),
    "tool-passthrough-uv-pip-list": Scenario(
        key="tool-passthrough-uv-pip-list",
        label="uv pip list wrapper passthrough",
        code=(
            "import secpipw.cli as c; "
            "c.run_tool=lambda *args, **kwargs: 0; "
            "raise SystemExit(c.uv_main(['pip', 'list']))"
        ),
    ),
    "tool-bridge-import": Scenario(
        key="tool-bridge-import",
        label="import secpipw.tool_bridge",
        code="import secpipw.tool_bridge",
    ),
    "tool-preflight-pipx-install": Scenario(
        key="tool-preflight-pipx-install",
        label="pipx install preflight parse",
        code=(
            "from secpipw.tool_bridge import preflight_pip_args_for_tool; "
            "preflight_pip_args_for_tool('pipx', ['install', 'black'])"
        ),
    ),
    "tool-preflight-poetry-add": Scenario(
        key="tool-preflight-poetry-add",
        label="poetry add preflight parse",
        code=(
            "from secpipw.tool_bridge import preflight_pip_args_for_tool; "
            "preflight_pip_args_for_tool('poetry', ['add', 'requests'])"
        ),
    ),
    "tool-preflight-uv-pip-install": Scenario(
        key="tool-preflight-uv-pip-install",
        label="uv pip install preflight parse",
        code=(
            "from secpipw.tool_bridge import preflight_pip_args_for_tool; "
            "preflight_pip_args_for_tool('uv', ['pip', 'install', 'requests'])"
        ),
    ),
    "pip-guard-import": Scenario(
        key="pip-guard-import",
        label="import secpipw.pip_guard",
        code="import secpipw.pip_guard",
    ),
    "pth-monitor-import": Scenario(
        key="pth-monitor-import",
        label="import secpipw.pth_monitor",
        code="import secpipw.pth_monitor",
    ),
    "pth-monitor-target-init": Scenario(
        key="pth-monitor-target-init",
        label="PthMonitor.from_install_args --target",
        code=(
            "import tempfile; "
            "from secpipw.pth_monitor import PthMonitor; "
            "PthMonitor.from_install_args(['--target', tempfile.mkdtemp()])"
        ),
    ),
    "pip-guard-class": Scenario(
        key="pip-guard-class",
        label="from secpipw.pip_guard import GuardedInstallCommand",
        code="from secpipw.pip_guard import GuardedInstallCommand",
    ),
}


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    env = _benchmark_env()

    records = []
    for scenario in args.scenarios:
        for index in range(args.runs):
            records.append(_run_scenario(scenario, index=index, args=args, env=env))

    payload = _payload(records, args)
    summary_path = args.output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    _print_summary(payload, summary_path)
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run local secpipw startup/hot-path scenarios with VizTracer."
    )
    parser.add_argument(
        "--scenario",
        dest="scenario_keys",
        action="append",
        choices=sorted(SCENARIOS),
        help="scenario to run; may be provided multiple times",
    )
    parser.add_argument("--runs", type=int, default=3, help="runs per scenario")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="directory for VizTracer reports and summary.json",
    )
    parser.add_argument(
        "--min-duration",
        type=float,
        default=0.001,
        help="VizTracer --min_duration value in seconds",
    )
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    args.scenarios = tuple(SCENARIOS[key] for key in (args.scenario_keys or SCENARIOS))
    return args


def _run_scenario(
    scenario: Scenario,
    *,
    index: int,
    args: argparse.Namespace,
    env: dict[str, str],
) -> dict:
    output_file = args.output_dir / f"{scenario.key}-{index}.html"
    command = [
        sys.executable,
        "-m",
        "viztracer",
        "--quiet",
        "--min_duration",
        str(args.min_duration),
        "-o",
        str(output_file),
        "-c",
        scenario.code,
    ]
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
    if completed.returncode != 0:
        _print_failure(scenario, command, completed)
        raise SystemExit(completed.returncode)
    return {
        "scenario": scenario.key,
        "label": scenario.label,
        "run": index,
        "duration_seconds": duration,
        "trace_file": str(output_file),
        "command": command,
    }


def _benchmark_env() -> dict[str, str]:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    pythonpath_entries = [str(ROOT / "src")]
    if existing_pythonpath:
        pythonpath_entries.append(existing_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _payload(records: list[dict], args: argparse.Namespace) -> dict:
    summaries = []
    for scenario in args.scenarios:
        durations = [
            record["duration_seconds"]
            for record in records
            if record["scenario"] == scenario.key
        ]
        summaries.append(
            {
                "scenario": scenario.key,
                "label": scenario.label,
                "avg": statistics.fmean(durations),
                "median": statistics.median(durations),
                "min": min(durations),
                "max": max(durations),
            }
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "runs": args.runs,
        "min_duration": args.min_duration,
        "summaries": summaries,
        "records": records,
    }


def _print_summary(payload: dict, summary_path: Path) -> None:
    print("\nVizTracer benchmark")
    for summary in payload["summaries"]:
        print(
            f"{summary['scenario']}: median {summary['median']:.4f}s, "
            f"avg {summary['avg']:.4f}s, min {summary['min']:.4f}s, "
            f"max {summary['max']:.4f}s"
        )
    print(f"\nwrote summary to {summary_path}")


def _print_failure(
    scenario: Scenario,
    command: list[str],
    completed: subprocess.CompletedProcess[str],
) -> None:
    print(f"\n{scenario.key} failed with exit code {completed.returncode}")
    print("command:", " ".join(command))
    if completed.stdout:
        print("\nstdout:\n" + completed.stdout)
    if completed.stderr:
        print("\nstderr:\n" + completed.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
