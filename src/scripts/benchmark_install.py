from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
import venv
from pathlib import Path


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )


def python_exe(venv_dir: Path) -> Path:
    if os_name() == "windows":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def pip_exe(venv_dir: Path) -> Path:
    if os_name() == "windows":
        return venv_dir / "Scripts" / "pip.exe"
    return venv_dir / "bin" / "pip"


def spip_exe(venv_dir: Path) -> Path:
    if os_name() == "windows":
        return venv_dir / "Scripts" / "spip.exe"
    return venv_dir / "bin" / "spip"


def os_name() -> str:
    return "windows" if sys.platform.startswith("win") else "posix"


def install_target(
    exe: Path,
    base_args: list[str],
    target: Path,
    cwd: Path,
) -> tuple[float, subprocess.CompletedProcess[str]]:
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)

    cmd = [str(exe), *base_args, "--target", str(target)]
    start = time.perf_counter()
    completed = run(cmd, cwd=cwd)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    return elapsed_ms, completed


def main() -> int:
    package = sys.argv[1] if len(sys.argv) > 1 else "packaging==24.2"
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    warmups = int(sys.argv[3]) if len(sys.argv) > 3 else 1

    repo_root = Path(__file__).resolve().parents[2]
    bench_root = repo_root / ".tmp-tests" / "benchmark-install"
    results_dir = repo_root / ".tmp-tests" / "benchmark-results"
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    result_path = results_dir / f"install-benchmark-{timestamp}.json"

    if bench_root.exists():
        shutil.rmtree(bench_root)
    bench_root.mkdir(parents=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    venv_dir = bench_root / "venv"
    wheelhouse = bench_root / "wheelhouse"
    targets = bench_root / "targets"
    wheelhouse.mkdir()
    targets.mkdir()

    venv.EnvBuilder(with_pip=True).create(venv_dir)
    py = python_exe(venv_dir)
    pip = pip_exe(venv_dir)
    spip = spip_exe(venv_dir)

    for cmd in (
        [
            str(py),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "-q",
            "--upgrade",
            "pip",
        ],
        [str(py), "-m", "pip", "install", "-q", "-e", str(repo_root)],
        [
            str(pip),
            "download",
            "--disable-pip-version-check",
            "--no-deps",
            "--dest",
            str(wheelhouse),
            package,
        ],
    ):
        completed = run(cmd, cwd=repo_root)
        if completed.returncode != 0:
            sys.stderr.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            return completed.returncode

    wheels = sorted(wheelhouse.glob("*.whl"))
    if not wheels:
        sys.stderr.write("benchmark wheel not found\n")
        return 1

    pip_args = [
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--no-index",
        "--find-links",
        str(wheelhouse),
        package,
    ]
    spip_args = [
        "install",
        "--no-index",
        "--find-links",
        str(wheelhouse),
        package,
    ]

    for i in range(1, warmups + 1):
        for label, exe, args in (
            ("pip-warmup", pip, pip_args),
            ("secured_pip-warmup", spip, spip_args),
        ):
            elapsed_ms, completed = install_target(
                exe, args, targets / f"{label}-{i}", repo_root
            )
            if completed.returncode != 0:
                sys.stderr.write(f"{label} failed after {elapsed_ms} ms\n")
                sys.stderr.write(completed.stdout)
                sys.stderr.write(completed.stderr)
                return completed.returncode

    pip_runs: list[dict[str, object]] = []
    secured_runs: list[dict[str, object]] = []
    for i in range(1, runs + 1):
        elapsed_ms, completed = install_target(
            pip, pip_args, targets / f"pip-{i}", repo_root
        )
        if completed.returncode != 0:
            sys.stderr.write(f"pip run {i} failed after {elapsed_ms} ms\n")
            sys.stderr.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            return completed.returncode
        pip_runs.append({"index": i, "duration_ms": elapsed_ms})

        elapsed_ms, completed = install_target(
            spip, spip_args, targets / f"secured_pip-{i}", repo_root
        )
        if completed.returncode != 0:
            sys.stderr.write(f"secured_pip run {i} failed after {elapsed_ms} ms\n")
            sys.stderr.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            return completed.returncode
        secured_runs.append({"index": i, "duration_ms": elapsed_ms})

    pip_avg = round(sum(run["duration_ms"] for run in pip_runs) / len(pip_runs), 2)
    secured_avg = round(
        sum(run["duration_ms"] for run in secured_runs) / len(secured_runs), 2
    )
    delta_ms = round(secured_avg - pip_avg, 2)
    delta_pct = round(((secured_avg - pip_avg) / pip_avg) * 100, 2) if pip_avg else 0.0

    result = {
        "package": package,
        "wheel": wheels[0].name,
        "runs": runs,
        "warmups": warmups,
        "python": run([str(py), "--version"]).stdout.strip()
        or run([str(py), "--version"]).stderr.strip(),
        "pip": run([str(pip), "--version"]).stdout.strip()
        or run([str(pip), "--version"]).stderr.strip(),
        "spip": run([str(spip), "--version"]).stdout.strip()
        or run([str(spip), "--version"]).stderr.strip(),
        "benchmark_root": str(bench_root),
        "pip_runs": pip_runs,
        "secured_pip_runs": secured_runs,
        "pip_avg_ms": pip_avg,
        "secured_pip_avg_ms": secured_avg,
        "delta_ms": delta_ms,
        "delta_pct": delta_pct,
    }

    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
