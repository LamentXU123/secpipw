import json
import os
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from secpipw.install_plan import (
    InstallPlanError,
    render_install_plan,
    resolve_install_plan,
)


class InstallPlanTests(unittest.TestCase):
    def test_resolve_install_plan_can_cache_reports(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.31.0"},
                    "download_info": {"url": "https://example.com/requests.whl"},
                }
            ],
        }
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(report),
                "stderr": "",
            },
        )()
        cache_root = Path(".tmp-tests") / f"install-plan-cache-{uuid4().hex}"
        cache_root.mkdir(parents=True, exist_ok=True)
        try:
            with patch(
                "secpipw.install_plan._install_plan_cache_root",
                return_value=cache_root,
            ):
                with patch(
                    "secpipw.install_plan.subprocess.run",
                    return_value=completed,
                ) as run:
                    first = resolve_install_plan(
                        ["requests==2.31.0"],
                        use_cache=True,
                    )

                with patch(
                    "secpipw.install_plan.subprocess.run",
                    side_effect=AssertionError("cache should avoid a second pip call"),
                ):
                    second = resolve_install_plan(
                        ["requests==2.31.0"],
                        use_cache=True,
                    )

            self.assertEqual(first.packages, second.packages)
            run.assert_called_once()
        finally:
            shutil.rmtree(cache_root, ignore_errors=True)

    def test_resolve_install_plan_cache_ignores_target_directory(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.31.0"},
                    "download_info": {"url": "https://example.com/requests.whl"},
                }
            ],
        }
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(report),
                "stderr": "",
            },
        )()
        cache_root = Path(".tmp-tests") / f"install-plan-cache-{uuid4().hex}"
        cache_root.mkdir(parents=True, exist_ok=True)
        try:
            with patch(
                "secpipw.install_plan._install_plan_cache_root",
                return_value=cache_root,
            ):
                with patch(
                    "secpipw.install_plan.subprocess.run",
                    return_value=completed,
                ) as run:
                    resolve_install_plan(
                        ["--target", "vendor-a", "requests==2.31.0"],
                        use_cache=True,
                    )

                with patch(
                    "secpipw.install_plan.subprocess.run",
                    side_effect=AssertionError(
                        "cache key should ignore target-only output paths"
                    ),
                ):
                    resolve_install_plan(
                        ["--target", "vendor-b", "requests==2.31.0"],
                        use_cache=True,
                    )

            run.assert_called_once()
        finally:
            shutil.rmtree(cache_root, ignore_errors=True)

    def test_resolve_install_plan_cache_is_reused_across_working_directories(
        self,
    ) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.31.0"},
                    "download_info": {"url": "https://example.com/requests.whl"},
                }
            ],
        }
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(report),
                "stderr": "",
            },
        )()
        cache_root = (Path(".tmp-tests") / f"install-plan-cache-{uuid4().hex}").resolve()
        work_a = (Path(".tmp-tests") / f"install-plan-work-a-{uuid4().hex}").resolve()
        work_b = (Path(".tmp-tests") / f"install-plan-work-b-{uuid4().hex}").resolve()
        cache_root.mkdir(parents=True, exist_ok=True)
        work_a.mkdir(parents=True, exist_ok=True)
        work_b.mkdir(parents=True, exist_ok=True)
        previous_cwd = Path.cwd()
        try:
            with patch(
                "secpipw.install_plan._install_plan_cache_root",
                return_value=cache_root,
            ):
                os.chdir(work_a)
                with patch(
                    "secpipw.install_plan.subprocess.run",
                    return_value=completed,
                ) as run:
                    resolve_install_plan(
                        ["requests==2.31.0"],
                        use_cache=True,
                    )

                os.chdir(work_b)
                with patch(
                    "secpipw.install_plan.subprocess.run",
                    side_effect=AssertionError(
                        "cache should not depend on the current working directory"
                    ),
                ):
                    resolve_install_plan(
                        ["requests==2.31.0"],
                        use_cache=True,
                    )

            run.assert_called_once()
        finally:
            os.chdir(previous_cwd)
            shutil.rmtree(cache_root, ignore_errors=True)
            shutil.rmtree(work_a, ignore_errors=True)
            shutil.rmtree(work_b, ignore_errors=True)

    def test_resolve_install_plan_parses_report(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "is_yanked": True,
                    "yanked_reason": "broken release",
                    "metadata": {
                        "name": "requests",
                        "version": "2.31.0",
                        "requires_dist": ["urllib3>=2"],
                        "summary": "HTTP for Humans",
                        "author_email": "dev@example.org",
                    },
                    "download_info": {
                        "url": "https://files.pythonhosted.org/packages/xx/requests-2.31.0-py3-none-any.whl",
                        "archive_info": {
                            "hashes": {
                                "sha256": "abc123",
                            },
                        },
                    },
                },
                {
                    "requested": False,
                    "is_direct": False,
                    "metadata": {"name": "urllib3", "version": "2.2.1"},
                    "download_info": {
                        "url": "https://files.pythonhosted.org/packages/yy/urllib3-2.2.1-py3-none-any.whl"
                    },
                },
            ],
        }
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(report),
                "stderr": "",
            },
        )()

        with patch("secpipw.install_plan.subprocess.run", return_value=completed):
            plan = resolve_install_plan(["requests==2.31.0"])

        self.assertEqual(
            [package.name for package in plan.packages], ["requests", "urllib3"]
        )
        self.assertEqual(
            plan.packages[0].artifact_name, "requests-2.31.0-py3-none-any.whl"
        )
        self.assertTrue(plan.packages[0].requested)
        self.assertFalse(plan.packages[1].requested)
        self.assertEqual(plan.packages[0].requires_dist, ("urllib3>=2",))
        self.assertEqual(plan.packages[0].metadata["summary"], "HTTP for Humans")
        self.assertEqual(plan.packages[0].metadata["author_email"], "dev@example.org")
        self.assertEqual(plan.packages[0].archive_hash, "sha256=abc123")
        self.assertTrue(plan.packages[0].yanked)
        self.assertEqual(plan.packages[0].yanked_reason, "broken release")

    def test_resolve_install_plan_raises_with_pip_failure(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 2,
                "stdout": "",
                "stderr": "bad requirement",
            },
        )()

        with patch("secpipw.install_plan.subprocess.run", return_value=completed):
            with self.assertRaises(InstallPlanError) as context:
                resolve_install_plan(["bad"])

        self.assertEqual(context.exception.returncode, 2)
        self.assertIn("bad requirement", context.exception.stderr)

    def test_render_install_plan_lists_all_packages(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.31.0"},
                    "download_info": {"url": "https://example.com/requests.whl"},
                }
            ],
        }
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(report),
                "stderr": "",
            },
        )()

        with patch("secpipw.install_plan.subprocess.run", return_value=completed):
            plan = resolve_install_plan(["requests==2.31.0"])

        rendered = render_install_plan(plan)
        self.assertIn("resolved packages to download (1)", rendered)
        self.assertIn("requests==2.31.0 [requested]", rendered)

    def test_resolve_install_plan_sets_utf8_env_for_pip_report(self) -> None:
        report = {"version": "1", "install": []}
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(report),
                "stderr": "",
            },
        )()

        with patch(
            "secpipw.install_plan.subprocess.run", return_value=completed
        ) as run:
            resolve_install_plan(["requests==2.31.0"])

        env = run.call_args.kwargs["env"]
        self.assertEqual(env["PYTHONIOENCODING"], "utf-8")
        self.assertEqual(env["PYTHONUTF8"], "1")
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")

    def test_resolve_install_plan_can_ignore_installed_packages(self) -> None:
        report = {"version": "1", "install": []}
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(report),
                "stderr": "",
            },
        )()

        with patch(
            "secpipw.install_plan.subprocess.run",
            return_value=completed,
        ) as run:
            resolve_install_plan(
                ["requests==2.31.0"],
                ignore_installed=True,
            )

        command = run.call_args.args[0]
        self.assertIn("--ignore-installed", command)

    def test_resolve_install_plan_can_parse_uv_dry_run_output(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "Would install 2 packages\n + requests==2.34.2\n + urllib3==2.7.0\n",
                "stderr": "\n".join(
                    [
                        "DEBUG Adding direct dependency: requests*",
                        "DEBUG Found fresh response for: https://files.pythonhosted.org/packages/a0/f4/c67b0b3f1b9245e8d266f0f112c500d50e5b4e83cb6f3b71b6528104182a/requests-2.34.2-py3-none-any.whl.metadata",
                        "DEBUG Selecting: requests==2.34.2 [compatible] (requests-2.34.2-py3-none-any.whl)",
                        "DEBUG Adding transitive dependency for requests==2.34.2: urllib3>=1.26, <3",
                        "DEBUG Found fresh response for: https://files.pythonhosted.org/packages/7f/3e/5db95bcf282c52709639744ca2a8b149baccf648e39c8cc87553df9eae0c/urllib3-2.7.0-py3-none-any.whl.metadata",
                        "DEBUG Selecting: urllib3==2.7.0 [compatible] (urllib3-2.7.0-py3-none-any.whl)",
                    ]
                ),
            },
        )()

        with patch("secpipw.install_plan.subprocess.run", return_value=completed) as run:
            plan = resolve_install_plan(
                ["requests"],
                ignore_installed=True,
                use_cache=False,
                tool="uv",
                tool_args=["pip", "install", "requests"],
            )

        self.assertEqual([package.name for package in plan.packages], ["requests", "urllib3"])
        self.assertTrue(plan.packages[0].requested)
        self.assertFalse(plan.packages[1].requested)
        self.assertEqual(plan.packages[0].requires_dist, ("urllib3>=1.26, <3",))
        self.assertEqual(
            plan.packages[0].download_url,
            "https://files.pythonhosted.org/packages/a0/f4/c67b0b3f1b9245e8d266f0f112c500d50e5b4e83cb6f3b71b6528104182a/requests-2.34.2-py3-none-any.whl",
        )
        self.assertEqual(
            plan.packages[0].artifact_name,
            "requests-2.34.2-py3-none-any.whl",
        )
        self.assertEqual(
            run.call_args.args[0],
            ["uv", "pip", "install", "--dry-run", "-v", "--no-progress", "requests"],
        )

    def test_resolve_install_plan_falls_back_when_uv_dry_run_is_incomplete(self) -> None:
        uv_completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "Would install 1 package\n + requests==2.34.2\n",
                "stderr": "",
            },
        )()
        pip_report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "metadata": {"name": "requests", "version": "2.34.2"},
                    "download_info": {"url": "https://example.com/requests.whl"},
                }
            ],
        }
        pip_completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(pip_report),
                "stderr": "",
            },
        )()

        with patch(
            "secpipw.install_plan.subprocess.run",
            side_effect=[uv_completed, pip_completed],
        ) as run:
            plan = resolve_install_plan(
                ["requests"],
                ignore_installed=True,
                use_cache=False,
                tool="uv",
                tool_args=["pip", "install", "requests"],
            )

        self.assertEqual([package.name for package in plan.packages], ["requests"])
        self.assertEqual(run.call_count, 2)

    def test_install_plan_from_report_accepts_explicit_artifact_name(self) -> None:
        report = {
            "version": "uv-dry-run-v1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
                    "artifact_name": "ruff-0.15.16-py3-none-win_amd64.whl",
                    "metadata": {"name": "ruff", "version": "0.15.16"},
                    "download_info": {},
                }
            ],
        }

        from secpipw.install_plan import install_plan_from_report

        plan = install_plan_from_report(report)

        self.assertEqual(plan.packages[0].artifact_name, "ruff-0.15.16-py3-none-win_amd64.whl")

    def test_resolve_install_plan_can_use_uv_fast_path_for_pipx(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "Would install 1 package\n + ruff==0.15.16\n",
                "stderr": "\n".join(
                    [
                        "DEBUG Adding direct dependency: ruff*",
                        "DEBUG Selecting: ruff==0.15.16 [compatible] (ruff-0.15.16-py3-none-win_amd64.whl)",
                    ]
                ),
            },
        )()

        with patch("secpipw.install_plan.subprocess.run", return_value=completed) as run:
            plan = resolve_install_plan(
                ["ruff"],
                ignore_installed=True,
                use_cache=False,
                tool="pipx",
                tool_args=["install", "ruff"],
            )

        self.assertEqual([package.name for package in plan.packages], ["ruff"])
        command = run.call_args.args[0]
        self.assertEqual(command[:6], ["uv", "pip", "install", "--dry-run", "-v", "--no-progress"])
        self.assertIn("--no-config", command)
        self.assertNotIn("--ignore-installed", command)

    def test_resolve_install_plan_can_use_uv_fast_path_for_poetry(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "Would install 1 package\n + ruff==0.15.16\n",
                "stderr": "\n".join(
                    [
                        "DEBUG Adding direct dependency: ruff*",
                        "DEBUG Selecting: ruff==0.15.16 [compatible] (ruff-0.15.16-py3-none-win_amd64.whl)",
                    ]
                ),
            },
        )()

        with patch("secpipw.install_plan.subprocess.run", return_value=completed) as run:
            plan = resolve_install_plan(
                ["ruff"],
                ignore_installed=True,
                use_cache=False,
                tool="poetry",
                tool_args=["add", "ruff"],
            )

        self.assertEqual([package.name for package in plan.packages], ["ruff"])
        command = run.call_args.args[0]
        self.assertEqual(command[:6], ["uv", "pip", "install", "--dry-run", "-v", "--no-progress"])
        self.assertIn("--no-config", command)

    def test_uv_fast_path_cached_plan_preserves_download_url(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "Would install 1 package\n + ruff==0.15.16\n",
                "stderr": "\n".join(
                    [
                        "DEBUG Adding direct dependency: ruff*",
                        "DEBUG Found fresh response for: https://files.pythonhosted.org/packages/8b/9e/demo/ruff-0.15.16-py3-none-win_amd64.whl.metadata",
                        "DEBUG Selecting: ruff==0.15.16 [compatible] (ruff-0.15.16-py3-none-win_amd64.whl)",
                    ]
                ),
            },
        )()
        cache_root = Path(".tmp-tests") / f"install-plan-cache-{uuid4().hex}"
        cache_root.mkdir(parents=True, exist_ok=True)
        try:
            with patch(
                "secpipw.install_plan._install_plan_cache_root",
                return_value=cache_root,
            ):
                with patch(
                    "secpipw.install_plan.subprocess.run",
                    return_value=completed,
                ):
                    first = resolve_install_plan(
                        ["ruff"],
                        ignore_installed=True,
                        use_cache=True,
                        tool="uv",
                        tool_args=["pip", "install", "ruff"],
                    )
                with patch(
                    "secpipw.install_plan.subprocess.run",
                    side_effect=AssertionError("cache should satisfy second resolve"),
                ):
                    second = resolve_install_plan(
                        ["ruff"],
                        ignore_installed=True,
                        use_cache=True,
                        tool="uv",
                        tool_args=["pip", "install", "ruff"],
                    )

            self.assertEqual(
                first.packages[0].download_url,
                "https://files.pythonhosted.org/packages/8b/9e/demo/ruff-0.15.16-py3-none-win_amd64.whl",
            )
            self.assertEqual(second.packages[0].download_url, first.packages[0].download_url)
        finally:
            shutil.rmtree(cache_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
