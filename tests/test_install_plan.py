import json
import unittest
from unittest.mock import patch

from secured_pip.install_plan import (
    InstallPlanError,
    render_install_plan,
    resolve_install_plan,
)


class InstallPlanTests(unittest.TestCase):
    def test_resolve_install_plan_parses_report(self) -> None:
        report = {
            "version": "1",
            "install": [
                {
                    "requested": True,
                    "is_direct": False,
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

        with patch("secured_pip.install_plan.subprocess.run", return_value=completed):
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

        with patch("secured_pip.install_plan.subprocess.run", return_value=completed):
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

        with patch("secured_pip.install_plan.subprocess.run", return_value=completed):
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
            "secured_pip.install_plan.subprocess.run", return_value=completed
        ) as run:
            resolve_install_plan(["requests==2.31.0"])

        env = run.call_args.kwargs["env"]
        self.assertEqual(env["PYTHONIOENCODING"], "utf-8")
        self.assertEqual(env["PYTHONUTF8"], "1")
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")


if __name__ == "__main__":
    unittest.main()
