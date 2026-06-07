from __future__ import annotations

import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from secpipw import Severity
from secpipw import cli
from secpipw.install_plan import InstallPlan, InstallPlanError
from secpipw.tool_bridge import (
    preflight_pip_args_for_tool,
    tool_command_requires_preflight,
)
from secpipw.warning_gate import GateDecision


def _plan() -> InstallPlan:
    return InstallPlan(packages=(), raw_report={"install": []})


class ToolBridgeTests(unittest.TestCase):
    def test_pipx_install_maps_package_and_pip_args_to_pip_plan_args(self) -> None:
        args = preflight_pip_args_for_tool(
            "pipx",
            [
                "install",
                "black",
                "--pip-args",
                "--index-url https://example.test/simple --pre",
            ],
        )

        self.assertEqual(
            args,
            [
                "--index-url",
                "https://example.test/simple",
                "--pre",
                "black",
            ],
        )

    def test_pipx_install_prefers_spec_when_present(self) -> None:
        args = preflight_pip_args_for_tool(
            "pipx",
            ["install", "--spec", "black==24.4.2", "black"],
        )

        self.assertEqual(args, ["black==24.4.2"])

    def test_pipx_install_forwards_python_to_pip_plan_args(self) -> None:
        args = preflight_pip_args_for_tool(
            "pipx",
            ["install", "--python", "python3.12", "black"],
        )

        self.assertEqual(args, ["--python", "python3.12", "black"])

    def test_pipx_inject_skips_venv_name(self) -> None:
        args = preflight_pip_args_for_tool(
            "pipx",
            ["inject", "black", "requests", "urllib3"],
        )

        self.assertEqual(args, ["requests", "urllib3"])

    def test_pipx_run_includes_with_requirements(self) -> None:
        args = preflight_pip_args_for_tool(
            "pipx",
            ["run", "--with", "rich", "--spec", "black==24.4.2", "black"],
        )

        self.assertEqual(args, ["rich", "black==24.4.2"])

    def test_pipx_non_install_command_does_not_require_preflight(self) -> None:
        self.assertIsNone(preflight_pip_args_for_tool("pipx", ["list"]))
        self.assertFalse(tool_command_requires_preflight("pipx", ["list"]))

    def test_pipx_upgrade_requires_preflight_but_cannot_be_derived(self) -> None:
        self.assertIsNone(preflight_pip_args_for_tool("pipx", ["upgrade", "black"]))
        self.assertTrue(tool_command_requires_preflight("pipx", ["upgrade", "black"]))

    def test_poetry_add_maps_version_constraints(self) -> None:
        args = preflight_pip_args_for_tool(
            "poetry",
            ["add", "requests@^2.31.0", "urllib3@>=2"],
        )

        self.assertEqual(args, ["requests>=2.31.0,<3", "urllib3>=2"])

    def test_poetry_add_maps_caret_zero_version_constraints(self) -> None:
        args = preflight_pip_args_for_tool(
            "poetry",
            ["add", "example@^0.2.3", "sample@^0.0.3", "zero@^0.0"],
        )

        self.assertEqual(
            args,
            ["example>=0.2.3,<0.3", "sample>=0.0.3,<0.0.4", "zero>=0.0,<0.1"],
        )

    def test_poetry_add_maps_tilde_and_wildcard_constraints(self) -> None:
        args = preflight_pip_args_for_tool(
            "poetry",
            ["add", "example@~1.2", "sample@~1.2.3", "anyio@*"],
        )

        self.assertEqual(args, ["example>=1.2,<1.3", "sample>=1.2.3,<1.3", "anyio"])

    def test_poetry_add_maps_latest_and_prerelease(self) -> None:
        args = preflight_pip_args_for_tool(
            "poetry",
            ["add", "--allow-prereleases", "django@latest"],
        )

        self.assertEqual(args, ["--pre", "django"])

    def test_poetry_add_refuses_untranslated_custom_source(self) -> None:
        self.assertIsNone(
            preflight_pip_args_for_tool(
                "poetry",
                ["add", "--source", "internal", "private-package"],
            )
        )
        self.assertTrue(
            tool_command_requires_preflight(
                "poetry",
                ["add", "--source", "internal", "private-package"],
            )
        )

    def test_uv_pip_install_maps_supported_install_args(self) -> None:
        args = preflight_pip_args_for_tool(
            "uv",
            [
                "pip",
                "install",
                "--default-index",
                "https://example.test/simple",
                "--requirements",
                "requirements.txt",
                "--prerelease",
                "allow",
                "requests",
            ],
        )

        self.assertEqual(
            args,
            [
                "--index-url",
                "https://example.test/simple",
                "--pre",
                "-r",
                "requirements.txt",
                "requests",
            ],
        )

    def test_uv_pip_install_refuses_unsupported_resolution_args(self) -> None:
        self.assertIsNone(
            preflight_pip_args_for_tool(
                "uv",
                [
                    "pip",
                    "install",
                    "--index",
                    "https://internal.example/simple",
                    "private-package",
                ],
            )
        )
        self.assertTrue(
            tool_command_requires_preflight(
                "uv",
                [
                    "pip",
                    "install",
                    "--index",
                    "https://internal.example/simple",
                    "private-package",
                ],
            )
        )

    def test_uv_add_maps_common_package_args(self) -> None:
        args = preflight_pip_args_for_tool(
            "uv",
            ["add", "--dev", "--editable", "../local-package", "requests"],
        )

        self.assertEqual(
            args,
            ["--editable", "../local-package", "--editable", "requests"],
        )

    def test_uv_tool_install_maps_with_requirements(self) -> None:
        args = preflight_pip_args_for_tool(
            "uv",
            [
                "tool",
                "install",
                "ruff",
                "--with",
                "rich",
                "--with-requirements",
                "tools.txt",
            ],
        )

        self.assertEqual(args, ["-r", "tools.txt", "rich", "ruff"])

    def test_uv_tool_run_prefers_from_requirement(self) -> None:
        args = preflight_pip_args_for_tool(
            "uv",
            ["tool", "run", "--from", "ruff==0.6.0", "ruff", "check", "."],
        )

        self.assertEqual(args, ["ruff==0.6.0"])

    def test_uv_run_requires_preflight_but_cannot_be_derived(self) -> None:
        self.assertIsNone(preflight_pip_args_for_tool("uv", ["run", "pytest"]))
        self.assertTrue(tool_command_requires_preflight("uv", ["run", "pytest"]))

    def test_spipx_install_runs_checks_then_tool(self) -> None:
        with patch("secpipw.cli.resolve_install_plan", return_value=_plan()) as resolve:
            with patch(
                "secpipw.cli.run_install_checks",
                return_value=GateDecision(allow_install=True, exit_code=0),
            ) as checks:
                with patch(
                    "secpipw.cli.inspect_install_plan_artifacts",
                    return_value=[],
                ) as artifacts:
                    with patch("secpipw.cli.run_tool", return_value=9) as tool:
                        rc = cli.pipx_main(["install", "black"])

        self.assertEqual(rc, 9)
        resolve.assert_called_once_with(["black"])
        checks.assert_called_once()
        self.assertEqual(checks.call_args.args[1], ["black"])
        artifacts.assert_called_once()
        tool.assert_called_once_with("pipx", ["install", "black"])

    def test_spoetry_add_blocks_when_check_blocks(self) -> None:
        with patch("secpipw.cli.resolve_install_plan", return_value=_plan()):
            with patch(
                "secpipw.cli.run_install_checks",
                return_value=GateDecision(allow_install=False, exit_code=2),
            ):
                with patch("secpipw.cli.run_tool") as tool:
                    rc = cli.poetry_main(["add", "requsets"])

        self.assertEqual(rc, 2)
        tool.assert_not_called()

    def test_tool_entrypoint_resolution_failure_replays_pip_error(self) -> None:
        stderr = io.StringIO()

        with patch(
            "secpipw.cli.resolve_install_plan",
            side_effect=InstallPlanError(3, "bad requirement\n", ""),
        ):
            with patch("secpipw.cli.run_tool") as tool:
                with patch("sys.stderr", stderr):
                    rc = cli.pipx_main(["install", "bad req"])

        self.assertEqual(rc, 3)
        self.assertIn("bad requirement", stderr.getvalue())
        tool.assert_not_called()

    def test_tool_entrypoint_passthrough_for_non_install_command(self) -> None:
        with patch("secpipw.cli.run_tool", return_value=5) as tool:
            rc = cli.pipx_main(["list"])

        self.assertEqual(rc, 5)
        tool.assert_called_once_with("pipx", ["list"])

    def test_tool_entrypoint_install_refuses_when_plan_cannot_be_derived(self) -> None:
        stderr = io.StringIO()

        with patch("sys.stderr", stderr):
            with patch("secpipw.cli.run_tool") as tool:
                rc = cli.poetry_main(["add", "--source", "internal", "private-package"])

        self.assertEqual(rc, 2)
        tool.assert_not_called()
        self.assertIn("could not derive a pip install plan", stderr.getvalue())

    def test_spipx_entrypoint_uses_pipx_tool(self) -> None:
        with patch("secpipw.cli._tool_with_guard", return_value=6) as guarded:
            rc = cli.pipx_main(["list"])

        self.assertEqual(rc, 6)
        guarded.assert_called_once_with("pipx", ["list"])

    def test_spoetry_entrypoint_uses_poetry_tool(self) -> None:
        with patch("secpipw.cli._tool_with_guard", return_value=6) as guarded:
            rc = cli.poetry_main(["show"])

        self.assertEqual(rc, 6)
        guarded.assert_called_once_with("poetry", ["show"])

    def test_suv_entrypoint_uses_uv_tool(self) -> None:
        with patch("secpipw.cli._tool_with_guard", return_value=6) as guarded:
            rc = cli.uv_main(["pip", "list"])

        self.assertEqual(rc, 6)
        guarded.assert_called_once_with("uv", ["pip", "list"])

    def test_tool_wrapper_args_are_removed_before_running_tool(self) -> None:
        plan = InstallPlan(
            packages=(
                SimpleNamespace(
                    name="requests",
                    version="2.31.0",
                    requested=True,
                    is_direct=False,
                    download_url=None,
                    artifact_name=None,
                    archive_hash=None,
                    requires_dist=(),
                    metadata={},
                    yanked=False,
                    yanked_reason=None,
                ),
            ),
            raw_report={"install": []},
        )

        with patch("secpipw.cli.resolve_install_plan", return_value=plan):
            with patch(
                "secpipw.cli.run_install_checks",
                return_value=GateDecision(allow_install=True, exit_code=0),
            ) as checks:
                with patch(
                    "secpipw.cli.inspect_install_plan_artifacts",
                    return_value=[],
                ) as artifacts:
                    with patch("secpipw.cli.run_tool", return_value=0) as tool:
                        rc = cli.pipx_main(
                            [
                                "--spip-ignore",
                                "medium",
                                "--spip-debug",
                                "install",
                                "requests",
                            ]
                        )

        self.assertEqual(rc, 0)
        checks.assert_called_once_with(
            plan,
            ["requests"],
            ignore_warning=False,
            ignore_severity=Severity.MEDIUM,
            sensitivity=Severity.LOW,
            debug=True,
        )
        artifacts.assert_not_called()
        tool.assert_called_once_with("pipx", ["install", "requests"])

    def test_tool_wrapper_args_after_tool_command_are_not_removed(self) -> None:
        stderr = io.StringIO()

        with patch("sys.stderr", stderr):
            with patch("secpipw.cli.run_tool") as tool:
                rc = cli.pipx_main(
                    ["install", "requests", "--spip-ignore", "medium"]
                )

        self.assertEqual(rc, 2)
        tool.assert_not_called()
        self.assertIn("could not derive a pip install plan", stderr.getvalue())

    def test_suv_install_runs_checks_then_tool(self) -> None:
        with patch("secpipw.cli.resolve_install_plan", return_value=_plan()) as resolve:
            with patch(
                "secpipw.cli.run_install_checks",
                return_value=GateDecision(allow_install=True, exit_code=0),
            ) as checks:
                with patch(
                    "secpipw.cli.inspect_install_plan_artifacts",
                    return_value=[],
                ):
                    with patch("secpipw.cli.run_tool", return_value=8) as tool:
                        rc = cli.uv_main(["pip", "install", "requests"])

        self.assertEqual(rc, 8)
        resolve.assert_called_once_with(["requests"])
        checks.assert_called_once()
        tool.assert_called_once_with("uv", ["pip", "install", "requests"])

    def test_spip_tool_subcommands_are_rejected(self) -> None:
        stderr = io.StringIO()

        with patch("sys.stderr", stderr):
            with patch("secpipw.cli.run_tool") as tool:
                rc = cli.main(["pipx", "install", "black"])

        self.assertEqual(rc, 2)
        self.assertIn("use spipx instead", stderr.getvalue())
        tool.assert_not_called()


if __name__ == "__main__":
    unittest.main()
