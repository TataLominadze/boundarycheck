import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from boundarycheck.cli import main


ROOT = Path(__file__).parent


class CliTests(unittest.TestCase):
    def test_scan_accepts_multiple_overrides_and_suppresses_compose_json(self) -> None:
        with (ROOT / "fixtures" / "secure-compose.json").open(
            encoding="utf-8"
        ) as file:
            config = json.load(file)
        config["services"]["api"]["environment"] = {
            "DB_PASSWORD": "test-secret-must-not-be-printed"
        }
        result = CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(config),
            stderr="",
        )
        output = io.StringIO()
        args = [
            "scan",
            "--compose",
            "base.yaml",
            "--compose-override",
            "first.yaml",
            "--compose-override",
            "second.yaml",
            "--policy",
            str(ROOT.parent / "security-policy.json"),
        ]

        with patch("boundarycheck.cli.subprocess.run", return_value=result) as run:
            with redirect_stdout(output):
                exit_code = main(args)

        self.assertEqual(exit_code, 0)
        self.assertIn("PASS", output.getvalue())
        self.assertNotIn("test-secret-must-not-be-printed", output.getvalue())
        command = run.call_args.args[0]
        self.assertEqual(
            command,
            [
                "docker",
                "compose",
                "-f",
                "base.yaml",
                "-f",
                "first.yaml",
                "-f",
                "second.yaml",
                "config",
                "--format",
                "json",
            ],
        )
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_compose_error_does_not_print_suppressed_output(self) -> None:
        result = CompletedProcess(
            args=[],
            returncode=1,
            stdout="test-secret-must-not-be-printed",
            stderr="test-secret-must-not-be-printed",
        )
        output = io.StringIO()
        errors = io.StringIO()
        args = [
            "scan",
            "--compose",
            "base.yaml",
            "--policy",
            str(ROOT.parent / "security-policy.json"),
        ]

        with patch("boundarycheck.cli.subprocess.run", return_value=result):
            with redirect_stdout(output), redirect_stderr(errors):
                exit_code = main(args)

        self.assertEqual(exit_code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("output was suppressed", errors.getvalue())
        self.assertNotIn("test-secret-must-not-be-printed", errors.getvalue())

    def test_missing_compose_cli_reports_a_clear_error(self) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        args = [
            "scan",
            "--compose",
            "base.yaml",
            "--policy",
            str(ROOT.parent / "security-policy.json"),
        ]

        with patch(
            "boundarycheck.cli.subprocess.run", side_effect=FileNotFoundError
        ):
            with redirect_stdout(output), redirect_stderr(errors):
                exit_code = main(args)

        self.assertEqual(exit_code, 2)
        self.assertIn("Docker Compose CLI was not found", errors.getvalue())

    def test_json_report_is_structured_and_returns_violation_exit_code(self) -> None:
        config = {
            "services": {
                "proxy": {
                    "networks": {"app_network": {}, "db_network": {}},
                    "environment": {"PASSWORD": "test-secret-must-not-be-printed"},
                },
                "api": {"networks": {"app_network": {}, "db_network": {}}},
                "db": {"networks": {"db_network": {}}},
            }
        }
        result = CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(config),
            stderr="",
        )
        output = io.StringIO()
        args = [
            "scan",
            "--compose",
            "base.yaml",
            "--policy",
            str(ROOT.parent / "security-policy.json"),
            "--format",
            "json",
        ]

        with patch("boundarycheck.cli.subprocess.run", return_value=result):
            with redirect_stdout(output):
                exit_code = main(args)

        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["violations"][0]["rule_id"], "BC-NET-001")
        self.assertNotIn("test-secret-must-not-be-printed", output.getvalue())

    def test_json_scanner_error_is_a_json_report(self) -> None:
        output = io.StringIO()
        args = [
            "scan",
            "--compose",
            "base.yaml",
            "--policy",
            str(ROOT.parent / "security-policy.json"),
            "--format",
            "json",
        ]

        with patch(
            "boundarycheck.cli.subprocess.run", side_effect=FileNotFoundError
        ):
            with redirect_stdout(output):
                exit_code = main(args)

        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(report["status"], "ERROR")
        self.assertIn("Docker Compose CLI was not found", report["error"]["message"])

    def test_container_hardening_findings_return_violation_exit_code(self) -> None:
        with (ROOT / "fixtures" / "secure-compose.json").open(
            encoding="utf-8"
        ) as file:
            config = json.load(file)
        config["services"]["privileged_app"] = {"privileged": True}
        config["services"]["host_app"] = {"network_mode": "host"}
        config["services"]["docker_app"] = {
            "volumes": [
                {
                    "type": "bind",
                    "source": "/var/run/docker.sock",
                    "target": "/var/run/docker.sock",
                }
            ]
        }
        result = CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(config),
            stderr="",
        )
        output = io.StringIO()
        args = [
            "scan",
            "--compose",
            "base.yaml",
            "--policy",
            str(ROOT.parent / "security-policy.json"),
            "--format",
            "json",
        ]

        with patch("boundarycheck.cli.subprocess.run", return_value=result):
            with redirect_stdout(output):
                exit_code = main(args)

        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(
            {
                finding["rule_id"]
                for finding in report["violations"]
                if finding["rule_id"].startswith("BC-CONT-")
            },
            {"BC-CONT-001", "BC-CONT-002", "BC-CONT-003"},
        )


if __name__ == "__main__":
    unittest.main()
