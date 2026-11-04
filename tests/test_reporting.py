import json
import unittest

from boundarycheck.reporting import (
    build_report,
    format_json_report,
    format_text_report,
)
from boundarycheck.scanner import evaluate_policy


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = {
            "forbidden_shared_networks": [{"services": ["proxy", "db"]}],
            "no_published_ports": ["api"],
            "expected_networks": {
                "proxy": ["app_network"],
                "api": ["app_network"],
                "db": ["db_network"],
            },
            "no_privileged_containers": True,
            "no_host_network": True,
            "no_docker_socket": True,
        }

    def test_json_report_contains_complete_finding_details(self) -> None:
        config = {
            "services": {
                "proxy": {"networks": {"app_network": {}, "db_network": {}}},
                "api": {"networks": {"app_network": {}}, "ports": [{"published": "8080"}]},
                "db": {"networks": {"db_network": {}}},
            }
        }

        report = json.loads(
            format_json_report(evaluate_policy(config, self.policy))
        )

        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["summary"]["violation_count"], 3)
        self.assertFalse(report["runtime_connectivity_tested"])
        finding = report["violations"][0]
        self.assertEqual(finding["rule_id"], "BC-NET-001")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["affected_services"], ["proxy", "db"])
        self.assertIn("share network", finding["description"])
        self.assertIn("shared_networks", finding["evidence"])
        self.assertTrue(finding["remediation"])
        self.assertEqual(report["violations"][1]["rule_id"], "BC-NET-003")
        self.assertEqual(report["violations"][2]["rule_id"], "BC-NET-002")

    def test_reports_do_not_include_unrelated_sensitive_configuration(self) -> None:
        secret = "report-must-not-leak-this-secret"
        config = {
            "services": {
                "proxy": {
                    "networks": {"app_network": {}, "db_network": {}},
                    "environment": {"PASSWORD": secret},
                    "labels": {"private.label": secret},
                    "image": secret,
                },
                "api": {
                    "networks": {"app_network": {}},
                    "ports": [{"published": secret}],
                },
                "db": {"networks": {"db_network": {}}},
            }
        }
        violations = evaluate_policy(config, self.policy)

        self.assertNotIn(secret, format_json_report(violations))
        self.assertNotIn(secret, format_text_report(violations))

    def test_text_report_includes_finding_details_and_remediation(self) -> None:
        config = {
            "services": {
                "proxy": {"networks": {"app_network": {}, "db_network": {}}},
                "api": {"networks": {"app_network": {}, "db_network": {}}},
                "db": {"networks": {"db_network": {}}},
            }
        }

        report = format_text_report(evaluate_policy(config, self.policy))

        self.assertIn("[HIGH] BC-NET-001", report)
        self.assertIn("Affected service(s): proxy, db", report)
        self.assertIn("Violation: Services 'proxy' and 'db' share", report)
        self.assertIn('"shared_networks": ["db_network"]', report)
        self.assertIn("Remediation:", report)

    def test_empty_report_is_pass_in_text_and_json(self) -> None:
        report = build_report([])

        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["summary"]["violation_count"], 0)
        self.assertIn("PASS", format_text_report([]))
        self.assertEqual(json.loads(format_json_report([])), report)

    def test_container_hardening_findings_are_in_text_and_json_reports(self) -> None:
        config = {
            "services": {
                "privileged_app": {"privileged": True},
                "host_app": {"network_mode": "host"},
                "docker_app": {
                    "volumes": [
                        {
                            "type": "bind",
                            "source": "/var/run/docker.sock",
                            "target": "/var/run/docker.sock",
                        }
                    ]
                },
            }
        }
        violations = evaluate_policy(config, self.policy)

        report = json.loads(format_json_report(violations))
        container_findings = [
            finding
            for finding in report["violations"]
            if finding["rule_id"].startswith("BC-CONT-")
        ]
        self.assertEqual(
            [finding["rule_id"] for finding in container_findings],
            ["BC-CONT-001", "BC-CONT-002", "BC-CONT-003"],
        )
        self.assertIn(
            "services.docker_app.volumes",
            container_findings[2]["evidence"]["configuration"],
        )
        self.assertIn(
            "Remove the Docker socket mount",
            container_findings[2]["remediation"],
        )

        text_report = format_text_report(violations)
        for rule_id in ("BC-CONT-001", "BC-CONT-002", "BC-CONT-003"):
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule_id, text_report)
        self.assertIn("/var/run/docker.sock", text_report)
        self.assertIn("Remediation:", text_report)


if __name__ == "__main__":
    unittest.main()
