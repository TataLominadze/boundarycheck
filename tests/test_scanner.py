import json
import unittest
from pathlib import Path

from boundarycheck.scanner import ScanError, evaluate_policy


ROOT = Path(__file__).parent


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as file:
        return json.load(file)


class PolicyEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_json(ROOT.parent / "security-policy.json")

    def test_secure_configuration_passes(self) -> None:
        config = load_json(ROOT / "fixtures" / "secure-compose.json")

        self.assertEqual(evaluate_policy(config, self.policy), [])

    def test_insecure_configuration_reports_proxy_database_sharing(self) -> None:
        config = load_json(ROOT / "fixtures" / "insecure-compose.json")

        violations = evaluate_policy(config, self.policy)

        self.assertTrue(
            any(
                violation.rule == "forbidden_shared_networks"
                and "proxy" in violation.message
                and "db" in violation.message
                and "db_network" in violation.message
                for violation in violations
            )
        )

    def test_api_and_database_published_ports_are_rejected(self) -> None:
        config = load_json(ROOT / "fixtures" / "secure-compose.json")
        config["services"]["api"]["ports"] = [{"target": 8000, "published": "8000"}]
        config["services"]["db"]["ports"] = [{"target": 5432, "published": "5432"}]

        violations = evaluate_policy(config, self.policy)

        self.assertEqual(
            [violation.rule for violation in violations],
            ["no_published_ports", "no_published_ports"],
        )
        self.assertIn("api", violations[0].message)
        self.assertIn("db", violations[1].message)

    def test_missing_expected_network_is_rejected(self) -> None:
        config = load_json(ROOT / "fixtures" / "secure-compose.json")
        del config["services"]["api"]["networks"]["db_network"]

        violations = evaluate_policy(config, self.policy)

        self.assertTrue(any(violation.rule == "expected_networks" for violation in violations))

    def test_invalid_compose_shape_is_rejected(self) -> None:
        with self.assertRaises(ScanError):
            evaluate_policy({}, self.policy)

    def test_secure_container_hardening_fixtures_pass(self) -> None:
        for rule_name in ("privileged", "host-network", "docker-socket"):
            with self.subTest(rule=rule_name):
                config = load_json(
                    ROOT / "fixtures" / f"secure-{rule_name}-compose.json"
                )
                policy = {self._policy_key(rule_name): True}

                self.assertEqual(evaluate_policy(config, policy), [])

    def test_insecure_container_hardening_fixtures_are_reported(self) -> None:
        expected = {
            "privileged": (
                "BC-CONT-001",
                "HIGH",
                {
                    "configuration": "services.app.privileged",
                    "privileged": True,
                },
            ),
            "host-network": (
                "BC-CONT-002",
                "HIGH",
                {
                    "configuration": "services.app.network_mode",
                    "network_mode": "host",
                },
            ),
            "docker-socket": (
                "BC-CONT-003",
                "CRITICAL",
                {
                    "configuration": "services.app.volumes",
                    "mount_type": "bind",
                    "source": "/var/run/docker.sock",
                    "target": "/var/run/docker.sock",
                },
            ),
        }
        for rule_name, (rule_id, severity, evidence) in expected.items():
            with self.subTest(rule=rule_name):
                config = load_json(
                    ROOT / "fixtures" / f"insecure-{rule_name}-compose.json"
                )
                violations = evaluate_policy(
                    config, {self._policy_key(rule_name): True}
                )

                self.assertEqual(len(violations), 1)
                self.assertEqual(violations[0].rule_id, rule_id)
                self.assertEqual(violations[0].severity, severity)
                self.assertEqual(violations[0].evidence, evidence)
                self.assertTrue(violations[0].message)
                self.assertTrue(violations[0].remediation)

    def test_container_requirements_are_disabled_when_policy_fields_are_missing(
        self,
    ) -> None:
        config = {
            "services": {
                "privileged": {"privileged": True},
                "host_network": {"network_mode": "host"},
                "docker_socket": {
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

        self.assertEqual(evaluate_policy(config, {}), [])

    def test_malformed_container_security_fields_are_rejected(self) -> None:
        malformed = (
            ({"privileged": "true"}, {"no_privileged_containers": True}),
            ({"network_mode": ["host"]}, {"no_host_network": True}),
            ({"volumes": [{"type": "bind"}]}, {"no_docker_socket": True}),
        )
        for service, policy in malformed:
            with self.subTest(service=service):
                with self.assertRaises(ScanError):
                    evaluate_policy({"services": {"app": service}}, policy)

    def test_container_requirement_policy_fields_must_be_boolean(self) -> None:
        for policy_key in (
            "no_privileged_containers",
            "no_host_network",
            "no_docker_socket",
        ):
            with self.subTest(policy_key=policy_key):
                with self.assertRaises(ScanError):
                    evaluate_policy(
                        {"services": {"app": {}}},
                        {policy_key: "true"},
                    )

    @staticmethod
    def _policy_key(rule_name: str) -> str:
        return {
            "privileged": "no_privileged_containers",
            "host-network": "no_host_network",
            "docker-socket": "no_docker_socket",
        }[rule_name]


if __name__ == "__main__":
    unittest.main()
