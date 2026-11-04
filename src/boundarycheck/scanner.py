"""Policy evaluation for normalized Docker Compose configuration."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class ScanError(ValueError):
    """Raised when a Compose configuration or security policy is invalid."""


@dataclass(frozen=True)
class Violation:
    rule: str
    message: str
    rule_id: str
    severity: str
    services: tuple[str, ...]
    evidence: Mapping[str, Any]
    remediation: str


def _string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ScanError(f"Policy field '{field_name}' must be a list of non-empty strings.")
    return value


def _service_networks(service: Mapping[str, Any], service_name: str) -> set[str]:
    networks = service.get("networks", {})
    if networks is None:
        return set()
    if isinstance(networks, Mapping):
        if any(not isinstance(name, str) for name in networks):
            raise ScanError(f"Service '{service_name}' has an invalid network name.")
        return set(networks)
    if isinstance(networks, list) and all(
        isinstance(name, str) and name for name in networks
    ):
        return set(networks)
    raise ScanError(f"Service '{service_name}' has an invalid networks section.")


def _policy_enabled(policy: Mapping[str, Any], field_name: str) -> bool:
    enabled = policy.get(field_name, False)
    if not isinstance(enabled, bool):
        raise ScanError(f"Policy field '{field_name}' must be a boolean.")
    return enabled


def _docker_socket_mounts(
    service: Mapping[str, Any], service_name: str
) -> list[tuple[str, str]]:
    mounts = service.get("volumes", [])
    if mounts is None:
        return []
    if not isinstance(mounts, list):
        raise ScanError(f"Service '{service_name}' has an invalid volumes section.")

    socket_mounts: list[tuple[str, str]] = []
    for mount in mounts:
        if not isinstance(mount, Mapping):
            raise ScanError(f"Service '{service_name}' has an invalid volume mount.")
        mount_type = mount.get("type")
        if not isinstance(mount_type, str) or not mount_type:
            raise ScanError(f"Service '{service_name}' has an invalid volume mount type.")
        if mount_type != "bind":
            continue

        source = mount.get("source")
        target = mount.get("target")
        if not isinstance(source, str) or not source:
            raise ScanError(f"Service '{service_name}' has an invalid bind source.")
        if not isinstance(target, str) or not target:
            raise ScanError(f"Service '{service_name}' has an invalid bind target.")

        paths = (source, target)
        if any(
            path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
            == "docker.sock"
            for path in paths
        ):
            socket_mounts.append((source, target))
    return socket_mounts


def evaluate_policy(
    compose_config: Mapping[str, Any], policy: Mapping[str, Any]
) -> list[Violation]:
    """Compare normalized Compose JSON with a BoundaryCheck JSON policy."""
    if not isinstance(compose_config, Mapping):
        raise ScanError("Compose configuration must be a JSON object.")
    services = compose_config.get("services")
    if not isinstance(services, Mapping):
        raise ScanError("Compose configuration must contain a services object.")
    if any(not isinstance(service, Mapping) for service in services.values()):
        raise ScanError("Every Compose service must be a JSON object.")
    if not isinstance(policy, Mapping):
        raise ScanError("Security policy must be a JSON object.")

    service_networks = {
        name: _service_networks(details, name) for name, details in services.items()
    }
    violations: list[Violation] = []

    forbidden_pairs = policy.get("forbidden_shared_networks", [])
    if not isinstance(forbidden_pairs, list):
        raise ScanError("Policy field 'forbidden_shared_networks' must be a list.")
    for rule in forbidden_pairs:
        if not isinstance(rule, Mapping):
            raise ScanError("Each forbidden shared-network rule must be an object.")
        pair = _string_list(rule.get("services"), "forbidden_shared_networks.services")
        if len(pair) != 2:
            raise ScanError("Each forbidden shared-network rule must name exactly two services.")
        first, second = pair
        shared = service_networks.get(first, set()) & service_networks.get(second, set())
        if shared:
            names = ", ".join(sorted(shared))
            violations.append(
                Violation(
                    "forbidden_shared_networks",
                    f"Services '{first}' and '{second}' share network(s): {names}.",
                    "BC-NET-001",
                    "HIGH",
                    (first, second),
                    {
                        "configuration": [
                            f"services.{first}.networks",
                            f"services.{second}.networks",
                        ],
                        "shared_networks": sorted(shared),
                    },
                    "Remove the shared network from one service and keep only "
                    "the communication paths each service requires.",
                )
            )

    no_published_ports = _string_list(
        policy.get("no_published_ports", []), "no_published_ports"
    )
    for service_name in no_published_ports:
        service = services.get(service_name)
        if service is None:
            continue
        ports = service.get("ports", [])
        if ports is None:
            ports = []
        if not isinstance(ports, list):
            raise ScanError(f"Service '{service_name}' has an invalid ports section.")
        if ports:
            violations.append(
                Violation(
                    "no_published_ports",
                    f"Service '{service_name}' has {len(ports)} published port "
                    f"mapping(s); none are allowed.",
                    "BC-NET-003",
                    "HIGH",
                    (service_name,),
                    {
                        "configuration": f"services.{service_name}.ports",
                        "published_mapping_count": len(ports),
                    },
                    "Remove host-published ports from this service. Use an "
                    "internal Compose network for service-to-service traffic.",
                )
            )

    expected_networks = policy.get("expected_networks", {})
    if not isinstance(expected_networks, Mapping):
        raise ScanError("Policy field 'expected_networks' must be an object.")
    for service_name, expected in expected_networks.items():
        if not isinstance(service_name, str) or not service_name:
            raise ScanError("Expected network entries must use non-empty service names.")
        expected_set = set(_string_list(expected, f"expected_networks.{service_name}"))
        actual_set = service_networks.get(service_name, set())
        if actual_set != expected_set:
            expected_names = ", ".join(sorted(expected_set)) or "(none)"
            actual_names = ", ".join(sorted(actual_set)) or "(none)"
            violations.append(
                Violation(
                    "expected_networks",
                    f"Service '{service_name}' networks differ: expected "
                    f"[{expected_names}], found [{actual_names}].",
                    "BC-NET-002",
                    "MEDIUM",
                    (service_name,),
                    {
                        "configuration": f"services.{service_name}.networks",
                        "expected_networks": sorted(expected_set),
                        "actual_networks": sorted(actual_set),
                    },
                    "Attach this service only to its expected networks, or "
                    "update the security policy if the intended topology changed.",
                )
            )

    no_privileged_containers = _policy_enabled(policy, "no_privileged_containers")
    no_host_network = _policy_enabled(policy, "no_host_network")
    no_docker_socket = _policy_enabled(policy, "no_docker_socket")

    for service_name, service in services.items():
        if no_privileged_containers:
            privileged = service.get("privileged", False)
            if not isinstance(privileged, bool):
                raise ScanError(
                    f"Service '{service_name}' has an invalid privileged setting."
                )
            if privileged:
                violations.append(
                    Violation(
                        "no_privileged_containers",
                        f"Service '{service_name}' enables privileged mode.",
                        "BC-CONT-001",
                        "HIGH",
                        (service_name,),
                        {
                            "configuration": f"services.{service_name}.privileged",
                            "privileged": True,
                        },
                        "Disable privileged mode and grant only the specific "
                        "capabilities and device access the service requires.",
                    )
                )

        if no_host_network:
            network_mode = service.get("network_mode")
            if network_mode is not None and not isinstance(network_mode, str):
                raise ScanError(
                    f"Service '{service_name}' has an invalid network_mode setting."
                )
            if network_mode == "host":
                violations.append(
                    Violation(
                        "no_host_network",
                        f"Service '{service_name}' uses host networking.",
                        "BC-CONT-002",
                        "HIGH",
                        (service_name,),
                        {
                            "configuration": f"services.{service_name}.network_mode",
                            "network_mode": "host",
                        },
                        "Use a dedicated Compose network and publish only the "
                        "specific ports the service needs.",
                    )
                )

        if no_docker_socket:
            for source, target in _docker_socket_mounts(service, service_name):
                violations.append(
                    Violation(
                        "no_docker_socket",
                        f"Service '{service_name}' bind-mounts a path named "
                        "'docker.sock'.",
                        "BC-CONT-003",
                        "CRITICAL",
                        (service_name,),
                        {
                            "configuration": f"services.{service_name}.volumes",
                            "mount_type": "bind",
                            "source": source,
                            "target": target,
                        },
                        "Remove the Docker socket mount. If Docker API access is "
                        "essential, use a narrowly scoped, authenticated proxy "
                        "instead of exposing the daemon socket directly.",
                    )
                )

    return violations
