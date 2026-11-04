"""Human-readable and JSON reports for policy scan results."""

import json
from collections.abc import Sequence
from typing import Any

from boundarycheck.scanner import Violation


def build_report(violations: Sequence[Violation]) -> dict[str, Any]:
    """Build a structured report without copying the full Compose configuration."""
    findings = [
        {
            "rule_id": violation.rule_id,
            "severity": violation.severity,
            "affected_services": list(violation.services),
            "description": violation.message,
            "evidence": dict(violation.evidence),
            "remediation": violation.remediation,
        }
        for violation in violations
    ]
    return {
        "status": "FAIL" if findings else "PASS",
        "summary": {"violation_count": len(findings)},
        "violations": findings,
        "runtime_connectivity_tested": False,
    }


def format_json_report(violations: Sequence[Violation]) -> str:
    """Return a machine-readable JSON report."""
    return json.dumps(build_report(violations), indent=2, sort_keys=True)


def format_text_report(violations: Sequence[Violation]) -> str:
    """Return a concise report suitable for a terminal."""
    if not violations:
        return (
            "PASS: no policy violations detected.\n"
            "Static configuration only; runtime network connectivity was not tested."
        )

    lines = [f"FAIL: {len(violations)} policy violation(s) detected."]
    for violation in violations:
        services = ", ".join(violation.services)
        evidence = json.dumps(dict(violation.evidence), sort_keys=True)
        lines.extend(
            [
                f"\n[{violation.severity}] {violation.rule_id} "
                f"({violation.rule})",
                f"Affected service(s): {services}",
                f"Violation: {violation.message}",
                f"Evidence: {evidence}",
                f"Remediation: {violation.remediation}",
            ]
        )
    lines.append("Static configuration only; runtime network connectivity was not tested.")
    return "\n".join(lines)


def format_error(error: str, output_format: str) -> str:
    """Format a scanner error for the requested output format."""
    if output_format == "json":
        return json.dumps(
            {
                "status": "ERROR",
                "error": {"message": error},
                "summary": {"violation_count": 0},
                "violations": [],
                "runtime_connectivity_tested": False,
            },
            indent=2,
            sort_keys=True,
        )
    return f"ERROR: {error}"
