"""Command-line interface for scanning Docker Compose configurations."""

import argparse
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from boundarycheck.reporting import format_error, format_json_report, format_text_report
from boundarycheck.scanner import ScanError, evaluate_policy


def _load_json_file(path: Path, description: str) -> Any:
    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except OSError as error:
        raise ScanError(f"Could not read {description} file '{path}'.") from error
    except json.JSONDecodeError as error:
        raise ScanError(f"{description.capitalize()} file '{path}' is not valid JSON.") from error


def _compose_configuration(compose_files: Sequence[Path]) -> Mapping[str, Any]:
    command = ["docker", "compose"]
    for path in compose_files:
        command.extend(("-f", str(path)))
    command.extend(("config", "--format", "json"))

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as error:
        raise ScanError(
            "Docker Compose CLI was not found; install Docker Compose V2 to scan Compose files."
        ) from error
    except OSError as error:
        raise ScanError("Could not run Docker Compose config.") from error

    if result.returncode != 0:
        raise ScanError(
            "Docker Compose config failed "
            f"(exit code {result.returncode}); its output was suppressed."
        )
    try:
        configuration = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ScanError("Docker Compose config did not return valid JSON.") from error
    if not isinstance(configuration, Mapping):
        raise ScanError("Docker Compose config must return a JSON object.")
    return configuration


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="boundarycheck",
        description="Static infrastructure checks for Docker Compose configurations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser(
        "scan",
        help="check normalized Compose configuration against a JSON policy",
        description="Check normalized Docker Compose configuration against a JSON policy.",
    )
    scan_parser.add_argument(
        "--compose",
        required=True,
        type=Path,
        help="base Docker Compose file",
    )
    scan_parser.add_argument(
        "--compose-override",
        action="append",
        default=[],
        type=Path,
        help="additional Compose override file (repeatable)",
    )
    scan_parser.add_argument(
        "--policy",
        required=True,
        type=Path,
        help="JSON security policy file",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    args = parser.parse_args(argv)

    try:
        policy = _load_json_file(args.policy, "policy")
        if not isinstance(policy, Mapping):
            raise ScanError("Security policy must be a JSON object.")
        configuration = _compose_configuration(
            [args.compose, *args.compose_override]
        )
        violations = evaluate_policy(configuration, policy)
    except ScanError as error:
        error_stream = sys.stdout if args.format == "json" else sys.stderr
        print(format_error(str(error), args.format), file=error_stream)
        return 2

    formatter = format_json_report if args.format == "json" else format_text_report
    print(formatter(violations))
    if violations:
        return 1

    return 0
