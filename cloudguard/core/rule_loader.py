"""YAML rule loader for CloudGuard security rules.

Per PRD §5 (Rule Engine): Security rules stored as configuration files.
Per MVP §12: rules/ directory with per-service YAML files.
"""

from __future__ import annotations

import importlib.resources
from pathlib import Path
from typing import Any

import yaml


def get_rules_dir() -> Path:
    """Get the path to the rules directory."""
    return Path(__file__).parent.parent / "rules"


def load_rules_for_service(service: str) -> list[dict[str, Any]]:
    """Load YAML rules for a specific AWS service.

    Args:
        service: AWS service name (e.g., 'iam', 's3', 'ec2').

    Returns:
        List of rule dictionaries.

    Raises:
        FileNotFoundError: If rules file does not exist.
        ValueError: If rules file is malformed.
    """
    rules_dir = get_rules_dir()
    rules_file = rules_dir / f"{service}_rules.yaml"

    if not rules_file.exists():
        raise FileNotFoundError(
            f"Rules file not found: {rules_file}. "
            f"Expected at cloudguard/rules/{service}_rules.yaml"
        )

    with open(rules_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "rules" not in data:
        raise ValueError(
            f"Malformed rules file {rules_file}: "
            "Expected top-level 'rules' key with a list of rule definitions."
        )

    rules = data["rules"]
    if not isinstance(rules, list):
        raise ValueError(f"'rules' in {rules_file} must be a list.")

    # Validate each rule has required fields
    required_fields = {"id", "description", "severity", "cvss_vector", "mitigation"}
    for i, rule in enumerate(rules):
        missing = required_fields - set(rule.keys())
        if missing:
            raise ValueError(
                f"Rule {i} in {rules_file} missing required fields: {missing}"
            )

    return rules


def load_all_rules() -> dict[str, list[dict[str, Any]]]:
    """Load all YAML rules from the rules directory.

    Returns:
        Dictionary mapping service name to list of rule dicts.
    """
    rules_dir = get_rules_dir()
    all_rules: dict[str, list[dict[str, Any]]] = {}

    if not rules_dir.exists():
        return all_rules

    for rules_file in sorted(rules_dir.glob("*_rules.yaml")):
        service = rules_file.stem.replace("_rules", "")
        try:
            all_rules[service] = load_rules_for_service(service)
        except (ValueError, FileNotFoundError):
            continue

    return all_rules
