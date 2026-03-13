"""Tests for the rule loader."""

import pytest
from cloudguard.core.rule_loader import load_rules_for_service, load_all_rules


class TestRuleLoader:
    """Test YAML rule loading and validation."""

    def test_load_iam_rules(self):
        """Should load IAM rules successfully."""
        rules = load_rules_for_service("iam")
        assert len(rules) >= 5
        for rule in rules:
            assert "id" in rule
            assert "severity" in rule
            assert "cvss_vector" in rule
            assert "mitigation" in rule
            assert "description" in rule

    def test_load_s3_rules(self):
        """Should load S3 rules successfully."""
        rules = load_rules_for_service("s3")
        assert len(rules) >= 4
        assert any(r["id"] == "s3-public-access" for r in rules)

    def test_load_nonexistent_service(self):
        """Should raise FileNotFoundError for unknown service."""
        with pytest.raises(FileNotFoundError):
            load_rules_for_service("nonexistent")

    def test_load_all_rules(self):
        """Should load rules for all services."""
        all_rules = load_all_rules()
        assert len(all_rules) >= 15  # At least 15 of 20 services have rules
        for service, rules in all_rules.items():
            assert len(rules) > 0

    def test_rule_has_valid_severity(self):
        """All rules should have valid severity levels."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        all_rules = load_all_rules()
        for service, rules in all_rules.items():
            for rule in rules:
                assert rule["severity"].upper() in valid, (
                    f"Rule {rule['id']} has invalid severity: {rule['severity']}"
                )

    def test_rule_has_valid_cvss_vector(self):
        """All rules should have valid CVSS v3.1 vector strings."""
        all_rules = load_all_rules()
        for service, rules in all_rules.items():
            for rule in rules:
                assert rule["cvss_vector"].startswith("CVSS:3.1/"), (
                    f"Rule {rule['id']} has invalid CVSS vector: {rule['cvss_vector']}"
                )
