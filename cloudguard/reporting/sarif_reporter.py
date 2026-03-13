"""SARIF 2.1.0 reporter for CloudGuard scan results."""

from __future__ import annotations

import json
from typing import Any

from cloudguard import __version__
from cloudguard.core.models import ScanResult


class SARIFReporter:
    """Generate SARIF 2.1.0 format output."""

    def generate(self, result: ScanResult) -> str:
        """Create a SARIF 2.1.0 JSON report."""
        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CloudGuard",
                            "version": __version__,
                            "informationUri": "https://github.com/cloudguard/cloudguard",
                            "rules": self._build_rules(result),
                        }
                    },
                    "results": self._build_results(result),
                }
            ],
        }
        return json.dumps(sarif, indent=2, default=str)

    def _build_rules(self, result: ScanResult) -> list[dict[str, Any]]:
        """Build SARIF rule definitions from unique rule IDs."""
        seen: set[str] = set()
        rules: list[dict[str, Any]] = []
        for f in result.findings:
            if f.rule_id not in seen:
                seen.add(f.rule_id)
                rules.append({
                    "id": f.rule_id,
                    "shortDescription": {"text": f.issue},
                    "defaultConfiguration": {
                        "level": self._severity_to_level(f.severity.value)
                    },
                    "properties": {
                        "cvssScore": f.cvss_score,
                        "cvssVector": f.cvss_vector,
                    },
                })
        return rules

    def _build_results(self, result: ScanResult) -> list[dict[str, Any]]:
        """Build SARIF result entries."""
        return [
            {
                "ruleId": f.rule_id,
                "level": self._severity_to_level(f.severity.value),
                "message": {"text": f"{f.issue}. Mitigation: {f.mitigation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"aws://{f.region}/{f.service}/{f.resource_id}"
                            }
                        }
                    }
                ],
                "properties": {
                    "service": f.service,
                    "resourceId": f.resource_id,
                    "cvssScore": f.cvss_score,
                },
            }
            for f in result.findings
        ]

    @staticmethod
    def _severity_to_level(severity: str) -> str:
        """Map CloudGuard severity to SARIF level."""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        return mapping.get(severity, "note")
