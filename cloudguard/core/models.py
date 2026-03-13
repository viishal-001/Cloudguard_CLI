"""Data models for CloudGuard scan findings and results.

Per MVP §8 (CLI Output) and PRD §5 (Output Requirements):
Each finding includes service, resource, issue, severity, CVSS, and mitigation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity classification per MVP §9."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security finding from a scan.

    Per PRD §5: Results must include Service, Resource, Issue, Severity, CVSS, Mitigation.
    """

    service: str
    resource_id: str
    rule_id: str
    issue: str
    severity: Severity
    cvss_vector: str
    cvss_score: float
    mitigation: str
    region: str = ""
    cis_mapping: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to dictionary."""
        return {
            "service": self.service,
            "resource_id": self.resource_id,
            "rule_id": self.rule_id,
            "issue": self.issue,
            "severity": self.severity.value,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "mitigation": self.mitigation,
            "region": self.region,
            "cis_mapping": self.cis_mapping,
            "details": self.details,
        }


@dataclass
class ScanResult:
    """Complete scan result containing all findings.

    Per PRD §8 (Database Schema — future): scan_id, timestamp, account_id, region.
    """

    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    account_id: str = ""
    region: str = ""
    findings: list[Finding] = field(default_factory=list)
    services_scanned: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    @property
    def summary(self) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Serialize scan result to dictionary."""
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "account_id": self.account_id,
            "region": self.region,
            "services_scanned": self.services_scanned,
            "scan_duration_seconds": self.scan_duration_seconds,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
