"""Base scanner abstract class for all CloudGuard service scanners.

Per MVP §11 Architecture: Service Scanners layer sits under the CloudGuard Engine.
Each scanner implements scan() to check a specific AWS service.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from cloudguard.core.models import Finding, Severity
from cloudguard.core.rule_loader import load_rules_for_service
from cloudguard.scoring.cvss import calculate_base_score

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Abstract base scanner that all service scanners must extend.

    Subclasses must:
    1. Set `service_name` class attribute (e.g., 'iam', 's3')
    2. Implement `_run_checks()` to perform actual AWS API calls
    """

    service_name: str = ""

    def __init__(self) -> None:
        self.rules: list[dict[str, Any]] = []

    def scan(self, session: boto3.Session, region: str = "us-east-1") -> list[Finding]:
        """Execute all checks for this service.

        Args:
            session: Boto3 session configured with credentials.
            region: AWS region to scan.

        Returns:
            List of Finding objects for detected misconfigurations.
        """
        findings: list[Finding] = []

        try:
            self.rules = load_rules_for_service(self.service_name)
        except FileNotFoundError:
            logger.warning("No rules found for service: %s", self.service_name)
            return findings
        except ValueError as e:
            logger.error("Invalid rules for %s: %s", self.service_name, e)
            return findings

        try:
            findings = self._run_checks(session, region)
        except (ClientError, BotoCoreError) as e:
            logger.error(
                "AWS API error scanning %s in %s: %s",
                self.service_name,
                region,
                e,
            )
        except Exception as e:
            logger.error(
                "Unexpected error scanning %s: %s",
                self.service_name,
                e,
            )

        return findings

    @abstractmethod
    def _run_checks(
        self, session: boto3.Session, region: str
    ) -> list[Finding]:
        """Implement service-specific checks.

        Args:
            session: Boto3 session.
            region: AWS region.

        Returns:
            List of findings.
        """
        ...

    def _create_finding(
        self,
        rule: dict[str, Any],
        resource_id: str,
        region: str,
        details: dict[str, Any] | None = None,
    ) -> Finding:
        """Create a Finding from a rule definition and resource context.

        Args:
            rule: Rule dictionary from YAML.
            resource_id: AWS resource identifier.
            region: AWS region.
            details: Additional context.

        Returns:
            Finding object with CVSS score calculated.
        """
        cvss_result = calculate_base_score(rule["cvss_vector"])

        return Finding(
            service=self.service_name.upper(),
            resource_id=resource_id,
            rule_id=rule["id"],
            issue=rule["description"],
            severity=Severity(rule["severity"].upper()),
            cvss_vector=rule["cvss_vector"],
            cvss_score=cvss_result.score,
            mitigation=rule["mitigation"],
            region=region,
            cis_mapping=rule.get("cis_mapping", ""),
            details=details or {},
        )
