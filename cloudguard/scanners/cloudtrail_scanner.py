"""CloudTrail Scanner — detects CloudTrail misconfigurations."""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cloudguard.core.models import Finding
from cloudguard.scanners.base import BaseScanner
from cloudguard.scanners.registry import register_scanner

logger = logging.getLogger(__name__)


@register_scanner
class CloudTrailScanner(BaseScanner):
    service_name = "cloudtrail"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        ct = session.client("cloudtrail", region_name=region)

        try:
            trails = ct.describe_trails().get("trailList", [])
            if not trails:
                rule = self._get_rule("cloudtrail-disabled")
                if rule:
                    findings.append(self._create_finding(rule, region, region))
                return findings

            for trail in trails:
                name = trail.get("Name", "unknown")
                if not trail.get("LogFileValidationEnabled"):
                    rule = self._get_rule("cloudtrail-no-log-validation")
                    if rule:
                        findings.append(self._create_finding(rule, name, region))
                if not trail.get("KmsKeyId"):
                    rule = self._get_rule("cloudtrail-not-encrypted")
                    if rule:
                        findings.append(self._create_finding(rule, name, region))
        except ClientError as e:
            logger.error("Could not describe CloudTrail trails: %s", e)

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None
