"""CloudWatch Scanner — detects CloudWatch misconfigurations."""

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
class CloudWatchScanner(BaseScanner):
    service_name = "cloudwatch"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        logs = session.client("logs", region_name=region)

        try:
            paginator = logs.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for lg in page["logGroups"]:
                    name = lg["logGroupName"]
                    if "retentionInDays" not in lg:
                        rule = self._get_rule("cloudwatch-no-log-group-retention")
                        if rule:
                            findings.append(self._create_finding(rule, name, region))
        except ClientError as e:
            logger.error("Could not describe CloudWatch log groups: %s", e)

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None
