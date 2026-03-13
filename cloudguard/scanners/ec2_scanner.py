"""EC2 Scanner — detects EC2 instance misconfigurations."""

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
class EC2Scanner(BaseScanner):
    """Scanner for AWS EC2 service."""

    service_name = "ec2"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        ec2 = session.client("ec2", region_name=region)

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        if instance["State"]["Name"] != "running":
                            continue
                        iid = instance["InstanceId"]
                        findings.extend(self._check_public_ip(instance, iid, region))
                        findings.extend(self._check_imds(ec2, instance, iid, region))
                        findings.extend(self._check_monitoring(instance, iid, region))
        except ClientError as e:
            logger.error("Could not describe EC2 instances: %s", e)

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for rule in self.rules:
            if rule["id"] == rule_id:
                return rule
        return None

    def _check_public_ip(
        self, instance: dict[str, Any], iid: str, region: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("ec2-public-ip")
        if not rule:
            return findings

        if instance.get("PublicIpAddress"):
            findings.append(
                self._create_finding(
                    rule, iid, region, {"public_ip": instance["PublicIpAddress"]}
                )
            )
        return findings

    def _check_imds(
        self, ec2: Any, instance: dict[str, Any], iid: str, region: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("ec2-imdsv1-enabled")
        if not rule:
            return findings

        metadata_options = instance.get("MetadataOptions", {})
        if metadata_options.get("HttpTokens") != "required":
            findings.append(self._create_finding(rule, iid, region))
        return findings

    def _check_monitoring(
        self, instance: dict[str, Any], iid: str, region: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("ec2-no-monitoring")
        if not rule:
            return findings

        monitoring = instance.get("Monitoring", {})
        if monitoring.get("State") != "enabled":
            findings.append(self._create_finding(rule, iid, region))
        return findings
