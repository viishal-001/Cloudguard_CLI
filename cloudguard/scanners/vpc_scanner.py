"""VPC Scanner — detects VPC misconfigurations."""

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
class VPCScanner(BaseScanner):
    service_name = "vpc"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        ec2 = session.client("ec2", region_name=region)

        try:
            vpcs = ec2.describe_vpcs()["Vpcs"]
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                findings.extend(self._check_flow_logs(ec2, vpc_id, region))
                findings.extend(self._check_default_sg(ec2, vpc_id, region))
        except ClientError as e:
            logger.error("Could not describe VPCs: %s", e)

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None

    def _check_flow_logs(self, ec2: Any, vpc_id: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("vpc-flow-logs-disabled")
        if not rule:
            return findings

        flow_logs = ec2.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )
        if not flow_logs["FlowLogs"]:
            findings.append(self._create_finding(rule, vpc_id, region))
        return findings

    def _check_default_sg(self, ec2: Any, vpc_id: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("vpc-default-sg-in-use")
        if not rule:
            return findings

        sgs = ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )
        for sg in sgs["SecurityGroups"]:
            if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                findings.append(self._create_finding(rule, sg["GroupId"], region))
        return findings
