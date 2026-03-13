"""Security Groups Scanner — detects overly permissive security groups.

Per PRD §2: Open security groups are a leading cause of data breaches.
"""

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
class SGScanner(BaseScanner):
    """Scanner for AWS Security Groups."""

    service_name = "sg"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        ec2 = session.client("ec2", region_name=region)

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    findings.extend(self._check_ingress(sg, sg_id, region))
        except ClientError as e:
            logger.error("Could not describe security groups: %s", e)

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for rule in self.rules:
            if rule["id"] == rule_id:
                return rule
        return None

    def _check_ingress(
        self, sg: dict[str, Any], sg_id: str, region: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)

                    if from_port <= 22 <= to_port:
                        rule = self._get_rule("sg-ssh-open")
                        if rule:
                            findings.append(self._create_finding(rule, sg_id, region))
                    elif from_port <= 3389 <= to_port:
                        rule = self._get_rule("sg-rdp-open")
                        if rule:
                            findings.append(self._create_finding(rule, sg_id, region))
                    else:
                        rule = self._get_rule("sg-unrestricted-ingress")
                        if rule:
                            findings.append(
                                self._create_finding(
                                    rule, sg_id, region,
                                    {"port_range": f"{from_port}-{to_port}"}
                                )
                            )

            for ipv6_range in perm.get("Ipv6Ranges", []):
                if ipv6_range.get("CidrIpv6") == "::/0":
                    rule = self._get_rule("sg-unrestricted-ingress")
                    if rule:
                        findings.append(
                            self._create_finding(rule, sg_id, region, {"ipv6": True})
                        )

        return findings
