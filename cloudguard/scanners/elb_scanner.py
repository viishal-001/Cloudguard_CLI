"""ELB Scanner."""

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
class ELBScanner(BaseScanner):
    service_name = "elb"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        elbv2 = session.client("elbv2", region_name=region)
        try:
            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    lb_arn = lb["LoadBalancerArn"]
                    lb_name = lb.get("LoadBalancerName", lb_arn)
                    listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                    has_https = any(l.get("Protocol") in ("HTTPS", "TLS") for l in listeners)
                    if not has_https and listeners:
                        rule = self._get_rule("elb-no-ssl")
                        if rule:
                            findings.append(self._create_finding(rule, lb_name, region))
                    attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                    attr_map = {a["Key"]: a["Value"] for a in attrs.get("Attributes", [])}
                    if attr_map.get("access_logs.s3.enabled") != "true":
                        rule = self._get_rule("elb-no-access-logging")
                        if rule:
                            findings.append(self._create_finding(rule, lb_name, region))
                    if attr_map.get("deletion_protection.enabled") != "true":
                        rule = self._get_rule("elb-deletion-protection-disabled")
                        if rule:
                            findings.append(self._create_finding(rule, lb_name, region))
        except ClientError as e:
            logger.error("Could not describe ELBs: %s", e)
        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None
