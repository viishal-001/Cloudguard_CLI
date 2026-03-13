"""EKS Scanner."""

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
class EKSScanner(BaseScanner):
    service_name = "eks"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        eks = session.client("eks", region_name=region)
        try:
            clusters = eks.list_clusters().get("clusters", [])
            for name in clusters:
                cluster = eks.describe_cluster(name=name)["cluster"]
                vpc_config = cluster.get("resourcesVpcConfig", {})
                if vpc_config.get("endpointPublicAccess"):
                    rule = self._get_rule("eks-public-endpoint")
                    if rule:
                        findings.append(self._create_finding(rule, name, region))
                logging_cfg = cluster.get("logging", {}).get("clusterLogging", [])
                all_enabled = all(
                    lc.get("enabled", False) for lc in logging_cfg
                )
                if not all_enabled:
                    rule = self._get_rule("eks-no-logging")
                    if rule:
                        findings.append(self._create_finding(rule, name, region))
                encryption = cluster.get("encryptionConfig", [])
                if not encryption:
                    rule = self._get_rule("eks-secrets-not-encrypted")
                    if rule:
                        findings.append(self._create_finding(rule, name, region))
        except ClientError as e:
            logger.error("Could not describe EKS clusters: %s", e)
        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None
