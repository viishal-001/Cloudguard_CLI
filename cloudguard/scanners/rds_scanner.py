"""RDS Scanner — detects RDS misconfigurations."""

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
class RDSScanner(BaseScanner):
    service_name = "rds"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rds = session.client("rds", region_name=region)

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    db_id = db["DBInstanceIdentifier"]
                    findings.extend(self._check_instance(db, db_id, region))
        except ClientError as e:
            logger.error("Could not describe RDS instances: %s", e)

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None

    def _check_instance(self, db: dict[str, Any], db_id: str, region: str) -> list[Finding]:
        findings: list[Finding] = []

        if db.get("PubliclyAccessible"):
            rule = self._get_rule("rds-public-access")
            if rule:
                findings.append(self._create_finding(rule, db_id, region))

        if not db.get("StorageEncrypted"):
            rule = self._get_rule("rds-no-encryption")
            if rule:
                findings.append(self._create_finding(rule, db_id, region))

        if not db.get("MultiAZ"):
            rule = self._get_rule("rds-no-multi-az")
            if rule:
                findings.append(self._create_finding(rule, db_id, region))

        if db.get("BackupRetentionPeriod", 0) == 0:
            rule = self._get_rule("rds-no-backup")
            if rule:
                findings.append(self._create_finding(rule, db_id, region))

        return findings
