"""DynamoDB Scanner."""

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
class DynamoDBScanner(BaseScanner):
    service_name = "dynamodb"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        ddb = session.client("dynamodb", region_name=region)
        try:
            paginator = ddb.get_paginator("list_tables")
            for page in paginator.paginate():
                for table_name in page["TableNames"]:
                    table = ddb.describe_table(TableName=table_name)["Table"]
                    sse = table.get("SSEDescription", {})
                    if sse.get("Status") != "ENABLED":
                        rule = self._get_rule("dynamodb-no-encryption")
                        if rule:
                            findings.append(self._create_finding(rule, table_name, region))
                    try:
                        backups = ddb.describe_continuous_backups(TableName=table_name)
                        pitr = backups.get("ContinuousBackupsDescription", {}).get(
                            "PointInTimeRecoveryDescription", {}
                        )
                        if pitr.get("PointInTimeRecoveryStatus") != "ENABLED":
                            rule = self._get_rule("dynamodb-no-pitr")
                            if rule:
                                findings.append(self._create_finding(rule, table_name, region))
                    except ClientError:
                        pass
        except ClientError as e:
            logger.error("Could not describe DynamoDB tables: %s", e)
        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None
