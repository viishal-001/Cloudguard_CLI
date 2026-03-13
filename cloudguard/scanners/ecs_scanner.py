"""ECS Scanner."""

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
class ECSScanner(BaseScanner):
    service_name = "ecs"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        ecs = session.client("ecs", region_name=region)
        try:
            paginator = ecs.get_paginator("list_task_definitions")
            for page in paginator.paginate(status="ACTIVE"):
                for td_arn in page["taskDefinitionArns"]:
                    td = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"]
                    td_name = td.get("family", td_arn.split("/")[-1])
                    if not td.get("taskRoleArn"):
                        rule = self._get_rule("ecs-task-role-missing")
                        if rule:
                            findings.append(self._create_finding(rule, td_name, region))
                    for container in td.get("containerDefinitions", []):
                        if container.get("privileged"):
                            rule = self._get_rule("ecs-privileged-container")
                            if rule:
                                findings.append(self._create_finding(
                                    rule, f"{td_name}/{container['name']}", region
                                ))
                        log_config = container.get("logConfiguration")
                        if not log_config:
                            rule = self._get_rule("ecs-no-logging")
                            if rule:
                                findings.append(self._create_finding(
                                    rule, f"{td_name}/{container['name']}", region
                                ))
        except ClientError as e:
            logger.error("Could not describe ECS task definitions: %s", e)
        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None
