"""Lambda Scanner — detects Lambda misconfigurations."""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cloudguard.core.models import Finding
from cloudguard.scanners.base import BaseScanner
from cloudguard.scanners.registry import register_scanner

logger = logging.getLogger(__name__)

DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "dotnetcore2.1", "dotnetcore3.1",
    "ruby2.5", "ruby2.7",
    "java8", "go1.x",
}


@register_scanner
class LambdaScanner(BaseScanner):
    service_name = "lambda"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        lam = session.client("lambda", region_name=region)

        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    name = fn["FunctionName"]
                    findings.extend(self._check_public(lam, name, region))
                    findings.extend(self._check_dlq(fn, name, region))
                    findings.extend(self._check_runtime(fn, name, region))
        except ClientError as e:
            logger.error("Could not list Lambda functions: %s", e)

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None

    def _check_public(self, lam: Any, name: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("lambda-public-access")
        if not rule:
            return findings

        try:
            policy_str = lam.get_policy(FunctionName=name)["Policy"]
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    findings.append(self._create_finding(rule, name, region))
                    break
        except ClientError:
            pass
        return findings

    def _check_dlq(self, fn: dict[str, Any], name: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("lambda-no-dlq")
        if not rule:
            return findings

        dlq = fn.get("DeadLetterConfig", {})
        if not dlq.get("TargetArn"):
            findings.append(self._create_finding(rule, name, region))
        return findings

    def _check_runtime(self, fn: dict[str, Any], name: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("lambda-runtime-deprecated")
        if not rule:
            return findings

        runtime = fn.get("Runtime", "")
        if runtime in DEPRECATED_RUNTIMES:
            findings.append(
                self._create_finding(rule, name, region, {"runtime": runtime})
            )
        return findings
