"""S3 Scanner — detects S3 bucket misconfigurations.

Per MVP §6: S3 is service #2. Per PRD §2: Public S3 buckets are a leading cause of breaches.
Per MVP §8: Example output shows "mybucket  Public Bucket  HIGH  8.5".
"""

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


@register_scanner
class S3Scanner(BaseScanner):
    """Scanner for AWS S3 service."""

    service_name = "s3"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        s3 = session.client("s3", region_name=region)

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError as e:
            logger.error("Could not list S3 buckets: %s", e)
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            findings.extend(self._check_public_access(s3, name, region))
            findings.extend(self._check_encryption(s3, name, region))
            findings.extend(self._check_versioning(s3, name, region))
            findings.extend(self._check_logging(s3, name, region))
            findings.extend(self._check_ssl_policy(s3, name, region))

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for rule in self.rules:
            if rule["id"] == rule_id:
                return rule
        return None

    def _check_public_access(self, s3: Any, bucket: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("s3-public-access")
        if not rule:
            return findings

        try:
            public_access = s3.get_public_access_block(Bucket=bucket)
            config = public_access["PublicAccessBlockConfiguration"]
            if not all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ]):
                findings.append(self._create_finding(rule, bucket, region))
        except ClientError as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                findings.append(self._create_finding(rule, bucket, region))

        return findings

    def _check_encryption(self, s3: Any, bucket: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("s3-no-encryption")
        if not rule:
            return findings

        try:
            s3.get_bucket_encryption(Bucket=bucket)
        except ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                findings.append(self._create_finding(rule, bucket, region))

        return findings

    def _check_versioning(self, s3: Any, bucket: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("s3-no-versioning")
        if not rule:
            return findings

        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket)
            if versioning.get("Status") != "Enabled":
                findings.append(self._create_finding(rule, bucket, region))
        except ClientError:
            pass

        return findings

    def _check_logging(self, s3: Any, bucket: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("s3-no-logging")
        if not rule:
            return findings

        try:
            logging_config = s3.get_bucket_logging(Bucket=bucket)
            if "LoggingEnabled" not in logging_config:
                findings.append(self._create_finding(rule, bucket, region))
        except ClientError:
            pass

        return findings

    def _check_ssl_policy(self, s3: Any, bucket: str, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rule = self._get_rule("s3-no-ssl-enforcement")
        if not rule:
            return findings

        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket)["Policy"]
            policy = json.loads(policy_str)
            has_ssl_deny = False
            for stmt in policy.get("Statement", []):
                condition = stmt.get("Condition", {})
                if stmt.get("Effect") == "Deny" and "Bool" in condition:
                    if condition["Bool"].get("aws:SecureTransport") == "false":
                        has_ssl_deny = True
            if not has_ssl_deny:
                findings.append(self._create_finding(rule, bucket, region))
        except ClientError as e:
            if "NoSuchBucketPolicy" in str(e):
                findings.append(self._create_finding(rule, bucket, region))

        return findings
