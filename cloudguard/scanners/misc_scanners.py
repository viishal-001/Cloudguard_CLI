"""KMS, Secrets Manager, SNS, SQS, and Config Scanners."""

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
class KMSScanner(BaseScanner):
    service_name = "kms"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        kms = session.client("kms", region_name=region)
        try:
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key in page["Keys"]:
                    key_id = key["KeyId"]
                    try:
                        meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                        if meta.get("KeyManager") != "CUSTOMER":
                            continue
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        if not rotation.get("KeyRotationEnabled"):
                            rule = self._get_rule("kms-key-rotation-disabled")
                            if rule:
                                findings.append(self._create_finding(rule, key_id, region))
                    except ClientError:
                        pass
        except ClientError as e:
            logger.error("Could not list KMS keys: %s", e)
        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None


@register_scanner
class SecretsManagerScanner(BaseScanner):
    service_name = "secretsmanager"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        sm = session.client("secretsmanager", region_name=region)
        try:
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page["SecretList"]:
                    name = secret.get("Name", secret.get("ARN", "unknown"))
                    if not secret.get("RotationEnabled"):
                        rule = self._get_rule("secretsmanager-no-rotation")
                        if rule:
                            findings.append(self._create_finding(rule, name, region))
        except ClientError as e:
            logger.error("Could not list secrets: %s", e)
        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None


@register_scanner
class SNSScanner(BaseScanner):
    service_name = "sns"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        sns = session.client("sns", region_name=region)
        try:
            paginator = sns.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page["Topics"]:
                    arn = topic["TopicArn"]
                    name = arn.split(":")[-1]
                    attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
                    policy = json.loads(attrs.get("Policy", "{}"))
                    for stmt in policy.get("Statement", []):
                        principal = stmt.get("Principal", "")
                        if principal == "*" or (isinstance(principal, dict) and "*" in str(principal)):
                            rule = self._get_rule("sns-public-access")
                            if rule:
                                findings.append(self._create_finding(rule, name, region))
                            break
                    if not attrs.get("KmsMasterKeyId"):
                        rule = self._get_rule("sns-no-encryption")
                        if rule:
                            findings.append(self._create_finding(rule, name, region))
        except ClientError as e:
            logger.error("Could not describe SNS topics: %s", e)
        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None


@register_scanner
class SQSScanner(BaseScanner):
    service_name = "sqs"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        sqs = session.client("sqs", region_name=region)
        try:
            queues = sqs.list_queues().get("QueueUrls", [])
            for url in queues:
                name = url.split("/")[-1]
                attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
                policy = json.loads(attrs.get("Policy", "{}"))
                for stmt in policy.get("Statement", []):
                    principal = stmt.get("Principal", "")
                    if principal == "*" or (isinstance(principal, dict) and "*" in str(principal)):
                        rule = self._get_rule("sqs-public-access")
                        if rule:
                            findings.append(self._create_finding(rule, name, region))
                        break
                if not attrs.get("KmsMasterKeyId"):
                    rule = self._get_rule("sqs-no-encryption")
                    if rule:
                        findings.append(self._create_finding(rule, name, region))
        except ClientError as e:
            logger.error("Could not describe SQS queues: %s", e)
        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None


@register_scanner
class ConfigScanner(BaseScanner):
    service_name = "config"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        config = session.client("config", region_name=region)
        try:
            recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
            if not recorders:
                rule = self._get_rule("config-not-enabled")
                if rule:
                    findings.append(self._create_finding(rule, region, region))
            else:
                for recorder in recorders:
                    recording_group = recorder.get("recordingGroup", {})
                    if not recording_group.get("includeGlobalResourceTypes"):
                        rule = self._get_rule("config-no-global-resources")
                        if rule:
                            findings.append(self._create_finding(
                                rule, recorder.get("name", "default"), region
                            ))
        except ClientError as e:
            logger.error("Could not describe Config: %s", e)
        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None
