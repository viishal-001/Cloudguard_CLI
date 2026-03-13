"""IAM Scanner — detects IAM misconfigurations.

Per MVP §6: IAM is service #1 of 20 scanned services.
Per PRD §2: Over-permissive IAM roles are a leading cause of breaches.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cloudguard.core.models import Finding
from cloudguard.scanners.base import BaseScanner
from cloudguard.scanners.registry import register_scanner

logger = logging.getLogger(__name__)


@register_scanner
class IAMScanner(BaseScanner):
    """Scanner for AWS IAM service."""

    service_name = "iam"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        iam = session.client("iam", region_name=region)

        findings.extend(self._check_root_access_keys(iam, region))
        findings.extend(self._check_mfa(iam, region))
        findings.extend(self._check_wildcard_policies(iam, region))
        findings.extend(self._check_password_policy(iam, region))
        findings.extend(self._check_inline_policies(iam, region))

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        """Get a rule by ID."""
        for rule in self.rules:
            if rule["id"] == rule_id:
                return rule
        return None

    def _check_root_access_keys(self, iam: Any, region: str) -> list[Finding]:
        """Check if root account has access keys."""
        findings: list[Finding] = []
        rule = self._get_rule("iam-root-access-keys")
        if not rule:
            return findings

        try:
            summary = iam.get_account_summary()
            if summary["SummaryMap"].get("AccountAccessKeysPresent", 0) > 0:
                findings.append(
                    self._create_finding(rule, "root-account", region)
                )
        except ClientError as e:
            logger.debug("Could not check root access keys: %s", e)

        return findings

    def _check_mfa(self, iam: Any, region: str) -> list[Finding]:
        """Check if IAM users have MFA enabled."""
        findings: list[Finding] = []
        rule = self._get_rule("iam-mfa-disabled")
        if not rule:
            return findings

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    mfa_devices = iam.list_mfa_devices(UserName=username)
                    if not mfa_devices["MFADevices"]:
                        # Check if user has console access
                        try:
                            iam.get_login_profile(UserName=username)
                            findings.append(
                                self._create_finding(
                                    rule,
                                    username,
                                    region,
                                    {"has_console_access": True},
                                )
                            )
                        except ClientError:
                            pass  # No console access, MFA less critical
        except ClientError as e:
            logger.debug("Could not check MFA: %s", e)

        return findings

    def _check_wildcard_policies(self, iam: Any, region: str) -> list[Finding]:
        """Check for IAM policies with wildcard permissions."""
        findings: list[Finding] = []
        rule = self._get_rule("iam-wildcard-policy")
        if not rule:
            return findings

        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local", OnlyAttached=True):
                for policy in page["Policies"]:
                    policy_version = iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                    document = policy_version["PolicyVersion"]["Document"]
                    statements = document.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    for stmt in statements:
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            resources = stmt.get("Resource", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]

                            if "*" in actions and "*" in resources:
                                findings.append(
                                    self._create_finding(
                                        rule,
                                        policy["PolicyName"],
                                        region,
                                        {"policy_arn": policy["Arn"]},
                                    )
                                )
                                break
        except ClientError as e:
            logger.debug("Could not check policies: %s", e)

        return findings

    def _check_password_policy(self, iam: Any, region: str) -> list[Finding]:
        """Check account password policy."""
        findings: list[Finding] = []
        rule = self._get_rule("iam-password-policy-weak")
        if not rule:
            return findings

        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append("min_length < 14")
            if not policy.get("RequireSymbols", False):
                issues.append("no_symbols")
            if not policy.get("RequireNumbers", False):
                issues.append("no_numbers")
            if not policy.get("RequireUppercaseCharacters", False):
                issues.append("no_uppercase")
            if not policy.get("RequireLowercaseCharacters", False):
                issues.append("no_lowercase")

            if issues:
                findings.append(
                    self._create_finding(
                        rule, "account-password-policy", region, {"issues": issues}
                    )
                )
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                findings.append(
                    self._create_finding(rule, "account-password-policy", region)
                )
            else:
                logger.debug("Could not check password policy: %s", e)

        return findings

    def _check_inline_policies(self, iam: Any, region: str) -> list[Finding]:
        """Check for users with inline policies."""
        findings: list[Finding] = []
        rule = self._get_rule("iam-inline-policy")
        if not rule:
            return findings

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    policies = iam.list_user_policies(UserName=username)
                    if policies["PolicyNames"]:
                        findings.append(
                            self._create_finding(
                                rule,
                                username,
                                region,
                                {"inline_policies": policies["PolicyNames"]},
                            )
                        )
        except ClientError as e:
            logger.debug("Could not check inline policies: %s", e)

        return findings
