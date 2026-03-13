"""Pre-scan permission checks for CloudGuard.

Per prompt spec §C.2: Implement a permission-check routine that:
- Maintains a required_checks dict mapping service → minimal safe API call
- For each service selected, runs the minimal safe call and detects AccessDenied
- Produces a human-friendly report of missing permissions
- If all services fail, abort; if some fail, offer to continue with permitted

Per PRD §9: Use read-only IAM roles.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

import boto3
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)


@dataclass
class PermissionCheckResult:
    """Result of checking permissions for a single service."""

    service: str
    permitted: bool
    error: str = ""
    missing_actions: list[str] = field(default_factory=list)


@dataclass
class PermissionReport:
    """Aggregate report of all permission checks."""

    results: list[PermissionCheckResult] = field(default_factory=list)

    @property
    def all_permitted(self) -> bool:
        return all(r.permitted for r in self.results)

    @property
    def none_permitted(self) -> bool:
        return not any(r.permitted for r in self.results)

    @property
    def permitted_services(self) -> list[str]:
        return [r.service for r in self.results if r.permitted]

    @property
    def denied_services(self) -> list[str]:
        return [r.service for r in self.results if not r.permitted]

    def summary(self) -> str:
        """Human-friendly permission report."""
        lines = ["Permission Check Results:", "=" * 40]
        for r in self.results:
            status = "✅ PERMITTED" if r.permitted else "❌ DENIED"
            lines.append(f"  {r.service.upper():20s} {status}")
            if not r.permitted and r.error:
                lines.append(f"    Error: {r.error}")
            if r.missing_actions:
                lines.append(f"    Missing: {', '.join(r.missing_actions)}")

        lines.append("=" * 40)
        total = len(self.results)
        ok = len(self.permitted_services)
        lines.append(f"  {ok}/{total} services accessible")

        if self.denied_services:
            lines.append("")
            lines.append("Fix: Attach infra/cloudguard-readonly-policy.json to your IAM role/user.")
            lines.append("     Or limit scan: cloudguard scan --services " + ",".join(self.permitted_services))

        return "\n".join(lines)


# Mapping of service name → (boto3 client name, minimal safe API call, required IAM actions)
# These calls are genuinely read-only and return quickly.
PERMISSION_CHECKS: dict[str, tuple[str, str, dict[str, Any], list[str]]] = {
    "iam": ("iam", "get_account_summary", {}, ["iam:GetAccountSummary"]),
    "s3": ("s3", "list_buckets", {}, ["s3:ListAllMyBuckets"]),
    "ec2": ("ec2", "describe_instances", {"MaxResults": 5}, ["ec2:DescribeInstances"]),
    "sg": ("ec2", "describe_security_groups", {"MaxResults": 5}, ["ec2:DescribeSecurityGroups"]),
    "rds": ("rds", "describe_db_instances", {}, ["rds:DescribeDBInstances"]),
    "vpc": ("ec2", "describe_vpcs", {"MaxResults": 5}, ["ec2:DescribeVpcs"]),
    "cloudtrail": ("cloudtrail", "describe_trails", {}, ["cloudtrail:DescribeTrails"]),
    "cloudwatch": ("logs", "describe_log_groups", {"limit": 1}, ["logs:DescribeLogGroups"]),
    "lambda": ("lambda", "list_functions", {"MaxItems": 1}, ["lambda:ListFunctions"]),
    "apigateway": ("apigateway", "get_rest_apis", {}, ["apigateway:GET"]),
    "ebs": ("ec2", "describe_volumes", {"MaxResults": 5}, ["ec2:DescribeVolumes"]),
    "eks": ("eks", "list_clusters", {}, ["eks:ListClusters"]),
    "ecs": ("ecs", "list_task_definitions", {"maxResults": 1}, ["ecs:ListTaskDefinitions"]),
    "elb": ("elbv2", "describe_load_balancers", {}, ["elasticloadbalancing:DescribeLoadBalancers"]),
    "dynamodb": ("dynamodb", "list_tables", {"Limit": 1}, ["dynamodb:ListTables"]),
    "kms": ("kms", "list_keys", {}, ["kms:ListKeys"]),
    "secretsmanager": ("secretsmanager", "list_secrets", {"MaxResults": 1}, ["secretsmanager:ListSecrets"]),
    "sns": ("sns", "list_topics", {}, ["sns:ListTopics"]),
    "sqs": ("sqs", "list_queues", {}, ["sqs:ListQueues"]),
    "config": ("config", "describe_configuration_recorders", {}, ["config:DescribeConfigurationRecorders"]),
}


def check_permissions(
    session: boto3.Session,
    services: list[str],
    region: str = "us-east-1",
) -> PermissionReport:
    """Check permissions for selected services by running minimal safe API calls.

    Per prompt spec §C.2: For each service selected, run the minimal safe call
    and detect AccessDenied.

    Args:
        session: Authenticated Boto3 session.
        services: List of service names to check.
        region: AWS region.

    Returns:
        PermissionReport with per-service results.
    """
    report = PermissionReport()

    for service in services:
        if service not in PERMISSION_CHECKS:
            report.results.append(
                PermissionCheckResult(
                    service=service,
                    permitted=False,
                    error=f"Unknown service: {service}",
                )
            )
            continue

        client_name, method_name, kwargs, required_actions = PERMISSION_CHECKS[service]

        try:
            client = session.client(client_name, region_name=region)
            method = getattr(client, method_name)
            method(**kwargs)
            report.results.append(
                PermissionCheckResult(service=service, permitted=True)
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException", "UnauthorizedAccess"):
                report.results.append(
                    PermissionCheckResult(
                        service=service,
                        permitted=False,
                        error=f"AccessDenied: {error_code}",
                        missing_actions=required_actions,
                    )
                )
            else:
                # Non-auth error — service is accessible but returned another error
                # (e.g., no resources exist) — treat as permitted
                report.results.append(
                    PermissionCheckResult(service=service, permitted=True)
                )
        except (BotoCoreError, Exception) as e:
            report.results.append(
                PermissionCheckResult(
                    service=service,
                    permitted=False,
                    error=str(e)[:120],
                )
            )

    return report
