"""API Gateway Scanner."""

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
class APIGatewayScanner(BaseScanner):
    service_name = "apigateway"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        apigw = session.client("apigateway", region_name=region)

        try:
            apis = apigw.get_rest_apis().get("items", [])
            for api in apis:
                api_id = api["id"]
                api_name = api.get("name", api_id)
                resources = apigw.get_resources(restApiId=api_id).get("items", [])
                for resource in resources:
                    for method in resource.get("resourceMethods", {}).keys():
                        try:
                            method_resp = apigw.get_method(
                                restApiId=api_id,
                                resourceId=resource["id"],
                                httpMethod=method,
                            )
                            if method_resp.get("authorizationType") == "NONE":
                                rule = self._get_rule("apigateway-no-auth")
                                if rule:
                                    findings.append(
                                        self._create_finding(
                                            rule, f"{api_name}/{resource.get('path', '')}/{method}", region
                                        )
                                    )
                        except ClientError:
                            pass
        except ClientError as e:
            logger.error("Could not describe API Gateway: %s", e)

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None
