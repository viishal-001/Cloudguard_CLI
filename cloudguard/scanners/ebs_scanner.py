"""EBS Scanner."""

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
class EBSScanner(BaseScanner):
    service_name = "ebs"

    def _run_checks(self, session: boto3.Session, region: str) -> list[Finding]:
        findings: list[Finding] = []
        ec2 = session.client("ec2", region_name=region)

        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page["Volumes"]:
                    vol_id = vol["VolumeId"]
                    if not vol.get("Encrypted"):
                        rule = self._get_rule("ebs-unencrypted")
                        if rule:
                            findings.append(self._create_finding(rule, vol_id, region))
        except ClientError as e:
            logger.error("Could not describe EBS volumes: %s", e)

        try:
            snapshots = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
            for snap in snapshots:
                snap_id = snap["SnapshotId"]
                attrs = ec2.describe_snapshot_attribute(
                    SnapshotId=snap_id, Attribute="createVolumePermission"
                )
                for perm in attrs.get("CreateVolumePermissions", []):
                    if perm.get("Group") == "all":
                        rule = self._get_rule("ebs-snapshot-public")
                        if rule:
                            findings.append(self._create_finding(rule, snap_id, region))
        except ClientError as e:
            logger.debug("Could not check EBS snapshots: %s", e)

        return findings

    def _get_rule(self, rule_id: str) -> dict[str, Any] | None:
        for r in self.rules:
            if r["id"] == rule_id:
                return r
        return None
