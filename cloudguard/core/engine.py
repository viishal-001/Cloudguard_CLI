"""CloudGuard scan engine — orchestrates scanning across AWS services.

Per MVP §11 Architecture: CloudGuard Engine sits between CLI and Service Scanners.
Per PRD §7: CLI → CloudGuard Engine → Service Scanner Layer → Rule Engine → CVSS Scoring → Reporting.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import boto3

from cloudguard.core.models import ScanResult
from cloudguard.scanners.registry import get_all_scanners, get_scanner, list_services

logger = logging.getLogger(__name__)


class ScanEngine:
    """Main scanning engine that orchestrates service scanners.

    Per MVP §2 Objectives:
    - Scan AWS infrastructure using AWS APIs
    - Detect misconfigurations across 20 services
    - Assign severity and CVSS scores
    """

    def __init__(
        self,
        profile: str | None = None,
        region: str = "us-east-1",
    ) -> None:
        """Initialize the scan engine.

        Args:
            profile: AWS profile name (uses default if None).
            region: AWS region to scan.
        """
        self.profile = profile
        self.region = region
        self._session: boto3.Session | None = None

    def _get_session(self) -> boto3.Session:
        """Create or return the Boto3 session."""
        if self._session is None:
            kwargs: dict[str, Any] = {"region_name": self.region}
            if self.profile:
                kwargs["profile_name"] = self.profile
            self._session = boto3.Session(**kwargs)
        return self._session

    def _get_account_id(self, session: boto3.Session) -> str:
        """Get the AWS account ID from STS."""
        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            return identity.get("Account", "unknown")
        except Exception:
            return "unknown"

    def run(
        self,
        services: list[str] | None = None,
        scan_all: bool = False,
    ) -> ScanResult:
        """Execute a scan across specified services.

        Args:
            services: List of service names to scan. If None and scan_all is True,
                      scans all registered services.
            scan_all: If True, scan all registered services.

        Returns:
            ScanResult with all findings.
        """
        start_time = time.time()
        session = self._get_session()
        account_id = self._get_account_id(session)

        result = ScanResult(
            account_id=account_id,
            region=self.region,
        )

        # Determine which services to scan
        if scan_all:
            target_services = list_services()
        elif services:
            target_services = [s.lower().strip() for s in services]
        else:
            target_services = list_services()

        result.services_scanned = target_services

        logger.info(
            "Starting scan: account=%s, region=%s, services=%s",
            account_id,
            self.region,
            target_services,
        )

        for service_name in target_services:
            try:
                scanner = get_scanner(service_name)
                logger.info("Scanning service: %s", service_name)
                findings = scanner.scan(session, self.region)
                result.findings.extend(findings)
                logger.info(
                    "Service %s: found %d issues", service_name, len(findings)
                )
            except KeyError:
                logger.warning("No scanner registered for service: %s", service_name)
            except Exception as e:
                logger.error("Error scanning %s: %s", service_name, e)

        result.scan_duration_seconds = round(time.time() - start_time, 2)

        logger.info(
            "Scan complete: %d findings in %.2fs",
            len(result.findings),
            result.scan_duration_seconds,
        )

        return result
