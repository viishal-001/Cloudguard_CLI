"""Tests for permission pre-checks."""

import boto3
import pytest
from moto import mock_aws

from cloudguard.core.permission_checks import check_permissions, PermissionReport


class TestPermissionChecks:
    """Test pre-scan permission verification."""

    @mock_aws
    def test_all_services_accessible(self):
        """With moto, all basic services should be accessible."""
        session = boto3.Session(region_name="us-east-1")
        report = check_permissions(session, ["s3", "ec2", "iam"], "us-east-1")
        assert len(report.results) == 3
        # moto services should be accessible
        assert len(report.permitted_services) >= 1

    @mock_aws
    def test_unknown_service(self):
        """Unknown service should be marked as denied."""
        session = boto3.Session(region_name="us-east-1")
        report = check_permissions(session, ["nonexistent"], "us-east-1")
        assert report.results[0].permitted is False
        assert "Unknown service" in report.results[0].error

    @mock_aws
    def test_report_summary(self):
        """Summary should be human-readable."""
        session = boto3.Session(region_name="us-east-1")
        report = check_permissions(session, ["s3"], "us-east-1")
        summary = report.summary()
        assert "Permission Check Results" in summary
        assert "services accessible" in summary

    @mock_aws
    def test_partial_access(self):
        """Report should distinguish permitted vs denied."""
        session = boto3.Session(region_name="us-east-1")
        report = check_permissions(session, ["s3", "nonexistent"], "us-east-1")
        assert "s3" in report.permitted_services
        assert "nonexistent" in report.denied_services

    @mock_aws
    def test_all_denied_flag(self):
        """none_permitted should be True when all services fail."""
        session = boto3.Session(region_name="us-east-1")
        report = check_permissions(session, ["nonexistent"], "us-east-1")
        assert report.none_permitted is True
