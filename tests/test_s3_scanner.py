"""Tests for S3 scanner using moto."""

import boto3
import pytest
from moto import mock_aws

from cloudguard.scanners.s3_scanner import S3Scanner


class TestS3Scanner:
    """Test S3 scanner with mocked AWS."""

    @mock_aws
    def test_detects_public_bucket(self):
        """Should detect a bucket without public access block."""
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-public-bucket")
        # No public access block set = finding

        scanner = S3Scanner()
        findings = scanner.scan(session, "us-east-1")

        public_findings = [f for f in findings if f.rule_id == "s3-public-access"]
        assert len(public_findings) >= 1

    @mock_aws
    def test_detects_unversioned_bucket(self):
        """Should detect a bucket without versioning."""
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-no-version")

        scanner = S3Scanner()
        findings = scanner.scan(session, "us-east-1")

        version_findings = [f for f in findings if f.rule_id == "s3-no-versioning"]
        assert len(version_findings) >= 1

    @mock_aws
    def test_no_findings_when_secure(self):
        """Bucket with versioning enabled should not trigger versioning finding."""
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="secure-bucket")
        s3.put_bucket_versioning(
            Bucket="secure-bucket",
            VersioningConfiguration={"Status": "Enabled"},
        )

        scanner = S3Scanner()
        findings = scanner.scan(session, "us-east-1")

        version_findings = [f for f in findings if f.rule_id == "s3-no-versioning"]
        assert len(version_findings) == 0

    @mock_aws
    def test_finding_has_cvss_score(self):
        """Findings should include CVSS scores."""
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-cvss")

        scanner = S3Scanner()
        findings = scanner.scan(session, "us-east-1")

        for f in findings:
            assert f.cvss_score > 0
            assert f.cvss_vector.startswith("CVSS:3.1/")
