"""Tests for IAM scanner using moto."""

import json
import boto3
import pytest
from moto import mock_aws

from cloudguard.scanners.iam_scanner import IAMScanner


class TestIAMScanner:
    """Test IAM scanner with mocked AWS."""

    @mock_aws
    def test_detects_user_without_mfa(self):
        """Should detect IAM user without MFA who has console access."""
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user")
        iam.create_login_profile(UserName="test-user", Password="TestPass123!")

        scanner = IAMScanner()
        findings = scanner.scan(session, "us-east-1")

        mfa_findings = [f for f in findings if f.rule_id == "iam-mfa-disabled"]
        assert len(mfa_findings) >= 1
        assert mfa_findings[0].resource_id == "test-user"

    @mock_aws
    def test_detects_wildcard_policy(self):
        """Should detect IAM policy with wildcard permissions."""
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam", region_name="us-east-1")

        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }],
        })
        iam.create_policy(
            PolicyName="admin-policy",
            PolicyDocument=policy_doc,
        )
        # Attach to a user to make it "attached"
        iam.create_user(UserName="admin")
        policy_arn = f"arn:aws:iam::{session.client('sts').get_caller_identity()['Account']}:policy/admin-policy"
        iam.attach_user_policy(UserName="admin", PolicyArn=policy_arn)

        scanner = IAMScanner()
        findings = scanner.scan(session, "us-east-1")

        wildcard_findings = [f for f in findings if f.rule_id == "iam-wildcard-policy"]
        assert len(wildcard_findings) >= 1

    @mock_aws
    def test_detects_inline_policy(self):
        """Should detect user with inline policy."""
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam", region_name="us-east-1")
        iam.create_user(UserName="inline-user")
        iam.put_user_policy(
            UserName="inline-user",
            PolicyName="inline-test",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
            }),
        )

        scanner = IAMScanner()
        findings = scanner.scan(session, "us-east-1")

        inline_findings = [f for f in findings if f.rule_id == "iam-inline-policy"]
        assert len(inline_findings) >= 1

    @mock_aws
    def test_findings_have_mitigation(self):
        """All findings should include mitigation text."""
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test")
        iam.create_login_profile(UserName="test", Password="Pass123!")

        scanner = IAMScanner()
        findings = scanner.scan(session, "us-east-1")

        for f in findings:
            assert f.mitigation, f"Finding {f.rule_id} missing mitigation"
