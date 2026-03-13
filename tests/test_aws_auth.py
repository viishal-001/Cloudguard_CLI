"""Tests for AWS auth module using moto."""

import os
import json
import boto3
import pytest
from moto import mock_aws

from cloudguard.core.aws_auth import (
    AuthError,
    IdentityInfo,
    get_session_from_profile,
    get_session_from_env,
    assume_role_and_get_session,
    resolve_session,
    verify_identity,
    check_allowlist,
)


class TestIdentityInfo:
    """Test IdentityInfo display logic."""

    def test_display_name_user(self):
        info = IdentityInfo("123456789012", "arn:aws:iam::123456789012:user/alice", "AIDEXAMPLE")
        assert info.display_name == "alice"

    def test_display_name_role(self):
        info = IdentityInfo("123456789012", "arn:aws:sts::123456789012:assumed-role/MyRole/session", "AROAEXAMPLE")
        assert info.display_name == "MyRole/session"

    def test_str(self):
        info = IdentityInfo("123", "arn:aws:iam::123:user/bob", "AID")
        output = str(info)
        assert "Account: 123" in output
        assert "Caller ARN:" in output
        assert "User:" in output


class TestGetSessionFromEnv:
    """Test environment variable auth flow."""

    @mock_aws
    def test_env_session_success(self):
        os.environ["AWS_ACCESS_KEY_ID"] = "testing"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
        session = get_session_from_env(region="us-east-1")
        assert session is not None

    def test_env_session_no_creds(self):
        old_key = os.environ.pop("AWS_ACCESS_KEY_ID", None)
        old_secret = os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
        try:
            with pytest.raises(AuthError, match="No AWS credentials found"):
                get_session_from_env()
        finally:
            if old_key:
                os.environ["AWS_ACCESS_KEY_ID"] = old_key
            if old_secret:
                os.environ["AWS_SECRET_ACCESS_KEY"] = old_secret


class TestVerifyIdentity:
    """Test STS identity verification."""

    @mock_aws
    def test_verify_identity_returns_info(self):
        session = boto3.Session(region_name="us-east-1")
        identity = verify_identity(session)
        assert identity.account is not None
        assert identity.arn is not None
        assert len(identity.account) == 12


class TestCheckAllowlist:
    """Test account allowlist enforcement."""

    def test_empty_allowlist_permits_all(self):
        info = IdentityInfo("123456789012", "arn", "uid")
        assert check_allowlist(info, []) is True

    def test_account_in_allowlist(self):
        info = IdentityInfo("123456789012", "arn", "uid")
        assert check_allowlist(info, ["123456789012"]) is True

    def test_account_not_in_allowlist(self):
        info = IdentityInfo("123456789012", "arn", "uid")
        assert check_allowlist(info, ["999999999999"]) is False


class TestResolveSession:
    """Test auth flow resolution priority."""

    @mock_aws
    def test_resolve_env_fallback(self):
        """Should fall back to env when no profile or role-arn."""
        os.environ["AWS_ACCESS_KEY_ID"] = "testing"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
        session = resolve_session(region="us-east-1")
        assert session is not None

    @mock_aws
    def test_resolve_with_role_arn(self):
        """Assume-role should be attempted when role_arn is provided."""
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam", region_name="us-east-1")

        # Create a role for moto
        trust_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            }],
        })
        role = iam.create_role(
            RoleName="CloudGuardTestRole",
            AssumeRolePolicyDocument=trust_policy,
        )
        role_arn = role["Role"]["Arn"]

        result_session = resolve_session(role_arn=role_arn, region="us-east-1")
        assert result_session is not None
