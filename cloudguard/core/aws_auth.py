"""AWS authentication and session management for CloudGuard.

Per PRD §5: System must authenticate with AWS.
Per PRD §6: No credential storage (non-functional req).
Per PRD §9: Use read-only IAM roles, never store credentials.

Supports 5 auth flows:
1. Local AWS CLI profile (--profile)
2. Assume-role cross-account (--role-arn)
3. AWS SSO / IAM Identity Center
4. Environment variables (explicit only, with warning)
5. CI/OIDC (documented, no code needed — uses env vars from configure-aws-credentials)

Security invariants:
- Credentials live only in memory
- STS temporary creds preferred
- Optional encrypted cache (user opt-in with passphrase)
"""

from __future__ import annotations

import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Raised when authentication fails."""
    pass


class IdentityInfo:
    """Holds the caller identity returned by STS.

    Per prompt spec §C.1: Must display Account, ARN, User before scanning.
    """

    def __init__(self, account: str, arn: str, user_id: str) -> None:
        self.account = account
        self.arn = arn
        self.user_id = user_id

    @property
    def display_name(self) -> str:
        """Extract a human-friendly name from the ARN."""
        # arn:aws:iam::123456789012:user/alice → alice
        # arn:aws:sts::123456789012:assumed-role/MyRole/session → MyRole/session
        parts = self.arn.split("/")
        return "/".join(parts[1:]) if len(parts) > 1 else self.arn

    def __str__(self) -> str:
        return (
            f"Account: {self.account}\n"
            f"Caller ARN: {self.arn}\n"
            f"User: {self.display_name}"
        )


def get_session_from_profile(profile: str, region: str = "us-east-1") -> boto3.Session:
    """Create a Boto3 session from a named AWS CLI profile.

    Args:
        profile: AWS CLI profile name.
        region: AWS region.

    Returns:
        Configured Boto3 session.

    Raises:
        AuthError: If profile doesn't exist or credentials are invalid.
    """
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        # Validate the profile has credentials
        session.client("sts").get_caller_identity()
        return session
    except (ClientError, BotoCoreError, NoCredentialsError) as e:
        raise AuthError(
            f"Failed to authenticate with profile '{profile}': {e}\n"
            f"Remediation: Check ~/.aws/credentials and ~/.aws/config for profile '{profile}'.\n"
            f"Run 'aws configure --profile {profile}' to set up credentials."
        ) from e


def assume_role_and_get_session(
    role_arn: str,
    external_id: str | None = None,
    session_name: str = "CloudGuardSession",
    duration: int = 3600,
    region: str = "us-east-1",
    source_profile: str | None = None,
) -> boto3.Session:
    """Assume an IAM role and return a session with temporary credentials.

    Per prompt spec §A.2: Implementation must return an in-memory boto3.Session.
    Only stores temporary credentials in memory.

    Args:
        role_arn: ARN of the role to assume.
        external_id: Optional external ID for cross-account access.
        session_name: Name for the assumed-role session.
        duration: Session duration in seconds (900-43200, default 3600).
        region: AWS region.
        source_profile: Optional source profile for the initial STS call.

    Returns:
        Boto3 session with temporary credentials.

    Raises:
        AuthError: If role assumption fails.
    """
    try:
        # Use source profile if provided, else default credentials
        if source_profile:
            source_session = boto3.Session(profile_name=source_profile, region_name=region)
        else:
            source_session = boto3.Session(region_name=region)

        sts = source_session.client("sts")

        assume_kwargs: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": duration,
        }
        if external_id:
            assume_kwargs["ExternalId"] = external_id

        response = sts.assume_role(**assume_kwargs)
        creds = response["Credentials"]

        # Create a new session with the temporary credentials — in memory only
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    except (ClientError, BotoCoreError) as e:
        raise AuthError(
            f"Failed to assume role '{role_arn}': {e}\n"
            f"Remediation:\n"
            f"  1. Verify the role ARN is correct\n"
            f"  2. Check the trust policy allows your current identity\n"
            f"  3. If using external ID, verify it matches the trust policy\n"
            f"  4. See infra/trust-policy-template.json for setup"
        ) from e


def get_session_from_env(region: str = "us-east-1") -> boto3.Session:
    """Create a session from environment variables.

    Per prompt spec §A.5: Accept env vars but print a warning and recommend
    OIDC or profiles.

    Returns:
        Boto3 session.

    Raises:
        AuthError: If no credentials are found in environment.
    """
    key_id = os.environ.get("AWS_ACCESS_KEY_ID")
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY")

    if not key_id or not secret:
        raise AuthError(
            "No AWS credentials found in environment variables.\n"
            "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or use --profile.\n"
            "Recommended: Use named profiles or OIDC for better security."
        )

    logger.warning(
        "⚠️  Using environment variable credentials. "
        "Consider using --profile or OIDC for better security."
    )

    return boto3.Session(
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
        region_name=region,
    )


def resolve_session(
    profile: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    session_duration: int = 3600,
    region: str = "us-east-1",
) -> boto3.Session:
    """Resolve the correct auth flow based on CLI arguments.

    Priority order (per prompt spec §A):
    1. Assume-role (if --role-arn provided)
    2. Named profile (if --profile provided)
    3. Environment variables (fallback)

    Args:
        profile: AWS CLI profile name.
        role_arn: ARN of role to assume.
        external_id: External ID for cross-account assume-role.
        session_duration: Duration for assumed role session.
        region: AWS region.

    Returns:
        Authenticated Boto3 session.
    """
    if role_arn:
        logger.info("Auth flow: assume-role → %s", role_arn)
        return assume_role_and_get_session(
            role_arn=role_arn,
            external_id=external_id,
            duration=session_duration,
            region=region,
            source_profile=profile,
        )
    elif profile:
        logger.info("Auth flow: named profile → %s", profile)
        return get_session_from_profile(profile, region)
    else:
        logger.info("Auth flow: environment variables / default chain")
        return get_session_from_env(region)


def verify_identity(session: boto3.Session) -> IdentityInfo:
    """Call STS GetCallerIdentity and return structured identity info.

    Per prompt spec §C.1: Must call sts.get_caller_identity() immediately
    and display Account, Caller ARN, User.

    Args:
        session: Authenticated Boto3 session.

    Returns:
        IdentityInfo with account, ARN, and user details.

    Raises:
        AuthError: If identity verification fails.
    """
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return IdentityInfo(
            account=identity["Account"],
            arn=identity["Arn"],
            user_id=identity["UserId"],
        )
    except (ClientError, BotoCoreError, NoCredentialsError) as e:
        raise AuthError(
            f"Failed to verify identity: {e}\n"
            "Remediation:\n"
            "  1. Check your AWS credentials are valid\n"
            "  2. Ensure sts:GetCallerIdentity is allowed in your IAM policy\n"
            "  3. See infra/cloudguard-readonly-policy.json"
        ) from e


def check_allowlist(identity: IdentityInfo, allowlist: list[str]) -> bool:
    """Verify the current account is in the allowlist.

    Per prompt spec §B: --allowlist restricts which accounts can be scanned.

    Args:
        identity: Verified caller identity.
        allowlist: List of permitted AWS account IDs.

    Returns:
        True if account is allowed.
    """
    if not allowlist:
        return True  # No allowlist = all accounts permitted
    return identity.account in allowlist
