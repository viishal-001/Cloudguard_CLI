"""Pytest configuration and fixtures for CloudGuard tests.

Uses moto to mock AWS services (per MVP §5: pytest + moto).
"""

from __future__ import annotations

import os
import pytest
import boto3
from moto import mock_aws


@pytest.fixture(autouse=True)
def aws_credentials():
    """Set dummy AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    yield
    for key in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SECURITY_TOKEN", "AWS_SESSION_TOKEN"]:
        os.environ.pop(key, None)


@pytest.fixture
def aws_session():
    """Create a boto3 session with moto credentials."""
    return boto3.Session(region_name="us-east-1")


@pytest.fixture
def mock_aws_env():
    """Context manager for mocking all AWS services."""
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")
