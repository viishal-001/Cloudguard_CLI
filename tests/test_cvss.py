"""Tests for the CVSS scoring engine."""

import pytest
from cloudguard.scoring.cvss import calculate_base_score, score_to_severity
from cloudguard.core.models import Severity


class TestCVSSScoring:
    """Test CVSS v3.1 base score calculation."""

    def test_critical_score(self):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H should be 10.0."""
        result = calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert result.score == 10.0
        assert result.severity == Severity.CRITICAL

    def test_high_score(self):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N should be ~7.5."""
        result = calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        assert 7.0 <= result.score <= 8.0
        assert result.severity == Severity.HIGH

    def test_medium_score(self):
        """CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N should be medium."""
        result = calculate_base_score("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N")
        assert 0.0 < result.score < 7.0
        assert result.severity in (Severity.LOW, Severity.MEDIUM)

    def test_zero_score(self):
        """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N should be 0.0."""
        result = calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert result.score == 0.0
        assert result.severity == Severity.INFO

    def test_invalid_vector_prefix(self):
        with pytest.raises(ValueError, match="Invalid CVSS vector prefix"):
            calculate_base_score("INVALID/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_missing_metrics(self):
        with pytest.raises(ValueError, match="missing required metrics"):
            calculate_base_score("CVSS:3.1/AV:N/AC:L")

    def test_score_to_severity_mapping(self):
        assert score_to_severity(9.5) == Severity.CRITICAL
        assert score_to_severity(7.5) == Severity.HIGH
        assert score_to_severity(5.0) == Severity.MEDIUM
        assert score_to_severity(2.0) == Severity.LOW
        assert score_to_severity(0.0) == Severity.INFO
