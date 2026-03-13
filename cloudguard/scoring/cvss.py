"""CVSS v3.1 scoring engine for CloudGuard.

Per MVP §10 (CVSS Mapping) and PRD §4 (Risk Scoring):
Each vulnerability includes severity, CVSS score, and risk category.
Score ranges: 9-10 Critical, 7-8.9 High, 4-6.9 Medium, 0-3.9 Low.

This module implements a deterministic CVSS v3.1 base score calculator
from vector strings like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from cloudguard.core.models import Severity


# CVSS v3.1 metric value tables
_AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_VALUES = {"L": 0.77, "H": 0.44}
_PR_VALUES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_VALUES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_VALUES = {"N": 0.85, "R": 0.62}
_S_VALUES = {"U": "Unchanged", "C": "Changed"}
_CIA_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}


@dataclass
class CVSSResult:
    """Result of a CVSS v3.1 base score calculation."""

    vector: str
    score: float
    severity: Severity

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "vector": self.vector,
            "score": self.score,
            "severity": self.severity.value,
        }


def _roundup(value: float) -> float:
    """CVSS v3.1 roundup function — round up to nearest 0.1."""
    return math.ceil(value * 10) / 10


def _parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector string into metric:value pairs.

    Args:
        vector: CVSS vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        Dictionary of metric abbreviation to value abbreviation.

    Raises:
        ValueError: If the vector format is invalid.
    """
    if not vector.startswith("CVSS:3.1/") and not vector.startswith("CVSS:3.0/"):
        raise ValueError(f"Invalid CVSS vector prefix: {vector}")

    parts = vector.split("/")[1:]  # Skip "CVSS:3.1" prefix
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"Invalid metric format in vector: {part}")
        key, val = part.split(":", 1)
        metrics[key] = val

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - set(metrics.keys())
    if missing:
        raise ValueError(f"CVSS vector missing required metrics: {missing}")

    return metrics


def calculate_base_score(vector: str) -> CVSSResult:
    """Calculate CVSS v3.1 base score from a vector string.

    Implements the official CVSS v3.1 base scoring algorithm.

    Args:
        vector: CVSS v3.1 vector string.

    Returns:
        CVSSResult with score and severity.
    """
    metrics = _parse_vector(vector)

    # Extract metric values
    av = _AV_VALUES[metrics["AV"]]
    ac = _AC_VALUES[metrics["AC"]]
    ui = _UI_VALUES[metrics["UI"]]
    scope_changed = metrics["S"] == "C"

    if scope_changed:
        pr = _PR_VALUES_CHANGED[metrics["PR"]]
    else:
        pr = _PR_VALUES_UNCHANGED[metrics["PR"]]

    c = _CIA_VALUES[metrics["C"]]
    i = _CIA_VALUES[metrics["I"]]
    a = _CIA_VALUES[metrics["A"]]

    # Calculate Impact Sub Score (ISS)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    # Calculate Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    # Calculate Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # Calculate Base Score
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))

    severity = score_to_severity(score)

    return CVSSResult(vector=vector, score=score, severity=severity)


def score_to_severity(score: float) -> Severity:
    """Convert a CVSS score to a severity level.

    Per MVP §10:
    - 9-10: Critical
    - 7-8.9: High
    - 4-6.9: Medium
    - 0-3.9: Low
    """
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score > 0.0:
        return Severity.LOW
    else:
        return Severity.INFO
