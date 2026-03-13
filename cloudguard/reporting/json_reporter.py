"""JSON reporter for CloudGuard scan results."""

from __future__ import annotations

import json

from cloudguard.core.models import ScanResult


class JSONReporter:
    """Generate JSON output from scan results."""

    def generate(self, result: ScanResult) -> str:
        """Serialize scan result to formatted JSON string."""
        return json.dumps(result.to_dict(), indent=2, default=str)
