"""Table reporter for CloudGuard — Rich terminal output.

Per MVP §8: CLI output shows SERVICE, RESOURCE, ISSUE, SEVERITY, CVSS in a table.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cloudguard.core.models import ScanResult

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


class TableReporter:
    """Generate Rich table output for terminal display."""

    def print_report(self, result: ScanResult, console: Console) -> None:
        """Print scan results as a Rich table.

        Per MVP §8 example output format.
        """
        # Summary panel
        summary = result.summary
        summary_text = (
            f"Scan ID: {result.scan_id[:8]}...\n"
            f"Account: {result.account_id}\n"
            f"Region: {result.region}\n"
            f"Duration: {result.scan_duration_seconds}s\n"
            f"Services: {', '.join(result.services_scanned)}\n\n"
            f"[bold red]CRITICAL: {summary.get('CRITICAL', 0)}[/bold red]  "
            f"[red]HIGH: {summary.get('HIGH', 0)}[/red]  "
            f"[yellow]MEDIUM: {summary.get('MEDIUM', 0)}[/yellow]  "
            f"[blue]LOW: {summary.get('LOW', 0)}[/blue]  "
            f"[dim]INFO: {summary.get('INFO', 0)}[/dim]"
        )
        console.print(Panel(summary_text, title="📊 Scan Summary", border_style="green"))

        if not result.findings:
            console.print("\n[bold green]✅ No misconfigurations found![/bold green]")
            return

        # Findings table
        table = Table(
            title="Security Findings",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("SERVICE", style="cyan", min_width=10)
        table.add_column("RESOURCE", min_width=15)
        table.add_column("ISSUE", min_width=30)
        table.add_column("SEVERITY", min_width=10)
        table.add_column("CVSS", justify="right", min_width=5)

        # Sort by severity (CRITICAL first)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            result.findings,
            key=lambda f: severity_order.get(f.severity.value, 5),
        )

        for finding in sorted_findings:
            sev = finding.severity.value
            style = SEVERITY_COLORS.get(sev, "white")
            table.add_row(
                finding.service,
                finding.resource_id,
                finding.issue,
                Text(sev, style=style),
                f"{finding.cvss_score:.1f}",
            )

        console.print(table)
        console.print(
            f"\n[bold]Total: {len(result.findings)} findings[/bold]"
        )
