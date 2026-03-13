"""CloudGuard CLI — Production-grade command-line interface for AWS security scanning.

Per MVP §7: Commands include scan --all, scan --services, scan --output, checks.
Per MVP §5: Uses Click CLI framework.
Per prompt spec §6: Pre-scan identity check + confirmation.
Per prompt spec §7: Pre-scan permission checks.
Per prompt spec §B: Full auth flags and safety gates.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from cloudguard import __version__
from cloudguard.core.aws_auth import (
    AuthError,
    IdentityInfo,
    resolve_session,
    verify_identity,
    check_allowlist,
)
from cloudguard.core.engine import ScanEngine
from cloudguard.core.models import ScanResult, Severity
from cloudguard.core.permission_checks import check_permissions
from cloudguard.core.rule_loader import load_all_rules
from cloudguard.reporting.json_reporter import JSONReporter
from cloudguard.reporting.table_reporter import TableReporter
from cloudguard.reporting.sarif_reporter import SARIFReporter
from cloudguard.reporting.html_reporter import HTMLReporter
from cloudguard.reporting.markdown_reporter import MarkdownReporter

# Import all scanners to trigger registration
import cloudguard.scanners.iam_scanner  # noqa: F401
import cloudguard.scanners.s3_scanner  # noqa: F401
import cloudguard.scanners.ec2_scanner  # noqa: F401
import cloudguard.scanners.sg_scanner  # noqa: F401
import cloudguard.scanners.rds_scanner  # noqa: F401
import cloudguard.scanners.vpc_scanner  # noqa: F401
import cloudguard.scanners.cloudtrail_scanner  # noqa: F401
import cloudguard.scanners.cloudwatch_scanner  # noqa: F401
import cloudguard.scanners.lambda_scanner  # noqa: F401
import cloudguard.scanners.apigateway_scanner  # noqa: F401
import cloudguard.scanners.ebs_scanner  # noqa: F401
import cloudguard.scanners.eks_scanner  # noqa: F401
import cloudguard.scanners.ecs_scanner  # noqa: F401
import cloudguard.scanners.elb_scanner  # noqa: F401
import cloudguard.scanners.dynamodb_scanner  # noqa: F401
import cloudguard.scanners.misc_scanners  # noqa: F401

from cloudguard.scanners.registry import list_services

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


def setup_logging(verbose: bool = False) -> None:
    """Configure logging level. Per prompt spec §5: Logs never include secrets."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


HELP_EPILOG = """\b
------------------------------------------------------------
  QUICK REFERENCE -- All Available Options
------------------------------------------------------------

\b
cloudguard scan
  --all                       Scan all 20 supported AWS services
  -s, --services TEXT         Comma-separated services (e.g. s3,iam,ec2)
  -r, --regions TEXT          Comma-separated AWS regions (default: us-east-1)
  -o, --output FORMAT         Output: table | json | sarif | html | md
  -p, --profile TEXT          AWS CLI profile name
  --role-arn TEXT              IAM role ARN to assume (cross-account)
  --external-id TEXT          External ID for assume-role
  --session-duration INT      Assume-role session length in seconds (default: 3600)
  --allowlist TEXT             Comma-separated allowed AWS account IDs
  --concurrency INT           Max parallel scanner threads (default: 4)
  --force                     Skip interactive confirmation prompt
  --no-cache                  Do not persist credentials (already default)
  -v, --verbose               Enable debug logging

\b
cloudguard checks
  --service TEXT              Filter rules by service name (e.g. iam)
  --severity TEXT             Filter by minimum severity (e.g. high)

\b
cloudguard simulate
  --scenario TEXT (required)  Simulation scenario name
  --sandbox (required)        Confirm sandbox-only mode
  --allowlist TEXT (required)  Comma-separated allowed account IDs

\b
cloudguard report
  -f, --format FORMAT         Output: json | table | sarif | html | md
  --scan-id TEXT              Scan ID to report on (future feature)

\b
Global Options
  --version                   Show version and exit
  --help                      Show this help message and exit

Run 'cloudguard <command> --help' for detailed help on any command.
"""


@click.group(epilog=HELP_EPILOG)
@click.version_option(version=__version__, prog_name="cloudguard")
def cli() -> None:
    """CloudGuard — AWS Cloud Security Misconfiguration Scanner.

    \b
    Detect misconfigurations, score vulnerabilities, and get remediation guidance.
    Read-only by default. Never stores credentials.
    """
    pass


@cli.command()
@click.option("--all", "scan_all", is_flag=True, help="Scan all supported AWS services")
@click.option(
    "--services", "-s", default=None,
    help="Comma-separated list of services to scan (e.g., s3,iam,ec2)"
)
@click.option("--regions", "-r", default="us-east-1", help="Comma-separated AWS regions to scan")
@click.option(
    "--output", "-o", "output_format",
    type=click.Choice(["table", "json", "sarif", "html", "md"], case_sensitive=False),
    default="table",
    help="Output format"
)
@click.option("--profile", "-p", default=None, help="AWS CLI profile name")
@click.option("--role-arn", default=None, help="IAM role ARN to assume (cross-account)")
@click.option("--external-id", default=None, help="External ID for assume-role")
@click.option("--session-duration", default=3600, type=int, help="Assume-role session duration (seconds)")
@click.option("--no-cache", is_flag=True, help="Do not persist credentials (default behavior)")
@click.option("--allowlist", default=None, help="Comma-separated allowed account IDs")
@click.option("--concurrency", default=4, type=int, help="Max concurrent scanner threads (default: 4)")
@click.option("--force", is_flag=True, help="Skip interactive confirmation (advanced)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def scan(
    scan_all: bool,
    services: Optional[str],
    regions: str,
    output_format: str,
    profile: Optional[str],
    role_arn: Optional[str],
    external_id: Optional[str],
    session_duration: int,
    no_cache: bool,
    allowlist: Optional[str],
    concurrency: int,
    force: bool,
    verbose: bool,
) -> None:
    """Scan AWS infrastructure for security misconfigurations.

    \b
    Examples:
      cloudguard scan --all
      cloudguard scan --services s3,iam --regions us-west-2
      cloudguard scan --all --profile readonly --output json
      cloudguard scan --all --role-arn arn:aws:iam::TARGET:role/CloudGuardRole
    """
    setup_logging(verbose)

    if not scan_all and not services:
        console.print("[yellow]No services specified. Use --all or --services.[/yellow]")
        console.print("Available services: " + ", ".join(list_services()))
        sys.exit(1)

    service_list: list[str] | None = None
    if services:
        service_list = [s.strip().lower() for s in services.split(",")]

    target_services = service_list or list_services() if scan_all or service_list else list_services()
    region_list = [r.strip() for r in regions.split(",")]
    allowlist_ids = [a.strip() for a in allowlist.split(",")] if allowlist else []

    console.print(
        Panel(
            f"[bold cyan]CloudGuard v{__version__}[/bold cyan]\n"
            f"Regions: {', '.join(region_list)}\n"
            f"Services: {'ALL' if scan_all else ', '.join(target_services)}\n"
            f"Concurrency: {concurrency}",
            title="🔒 Security Scan",
            border_style="cyan",
        )
    )

    # ── Step 1: Authenticate ─────────────────────────────────────────────
    try:
        session = resolve_session(
            profile=profile,
            role_arn=role_arn,
            external_id=external_id,
            session_duration=session_duration,
            region=region_list[0],
        )
    except AuthError as e:
        console.print(f"[bold red]Authentication failed:[/bold red]\n{e}")
        sys.exit(1)

    # ── Step 2: Verify identity (prompt spec §C.1) ───────────────────────
    try:
        identity = verify_identity(session)
    except AuthError as e:
        console.print(f"[bold red]Identity verification failed:[/bold red]\n{e}")
        sys.exit(1)

    console.print(
        Panel(
            f"[green]Account:[/green] {identity.account}\n"
            f"[green]Caller ARN:[/green] {identity.arn}\n"
            f"[green]User:[/green] {identity.display_name}",
            title="🔑 Caller Identity",
            border_style="green",
        )
    )

    # ── Step 2b: Allowlist check ──────────────────────────────────────────
    if allowlist_ids and not check_allowlist(identity, allowlist_ids):
        console.print(
            f"[bold red]ABORT:[/bold red] Account {identity.account} is not in allowlist: {allowlist_ids}"
        )
        sys.exit(1)

    # ── Step 2c: Interactive confirmation (prompt spec §C.1) ─────────────
    if not force:
        confirm = click.confirm(
            f"Are you sure you want to scan account {identity.account}?",
            default=False,
        )
        if not confirm:
            console.print("[yellow]Scan aborted by user.[/yellow]")
            sys.exit(0)

    # ── Step 3: Permission pre-checks (prompt spec §C.2) ─────────────────
    console.print("\n[bold]Running permission pre-checks...[/bold]")
    perm_report = check_permissions(session, target_services, region_list[0])
    console.print(perm_report.summary())

    if perm_report.none_permitted:
        console.print(
            "\n[bold red]ABORT:[/bold red] No services are accessible. "
            "Attach infra/cloudguard-readonly-policy.json to your IAM entity."
        )
        sys.exit(1)

    if perm_report.denied_services:
        console.print(
            f"\n[yellow]⚠ {len(perm_report.denied_services)} service(s) inaccessible. "
            f"Continuing with: {', '.join(perm_report.permitted_services)}[/yellow]"
        )
        target_services = perm_report.permitted_services

    # ── Step 4: Run scan ──────────────────────────────────────────────────
    engine = ScanEngine(profile=profile, region=region_list[0])
    # Override the engine's session with our authenticated one
    engine._session = session

    with console.status("[bold green]Scanning AWS infrastructure...[/bold green]"):
        result = engine.run(services=target_services)

    # ── Step 5: Output results ────────────────────────────────────────────
    _output_results(result, output_format)


def _output_results(result: ScanResult, output_format: str) -> None:
    """Output scan results in the specified format."""
    if output_format == "json":
        click.echo(JSONReporter().generate(result))
    elif output_format == "sarif":
        click.echo(SARIFReporter().generate(result))
    elif output_format == "html":
        click.echo(HTMLReporter().generate(result))
    elif output_format == "md":
        click.echo(MarkdownReporter().generate(result))
    else:
        TableReporter().print_report(result, console)


@cli.command()
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["json", "table", "sarif", "html", "md"], case_sensitive=False),
    default="table",
)
@click.option("--scan-id", default=None, help="Scan ID to report on (future)")
def report(output_format: str, scan_id: Optional[str]) -> None:
    """Generate a report from scan results (placeholder for future scan storage)."""
    console.print("[yellow]Report command: scan storage not yet implemented.[/yellow]")
    console.print("Run 'cloudguard scan --all --output json' to generate a report directly.")


@cli.command()
@click.option("--service", default=None, help="Filter checks by service")
@click.option("--severity", default=None, help="Filter by minimum severity")
def checks(service: Optional[str], severity: Optional[str]) -> None:
    """List all available security checks/rules.

    \b
    Examples:
      cloudguard checks
      cloudguard checks --service iam
      cloudguard checks --severity high
    """
    all_rules = load_all_rules()

    # Apply filters
    if service:
        all_rules = {k: v for k, v in all_rules.items() if k == service.lower()}

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_severity = severity_order.get(severity.upper(), 4) if severity else 4

    table = Table(
        title="CloudGuard Security Checks",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Rule ID", style="cyan", min_width=25)
    table.add_column("Service", style="green", min_width=10)
    table.add_column("Severity", min_width=10)
    table.add_column("Description", min_width=40)
    table.add_column("CIS Mapping", min_width=10)

    count = 0
    for svc, rules in sorted(all_rules.items()):
        for rule in rules:
            sev = rule["severity"].upper()
            if severity_order.get(sev, 4) > min_severity:
                continue
            style = SEVERITY_COLORS.get(sev, "white")
            table.add_row(
                rule["id"],
                svc.upper(),
                Text(sev, style=style),
                rule["description"],
                rule.get("cis_mapping", "—"),
            )
            count += 1

    console.print(table)
    console.print(f"\n[bold]Total: {count} checks across {len(all_rules)} services[/bold]")


@cli.command()
@click.option("--scenario", required=True, help="Simulation scenario name")
@click.option("--sandbox", is_flag=True, help="Confirm running in sandbox mode")
@click.option("--allowlist", default=None, help="Comma-separated AWS account IDs", required=True)
def simulate(scenario: str, sandbox: bool, allowlist: str) -> None:
    """Run a safe attack simulation (sandbox only).

    Per PRD §11: Attack simulations must run only on authorized accounts,
    avoid destructive actions, and comply with AWS penetration testing policies.

    \b
    Requires ALL of:
      --sandbox flag
      --allowlist with account IDs
      Interactive confirmation
    """
    if not sandbox:
        console.print(
            "[bold red]ERROR:[/bold red] Simulation requires --sandbox flag.\n"
            "Simulations must only run against authorized sandbox accounts.\n"
            "See README_SIMULATION.md for ethical guidelines."
        )
        sys.exit(1)

    allowed_accounts = [a.strip() for a in allowlist.split(",")]
    console.print(
        Panel(
            f"[yellow]Scenario: {scenario}[/yellow]\n"
            f"Allowed accounts: {', '.join(allowed_accounts)}\n\n"
            "⚠️  This will run non-destructive enumeration against the target account.\n"
            "You must have written authorization for this account.",
            title="🧪 Simulation Mode",
            border_style="yellow",
        )
    )

    confirm = click.confirm(
        f"Confirm simulation against accounts {allowed_accounts}?",
        default=False,
    )
    if not confirm:
        console.print("[yellow]Simulation aborted.[/yellow]")
        sys.exit(0)

    console.print(
        "[yellow]Simulation feature under development. "
        "See README_SIMULATION.md for roadmap.[/yellow]"
    )


# Provide entrypoint for `python -m cloudguard`
def main() -> None:
    """CLI entrypoint."""
    cli()


if __name__ == "__main__":
    main()
