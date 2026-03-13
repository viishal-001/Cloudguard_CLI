"""Tests for CLI commands."""

from click.testing import CliRunner
from cloudguard.cli import cli


class TestCLI:
    """Test Click CLI commands."""

    def test_help(self):
        """cloudguard --help should work."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "CloudGuard" in result.output

    def test_version(self):
        """cloudguard --version should show version."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_checks_command(self):
        """cloudguard checks should list all rules."""
        runner = CliRunner()
        result = runner.invoke(cli, ["checks"])
        assert result.exit_code == 0
        assert "iam" in result.output.lower() or "IAM" in result.output

    def test_scan_no_services(self):
        """cloudguard scan without --all or --services should warn."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code == 1

    def test_simulate_requires_sandbox(self):
        """cloudguard simulate without --sandbox should error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["simulate", "--scenario", "test", "--allowlist", "123456789012"])
        assert result.exit_code == 1
        assert "sandbox" in result.output.lower()

    def test_simulate_with_sandbox_prompts(self):
        """cloudguard simulate --sandbox --allowlist should prompt for confirmation."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["simulate", "--scenario", "test", "--sandbox", "--allowlist", "123456789012"],
            input="n\n",  # Decline confirmation
        )
        assert result.exit_code == 0
        assert "aborted" in result.output.lower() or "confirm" in result.output.lower()

    def test_report_placeholder(self):
        """cloudguard report should show placeholder message."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report"])
        assert result.exit_code == 0
