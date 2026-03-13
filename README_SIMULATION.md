# Attack Simulation — Ethical Guidelines

## Overview

CloudGuard's `simulate` command provides **safe, non-destructive** attack simulations for educational and testing purposes.

## Safety Requirements

Per PRD §11 and AWS Penetration Testing Policy:

1. **Sandbox only**: Simulations run ONLY against explicitly authorized sandbox accounts
2. **Non-destructive**: All tests are read-only or create temporary resources that are cleaned up
3. **Opt-in**: Requires `--sandbox` flag AND `--allowlist` with account IDs
4. **Logged**: All simulation actions are logged for audit purposes

## Usage

```bash
cloudguard simulate --scenario s3-enum --sandbox --allowlist 123456789012
```

## Legal Requirements

- You must own or have written authorization for the AWS account
- Review [AWS Penetration Testing Policy](https://aws.amazon.com/security/penetration-testing/)
- Simulations must not violate AWS Acceptable Use Policy
- Do NOT run against production accounts or third-party infrastructure

## Available Scenarios (Planned)

| Scenario | Description | Destructive? |
|----------|-------------|-------------|
| s3-enum | S3 bucket enumeration | No |
| iam-enum | IAM user/role enumeration | No |
| metadata-probe | EC2 metadata service probe | No |

## Disclaimer

CloudGuard simulation features are for **educational purposes**. The authors are not responsible for misuse. Always obtain proper authorization before testing.
