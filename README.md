# CloudGuard

> **AWS Cloud Security Misconfiguration Scanner**
> Scan your AWS infrastructure, find security issues, and get step-by-step fixes — all from your terminal.

[![CI](https://github.com/viishal-001/CLOUDGUARD/actions/workflows/ci.yml/badge.svg)](https://github.com/viishal-001/CLOUDGUARD/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Table of Contents

1. [What Is CloudGuard?](#1-what-is-cloudguard)
2. [What Can It Detect?](#2-what-can-it-detect)
3. [Prerequisites](#3-prerequisites)
4. [Installation](#4-installation)
   - [Option A: Install from Source (pip)](#option-a-install-from-source-pip)
   - [Option B: Using Docker](#option-b-using-docker)
5. [AWS Account Setup](#5-aws-account-setup)
   - [Step 5.1: Create a Read-Only IAM User or Role](#step-51-create-a-read-only-iam-user-or-role)
   - [Step 5.2: Configure AWS Credentials on Your Machine](#step-52-configure-aws-credentials-on-your-machine)
6. [Your First Scan](#6-your-first-scan)
7. [All Commands and Options](#7-all-commands-and-options)
   - [cloudguard scan](#cloudguard-scan)
   - [cloudguard checks](#cloudguard-checks)
   - [cloudguard report](#cloudguard-report)
   - [cloudguard simulate](#cloudguard-simulate)
8. [Authentication Options](#8-authentication-options)
   - [Option 1: Named Profile (Recommended)](#option-1-named-profile-recommended)
   - [Option 2: Assume-Role (Cross-Account)](#option-2-assume-role-cross-account)
   - [Option 3: AWS SSO / IAM Identity Center](#option-3-aws-sso--iam-identity-center)
   - [Option 4: Environment Variables](#option-4-environment-variables)
   - [Option 5: CI/CD with OIDC](#option-5-cicd-with-oidc)
9. [Understanding the Output](#9-understanding-the-output)
10. [Output Formats and Saving Reports](#10-output-formats-and-saving-reports)
11. [Safety Features](#11-safety-features)
12. [Troubleshooting](#12-troubleshooting)
13. [Frequently Asked Questions](#13-frequently-asked-questions)
14. [Project Structure](#14-project-structure)
15. [Contributing](#15-contributing)
16. [License](#16-license)

---

## 1. What Is CloudGuard?

CloudGuard is a free, open-source command-line tool that checks your Amazon Web Services (AWS) account for **security problems** — things like publicly accessible storage buckets, users without multi-factor authentication, unencrypted databases, and overly permissive firewall rules.

> **Project Reference:** This tool implements all requirements specified in `cloudguard_mvp.md` (MVP v2.0) and `cloudguard_prd.md` (Product Requirements Document).

**Key facts:**
- **Read-only** — CloudGuard only *looks* at your AWS setup; it never changes, deletes, or creates anything.
- **Local** — All scanning happens on your machine. No data is sent anywhere.
- **Safe** — Credentials are never stored, logged, or transmitted.

---

## 2. What Can It Detect?

CloudGuard scans **20 AWS services** with **59 security rules**:

| # | Service | Example Checks |
|---|---------|----------------|
| 1 | **IAM** | Root access keys, missing MFA, wildcard permissions, weak password policy |
| 2 | **S3** | Public buckets, missing encryption, no versioning |
| 3 | **EC2** | Public IPs, IMDSv1 enabled, disabled monitoring |
| 4 | **Security Groups** | SSH/RDP open to `0.0.0.0/0`, unrestricted ingress |
| 5 | **RDS** | Public databases, no encryption, no backups |
| 6 | **VPC** | Flow logs disabled, default security group in use |
| 7 | **CloudTrail** | Trail disabled, no log validation, no KMS encryption |
| 8 | **CloudWatch** | No root-usage alarm, no log retention |
| 9 | **Lambda** | Public access, deprecated runtimes, no dead-letter queue |
| 10 | **API Gateway** | No authorization, no logging |
| 11 | **EBS** | Unencrypted volumes, public snapshots |
| 12 | **EKS** | Public cluster endpoint, no secrets encryption |
| 13 | **ECS** | Privileged containers, missing task role |
| 14 | **ELB** | No HTTPS listener, no access logging |
| 15 | **DynamoDB** | No encryption, no point-in-time recovery |
| 16 | **KMS** | Key rotation disabled, public key policy |
| 17 | **Secrets Manager** | No automatic rotation, unused secrets |
| 18 | **SNS** | Public topic access, no encryption |
| 19 | **SQS** | Public queue access, no encryption |
| 20 | **AWS Config** | Recorder disabled, global resources not tracked |

To see the full list with severity levels and CIS benchmark mappings, run:
```bash
cloudguard checks
```

---

## 3. Prerequisites

Before installing CloudGuard, you need:

### 3.1 Python 3.10 or Later

Check if you already have Python:
```bash
python --version
```

If it says `Python 3.10` or higher, you're good. If not:

- **Windows**: Download from [python.org/downloads](https://www.python.org/downloads/). During installation, **check the box** that says "Add Python to PATH".
- **macOS**: `brew install python@3.11` (requires [Homebrew](https://brew.sh))
- **Linux (Ubuntu/Debian)**: `sudo apt update && sudo apt install python3.11 python3.11-venv python3-pip`
- **Linux (Fedora)**: `sudo dnf install python3.11`

### 3.2 pip (Python Package Manager)

pip usually comes with Python. Verify:
```bash
pip --version
```

If not found, install it:
```bash
python -m ensurepip --upgrade
```

### 3.3 An AWS Account

You need an AWS account with resources to scan. If you're a student, you can use [AWS Free Tier](https://aws.amazon.com/free/).

### 3.4 AWS CLI (Recommended but Optional)

The AWS CLI makes configuring credentials easier:
- **Windows**: Download the installer from [AWS CLI install page](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **macOS**: `brew install awscli`
- **Linux**: `sudo apt install awscli` or `pip install awscli`

Verify:
```bash
aws --version
```

---

## 4. Installation

### Option A: Install from Source (pip)

1. **Download the project** (clone or download ZIP):
   ```bash
   git clone https://github.com/viishal-001/CLOUDGUARD.git
   cd CLOUDGUARD
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS / Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install CloudGuard**:
   ```bash
   pip install -e .
   ```

4. **Verify the installation**:
   ```bash
   cloudguard --version
   ```
   You should see: `cloudguard, version 0.1.0`

> **Tip:** If `cloudguard` is not found, use `python -m cloudguard` instead.

### Option B: Using Docker

If you prefer not to install Python, use Docker:

1. **Build the image**:
   ```bash
   docker build -t cloudguard .
   ```

2. **Run CloudGuard**:
   ```bash
   docker run --rm \
     -e AWS_ACCESS_KEY_ID \
     -e AWS_SECRET_ACCESS_KEY \
     -e AWS_SESSION_TOKEN \
     cloudguard scan --all --force
   ```

> **Note:** When using Docker, pass your AWS credentials as environment variables (see [Option 4: Environment Variables](#option-4-environment-variables)).

<!-- AUTOGENERATED -->
### Option C: Developer / Contributor Setup

If you want to modify CloudGuard or run tests:
```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"

# Run tests
pytest -q

# Run security linting (what CI runs)
bandit -r cloudguard/ -ll
safety check
```
See [CONTRIBUTING.md](CONTRIBUTING.md) for full details on contributing, adding rules, and running CI locally.

### Option D: Running the Sample Test Sandbox

For safe, local testing without messing up your real AWS account, CloudGuard includes a sample CloudFormation template containing intentional misconfigurations.

```bash
cd sample-aws

# 1. Deploy the vulnerable sandbox resources
# WARNING: Only run this on a dedicated sandbox account!
aws cloudformation create-stack \
  --stack-name CloudGuardTest \
  --template-body file://sandbox.yaml \
  --capabilities CAPABILITY_NAMED_IAM

# Wait for creation to finish...

# 2. Run CloudGuard against it
cloudguard scan --all --profile your-sandbox-profile

# 3. CLEAN UP (Crucial!)
./cleanup.sh
```
<!-- /AUTOGENERATED -->

---

## 5. AWS Account Setup

CloudGuard needs **read-only permission** to look at your AWS resources. It will never modify anything.

### Step 5.1: Create a Read-Only IAM User or Role

#### Method A: Using the AWS Console (Web Browser)

1. Sign in to the [AWS Console](https://console.aws.amazon.com/)
2. Go to **IAM** → **Policies** → **Create policy**
3. Click the **JSON** tab
4. Copy and paste the contents of `infra/cloudguard-readonly-policy.json` from this project
5. Click **Next**, name the policy `CloudGuardReadOnly`, and click **Create policy**
6. Go to **IAM** → **Users** → **Create user**
7. Name the user `cloudguard-scanner`
8. On the permissions page, click **Attach policies directly** → search for `CloudGuardReadOnly` → check the box → **Next** → **Create user**
9. Click on the user → **Security credentials** tab → **Create access key**
10. Select **Command Line Interface (CLI)** → confirm → **Create access key**
11. **Save the Access Key ID and Secret Access Key** — you'll need them in the next step

> ⚠️ **Security warning:** Treat these credentials like a password. Never share them, commit them to code, or post them online.

#### Method B: Using the AWS CLI

```bash
# Create the policy
aws iam create-policy \
  --policy-name CloudGuardReadOnly \
  --policy-document file://infra/cloudguard-readonly-policy.json

# Create the user
aws iam create-user --user-name cloudguard-scanner

# Attach the policy (replace ACCOUNT_ID with your 12-digit AWS account number)
aws iam attach-user-policy \
  --user-name cloudguard-scanner \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/CloudGuardReadOnly

# Create access keys
aws iam create-access-key --user-name cloudguard-scanner
```

### Step 5.2: Configure AWS Credentials on Your Machine

Now that you have an Access Key ID and Secret Access Key, tell your machine how to use them:

```bash
aws configure --profile cloudguard
```

It will ask you four questions:
```
AWS Access Key ID [None]: PASTE_YOUR_ACCESS_KEY_HERE
AWS Secret Access Key [None]: PASTE_YOUR_SECRET_KEY_HERE
Default region name [None]: us-east-1
Default output format [None]: json
```

> **What is a "region"?** AWS has data centers around the world. Each one has a code name like `us-east-1` (Virginia, USA), `eu-west-1` (Ireland), or `ap-south-1` (Mumbai, India). Pick the region closest to where you created your AWS resources.

**Verify your credentials work:**
```bash
aws sts get-caller-identity --profile cloudguard
```

You should see your Account ID, User ARN, and User ID. If you see an error, double-check your Access Key and Secret Key.

---

## 6. Your First Scan

Now you're ready to run your first scan! Here is what will happen step-by-step:

1. CloudGuard connects to your AWS account (read-only)
2. It shows you which account you're connected to and asks for confirmation
3. It checks that it has permission to scan each service
4. It scans all 20 services and compares them against the 59 security rules
5. It shows you a table of every issue found, with severity and a CVSS score

**Run the scan:**
```bash
cloudguard scan --all --profile cloudguard
```

CloudGuard will show:
```
🔒 Security Scan
CloudGuard v0.1.0
Regions: us-east-1
Services: ALL
Concurrency: 4

🔑 Caller Identity
Account: 123456789012
Caller ARN: arn:aws:iam::123456789012:user/cloudguard-scanner
User: cloudguard-scanner

Are you sure you want to scan account 123456789012? [y/N]: y

Running permission pre-checks...
  IAM                  ✅ PERMITTED
  S3                   ✅ PERMITTED
  EC2                  ✅ PERMITTED
  ...

Scanning AWS infrastructure...

📊 Scan Summary
CRITICAL: 1  HIGH: 3  MEDIUM: 5  LOW: 2  INFO: 0

┌──────────┬───────────────┬─────────────────────────┬──────────┬──────┐
│ SERVICE  │ RESOURCE      │ ISSUE                   │ SEVERITY │ CVSS │
├──────────┼───────────────┼─────────────────────────┼──────────┼──────┤
│ IAM      │ root          │ Root has active keys     │ CRITICAL │  9.9 │
│ S3       │ my-bucket     │ Public bucket access     │ HIGH     │  8.5 │
│ EC2      │ sg-abc123     │ SSH open to 0.0.0.0/0   │ HIGH     │  7.6 │
│ RDS      │ my-database   │ Publicly accessible      │ HIGH     │  8.2 │
│ ...      │ ...           │ ...                     │ ...      │  ... │
└──────────┴───────────────┴─────────────────────────┴──────────┴──────┘

Total: 11 findings
```

---

## 7. All Commands and Options

### cloudguard scan

The main command. Scans your AWS account for security issues.

```bash
cloudguard scan [OPTIONS]
```

| Option | Short | What It Does | Example |
|--------|-------|-------------|---------|
| `--all` | | Scan all 20 AWS services | `cloudguard scan --all` |
| `--services` | `-s` | Scan only specific services (comma-separated) | `--services s3,iam,ec2` |
| `--profile` | `-p` | Which AWS credentials profile to use | `--profile cloudguard` |
| `--regions` | `-r` | Which AWS region(s) to scan (comma-separated) | `--regions us-east-1,eu-west-1` |
| `--output` | `-o` | Output format: `table`, `json`, `sarif`, `html`, `md` | `--output json` |
| `--role-arn` | | Assume an IAM role before scanning (for cross-account) | `--role-arn arn:aws:iam::TARGET:role/MyRole` |
| `--external-id` | | External ID used with `--role-arn` | `--external-id abc123` |
| `--session-duration` | | How long the assumed role session lasts (seconds) | `--session-duration 7200` |
| `--allowlist` | | Only allow scanning these account IDs (comma-separated) | `--allowlist 123456789012` |
| `--concurrency` | | How many services to scan in parallel (default: 4) | `--concurrency 2` |
| `--force` | | Skip the "Are you sure?" confirmation prompt | `--force` |
| `--no-cache` | | Don't cache credentials (this is already the default) | `--no-cache` |
| `--verbose` | `-v` | Show detailed debug output | `-v` |

**Examples:**

```bash
# Scan everything in your default region
cloudguard scan --all --profile cloudguard

# Scan only S3 and IAM
cloudguard scan --services s3,iam --profile cloudguard

# Scan a different region
cloudguard scan --all --profile cloudguard --regions eu-west-1

# Save results as a JSON file
cloudguard scan --all --profile cloudguard --output json > my-report.json

# Save results as an HTML report
cloudguard scan --all --profile cloudguard --output html > report.html

# Scan without being asked for confirmation (useful in scripts)
cloudguard scan --all --profile cloudguard --force

# Scan a different AWS account by assuming a role
cloudguard scan --all --role-arn arn:aws:iam::999999999999:role/CloudGuardRole
```

### cloudguard checks

Lists every security rule that CloudGuard checks for — without connecting to AWS.

```bash
cloudguard checks [OPTIONS]
```

| Option | Short | What It Does | Example |
|--------|-------|-------------|---------|
| `--service` | | Show rules for one service only | `--service iam` |
| `--severity` | | Show only rules of this severity or higher | `--severity high` |

**Examples:**

```bash
# List all 59 checks
cloudguard checks

# Show only IAM checks
cloudguard checks --service iam

# Show only CRITICAL and HIGH severity checks
cloudguard checks --severity high
```

### cloudguard report

Generate a report from stored scan results. *(This feature is under development — for now, use `--output` flag with `scan`.)*

```bash
cloudguard report [OPTIONS]
```

### cloudguard simulate

Run safe, non-destructive security simulations against a **sandbox** AWS account only.

```bash
cloudguard simulate --scenario <name> --sandbox --allowlist <account_id>
```

| Option | Required | What It Does |
|--------|----------|-------------|
| `--scenario` | Yes | Name of the simulation to run |
| `--sandbox` | Yes | Confirms you are running in a test environment |
| `--allowlist` | Yes | The AWS account ID(s) allowed for simulation |

> ⚠️ **Important:** Simulations must only be run against AWS accounts you own and have explicit authorization to test. See `README_SIMULATION.md` for ethical guidelines.

---

## 8. Authentication Options

CloudGuard supports 5 ways to connect to your AWS account. Pick the one that fits your situation.

### Option 1: Named Profile (Recommended)

Best for: **Most users**, personal accounts, development.

```bash
# First, set up a profile (one-time)
aws configure --profile cloudguard

# Then scan using that profile
cloudguard scan --all --profile cloudguard
```

### Option 2: Assume-Role (Cross-Account)

Best for: **Scanning multiple AWS accounts** from one machine, or scanning accounts you don't have direct credentials for.

**Setup in the target account:**
1. Create a role with the `infra/cloudguard-readonly-policy.json` permissions
2. Set the trust policy using `infra/trust-policy-template.json`

**Run the scan:**
```bash
cloudguard scan --all \
  --role-arn arn:aws:iam::TARGET_ACCOUNT_ID:role/CloudGuardRole \
  --external-id my-secret-id
```

### Option 3: AWS SSO / IAM Identity Center

Best for: **Organizations** using AWS SSO.

```bash
# Log in through SSO (one-time per session)
aws sso login --profile my-sso-profile

# Scan using the SSO profile
cloudguard scan --all --profile my-sso-profile
```

### Option 4: Environment Variables

Best for: **Docker** or environments where you can't use `aws configure`.

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-east-1

cloudguard scan --all
```

> ⚠️ CloudGuard will warn you that env-var credentials are less secure. Use named profiles or OIDC when possible.

### Option 5: CI/CD with OIDC

Best for: **Automated scanning** in GitHub Actions, without storing long-lived credentials.

See `.github/workflows/scan.yml` in this project for a ready-to-use template. It uses GitHub's OIDC provider to assume an AWS role without any stored secrets.

---

## 9. Understanding the Output

### Severity Levels

CloudGuard classifies every finding into one of five levels:

| Level | CVSS Score | What It Means | Action Required |
|-------|-----------|---------------|-----------------|
| 🔴 **CRITICAL** | 9.0–10.0 | Immediate risk of data breach or full compromise | Fix right away |
| 🟠 **HIGH** | 7.0–8.9 | Significant vulnerability that could be exploited | Fix within 24–48 hours |
| 🟡 **MEDIUM** | 4.0–6.9 | Moderate risk, may require specific conditions | Fix within a week |
| 🔵 **LOW** | 0.1–3.9 | Minor issue, best practice improvement | Schedule for later |
| ⚪ **INFO** | 0.0 | Informational only, not a vulnerability | Review when convenient |

### What Is a CVSS Score?

CVSS (Common Vulnerability Scoring System) is a standardized way to rate how serious a security problem is. The score goes from **0.0** (no risk) to **10.0** (maximum risk). Each CloudGuard rule has a pre-calculated CVSS score based on:

- How easily it can be exploited
- Whether it requires special access
- What damage it can cause

### Reading the Results Table

```
┌──────────┬───────────────┬──────────────────────────┬──────────┬──────┐
│ SERVICE  │ RESOURCE      │ ISSUE                    │ SEVERITY │ CVSS │
├──────────┼───────────────┼──────────────────────────┼──────────┼──────┤
│ S3       │ my-bucket     │ Public Bucket access      │ HIGH     │  8.5 │
└──────────┴───────────────┴──────────────────────────┴──────────┴──────┘
```

- **SERVICE**: Which AWS service has the issue (S3, IAM, EC2, etc.)
- **RESOURCE**: The specific AWS resource affected (bucket name, instance ID, etc.)
- **ISSUE**: A plain-English description of the security problem found
- **SEVERITY**: How serious it is (CRITICAL → INFO)
- **CVSS**: The numerical vulnerability score (0.0–10.0)

Each finding also includes a **mitigation** — step-by-step instructions to fix the problem. Use `--output md` or `--output json` to see the full mitigation text.

---

## 10. Output Formats and Saving Reports

CloudGuard can produce reports in 5 formats:

| Format | Flag | Best For | How to Save |
|--------|------|----------|-------------|
| **Table** | `--output table` | Quick viewing in your terminal | (displays directly) |
| **JSON** | `--output json` | Programmatic access, integration with other tools | `> report.json` |
| **SARIF** | `--output sarif` | GitHub Code Scanning, CI/CD pipelines | `> results.sarif` |
| **HTML** | `--output html` | Sharing with your team, opening in a browser | `> report.html` |
| **Markdown** | `--output md` | Documentation, GitHub/GitLab README embedding | `> report.md` |

**Examples:**

```bash
# View in terminal (default)
cloudguard scan --all --profile cloudguard

# Save as JSON
cloudguard scan --all --profile cloudguard --output json > scan-report.json

# Save as a shareable HTML page
cloudguard scan --all --profile cloudguard --output html > scan-report.html

# Save as Markdown for documentation
cloudguard scan --all --profile cloudguard --output md > scan-report.md

# Save as SARIF for GitHub Code Scanning
cloudguard scan --all --profile cloudguard --output sarif > results.sarif
```

To **open the HTML report**, double-click the `.html` file or:
```bash
# Windows
start scan-report.html

# macOS
open scan-report.html

# Linux
xdg-open scan-report.html
```

---

## 11. Safety Features

CloudGuard is designed to be safe to use against real AWS accounts:

| Safety Feature | What It Does |
|----------------|-------------|
| **Read-only** | Only uses List, Get, and Describe API calls. Never modifies your infrastructure. |
| **Identity check** | Shows which AWS account and user you're connected to before scanning. |
| **Confirmation prompt** | Asks "Are you sure?" before starting a scan (skip with `--force`). |
| **Permission pre-check** | Tests each service for AccessDenied before scanning, gracefully skips inaccessible services. |
| **Allowlist** | Restrict scanning to specific account IDs with `--allowlist`. |
| **No credential storage** | AWS credentials are never saved to disk, logged, or transmitted. |
| **Rate limiting** | Automatically slows down if AWS rate limits are hit (exponential backoff). |
| **Simulation gates** | The `simulate` command requires `--sandbox` flag, `--allowlist`, and interactive confirmation. |

> 🛡️ **Detailed Security Guide:** For full details on our read-only policies, how to set up Keyless OIDC for CI/CD, and the exact credential handling mechanisms, please read our comprehensive [SECURITY.md](SECURITY.md) guidelines.

---

## 12. Troubleshooting

### "cloudguard: command not found"

- Make sure you activated your virtual environment: `source venv/bin/activate` (Linux/Mac) or `venv\Scripts\activate` (Windows)
- Try using `python -m cloudguard` instead
- If you installed with pip, ensure the script directory is in your PATH

### "Authentication failed" / "No AWS credentials found"

- Run `aws configure --profile cloudguard` and enter your Access Key and Secret Key
- Run `aws sts get-caller-identity --profile cloudguard` to verify credentials work
- Check that `~/.aws/credentials` (Linux/Mac) or `%USERPROFILE%\.aws\credentials` (Windows) exists

### "AccessDenied" for some services

This means your IAM user/role doesn't have permission to scan that service.

1. Attach the `infra/cloudguard-readonly-policy.json` policy to your IAM user or role
2. CloudGuard will automatically skip services you can't access and scan the rest
3. Run `cloudguard scan --services s3,iam` to scan only specific services

### "Throttling" / Slow scan

AWS rate limits API calls. CloudGuard handles this automatically with retries, but you can:
- Reduce concurrency: `--concurrency 2`
- Scan fewer services: `--services s3,iam`

### "No misconfigurations found"

Congratulations! Your AWS account is well-configured. This is a good result. However, consider:
- Are you scanning the right region? Check with `--regions`
- Are all services accessible? Check the permission pre-check output
- Do you have resources in this region? An empty account will have no findings

---

## 13. Frequently Asked Questions

**Q: Will CloudGuard change anything in my AWS account?**
> No. CloudGuard is strictly read-only. It uses only List, Get, and Describe API calls. It will never create, modify, or delete any AWS resource.

**Q: Is it safe to use on a production AWS account?**
> Yes. It is designed for real AWS accounts. The read-only IAM policy ensures CloudGuard cannot make changes. The pre-scan identity check and confirmation prompt add an extra layer of safety.

**Q: Does CloudGuard send my data anywhere?**
> No. Everything runs locally on your machine. No data is collected, transmitted, or stored externally.

**Q: How much does it cost to run a scan?**
> CloudGuard uses AWS API calls, which are covered by the [AWS Free Tier](https://aws.amazon.com/free/) in most cases. A typical scan makes a few hundred read-only API calls — well within free-tier limits.

**Q: Can I scan multiple AWS accounts?**
> Yes. Use `--role-arn` to assume a role in each account. See [Option 2: Assume-Role](#option-2-assume-role-cross-account).

**Q: Can I scan multiple regions?**
> Yes. Use `--regions us-east-1,eu-west-1,ap-south-1` to scan multiple regions.

**Q: How do I add custom rules?**
> Rules are defined in YAML files under `cloudguard/rules/`. You can add new rules by creating a new YAML file following the format in existing files. See `CONTRIBUTING.md` for details.

---

## 14. Project Structure

```
CloudGuard/
├── cloudguard/                  # Main application code
│   ├── cli.py                   # Command-line interface
│   ├── core/
│   │   ├── aws_auth.py          # AWS authentication (5 methods)
│   │   ├── engine.py            # Scan orchestration
│   │   ├── models.py            # Data models
│   │   ├── permission_checks.py # Pre-scan permission verification
│   │   └── rule_loader.py       # YAML rule loader
│   ├── scanners/                # 20 service scanners
│   ├── rules/                   # 59 YAML security rules
│   ├── scoring/
│   │   └── cvss.py              # CVSS v3.1 vulnerability scorer
│   ├── reporting/               # JSON, Table, SARIF, HTML, Markdown
│   └── utils/
│       ├── aws_helpers.py       # Rate limiting, backoff
│       └── crypto.py            # Credential encryption (opt-in)
├── infra/
│   ├── cloudguard-readonly-policy.json   # IAM policy to attach
│   ├── trust-policy-template.json        # Cross-account trust
│   └── oidc-trust-policy-template.json   # GitHub OIDC trust
├── tests/                       # pytest + moto test suite
├── sample-aws/                  # Test sandbox CloudFormation template
├── .github/workflows/           # CI/CD pipelines
├── Dockerfile                   # Docker container
├── SECURITY.md                  # Detailed security documentation
├── ARCHITECTURE.md              # System architecture
├── RULES.md                     # Complete rules reference
└── README.md                    # This file
```

---

## 15. Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to set up a development environment
- How to add a new scanner or rule
- Code style guidelines
- Pull request process

---

## 16. License

MIT — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Made with ❤️ for cloud security</strong><br>
  <a href="SECURITY.md">Security Policy</a> · <a href="RULES.md">Rules Reference</a> · <a href="ARCHITECTURE.md">Architecture</a> · <a href="CONTRIBUTING.md">Contributing</a>
</p>
