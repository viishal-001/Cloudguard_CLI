# GitHub Setup Instructions

## Repository Secrets & Environment Variables
Do **not** commit AWS credentials to this repository. Ever.

If you need automated CI/CD scans using GitHub Actions, configure **OIDC (Keyless) Authentication**.
You do not need to store any secrets for this repo at this time unless using external tools (e.g. Dependabot, SonarCloud).

### How to Configure OIDC for GitHub Actions
1. In your AWS Account, create an OIDC Identity Provider for `token.actions.githubusercontent.com`.
2. Create an IAM Role for GitHub Actions (e.g. `CloudGuardOIDCRole`).
3. Attach the `infra/cloudguard-readonly-policy.json` to that role.
4. Establish the Trust Policy using the template below:

#### Trust Policy Template
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::TARGET_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                },
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": "repo:viishal-001/Cloudguard_CLI:ref:refs/heads/main"
                }
            }
        }
    ]
}
```

Then edit `.github/workflows/scan.yml` to use `arn:aws:iam::TARGET_ACCOUNT_ID:role/CloudGuardOIDCRole`.
