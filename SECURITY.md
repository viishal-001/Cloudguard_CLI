# Security Policy & Authentication Guide

> **CloudGuard is read-only by default.** It never stores credentials, never calls destructive APIs, and never sends data externally unless you explicitly opt in.

---

## Authentication Flows

CloudGuard supports 5 authentication methods. Pick the one that fits your environment.

### 1. Local AWS CLI Profile (Recommended for development)

```bash
cloudguard scan --all --profile my-readonly-profile
```

Setup:
```bash
aws configure --profile my-readonly-profile
# Enter Access Key ID, Secret Access Key, Region
```

### 2. Assume-Role (Cross-account scanning)

```bash
cloudguard scan --all \
  --role-arn arn:aws:iam::TARGET_ACCOUNT:role/CloudGuardRole \
  --external-id my-unique-external-id \
  --session-duration 3600
```

Setup in the target account:
1. Create a role with `infra/cloudguard-readonly-policy.json` as the permissions policy
2. Use `infra/trust-policy-template.json` as the trust policy (replace `TRUSTED_ACCOUNT_ID` and `EXTERNAL_ID_HERE`)

### 3. AWS SSO / IAM Identity Center

```bash
aws sso login --profile sso-profile
cloudguard scan --all --profile sso-profile
```

CloudGuard respects SSO sessions configured via `aws configure sso`.

### 4. CI/CD with OIDC (Recommended for automation)

Use GitHub Actions OIDC for keyless authentication:
1. Create an OIDC trust policy using `infra/oidc-trust-policy-template.json`
2. Configure the role with `infra/cloudguard-readonly-policy.json`
3. Use `.github/workflows/scan.yml` as a template

```yaml
# .github/workflows/scan.yml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::ACCOUNT:role/CloudGuardOIDC
    aws-region: us-east-1
- run: cloudguard scan --all --force --output sarif
```

> ⚠️ **Never commit long-lived credentials to repositories.** Always prefer OIDC or short-lived tokens.

### 5. Environment Variables (Explicit only)

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...  # optional, for temporary creds
cloudguard scan --all
```

CloudGuard will print a warning when using environment variables and recommend switching to profiles or OIDC.

---

## Pre-Scan Safety Checks

Every scan automatically performs:

1. **Identity verification**: Calls `sts:GetCallerIdentity` and displays your Account ID, ARN, and User
2. **Interactive confirmation**: Asks "Are you sure you want to scan account X?" (skip with `--force`)
3. **Permission pre-check**: Tests each selected service with a minimal safe API call
4. **Allowlist enforcement**: If `--allowlist` is set, aborts if the current account isn't listed

---

## Read-Only IAM Policy

CloudGuard requires **only read-only permissions**. The minimal policy is at:

```
infra/cloudguard-readonly-policy.json
```

### Explicitly Excluded Actions (by design)

| Excluded Action | Reason |
|----------------|--------|
| `s3:GetObject` | CloudGuard checks bucket configs, not object contents |
| `kms:Decrypt` | CloudGuard checks key rotation, not encrypted data |
| `secretsmanager:GetSecretValue` | CloudGuard checks rotation config, not secret values |
| All `Put*`, `Delete*`, `Modify*` | CloudGuard is read-only by design |

### Decryption Opt-In (Advanced)

If you need CloudGuard to verify encrypted data properties (not required for normal scanning):

1. Add `kms:Decrypt` and/or `secretsmanager:GetSecretValue` to the IAM policy
2. Pass `--allow-decrypt` flag (future feature)
3. CloudGuard will ask for interactive confirmation referencing the target account
4. All decrypt actions are audit-logged

> ⚠️ **CAUTION**: Granting decrypt permissions expands the blast radius if credentials are compromised. Only enable this in controlled environments.

---

## Credential Caching (Opt-In)

By default, CloudGuard **never** caches or persists credentials.

To enable encrypted credential caching for assumed-role sessions:

```bash
cloudguard scan --all --role-arn ... --cache
```

When enabled:
- Credentials are encrypted with PBKDF2 (600k iterations) + AES-256-GCM
- Stored at `~/.cloudguard/creds.enc` with file permissions `600`
- Requires a user-supplied passphrase
- To clear: `cloudguard cache clear` or delete `~/.cloudguard/creds.enc`

---

## Logging Security

CloudGuard logs **never** include:
- AWS access keys or secret keys
- Session tokens
- Secret values or decrypted data
- User passwords or passphrases

Logs only contain: timestamps, API call types, resource IDs, service names, and error codes.

---

## Reporting Vulnerabilities

Report security issues via private disclosure to the maintainers. Do not open public issues for security vulnerabilities.
