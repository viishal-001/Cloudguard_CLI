# CloudGuard Roadmap

## v1.0.0 — MVP (Current)
- [x] 20 AWS service scanners (IAM, S3, EC2, SG, RDS, VPC, CloudTrail, CloudWatch, Lambda, API Gateway, EBS, EKS, ECS, ELB, DynamoDB, KMS, Secrets Manager, SNS, SQS, Config)
- [x] 59 security rules mapped to CIS AWS Foundations Benchmark
- [x] CVSS v3.1 scoring engine
- [x] Click CLI with scan, checks, report, simulate commands
- [x] 5 output formats: Table (Rich), JSON, SARIF, HTML, Markdown
- [x] 5 authentication flows: Profile, Assume-Role, SSO, Env, OIDC
- [x] Pre-scan identity verification + permission checks
- [x] Exponential backoff + rate limiting
- [x] Optional encrypted credential cache (PBKDF2 + AES-GCM)
- [x] Read-only IAM policy + trust templates
- [x] Docker multi-stage build + docker-compose
- [x] GitHub Actions CI (lint, test, build, security audit)
- [x] pytest + moto test suite
- [x] Documentation: README, SECURITY, ARCHITECTURE, RULES, CONTRIBUTING, SIMULATION

## v1.1.0 — Stability & Coverage
- [ ] Expand to 100+ security rules across all services
- [ ] Add multi-region scanning (`--regions us-east-1,eu-west-1`)
- [ ] Encrypted SQLite scan history (opt-in)
- [ ] Scan diff reports (compare current vs previous)
- [ ] PyInstaller cross-platform binaries

## v2.0.0 — Web Dashboard (PRD §12 Phase 2)
- [ ] FastAPI REST API with scan endpoints
- [ ] React/Next.js web dashboard
- [ ] Scheduled scan cron jobs
- [ ] Scan result visualization and trending
- [ ] Team collaboration features

## v3.0.0 — Multi-Cloud (PRD §12 Phase 3)
- [ ] Azure security scanning
- [ ] GCP security scanning
- [ ] Kubernetes security posture

## v4.0.0 — AI & Automation (PRD §12 Phase 4)
- [ ] AI-powered threat detection
- [ ] Automated remediation (opt-in, gated)
- [ ] Compliance report generation (PCI-DSS, HIPAA, SOC2)
