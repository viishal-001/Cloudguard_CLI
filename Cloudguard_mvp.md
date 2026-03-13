
# CloudGuard MVP Document
## Version 2.0 – 20 AWS Services

## 1. Product Overview
**Project Name:** CloudGuard  
**Type:** Cloud Security Misconfiguration Scanner  
**Interface:** Command Line Interface (CLI)

CloudGuard is a cloud cybersecurity scanning tool designed to detect security misconfigurations in AWS environments.

The tool scans AWS infrastructure, identifies vulnerabilities, assigns severity and CVSS scores, and provides mitigation guidance.

The MVP focuses on core scanning capability across **20 AWS services** while maintaining a modular architecture for future expansion.

---

## 2. MVP Objectives
The CloudGuard MVP must demonstrate the following capabilities:

1. Scan AWS infrastructure using AWS APIs.
2. Detect security misconfigurations across 20 AWS services.
3. Assign severity levels and CVSS scores.
4. Provide mitigation recommendations.
5. Display results via CLI.
6. Export scan results in JSON format.
7. Maintain modular architecture for future web integration.

---

## 3. MVP Scope

### Included Features
| Feature | Description |
|--------|-------------|
AWS Service Scanner | Scan 20 AWS services
Security Rule Engine | Detect misconfigurations
Severity Classification | Categorize risks
CVSS Scoring | Vulnerability scoring
Mitigation Recommendations | Remediation guidance
CLI Interface | Command-based interaction
Report Generation | JSON and terminal output
Modular Architecture | Expandable scanning modules

### Excluded Features (Future)
- Web dashboard
- Real-time monitoring
- Continuous scanning
- Multi-cloud support
- AI threat detection
- Automated remediation

---

## 4. Target Users
| User | Purpose |
|-----|--------|
Cybersecurity Students | Learning cloud security
DevOps Engineers | Infrastructure review
Cloud Engineers | Security posture checks
Researchers | Vulnerability analysis

---

## 5. Technology Stack

### Programming Language
Python 3.10+

### CLI Framework
Click

Example command:
```bash
cloudguard scan --all
```

### AWS SDK
Boto3

Example:
```python
import boto3
s3 = boto3.client("s3")
```

### CVSS Scoring
Python library: `cvss`

### Output Formatting
Libraries:
- rich
- tabulate

### Database (Optional)
SQLite

### Development Tools
| Tool | Purpose |
|-----|--------|
Git | Version control
Docker | Containerization
pytest | Unit testing
Moto | Mock AWS services

---

## 6. AWS Services Scanned (20)

1. IAM
2. S3
3. EC2
4. Security Groups
5. RDS
6. VPC
7. CloudTrail
8. CloudWatch
9. Lambda
10. API Gateway
11. EBS
12. EKS
13. ECS
14. Elastic Load Balancer
15. DynamoDB
16. KMS
17. Secrets Manager
18. SNS
19. SQS
20. AWS Config

---

## 7. CLI Commands

Scan all services:
```bash
cloudguard scan --all
```

Scan specific services:
```bash
cloudguard scan --services s3,ec2,iam
```

Export results:
```bash
cloudguard scan --output json
```

List available checks:
```bash
cloudguard checks
```

---

## 8. CLI Output Example

```
SERVICE      RESOURCE        ISSUE                      SEVERITY  CVSS
S3           mybucket        Public Bucket               HIGH      8.5
IAM          AdminRole       Wildcard Policy             CRITICAL  9.0
EC2          i-0342          SSH Port Open               HIGH      7.6
RDS          db-prod         Public Database             HIGH      8.2
```

---

## 9. Severity Classification
| Level | Description |
|------|-------------|
Critical | Immediate risk
High | High exploitation potential
Medium | Moderate risk
Low | Minor issue

---

## 10. CVSS Mapping
| Score | Severity |
|------|----------|
9–10 | Critical
7–8.9 | High
4–6.9 | Medium
0–3.9 | Low

---

## 11. Architecture

```
User CLI
   |
CLI Interface
   |
CloudGuard Engine
   |
Service Scanners
   |
Rule Engine
   |
CVSS Scoring
   |
Report Generator
```

---

## 12. Project Structure

```
cloudguard/
│
├── cli/
├── scanners/
├── checks/
├── scoring/
├── reporting/
├── utils/
└── main.py
```

---

## 13. MVP Timeline

| Phase | Duration |
|------|----------|
Environment Setup | 1 week
AWS API Integration | 2 weeks
Scanner Development | 2 weeks
CLI Development | 1 week
Testing | 1 week

Total: ~7 weeks

---

## 14. MVP Success Criteria

CloudGuard MVP must:

- Scan 20 AWS services
- Detect 100+ misconfigurations
- Generate CVSS scored reports
- Run fully via CLI
