# CloudGuard Security Rules Reference

Complete list of all security checks with CIS AWS Foundations Benchmark mappings.

## IAM (6 rules)

| Rule ID | Severity | CVSS | CIS | Description |
|---------|----------|------|-----|-------------|
| iam-root-access-keys | CRITICAL | 10.0 | 1.4 | Root account has active access keys |
| iam-mfa-disabled | HIGH | 8.1 | 1.2 | IAM user does not have MFA enabled |
| iam-wildcard-policy | CRITICAL | 9.9 | 1.16 | IAM policy allows wildcard (*) on all resources |
| iam-unused-credentials | MEDIUM | 4.2 | 1.3 | Credentials unused for 90+ days |
| iam-password-policy-weak | MEDIUM | 5.4 | 1.5-1.11 | Account password policy insufficient |
| iam-inline-policy | LOW | 3.1 | 1.15 | User has inline policies attached |

## S3 (5 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| s3-public-access | CRITICAL | 2.1.1 | Bucket allows public access |
| s3-no-encryption | HIGH | 2.1.2 | No default encryption |
| s3-no-versioning | MEDIUM | 2.1.3 | Versioning not enabled |
| s3-no-logging | MEDIUM | 2.1.4 | Access logging not enabled |
| s3-no-ssl-enforcement | HIGH | 2.1.5 | Policy does not enforce SSL |

## EC2 (4 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| ec2-public-ip | MEDIUM | — | Instance has public IP |
| ec2-imdsv1-enabled | HIGH | 5.6 | IMDSv1 allowed |
| ec2-no-monitoring | LOW | — | Detailed monitoring disabled |
| ec2-unencrypted-volume | HIGH | 2.2.1 | Unencrypted EBS volumes |

## Security Groups (4 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| sg-unrestricted-ingress | HIGH | 5.2 | Ingress from 0.0.0.0/0 |
| sg-ssh-open | HIGH | 5.2 | SSH open to world |
| sg-rdp-open | HIGH | 5.3 | RDP open to world |
| sg-unrestricted-egress | LOW | — | All outbound allowed |

## RDS (4 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| rds-public-access | HIGH | 2.3.1 | Publicly accessible |
| rds-no-encryption | HIGH | 2.3.2 | No encryption at rest |
| rds-no-multi-az | MEDIUM | — | Multi-AZ disabled |
| rds-no-backup | MEDIUM | — | Automated backups disabled |

## VPC (2 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| vpc-flow-logs-disabled | MEDIUM | 3.9 | Flow logs not enabled |
| vpc-default-sg-in-use | MEDIUM | 5.4 | Default SG has rules |

## CloudTrail (3 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| cloudtrail-disabled | HIGH | 3.1 | CloudTrail not enabled |
| cloudtrail-no-log-validation | MEDIUM | 3.2 | Log validation disabled |
| cloudtrail-not-encrypted | MEDIUM | 3.7 | Logs not KMS encrypted |

## CloudWatch (2 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| cloudwatch-no-alarm-root | MEDIUM | 4.3 | No root usage alarm |
| cloudwatch-no-log-group-retention | LOW | — | No log retention policy |

## Lambda (3 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| lambda-public-access | HIGH | Public resource policy |
| lambda-no-dlq | LOW | No dead-letter queue |
| lambda-runtime-deprecated | MEDIUM | Deprecated runtime |

## API Gateway (3 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| apigateway-no-auth | HIGH | No authorization |
| apigateway-no-logging | MEDIUM | No execution logging |
| apigateway-no-waf | MEDIUM | No WAF association |

## EBS (2 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| ebs-unencrypted | HIGH | 2.2.1 | Volume not encrypted |
| ebs-snapshot-public | CRITICAL | — | Public snapshot |

## EKS (3 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| eks-public-endpoint | HIGH | Public API endpoint |
| eks-no-logging | MEDIUM | Control plane logging disabled |
| eks-secrets-not-encrypted | HIGH | Secrets not encrypted |

## ECS (3 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| ecs-task-role-missing | HIGH | No task role assigned |
| ecs-no-logging | MEDIUM | No logging configured |
| ecs-privileged-container | CRITICAL | Privileged mode enabled |

## ELB (3 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| elb-no-ssl | HIGH | No HTTPS listener |
| elb-no-access-logging | MEDIUM | Access logging disabled |
| elb-deletion-protection-disabled | LOW | Deletion protection off |

## DynamoDB (2 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| dynamodb-no-encryption | MEDIUM | No KMS encryption |
| dynamodb-no-pitr | MEDIUM | No point-in-time recovery |

## KMS (2 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| kms-key-rotation-disabled | MEDIUM | 3.8 | Auto rotation disabled |
| kms-key-exposed | CRITICAL | — | Key policy allows public access |

## Secrets Manager (2 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| secretsmanager-no-rotation | MEDIUM | No auto rotation |
| secretsmanager-not-used-recently | LOW | Unused for 90+ days |

## SNS (2 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| sns-public-access | HIGH | Public publishing/subscribing |
| sns-no-encryption | MEDIUM | No SSE enabled |

## SQS (2 rules)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| sqs-public-access | HIGH | Public access |
| sqs-no-encryption | MEDIUM | No SSE enabled |

## AWS Config (2 rules)

| Rule ID | Severity | CIS | Description |
|---------|----------|-----|-------------|
| config-not-enabled | MEDIUM | 3.5 | Config not enabled |
| config-no-global-resources | MEDIUM | 3.5 | Global resources not recorded |

---

**Total: 57 rules across 20 AWS services**
