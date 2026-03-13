#!/bin/bash
# CloudGuard Sandbox Cleanup Script
# Destroys all test resources created by sandbox.yaml

set -euo pipefail

STACK_NAME="${1:-cloudguard-sandbox}"
REGION="${2:-us-east-1}"

echo "🧹 Cleaning up CloudGuard sandbox stack: $STACK_NAME"
echo "   Region: $REGION"

# Empty S3 bucket before deletion
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="${STACK_NAME}-insecure-${ACCOUNT_ID}"

echo "   Emptying bucket: $BUCKET_NAME"
aws s3 rm "s3://${BUCKET_NAME}" --recursive 2>/dev/null || true

echo "   Deleting CloudFormation stack..."
aws cloudformation delete-stack \
    --stack-name "$STACK_NAME" \
    --region "$REGION"

echo "   Waiting for stack deletion..."
aws cloudformation wait stack-delete-complete \
    --stack-name "$STACK_NAME" \
    --region "$REGION"

echo "✅ Sandbox cleaned up successfully!"
