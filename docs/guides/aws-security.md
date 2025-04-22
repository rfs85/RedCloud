# AWS Security Guide

This guide provides detailed instructions for using RedClouds to audit AWS environments, with practical examples and best practices.

## Quick Start

### Basic AWS Security Audit
```bash
# Run a complete AWS security audit
python main.py audit --provider aws --format html --output aws-audit.html

# Audit specific services
python main.py audit --provider aws --service iam --service s3 --service ec2
```

## Common Use Cases

### 1. S3 Bucket Security Assessment

#### Finding Public Buckets
```bash
# Search for public S3 buckets
python main.py search --provider aws --type s3 --public-only

# Check specific bucket permissions
python main.py audit --provider aws --service s3 --resource my-bucket
```

#### Example Findings
```json
{
  "resource_id": "my-bucket",
  "findings": [
    {
      "severity": "HIGH",
      "check": "public_access",
      "details": "Bucket allows public list operations",
      "remediation": "Enable S3 Block Public Access"
    }
  ]
}
```

### 2. IAM Security Review

#### User Access Audit
```bash
# Audit IAM users and permissions
python main.py audit --provider aws --service iam --focus users

# Check for unused access keys
python main.py audit --provider aws --service iam --check unused_credentials
```

#### Policy Analysis Example
```yaml
findings:
  - user: "admin-user"
    issues:
      - type: "excessive_permissions"
        details: "User has wildcard (*) permissions on multiple services"
        affected_services:
          - "s3:*"
          - "ec2:*"
        recommendation: "Implement least-privilege access"
```

## Advanced Scenarios

### 1. Multi-Region Security Assessment

#### Configuration
```yaml
# config.yaml
aws:
  regions:
    - us-east-1
    - us-west-2
    - eu-west-1
  checks:
    - ec2_security_groups
    - rds_encryption
    - cloudtrail_logging
```

#### Execution
```bash
# Run multi-region audit
python main.py audit --provider aws --config config.yaml --all-regions
```

### 2. Continuous Security Monitoring

#### GitHub Actions Integration
```yaml
# .github/workflows/security-audit.yml
name: AWS Security Audit
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run RedClouds Audit
        run: |
          python main.py audit --provider aws --format json \
            --output audit-$(date +%F).json
```

## Security Best Practices

### 1. EC2 Instance Security

#### Security Group Audit
```bash
# Check for overly permissive security groups
python main.py audit --provider aws --service ec2 --check security_groups

# Find instances with public IP addresses
python main.py audit --provider aws --service ec2 --check public_ip
```

#### Example Security Group Findings
```json
{
  "group_id": "sg-12345",
  "violations": [
    {
      "rule": "Inbound 0.0.0.0/0:22",
      "severity": "HIGH",
      "recommendation": "Restrict SSH access to specific IP ranges"
    }
  ]
}
```

### 2. RDS Database Security

#### Encryption and Access Checks
```bash
# Audit RDS instances
python main.py audit --provider aws --service rds --check encryption

# Check public accessibility
python main.py audit --provider aws --service rds --check public_access
```

## Compliance Frameworks

### 1. CIS AWS Benchmark

#### Running CIS Checks
```bash
# Run all CIS benchmark checks
python main.py audit --provider aws --compliance cis

# Run specific CIS sections
python main.py audit --provider aws --compliance cis --section 1.0
```

### 2. Custom Compliance Framework

#### Framework Definition
```yaml
# custom-compliance.yaml
rules:
  - name: "enforce_mfa"
    service: "iam"
    check: "user_mfa"
    severity: "HIGH"
  - name: "encrypt_volumes"
    service: "ec2"
    check: "volume_encryption"
    severity: "MEDIUM"
```

#### Execution
```bash
# Run custom compliance checks
python main.py audit --provider aws --custom-rules custom-compliance.yaml
```

## Incident Response

### 1. Security Incident Investigation

#### Quick Assessment
```bash
# Check for unauthorized access
python main.py audit --provider aws --service cloudtrail --check unauthorized_api_calls

# Review resource modifications
python main.py audit --provider aws --service config --check resource_changes
```

### 2. Automated Remediation

#### Example Remediation Script
```python
from redclouds.remediation import AWSRemediation

def fix_security_group(group_id):
    remediation = AWSRemediation()
    remediation.remove_public_access(group_id)
    remediation.add_security_rules([
        {
            "port": 22,
            "cidr": "10.0.0.0/8",
            "description": "Internal SSH access"
        }
    ])
```

## Cost Optimization

### 1. Resource Utilization Analysis

#### Finding Idle Resources
```bash
# Check for unused resources
python main.py audit --provider aws --check resource_utilization

# Identify cost optimization opportunities
python main.py audit --provider aws --focus cost_optimization
```

### 2. Tag Compliance

#### Checking Resource Tags
```bash
# Audit resource tags
python main.py audit --provider aws --check tag_compliance

# Find untagged resources
python main.py search --provider aws --untagged-only
```

## Troubleshooting

### Common Issues

1. **Authentication Failures**
```bash
# Verify AWS credentials
python main.py verify-credentials --provider aws

# Test specific permissions
python main.py check-permissions --provider aws --service s3
```

2. **Rate Limiting**
```yaml
# config.yaml
aws:
  rate_limiting:
    max_retries: 3
    delay_seconds: 5
  api_quotas:
    enabled: true
    threshold: 80
```

### Debug Mode
```bash
# Enable debug logging
python main.py audit --provider aws --debug

# Save debug logs
python main.py audit --provider aws --debug --log-file aws-debug.log
``` 