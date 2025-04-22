# Google Cloud Platform (GCP) Security Guide

This guide provides detailed instructions for using RedClouds to audit GCP environments, with practical examples and best practices.

## Quick Start

### Basic GCP Security Audit
```bash
# Run a complete GCP security audit
python main.py audit --provider gcp --format html --output gcp-audit.html

# Audit specific services
python main.py audit --provider gcp --service iam --service storage --service compute
```

## Common Use Cases

### 1. Cloud Storage Security

#### Bucket Security Assessment
```bash
# Search for public buckets
python main.py search --provider gcp --type storage --public-only

# Check specific bucket permissions
python main.py audit --provider gcp --service storage --resource my-bucket
```

#### Example Findings
```json
{
  "resource_id": "my-bucket",
  "findings": [
    {
      "severity": "HIGH",
      "check": "public_access",
      "details": "Bucket allows allUsers access",
      "remediation": "Remove allUsers and allAuthenticatedUsers IAM bindings"
    }
  ]
}
```

### 2. IAM and Service Accounts

#### Identity Audit
```bash
# Audit IAM policies
python main.py audit --provider gcp --service iam --focus policies

# Check service accounts
python main.py audit --provider gcp --service iam --check service_accounts
```

#### Policy Analysis Example
```yaml
findings:
  - principal: "service-account@project.iam.gserviceaccount.com"
    issues:
      - type: "excessive_permissions"
        details: "Service account has Owner role at project level"
        affected_resources:
          - "projects/my-project"
        recommendation: "Implement least-privilege access using custom roles"
```

## Advanced Scenarios

### 1. Multi-Project Assessment

#### Configuration
```yaml
# config.yaml
gcp:
  projects:
    - name: "Production"
      id: "prod-project-id"
    - name: "Development"
      id: "dev-project-id"
  checks:
    - compute_instances
    - cloud_sql
    - vpc_security
```

#### Execution
```bash
# Run multi-project audit
python main.py audit --provider gcp --config config.yaml --all-projects
```

### 2. Continuous Security Monitoring

#### Cloud Build Integration
```yaml
# cloudbuild.yaml
steps:
- name: 'python'
  entrypoint: python
  args: ['main.py', 'audit', '--provider', 'gcp', '--format', 'json', '--output', 'gs://security-reports/audit-$BUILD_ID.json']
  env:
    - 'PROJECT_ID=$PROJECT_ID'
    
timeout: '1800s'
```

## Security Best Practices

### 1. Compute Engine Security

#### VM Instance Audit
```bash
# Check firewall rules
python main.py audit --provider gcp --service compute --check firewall_rules

# Find instances with public IPs
python main.py audit --provider gcp --service compute --check public_ip
```

#### Example Firewall Findings
```json
{
  "rule_name": "allow-all-ingress",
  "violations": [
    {
      "rule": "0.0.0.0/0:22",
      "severity": "HIGH",
      "recommendation": "Restrict SSH access to specific IP ranges using IAP"
    }
  ]
}
```

### 2. Cloud SQL Security

#### Database Security Assessment
```bash
# Audit Cloud SQL instances
python main.py audit --provider gcp --service sql --check encryption

# Check network access
python main.py audit --provider gcp --service sql --check public_access
```

## Compliance Frameworks

### 1. CIS GCP Benchmark

#### Running CIS Checks
```bash
# Run all CIS benchmark checks
python main.py audit --provider gcp --compliance cis

# Run specific CIS sections
python main.py audit --provider gcp --compliance cis --section 1.0
```

### 2. Custom Security Standards

#### Standard Definition
```yaml
# gcp-security.yaml
rules:
  - name: "enforce_cmek"
    service: "storage"
    check: "encryption_keys"
    severity: "HIGH"
  - name: "vpc_security"
    service: "compute"
    check: "network_security"
    severity: "MEDIUM"
```

#### Execution
```bash
# Run custom security checks
python main.py audit --provider gcp --custom-rules gcp-security.yaml
```

## Incident Response

### 1. Security Event Investigation

#### Cloud Audit Logs Analysis
```bash
# Check for suspicious activities
python main.py audit --provider gcp --service audit --check unauthorized_access

# Review configuration changes
python main.py audit --provider gcp --service audit --check config_changes
```

### 2. Automated Remediation

#### Example Remediation Script
```python
from redclouds.remediation import GCPRemediation

def secure_storage_bucket(bucket_name):
    remediation = GCPRemediation()
    remediation.remove_public_access(bucket_name)
    remediation.enforce_uniform_access([
        {
            "role": "roles/storage.objectViewer",
            "members": ["serviceAccount:app@project.iam.gserviceaccount.com"]
        }
    ])
```

## Organization Security

### 1. Organization Policy Compliance

#### Policy Checks
```bash
# Audit organization policies
python main.py audit --provider gcp --service org --check policies

# Check resource hierarchy
python main.py audit --provider gcp --service org --check hierarchy
```

### 2. Resource Management

#### Resource Inventory
```bash
# List all resources
python main.py search --provider gcp --output inventory.csv

# Find resources by label
python main.py search --provider gcp --label environment=production
```

## Cost Management

### 1. Resource Optimization

#### Finding Inefficient Resources
```bash
# Check resource utilization
python main.py audit --provider gcp --check resource_utilization

# Identify cost savings
python main.py audit --provider gcp --focus cost_optimization
```

### 2. Label Compliance

#### Checking Resource Labels
```bash
# Audit resource labels
python main.py audit --provider gcp --check label_compliance

# Find unlabeled resources
python main.py search --provider gcp --unlabeled-only
```

## Troubleshooting

### Common Issues

1. **Authentication Problems**
```bash
# Verify GCP credentials
python main.py verify-credentials --provider gcp

# Test IAM permissions
python main.py check-permissions --provider gcp --scope project
```

2. **API Quotas**
```yaml
# config.yaml
gcp:
  quotas:
    max_requests_per_100_seconds: 1000
    retry_count: 3
  monitoring:
    enabled: true
    quota_threshold: 0.8
```

### Debug Tools
```bash
# Enable debug mode
python main.py audit --provider gcp --debug

# Export debug information
python main.py audit --provider gcp --debug --log-file gcp-debug.log
```

### Integration Testing

#### Configuration Testing
```bash
# Test GCP configuration
python main.py validate-config --provider gcp

# Test service connectivity
python main.py test-connectivity --provider gcp --services storage,compute,sql
``` 