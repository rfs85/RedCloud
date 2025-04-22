# Azure Security Guide

This guide provides detailed instructions for using RedClouds to audit Azure environments, with practical examples and best practices.

## Quick Start

### Basic Azure Security Audit
```bash
# Run a complete Azure security audit
python main.py audit --provider azure --format html --output azure-audit.html

# Audit specific services
python main.py audit --provider azure --service identity --service storage --service compute
```

## Common Use Cases

### 1. Storage Account Security

#### Blob Container Assessment
```bash
# Search for public containers
python main.py search --provider azure --type storage --public-only

# Check specific storage account
python main.py audit --provider azure --service storage --resource mystorageaccount
```

#### Example Findings
```json
{
  "resource_id": "mystorageaccount",
  "findings": [
    {
      "severity": "HIGH",
      "check": "public_access",
      "details": "Container allows anonymous access",
      "remediation": "Disable anonymous access and implement SAS tokens"
    }
  ]
}
```

### 2. Identity and Access Management

#### Azure AD Security Review
```bash
# Audit Azure AD configuration
python main.py audit --provider azure --service identity --focus aad

# Check service principals
python main.py audit --provider azure --service identity --check service_principals
```

#### Role Assignment Analysis
```yaml
findings:
  - principal: "app-service-01"
    issues:
      - type: "excessive_permissions"
        details: "Service Principal has Contributor role at subscription level"
        affected_scope:
          - "/subscriptions/12345-67890"
        recommendation: "Implement least-privilege RBAC"
```

## Advanced Scenarios

### 1. Multi-Subscription Assessment

#### Configuration
```yaml
# config.yaml
azure:
  subscriptions:
    - name: "Production"
      id: "12345-67890"
    - name: "Development"
      id: "67890-12345"
  checks:
    - network_security_groups
    - key_vault_access
    - vm_disk_encryption
```

#### Execution
```bash
# Run multi-subscription audit
python main.py audit --provider azure --config config.yaml --all-subscriptions
```

### 2. Continuous Compliance Monitoring

#### Azure DevOps Pipeline Integration
```yaml
# azure-pipelines.yml
trigger:
  - none
schedules:
  - cron: "0 0 * * *"
    
steps:
- task: PythonScript@0
  inputs:
    scriptSource: 'filePath'
    scriptPath: 'main.py'
    arguments: 'audit --provider azure --format json --output $(Build.ArtifactStagingDirectory)/audit.json'
```

## Security Best Practices

### 1. Virtual Machine Security

#### Network Security Group Audit
```bash
# Check NSG rules
python main.py audit --provider azure --service network --check nsg_rules

# Find VMs with public IPs
python main.py audit --provider azure --service compute --check public_ip
```

#### Example NSG Findings
```json
{
  "nsg_name": "web-tier-nsg",
  "violations": [
    {
      "rule": "Allow_Inbound_Any_3389",
      "severity": "HIGH",
      "recommendation": "Restrict RDP access to VPN/bastion networks"
    }
  ]
}
```

### 2. Key Vault Security

#### Access and Secret Management
```bash
# Audit Key Vault configuration
python main.py audit --provider azure --service keyvault --check access_policies

# Check secret expiration
python main.py audit --provider azure --service keyvault --check secret_expiration
```

## Compliance Frameworks

### 1. Azure Security Benchmark

#### Running Benchmark Checks
```bash
# Run all benchmark checks
python main.py audit --provider azure --compliance asb

# Run specific sections
python main.py audit --provider azure --compliance asb --section network
```

### 2. Custom Security Standards

#### Standard Definition
```yaml
# azure-security.yaml
rules:
  - name: "enforce_disk_encryption"
    service: "compute"
    check: "disk_encryption"
    severity: "HIGH"
  - name: "private_endpoints"
    service: "storage"
    check: "network_access"
    severity: "MEDIUM"
```

#### Execution
```bash
# Run custom security checks
python main.py audit --provider azure --custom-rules azure-security.yaml
```

## Incident Response

### 1. Security Event Investigation

#### Activity Log Analysis
```bash
# Check for suspicious activities
python main.py audit --provider azure --service monitor --check activity_logs

# Review resource changes
python main.py audit --provider azure --service monitor --check resource_changes
```

### 2. Automated Remediation

#### Example Remediation Script
```python
from redclouds.remediation import AzureRemediation

def secure_storage_account(account_name):
    remediation = AzureRemediation()
    remediation.disable_public_access(account_name)
    remediation.enable_private_endpoints([
        {
            "vnet": "prod-vnet",
            "subnet": "services-subnet"
        }
    ])
```

## Cost Management

### 1. Resource Optimization

#### Finding Underutilized Resources
```bash
# Check resource utilization
python main.py audit --provider azure --check resource_utilization

# Identify cost savings
python main.py audit --provider azure --focus cost_optimization
```

### 2. Resource Tagging

#### Tag Compliance Check
```bash
# Audit resource tags
python main.py audit --provider azure --check tag_compliance

# Find untagged resources
python main.py search --provider azure --untagged-only
```

## Troubleshooting

### Common Issues

1. **Authentication Problems**
```bash
# Verify Azure credentials
python main.py verify-credentials --provider azure

# Test RBAC permissions
python main.py check-permissions --provider azure --scope subscription
```

2. **API Throttling**
```yaml
# config.yaml
azure:
  throttling:
    max_retries: 5
    backoff_factor: 2
  rate_limits:
    enabled: true
    max_requests_per_hour: 12000
```

### Diagnostic Tools
```bash
# Enable verbose logging
python main.py audit --provider azure --verbose

# Export diagnostic data
python main.py audit --provider azure --diagnostic-file azure-diag.json
```

### Integration Testing

#### Test Configuration
```bash
# Validate Azure configuration
python main.py validate-config --provider azure

# Test connectivity to services
python main.py test-connectivity --provider azure --services storage,compute,network
``` 