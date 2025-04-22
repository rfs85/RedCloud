# Cloud Provider Support

RedClouds provides comprehensive security auditing and resource discovery capabilities across major cloud providers. This guide details the supported features for each cloud platform.

## AWS (Amazon Web Services)

### Supported Services
- **Identity and Access Management (IAM)**
  - User and role permissions analysis
  - MFA configuration checks
  - Access key rotation status
  - Password policy compliance

- **Storage Services**
  - S3 bucket security assessment
  - EBS volume encryption verification
  - EFS security configuration
  - Backup configuration validation

- **Network Security**
  - VPC security group analysis
  - Network ACL review
  - Load balancer configuration
  - VPN and Direct Connect security

- **Compute Services**
  - EC2 instance security
  - Lambda function permissions
  - ECS/EKS cluster security
  - Auto Scaling configuration

- **Database Services**
  - RDS instance security
  - DynamoDB encryption
  - ElastiCache security
  - Redshift cluster configuration

## Azure

### Supported Services
- **Identity Management**
  - Azure AD configuration
  - Role assignments
  - Service principals
  - Managed identities

- **Storage**
  - Blob container security
  - File share permissions
  - Storage account encryption
  - Access policies

- **Networking**
  - Network Security Groups
  - Application Security Groups
  - Azure Firewall rules
  - Virtual Network peering

- **Compute**
  - Virtual Machine security
  - App Service configuration
  - AKS cluster security
  - Function Apps

- **Databases**
  - Azure SQL security
  - Cosmos DB configuration
  - MySQL/PostgreSQL security
  - Cache for Redis

## Google Cloud Platform (GCP)

### Supported Services
- **Identity & Security**
  - IAM roles and permissions
  - Service accounts
  - Organization policies
  - Security Command Center

- **Storage**
  - Cloud Storage bucket security
  - Persistent disk encryption
  - Filestore security
  - Archive storage

- **Networking**
  - VPC firewall rules
  - Cloud Load Balancing
  - Cloud CDN configuration
  - Cloud NAT setup

- **Compute**
  - Compute Engine VM security
  - GKE cluster configuration
  - Cloud Run security
  - App Engine settings

- **Databases**
  - Cloud SQL security
  - Cloud Spanner configuration
  - Cloud Bigtable security
  - Memorystore settings

## Cross-Cloud Features

### Resource Discovery
- Domain-based resource search
- Company name association
- Tag/label-based filtering
- Resource relationship mapping

### Security Assessment
- Compliance benchmarking
- Best practice validation
- Risk scoring
- Remediation recommendations

### Reporting Capabilities
- HTML reports
- JSON/CSV export
- Custom report templates
- Scheduled assessments

## Integration Capabilities

### CI/CD Integration
- GitHub Actions support
- GitLab CI integration
- Jenkins pipeline support
- Azure DevOps integration

### Monitoring Integration
- CloudWatch integration
- Azure Monitor support
- Cloud Monitoring (GCP)
- Custom metric export

### SIEM Integration
- Splunk integration
- ELK Stack support
- QRadar compatibility
- Azure Sentinel integration

# Cloud Provider Integration

RedClouds provides comprehensive integration with major cloud service providers to enable security assessments across multi-cloud environments.

## Supported Cloud Providers

### AWS Integration

The `AWSProvider` class enables integration with AWS services:

- **Authentication**
  - IAM roles and users
  - AWS STS support
  - Cross-account access
  - MFA integration

- **Service Coverage**
  - EC2 and VPC
  - S3 and storage services
  - IAM and security services
  - Lambda and serverless
  - RDS and databases
  - Container services

### Azure Integration

The `AzureProvider` class enables integration with Azure services:

- **Authentication**
  - Service principals
  - Managed identities
  - Azure AD integration
  - Role-based access

- **Service Coverage**
  - Virtual machines
  - Storage accounts
  - Identity and access
  - Functions and apps
  - SQL databases
  - AKS and containers

### GCP Integration

The `GCPProvider` class enables integration with Google Cloud services:

- **Authentication**
  - Service accounts
  - Workload identity
  - Cloud Identity
  - OAuth 2.0

- **Service Coverage**
  - Compute Engine
  - Cloud Storage
  - IAM and security
  - Cloud Functions
  - Cloud SQL
  - GKE and containers

## Usage

```python
from redclouds.cloud_providers import AWSProvider, AzureProvider, GCPProvider

# Initialize providers
aws = AWSProvider(
    region="us-west-2",
    profile="security-audit"
)

azure = AzureProvider(
    subscription_id="your-subscription-id",
    tenant_id="your-tenant-id"
)

gcp = GCPProvider(
    project_id="your-project-id",
    credentials_file="path/to/credentials.json"
)

# Example multi-cloud assessment
providers = [aws, azure, gcp]
for provider in providers:
    # Connect to provider
    provider.connect()
    
    # Run security checks
    findings = provider.run_security_checks()
    
    # Generate report
    provider.generate_report(findings)
```

## Authentication Configuration

### AWS Configuration

```yaml
aws:
  authentication:
    type: "role"  # or "user"
    role_arn: "arn:aws:iam::123456789012:role/SecurityAudit"
    external_id: "your-external-id"
    mfa_enabled: true
  regions:
    - "us-east-1"
    - "us-west-2"
  services:
    - "ec2"
    - "s3"
    - "iam"
```

### Azure Configuration

```yaml
azure:
  authentication:
    type: "service_principal"
    tenant_id: "your-tenant-id"
    client_id: "your-client-id"
    client_secret: "your-client-secret"
  subscriptions:
    - "subscription-id-1"
    - "subscription-id-2"
  services:
    - "compute"
    - "storage"
    - "keyvault"
```

### GCP Configuration

```yaml
gcp:
  authentication:
    type: "service_account"
    credentials_file: "path/to/credentials.json"
  projects:
    - "project-id-1"
    - "project-id-2"
  services:
    - "compute"
    - "storage"
    - "iam"
```

## Best Practices

1. **Authentication**
   - Use least privilege access
   - Enable MFA where possible
   - Rotate credentials regularly
   - Use managed identities

2. **Service Access**
   - Limit service scope
   - Enable audit logging
   - Monitor API usage
   - Regular access review

3. **Multi-Cloud**
   - Consistent naming
   - Standardized tagging
   - Unified monitoring
   - Central management

## Security Features

1. **Access Management**
   - Role-based access
   - Policy enforcement
   - Access reviews
   - Audit logging

2. **Resource Protection**
   - Encryption settings
   - Network security
   - Identity protection
   - Data security

3. **Compliance**
   - Policy compliance
   - Regulatory requirements
   - Industry standards
   - Best practices

## Monitoring and Alerts

1. **Resource Monitoring**
   - Usage metrics
   - Performance data
   - Security events
   - Cost tracking

2. **Security Monitoring**
   - Access patterns
   - Policy violations
   - Configuration changes
   - Threat detection

3. **Compliance Monitoring**
   - Policy adherence
   - Regulatory status
   - Audit findings
   - Risk assessment

## Integration Guidelines

1. **Initial Setup**
   - Provider registration
   - Authentication setup
   - Permission configuration
   - Service enablement

2. **Ongoing Management**
   - Credential rotation
   - Access reviews
   - Policy updates
   - Service monitoring

3. **Troubleshooting**
   - Connection issues
   - Permission errors
   - Service limits
   - API quotas 