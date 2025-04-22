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