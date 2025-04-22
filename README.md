# RedClouds - Multi-Cloud Security Auditing Tool

RedClouds is a command-line interface (CLI) tool designed to audit security configurations across multiple cloud providers (AWS, Azure, and GCP). It helps identify potential security misconfigurations and generates detailed reports to improve your cloud security posture.

## Features

- **Multi-Cloud Support**: Audit AWS, Azure, and GCP resources from a single tool
- **Comprehensive Security Checks**: Based on industry best practices and CIS Benchmarks
- **Flexible Reporting**: Generate reports in multiple formats (JSON, CSV, Markdown, plain text)
- **Modular Design**: Easily extend with new cloud providers, security checks, and report formats
- **Secure Credential Management**: Support for environment variables and cloud-native credential management

## Installation

1. Clone the repository:
```bash
git clone https://github.com/rfs85/redclouds.git
cd redclouds
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

RedClouds requires appropriate credentials for each cloud provider you wish to audit:

### AWS
- Set AWS credentials using environment variables:
  ```bash
  export AWS_ACCESS_KEY_ID="your_access_key"
  export AWS_SECRET_ACCESS_KEY="your_secret_key"
  export AWS_DEFAULT_REGION="your_region"
  ```
- Or use AWS CLI configuration: `aws configure`

### Azure
- Set Azure credentials using environment variables:
  ```bash
  export AZURE_SUBSCRIPTION_ID="your_subscription_id"
  export AZURE_CLIENT_ID="your_client_id"
  export AZURE_CLIENT_SECRET="your_client_secret"
  export AZURE_TENANT_ID="your_tenant_id"
  ```
- Or use Azure CLI: `az login`

### GCP
- Set GCP credentials using environment variables:
  ```bash
  export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/credentials.json"
  ```
- Or use gcloud CLI: `gcloud auth application-default login`

## Usage

RedClouds provides two main commands: `audit` and `search`.

### Audit Command
Use this to perform security audits of your cloud resources:
```bash
python main.py audit --provider [aws|azure|gcp|all] [OPTIONS]
```

Audit options:
- `--provider`: Specify cloud provider(s) to audit (required)
- `--config`: Path to configuration file (default: config.yaml)
- `--format`: Output format (text, json, csv, markdown)
- `--output`: Output file path
- `--service`: Specific services to audit (e.g., iam, storage, network)

Example:
```bash
# Audit AWS services and output in JSON format
python main.py audit --provider aws --format json --output aws-audit.json

# Audit specific services across all providers
python main.py audit --provider all --service iam --service storage
```

### Search Command
Use this to search for resources across cloud providers:
```bash
python main.py search --provider [aws|azure|gcp|all] [OPTIONS]
```

Search options:
- `--provider`: Specify cloud provider(s) to search (required)
- `--domain`: Domain name to search for (e.g., example.com)
- `--company`: Company name to search for
- `--config`: Path to configuration file (default: config.yaml)
- `--format`: Output format (text, json, csv)
- `--output`: Output file path

Example:
```bash
# Search for resources related to a domain
python main.py search --provider aws --domain example.com

# Search across all providers for a company
python main.py search --provider all --company "Example Corp"

# Search with specific output format
python main.py search --provider aws --domain example.com --format json --output results.json
```

Note: The search command can work without cloud credentials to find public resources, but will use credentials if available to find private resources as well.

## Security Checks

RedClouds performs various security checks across different resource types:

### IAM/Identity
- MFA status for privileged users
- Access key rotation
- Password policy compliance
- Service principal/managed identity usage

### Storage
- Public access configuration
- Encryption settings
- Lifecycle policies
- Access logging

### Networking
- Security group rules
- Network ACLs
- Public IP exposure
- VPN configurations

### Compute
- Instance security
- OS patching status
- Disk encryption
- Security group associations

### Databases
- Public accessibility
- Encryption settings
- Backup configurations
- Authentication methods

### Logging & Monitoring
- Audit logging status
- Alert configurations
- Log retention policies
- Monitoring coverage

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.
