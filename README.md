# RedClouds - Multi-Cloud Security Auditing Tool

<div align="center">

```
 ____           _  ____ _                 _     
|  _ \ ___  __| |/ ___| | ___  _   _  __| |___ 
| |_) / _ \/ _` | |   | |/ _ \| | | |/ _` / __|
|  _ <  __/ (_| | |___| | (_) | |_| | (_| \__ \
|_| \_\___|\__,_|\____|_|\___/ \__,_|\__,_|___/
                                               
   Multi-Cloud Security Auditing Tool v1.0.0
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen.svg)](docs/)

A powerful command-line tool for auditing and discovering security configurations across AWS, Azure, and GCP.

[Features](#features) • [Installation](#installation) • [Configuration](#configuration) • [Usage](#usage) • [Contributing](docs/CONTRIBUTING.md)

</div>

## 🚀 Features

### Core Capabilities
- **Multi-Cloud Support**: Unified security auditing for AWS, Azure, and GCP
- **Credential-Optional Scanning**: Public resource discovery without requiring cloud credentials
- **Comprehensive Security Checks**: Based on CIS Benchmarks and industry best practices
- **Resource Discovery**: Find resources by company name or domain across cloud providers

### Security Checks
- **Identity & Access Management (IAM)**
  - MFA enforcement
  - Password policies
  - Access key rotation
  - Service principal security
  
- **Storage Security**
  - Public access detection
  - Encryption configuration
  - Lifecycle management
  - Access logging status

- **Network Security**
  - Security group analysis
  - Network ACL review
  - Public IP exposure
  - VPN configuration audit

- **Compute Security**
  - Instance vulnerability assessment
  - OS patch status
  - Disk encryption verification
  - Security group associations

- **Database Security**
  - Public accessibility check
  - Encryption verification
  - Backup configuration
  - Authentication methods

- **Logging & Monitoring**
  - Audit logging status
  - Alert configuration
  - Log retention policies
  - Monitoring coverage

### Output Formats
- **Multiple Formats**: HTML, JSON, CSV, Markdown, Text
- **Interactive Console**: Rich terminal output with color-coding
- **Report Generation**: Detailed security findings with severity levels

## 🛠️ Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/rfs85/redclouds.git
   cd redclouds
   ```

2. **Set Up Virtual Environment**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix or MacOS:
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## ⚙️ Configuration

### Option 1: Environment Variables

#### AWS Configuration
```bash
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
export AWS_DEFAULT_REGION="your_region"
```

#### Azure Configuration
```bash
export AZURE_SUBSCRIPTION_ID="your_subscription_id"
export AZURE_CLIENT_ID="your_client_id"
export AZURE_CLIENT_SECRET="your_client_secret"
export AZURE_TENANT_ID="your_tenant_id"
```

#### GCP Configuration
```bash
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/credentials.json"
```

### Option 2: Configuration File
Create a `config.yaml` file:
```yaml
aws:
  access_key: "your_access_key"
  secret_key: "your_secret_key"
  region: "your_region"

azure:
  subscription_id: "your_subscription_id"
  client_id: "your_client_id"
  client_secret: "your_client_secret"
  tenant_id: "your_tenant_id"

gcp:
  credentials_path: "path/to/your/credentials.json"
  project_id: "your_project_id"
```

### Option 3: Cloud CLI Tools
- AWS: `aws configure`
- Azure: `az login`
- GCP: `gcloud auth application-default login`

## 📖 Usage

### Audit Command
Perform security audits across cloud providers:
```bash
python main.py audit [OPTIONS]

Options:
  --provider [aws|azure|gcp|all]  Cloud provider to audit (required)
  --config PATH                   Config file path (default: config.yaml)
  --format [text|json|csv|markdown|html]  Output format (default: text)
  --output PATH                   Output file path
  --service TEXT                  Specific services to audit (multiple allowed)

Examples:
# Audit AWS with HTML report
python main.py audit --provider aws --format html --output report.html

# Audit specific services
python main.py audit --provider all --service iam --service storage

# Audit Azure with JSON output
python main.py audit --provider azure --format json --output azure-audit.json
```

### Search Command
Discover resources across cloud providers:
```bash
python main.py search [OPTIONS]

Options:
  --provider [aws|azure|gcp|all]  Cloud provider to search (required)
  --domain TEXT                   Domain name to search for
  --company TEXT                  Company name to search for
  --format [text|json|csv|html]   Output format (default: text)
  --output PATH                   Output file path

Examples:
# Search for domain-related resources
python main.py search --provider all --domain example.com --format html

# Search for company resources
python main.py search --provider aws --company "Example Corp"

# Search with specific output
python main.py search --provider all --domain example.com --output results.html
```

## 🔒 Security Best Practices

1. **Credential Management**
   - Use environment variables for CI/CD pipelines
   - Implement role-based access control
   - Rotate credentials regularly

2. **Configuration Security**
   - Never commit `config.yaml` with real credentials
   - Use `.gitignore` to prevent sensitive file commits
   - Implement least-privilege access

3. **Audit Logging**
   - Enable cloud provider audit logging
   - Monitor API calls and access patterns
   - Set up alerts for suspicious activities

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guide
- Add unit tests for new features
- Update documentation
- Maintain backward compatibility

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Submit via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Report security vulnerabilities to security@redclouds.com

## 🙏 Acknowledgments

- Cloud Provider SDKs
  - [Boto3 (AWS)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
  - [Azure SDK for Python](https://azure.github.io/azure-sdk-for-python/)
  - [Google Cloud Python Client](https://googleapis.dev/python/google-api-core/latest/index.html)
- [Click](https://click.palletsprojects.com/) for CLI interface
- [Rich](https://rich.readthedocs.io/) for terminal formatting

## Documentation

- [Contributing Guidelines](docs/CONTRIBUTING.md)
- [Code of Conduct](docs/CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE)
