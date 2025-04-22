# Serverless Security Assessment

RedClouds provides comprehensive security assessment capabilities for serverless architectures across major cloud providers. This module helps identify security risks and misconfigurations in serverless functions and their associated resources.

## Features

### Function Security Checks

The `FunctionSecurityCheck` class performs security assessments on serverless functions:

- **IAM Permission Analysis**
  - Least privilege validation
  - Wildcard permission detection
  - Resource-level constraint verification

- **Runtime Configuration**
  - Runtime version validation
  - Timeout settings analysis
  - Environment configuration review

- **Environment Variables**
  - Sensitive data detection
  - Encryption validation
  - Secret management assessment

### API Gateway Security

The `APIGatewayCheck` class analyzes API Gateway configurations:

- **Authentication**
  - Auth mechanism validation
  - API key usage assessment
  - Token-based auth verification

- **API Policies**
  - Rate limiting configuration
  - WAF integration validation
  - Security policy assessment

## Usage

```python
from redclouds.security_checks.serverless_security import FunctionSecurityCheck, APIGatewayCheck

# Initialize the checks
function_check = FunctionSecurityCheck()
api_check = APIGatewayCheck()

# Example function assessment
function_config = {
    'iam_config': {
        'wildcard_actions': False,
        'resource_constraints': True
    },
    'runtime_config': {
        'outdated_runtime': False,
        'timeout': 60
    },
    'environment': {
        'DB_PASSWORD': 'secret123',
        'encryption_enabled': True
    }
}

function_findings = function_check.check(function_config)

# Example API Gateway assessment
api_config = {
    'auth_config': {
        'enabled': True,
        'type': 'jwt'
    },
    'policies': {
        'rate_limiting': True,
        'waf_enabled': True
    }
}

api_findings = api_check.check(api_config)
```

## Cloud Provider Integration

The serverless security module supports major cloud providers:

- **AWS Lambda**
  - Function configuration analysis
  - API Gateway integration
  - IAM role assessment
  - CloudWatch integration

- **Azure Functions**
  - Function app security
  - Managed identity validation
  - APIM security checks
  - Application Insights integration

- **Google Cloud Functions**
  - Function security
  - Cloud Run integration
  - IAM policy validation
  - Cloud Trace integration

## Best Practices

1. **Function Security**
   - Implement least privilege access
   - Use up-to-date runtimes
   - Encrypt environment variables
   - Set appropriate timeouts

2. **API Security**
   - Enable strong authentication
   - Implement rate limiting
   - Use WAF protection
   - Monitor API usage

3. **Secret Management**
   - Use secret management services
   - Rotate credentials regularly
   - Encrypt sensitive data
   - Implement access logging

## Configuration Examples

### Example IAM Policy (AWS)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
    ]
}
```

### Example Function Configuration (Azure)

```json
{
    "bindings": [
        {
            "authLevel": "function",
            "type": "httpTrigger",
            "direction": "in",
            "name": "req",
            "methods": ["post"]
        }
    ],
    "disabled": false,
    "scriptFile": "index.js"
}
```

## Remediation Guidelines

The module provides detailed remediation steps for common issues:

1. **IAM/Permission Issues**
   - Remove wildcard permissions
   - Add resource-level constraints
   - Implement least privilege
   - Regular permission review

2. **API Security Gaps**
   - Enable authentication
   - Configure rate limiting
   - Implement WAF rules
   - Monitor API usage

3. **Environment Security**
   - Use secret management
   - Enable encryption
   - Regular secret rotation
   - Access logging

## Monitoring and Alerting

The module integrates with cloud provider monitoring services:

1. **Metrics Collection**
   - Function invocations
   - Error rates
   - Latency metrics
   - Cold start tracking

2. **Security Alerts**
   - Permission changes
   - Configuration updates
   - Authentication failures
   - Rate limit breaches

3. **Compliance Reporting**
   - Security posture
   - Policy compliance
   - Audit trail
   - Risk assessment 