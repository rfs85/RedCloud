# Container and Kubernetes Security

RedClouds provides comprehensive security assessment capabilities for container and Kubernetes environments. This module helps identify security misconfigurations and vulnerabilities in your containerized workloads.

## Features

### Kubernetes Cluster Security Checks

The `KubernetesClusterCheck` class performs security assessments on Kubernetes clusters:

- **Control Plane Security**
  - RBAC configuration validation
  - etcd encryption status
  - API server security settings

- **Node Security**
  - Node authorization mode verification
  - Container runtime security (seccomp)
  - Node-level security configurations

- **Network Policies**
  - Default deny policy validation
  - Network segmentation assessment
  - Policy completeness checks

### Container Image Security

The `ContainerImageCheck` class analyzes container images for security issues:

- **Vulnerability Scanning**
  - Critical vulnerability detection
  - High-risk vulnerability identification
  - CVE assessment and reporting

- **Configuration Analysis**
  - Root user checks
  - Privileged mode detection
  - Security context validation

## Usage

```python
from redclouds.security_checks.container_security import KubernetesClusterCheck, ContainerImageCheck

# Initialize the checks
k8s_check = KubernetesClusterCheck()
container_check = ContainerImageCheck()

# Example Kubernetes cluster assessment
cluster_config = {
    'control_plane': {
        'rbac_enabled': True,
        'etcd_encrypted': False
    },
    'nodes': [
        {
            'name': 'worker-1',
            'authorization_mode': ['Webhook'],
            'seccomp_enabled': True
        }
    ],
    'network_policies': [
        {'type': 'default-deny'}
    ]
}

cluster_findings = k8s_check.check(cluster_config)

# Example container image assessment
image_config = {
    'scan_results': {
        'critical': 2,
        'high': 5
    },
    'config': {
        'user': 'root',
        'privileged': True
    }
}

image_findings = container_check.check(image_config)
```

## Integration with Cloud Providers

The container security module integrates with major cloud providers' container services:

- **AWS**
  - Amazon EKS security assessment
  - ECR image scanning integration
  - ECS task definition analysis

- **Azure**
  - AKS security validation
  - ACR vulnerability scanning
  - Container instance security checks

- **GCP**
  - GKE security assessment
  - Container Registry scanning
  - Cloud Run security validation

## Best Practices

1. **Cluster Security**
   - Enable RBAC for access control
   - Implement network policies
   - Use node authorization
   - Enable etcd encryption

2. **Container Security**
   - Avoid running as root
   - Disable privileged mode
   - Implement vulnerability scanning
   - Use minimal base images

3. **Network Security**
   - Implement default deny policies
   - Use network segmentation
   - Enable encryption in transit
   - Monitor network traffic

## Configuration Examples

### Example Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### Example Security Context

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

## Remediation Guidelines

The module provides detailed remediation steps for common issues:

1. **RBAC Issues**
   - Enable RBAC in cluster configuration
   - Review and update role bindings
   - Implement least privilege access

2. **Container Vulnerabilities**
   - Update base images regularly
   - Patch known vulnerabilities
   - Implement continuous scanning

3. **Network Policy Gaps**
   - Implement default deny policies
   - Define explicit allow rules
   - Regular policy review and updates 