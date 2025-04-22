"""Container and Kubernetes security checks for RedClouds."""

from typing import Dict, List, Any
from abc import ABC, abstractmethod

class ContainerSecurityCheck(ABC):
    """Base class for container security checks."""
    
    @abstractmethod
    def check(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Run the security check and return results."""
        pass

class KubernetesClusterCheck(ContainerSecurityCheck):
    """Check Kubernetes cluster security configurations."""
    
    def check(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        findings = {
            'status': 'UNKNOWN',
            'details': [],
            'remediation': []
        }
        
        # Check control plane security
        if resource.get('control_plane'):
            findings['details'].append(self._check_control_plane(resource['control_plane']))
            
        # Check node security
        if resource.get('nodes'):
            findings['details'].append(self._check_nodes(resource['nodes']))
            
        # Check network policies
        if resource.get('network_policies'):
            findings['details'].append(self._check_network_policies(resource['network_policies']))
            
        return findings
    
    def _check_control_plane(self, control_plane: Dict) -> Dict:
        """Check control plane security settings."""
        issues = []
        
        # Check API server settings
        if not control_plane.get('rbac_enabled', True):
            issues.append('RBAC is not enabled')
            
        # Check etcd encryption
        if not control_plane.get('etcd_encrypted', False):
            issues.append('etcd encryption is not enabled')
            
        return {
            'component': 'control_plane',
            'issues': issues
        }
    
    def _check_nodes(self, nodes: List[Dict]) -> Dict:
        """Check node security configurations."""
        issues = []
        
        for node in nodes:
            # Check node authorization mode
            if 'Webhook' not in node.get('authorization_mode', []):
                issues.append(f"Node {node['name']} is not using Webhook authorization")
                
            # Check container runtime security
            if not node.get('seccomp_enabled', False):
                issues.append(f"Node {node['name']} does not have seccomp enabled")
                
        return {
            'component': 'nodes',
            'issues': issues
        }
    
    def _check_network_policies(self, policies: List[Dict]) -> Dict:
        """Check network policies configuration."""
        issues = []
        
        # Check default deny policies
        has_default_deny = any(p.get('type') == 'default-deny' for p in policies)
        if not has_default_deny:
            issues.append('No default deny network policy found')
            
        return {
            'component': 'network_policies',
            'issues': issues
        }

class ContainerImageCheck(ContainerSecurityCheck):
    """Check container image security."""
    
    def check(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        findings = {
            'status': 'UNKNOWN',
            'details': [],
            'remediation': []
        }
        
        # Check image scanning results
        if resource.get('scan_results'):
            findings['details'].append(self._check_vulnerabilities(resource['scan_results']))
            
        # Check image configuration
        if resource.get('config'):
            findings['details'].append(self._check_configuration(resource['config']))
            
        return findings
    
    def _check_vulnerabilities(self, scan_results: Dict) -> Dict:
        """Check for vulnerabilities in container images."""
        issues = []
        
        # Check critical vulnerabilities
        critical_vulns = scan_results.get('critical', 0)
        if critical_vulns > 0:
            issues.append(f'Found {critical_vulns} critical vulnerabilities')
            
        # Check high vulnerabilities
        high_vulns = scan_results.get('high', 0)
        if high_vulns > 0:
            issues.append(f'Found {high_vulns} high vulnerabilities')
            
        return {
            'component': 'vulnerabilities',
            'issues': issues
        }
    
    def _check_configuration(self, config: Dict) -> Dict:
        """Check container image configuration."""
        issues = []
        
        # Check root user
        if config.get('user') == 'root':
            issues.append('Container running as root user')
            
        # Check privileged mode
        if config.get('privileged', False):
            issues.append('Container running in privileged mode')
            
        return {
            'component': 'configuration',
            'issues': issues
        } 