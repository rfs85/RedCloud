"""Serverless security assessment module for RedClouds."""

from typing import Dict, List, Any
from abc import ABC, abstractmethod

class ServerlessSecurityCheck(ABC):
    """Base class for serverless security checks."""
    
    @abstractmethod
    def check(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Run the security check and return results."""
        pass

class FunctionSecurityCheck(ServerlessSecurityCheck):
    """Check serverless function security configurations."""
    
    def check(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        findings = {
            'status': 'UNKNOWN',
            'details': [],
            'remediation': []
        }
        
        # Check IAM permissions
        if resource.get('iam_config'):
            findings['details'].append(self._check_iam_permissions(resource['iam_config']))
            
        # Check runtime configuration
        if resource.get('runtime_config'):
            findings['details'].append(self._check_runtime_config(resource['runtime_config']))
            
        # Check environment variables
        if resource.get('environment'):
            findings['details'].append(self._check_environment_variables(resource['environment']))
            
        return findings
    
    def _check_iam_permissions(self, iam_config: Dict) -> Dict:
        """Check IAM permissions for least privilege."""
        issues = []
        
        # Check for overly permissive roles
        if iam_config.get('wildcard_actions', False):
            issues.append('Function has wildcard (*) permissions in IAM role')
            
        # Check resource-level permissions
        if not iam_config.get('resource_constraints', True):
            issues.append('IAM role lacks resource-level constraints')
            
        return {
            'component': 'iam_permissions',
            'issues': issues
        }
    
    def _check_runtime_config(self, runtime_config: Dict) -> Dict:
        """Check runtime security settings."""
        issues = []
        
        # Check runtime version
        if runtime_config.get('outdated_runtime', False):
            issues.append('Function using outdated runtime version')
            
        # Check timeout settings
        if runtime_config.get('timeout', 0) > 300:  # 5 minutes
            issues.append('Function timeout exceeds recommended maximum')
            
        return {
            'component': 'runtime_config',
            'issues': issues
        }
    
    def _check_environment_variables(self, environment: Dict) -> Dict:
        """Check environment variable security."""
        issues = []
        
        # Check for sensitive data
        for key in environment.keys():
            if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'key', 'token']):
                issues.append(f'Potentially sensitive data in environment variable: {key}')
                
        # Check encryption
        if not environment.get('encryption_enabled', False):
            issues.append('Environment variables are not encrypted at rest')
            
        return {
            'component': 'environment_variables',
            'issues': issues
        }

class APIGatewayCheck(ServerlessSecurityCheck):
    """Check API Gateway security configurations."""
    
    def check(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        findings = {
            'status': 'UNKNOWN',
            'details': [],
            'remediation': []
        }
        
        # Check authentication
        if resource.get('auth_config'):
            findings['details'].append(self._check_authentication(resource['auth_config']))
            
        # Check API policies
        if resource.get('policies'):
            findings['details'].append(self._check_policies(resource['policies']))
            
        return findings
    
    def _check_authentication(self, auth_config: Dict) -> Dict:
        """Check API authentication settings."""
        issues = []
        
        # Check if authentication is enabled
        if not auth_config.get('enabled', False):
            issues.append('API endpoint lacks authentication')
            
        # Check auth type
        auth_type = auth_config.get('type')
        if auth_type == 'none':
            issues.append('No authentication mechanism configured')
        elif auth_type == 'api_key':
            issues.append('Using basic API key authentication - consider using stronger auth')
            
        return {
            'component': 'authentication',
            'issues': issues
        }
    
    def _check_policies(self, policies: Dict) -> Dict:
        """Check API Gateway policies."""
        issues = []
        
        # Check rate limiting
        if not policies.get('rate_limiting', False):
            issues.append('Rate limiting not enabled')
            
        # Check WAF integration
        if not policies.get('waf_enabled', False):
            issues.append('WAF integration not enabled')
            
        return {
            'component': 'policies',
            'issues': issues
        } 