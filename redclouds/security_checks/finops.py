"""FinOps integration module for RedClouds."""

from typing import Dict, List, Any
from abc import ABC, abstractmethod

class FinOpsCheck(ABC):
    """Base class for FinOps checks."""
    
    @abstractmethod
    def check(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Run the security check and return results."""
        pass

class CostOptimizationCheck(FinOpsCheck):
    """Check cost optimization and security alignment."""
    
    def check(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        findings = {
            'status': 'UNKNOWN',
            'details': [],
            'remediation': []
        }
        
        # Check resource utilization
        if resource.get('utilization_metrics'):
            findings['details'].append(self._check_resource_utilization(resource['utilization_metrics']))
            
        # Check cost allocation
        if resource.get('cost_config'):
            findings['details'].append(self._check_cost_allocation(resource['cost_config']))
            
        # Check security spending
        if resource.get('security_spend'):
            findings['details'].append(self._check_security_spending(resource['security_spend']))
            
        return findings
    
    def _check_resource_utilization(self, metrics: Dict) -> Dict:
        """Check resource utilization patterns."""
        issues = []
        
        # Check underutilization
        if metrics.get('utilization', 0) < 0.4:  # 40% threshold
            issues.append('Resource significantly underutilized')
            
        # Check overprovisioning
        if metrics.get('overprovisioned', False):
            issues.append('Resource may be overprovisioned')
            
        return {
            'component': 'resource_utilization',
            'issues': issues,
            'cost_impact': metrics.get('cost_impact', 'unknown')
        }
    
    def _check_cost_allocation(self, cost_config: Dict) -> Dict:
        """Check cost allocation and tagging."""
        issues = []
        
        # Check tagging compliance
        if not cost_config.get('tagging_compliant', False):
            issues.append('Resource not compliant with tagging policies')
            
        # Check budget alerts
        if not cost_config.get('budget_alerts', False):
            issues.append('Budget alerts not configured')
            
        return {
            'component': 'cost_allocation',
            'issues': issues,
            'monthly_cost': cost_config.get('monthly_cost', 'unknown')
        }
    
    def _check_security_spending(self, security_spend: Dict) -> Dict:
        """Check security-related spending."""
        issues = []
        
        # Check security tool utilization
        if security_spend.get('unused_tools', False):
            issues.append('Unused security tools detected')
            
        # Check cost effectiveness
        if not security_spend.get('cost_effective', True):
            issues.append('Security spending may not be cost-effective')
            
        return {
            'component': 'security_spending',
            'issues': issues,
            'optimization_potential': security_spend.get('optimization_potential', 'unknown')
        }

class ComplianceSpendingCheck(FinOpsCheck):
    """Check compliance-related spending and optimization."""
    
    def check(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        findings = {
            'status': 'UNKNOWN',
            'details': [],
            'remediation': []
        }
        
        # Check compliance costs
        if resource.get('compliance_costs'):
            findings['details'].append(self._check_compliance_costs(resource['compliance_costs']))
            
        # Check audit requirements
        if resource.get('audit_config'):
            findings['details'].append(self._check_audit_requirements(resource['audit_config']))
            
        return findings
    
    def _check_compliance_costs(self, costs: Dict) -> Dict:
        """Check compliance-related costs."""
        issues = []
        
        # Check cost distribution
        if costs.get('uneven_distribution', False):
            issues.append('Uneven distribution of compliance costs')
            
        # Check redundant controls
        if costs.get('redundant_controls', False):
            issues.append('Redundant compliance controls detected')
            
        return {
            'component': 'compliance_costs',
            'issues': issues,
            'annual_cost': costs.get('annual_cost', 'unknown')
        }
    
    def _check_audit_requirements(self, audit_config: Dict) -> Dict:
        """Check audit requirement costs."""
        issues = []
        
        # Check audit tool efficiency
        if not audit_config.get('efficient_tooling', True):
            issues.append('Audit tooling may not be cost-efficient')
            
        # Check automation level
        if audit_config.get('automation_level', 0) < 0.6:  # 60% threshold
            issues.append('Low automation level in audit processes')
            
        return {
            'component': 'audit_requirements',
            'issues': issues,
            'automation_savings': audit_config.get('automation_savings', 'unknown')
        } 