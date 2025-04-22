"""Custom policy engine module for RedClouds."""

from typing import Dict, List, Any, Callable
from abc import ABC, abstractmethod
import yaml
import re

class PolicyRule:
    """Represents a single policy rule."""
    
    def __init__(self, name: str, description: str, severity: str,
                 condition: Callable[[Dict[str, Any]], bool],
                 remediation: str):
        self.name = name
        self.description = description
        self.severity = severity
        self.condition = condition
        self.remediation = remediation

class PolicySet:
    """A collection of policy rules."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.rules: List[PolicyRule] = []
    
    def add_rule(self, rule: PolicyRule):
        """Add a rule to the policy set."""
        self.rules.append(rule)
    
    def evaluate(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate all rules against a resource."""
        results = {
            'policy_set': self.name,
            'description': self.description,
            'findings': []
        }
        
        for rule in self.rules:
            try:
                compliant = rule.condition(resource)
                finding = {
                    'rule_name': rule.name,
                    'description': rule.description,
                    'severity': rule.severity,
                    'status': 'PASS' if compliant else 'FAIL',
                    'remediation': rule.remediation if not compliant else None
                }
                results['findings'].append(finding)
            except Exception as e:
                results['findings'].append({
                    'rule_name': rule.name,
                    'description': rule.description,
                    'severity': rule.severity,
                    'status': 'ERROR',
                    'error': str(e)
                })
        
        return results

class PolicyEngine:
    """Main policy engine that manages and evaluates policy sets."""
    
    def __init__(self):
        self.policy_sets: Dict[str, PolicySet] = {}
    
    def load_policy_set(self, yaml_content: str) -> None:
        """Load a policy set from YAML configuration."""
        try:
            config = yaml.safe_load(yaml_content)
            policy_set = PolicySet(
                name=config['name'],
                description=config['description']
            )
            
            for rule_config in config['rules']:
                rule = self._create_rule_from_config(rule_config)
                policy_set.add_rule(rule)
            
            self.policy_sets[policy_set.name] = policy_set
            
        except Exception as e:
            raise ValueError(f"Failed to load policy set: {str(e)}")
    
    def _create_rule_from_config(self, rule_config: Dict) -> PolicyRule:
        """Create a PolicyRule from configuration."""
        condition = self._build_condition(rule_config['condition'])
        
        return PolicyRule(
            name=rule_config['name'],
            description=rule_config['description'],
            severity=rule_config['severity'],
            condition=condition,
            remediation=rule_config['remediation']
        )
    
    def _build_condition(self, condition_config: Dict) -> Callable[[Dict[str, Any]], bool]:
        """Build a condition function from configuration."""
        operator = condition_config['operator']
        
        if operator == 'exists':
            path = condition_config['path']
            return lambda resource: self._get_value(resource, path) is not None
            
        elif operator == 'equals':
            path = condition_config['path']
            value = condition_config['value']
            return lambda resource: self._get_value(resource, path) == value
            
        elif operator == 'not_equals':
            path = condition_config['path']
            value = condition_config['value']
            return lambda resource: self._get_value(resource, path) != value
            
        elif operator == 'regex_match':
            path = condition_config['path']
            pattern = re.compile(condition_config['pattern'])
            return lambda resource: bool(pattern.match(str(self._get_value(resource, path))))
            
        elif operator == 'greater_than':
            path = condition_config['path']
            value = condition_config['value']
            return lambda resource: self._get_value(resource, path) > value
            
        elif operator == 'less_than':
            path = condition_config['path']
            value = condition_config['value']
            return lambda resource: self._get_value(resource, path) < value
            
        elif operator == 'in_list':
            path = condition_config['path']
            values = condition_config['values']
            return lambda resource: self._get_value(resource, path) in values
            
        elif operator == 'all':
            conditions = [self._build_condition(c) for c in condition_config['conditions']]
            return lambda resource: all(c(resource) for c in conditions)
            
        elif operator == 'any':
            conditions = [self._build_condition(c) for c in condition_config['conditions']]
            return lambda resource: any(c(resource) for c in conditions)
            
        else:
            raise ValueError(f"Unsupported operator: {operator}")
    
    def _get_value(self, resource: Dict[str, Any], path: str) -> Any:
        """Get a value from a resource using dot notation path."""
        current = resource
        for part in path.split('.'):
            if isinstance(current, dict):
                if part not in current:
                    return None
                current = current[part]
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (IndexError, ValueError):
                    return None
            else:
                return None
        return current
    
    def evaluate_resource(self, resource: Dict[str, Any], policy_set_name: str = None) -> List[Dict[str, Any]]:
        """Evaluate a resource against specified or all policy sets."""
        results = []
        
        if policy_set_name:
            if policy_set_name not in self.policy_sets:
                raise ValueError(f"Policy set not found: {policy_set_name}")
            results.append(self.policy_sets[policy_set_name].evaluate(resource))
        else:
            for policy_set in self.policy_sets.values():
                results.append(policy_set.evaluate(resource))
        
        return results

# Example usage:
"""
# Example policy set YAML:
name: custom_security_policy
description: Custom security policy for cloud resources
rules:
  - name: require_encryption
    description: Ensure resource encryption is enabled
    severity: HIGH
    condition:
      operator: equals
      path: encryption.enabled
      value: true
    remediation: Enable encryption for the resource
  
  - name: check_access_logging
    description: Ensure access logging is enabled
    severity: MEDIUM
    condition:
      operator: all
      conditions:
        - operator: exists
          path: logging.enabled
        - operator: equals
          path: logging.retention_days
          value: 90
    remediation: Enable access logging with 90 days retention

# Usage:
engine = PolicyEngine()
engine.load_policy_set(yaml_content)
results = engine.evaluate_resource(resource_data, 'custom_security_policy')
""" 