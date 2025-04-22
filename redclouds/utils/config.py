"""Configuration management utilities."""
import os
import yaml
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    'aws': {
        'regions': ['us-east-1', 'us-west-2'],
        'checks': {
            'iam': {
                'max_access_key_age': 90,
                'require_mfa': True,
            },
            'storage': {
                'block_public_access': True,
                'require_encryption': True,
            },
            'network': {
                'block_public_ports': [22, 3389],
                'require_vpc_flow_logs': True,
            }
        }
    },
    'azure': {
        'regions': ['eastus', 'westus'],
        'checks': {
            'iam': {
                'max_service_principal_age': 365,
                'require_rbac': True,
            },
            'storage': {
                'secure_transfer_required': True,
                'require_encryption': True,
            },
            'network': {
                'deny_internet_inbound': True,
                'require_network_watcher': True,
            }
        }
    },
    'gcp': {
        'regions': ['us-central1', 'us-east1'],
        'checks': {
            'iam': {
                'max_service_account_key_age': 90,
                'require_org_policies': True,
            },
            'storage': {
                'uniform_bucket_level_access': True,
                'require_encryption': True,
            },
            'network': {
                'block_project_wide_ssh': True,
                'require_vpc_flow_logs': True,
            }
        }
    }
}


def load_config(config_path: str = None) -> Dict[str, Any]:
    """Load configuration from file or use defaults.

    Args:
        config_path: Optional path to configuration file

    Returns:
        Dict containing configuration settings
    """
    config = DEFAULT_CONFIG.copy()

    if config_path:
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        # Deep merge user config with defaults
                        _deep_merge(config, user_config)
            else:
                logger.warning(f"Config file not found: {config_path}")
        except Exception as e:
            logger.error(f"Error loading config file: {str(e)}")
            logger.warning("Using default configuration")

    return config


def _deep_merge(base: Dict, update: Dict) -> Dict:
    """Recursively merge two dictionaries.

    Args:
        base: Base dictionary to merge into
        update: Dictionary with updates to apply

    Returns:
        Updated base dictionary
    """
    for key, value in update.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base 