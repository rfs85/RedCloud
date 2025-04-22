"""Credential management utilities."""
import os
import json
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


def get_credentials(provider: str) -> Optional[Dict[str, str]]:
    """Get credentials for the specified cloud provider.

    Args:
        provider: Cloud provider name (aws, azure, gcp)

    Returns:
        Dictionary containing provider credentials or None if not found
    """
    provider = provider.lower()
    credentials = {}

    try:
        if provider == 'aws':
            credentials = _get_aws_credentials()
        elif provider == 'azure':
            credentials = _get_azure_credentials()
        elif provider == 'gcp':
            credentials = _get_gcp_credentials()
        else:
            logger.error(f"Unsupported provider: {provider}")
            return None

        return credentials if credentials else None

    except Exception as e:
        logger.error(f"Error getting credentials for {provider}: {str(e)}")
        return None


def _get_aws_credentials() -> Dict[str, str]:
    """Get AWS credentials from environment variables or AWS CLI config."""
    credentials = {}

    # Try environment variables first
    access_key = os.getenv('AWS_ACCESS_KEY_ID')
    secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    session_token = os.getenv('AWS_SESSION_TOKEN')
    region = os.getenv('AWS_DEFAULT_REGION')

    if access_key and secret_key:
        credentials['aws_access_key_id'] = access_key
        credentials['aws_secret_access_key'] = secret_key
        if session_token:
            credentials['aws_session_token'] = session_token
        if region:
            credentials['region'] = region
        return credentials

    # Try AWS CLI config
    try:
        import boto3
        session = boto3.Session()
        creds = session.get_credentials()
        if creds:
            credentials['aws_access_key_id'] = creds.access_key
            credentials['aws_secret_access_key'] = creds.secret_key
            if creds.token:
                credentials['aws_session_token'] = creds.token
            if session.region_name:
                credentials['region'] = session.region_name
    except Exception as e:
        logger.debug(f"Error loading AWS CLI credentials: {str(e)}")

    return credentials


def _get_azure_credentials() -> Dict[str, str]:
    """Get Azure credentials from environment variables or Azure CLI."""
    credentials = {}

    # Try environment variables first
    subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
    client_id = os.getenv('AZURE_CLIENT_ID')
    client_secret = os.getenv('AZURE_CLIENT_SECRET')
    tenant_id = os.getenv('AZURE_TENANT_ID')

    if all([subscription_id, client_id, client_secret, tenant_id]):
        credentials['subscription_id'] = subscription_id
        credentials['client_id'] = client_id
        credentials['client_secret'] = client_secret
        credentials['tenant_id'] = tenant_id
        return credentials

    # Try Azure CLI credentials
    try:
        from azure.identity import AzureCliCredential
        from azure.mgmt.subscription import SubscriptionClient
        
        credential = AzureCliCredential()
        subscription_client = SubscriptionClient(credential)
        subscriptions = list(subscription_client.subscriptions.list())
        
        if subscriptions:
            credentials['subscription_id'] = subscriptions[0].subscription_id
            credentials['credential'] = credential
    except Exception as e:
        logger.debug(f"Error loading Azure CLI credentials: {str(e)}")

    return credentials


def _get_gcp_credentials() -> Dict[str, str]:
    """Get GCP credentials from environment variables or application default credentials."""
    credentials = {}

    # Try environment variable for service account key file
    credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
    if credentials_path and os.path.exists(credentials_path):
        try:
            with open(credentials_path, 'r') as f:
                creds_data = json.load(f)
                credentials['type'] = creds_data.get('type')
                credentials['project_id'] = creds_data.get('project_id')
                credentials['private_key_id'] = creds_data.get('private_key_id')
                credentials['client_email'] = creds_data.get('client_email')
                return credentials
        except Exception as e:
            logger.debug(f"Error loading GCP service account key: {str(e)}")

    # Try application default credentials
    try:
        from google.oauth2 import service_account
        from google.auth import default

        credentials, project_id = default()
        if credentials and project_id:
            if isinstance(credentials, service_account.Credentials):
                credentials['type'] = 'service_account'
                credentials['project_id'] = project_id
                credentials['client_email'] = credentials.service_account_email
            else:
                credentials['type'] = 'authorized_user'
                credentials['project_id'] = project_id
    except Exception as e:
        logger.debug(f"Error loading GCP application default credentials: {str(e)}")

    return credentials 