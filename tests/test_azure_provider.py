"""Unit tests for Azure cloud provider."""

import unittest
from unittest.mock import patch, MagicMock
from redclouds.cloud_providers.azure import Azure
from redclouds.cloud_providers.base import AuditResult, Severity

class TestAzureProvider(unittest.TestCase):
    """Test cases for Azure provider implementation."""

    def setUp(self):
        """Set up test fixtures."""
        self.credentials = {
            'subscription_id': 'test-sub',
            'client_id': 'test-client',
            'client_secret': 'test-secret'
        }
        self.azure = Azure(credentials=self.credentials, region='eastus')

    @patch('azure.identity.ClientSecretCredential')
    def test_connect_success(self, mock_credential):
        """Test successful Azure connection."""
        mock_credential.return_value = MagicMock()
        self.assertTrue(self.azure.connect())

    @patch('azure.identity.ClientSecretCredential')
    def test_connect_failure(self, mock_credential):
        """Test Azure connection failure."""
        mock_credential.side_effect = Exception("Connection failed")
        self.assertFalse(self.azure.connect())

    @patch('azure.mgmt.subscription.SubscriptionClient')
    def test_validate_credentials_success(self, mock_sub_client):
        """Test successful credentials validation."""
        mock_sub = MagicMock()
        mock_sub.subscription_id = 'test-sub'
        mock_sub.display_name = 'Test Subscription'
        mock_sub_client.return_value.subscriptions.list.return_value = [mock_sub]
        self.assertTrue(self.azure.validate_credentials())

    @patch('azure.mgmt.subscription.SubscriptionClient')
    def test_validate_credentials_failure(self, mock_sub_client):
        """Test credentials validation failure."""
        mock_sub_client.return_value.subscriptions.list.side_effect = Exception("Invalid credentials")
        self.assertFalse(self.azure.validate_credentials())

    def test_discover_tenants(self):
        """Test tenant discovery functionality."""
        tenants = self.azure._discover_tenants()
        self.assertIsInstance(tenants, set)

    def test_discover_storage_accounts(self):
        """Test storage account discovery functionality."""
        storage_accounts = self.azure._discover_storage_accounts()
        self.assertIsInstance(storage_accounts, set)

    @patch('azure.mgmt.storage.StorageManagementClient')
    def test_audit_storage(self, mock_storage_client):
        """Test storage audit functionality."""
        # Mock storage account
        mock_account = MagicMock()
        mock_account.id = '/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/test-storage'
        mock_account.name = 'test-storage'
        mock_account.encryption.services.blob.enabled = True
        
        mock_storage_client.return_value.storage_accounts.list.return_value = [mock_account]
        
        # Run audit
        results = self.azure.audit_storage()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

    @patch('azure.mgmt.network.NetworkManagementClient')
    def test_audit_network(self, mock_network_client):
        """Test network audit functionality."""
        # Mock NSG
        mock_nsg = MagicMock()
        mock_nsg.name = 'test-nsg'
        mock_nsg.security_rules = [{
            'name': 'test-rule',
            'direction': 'Inbound',
            'source_address_prefix': '*',
            'destination_port_range': '22',
            'access': 'Allow'
        }]
        
        mock_network_client.return_value.network_security_groups.list_all.return_value = [mock_nsg]
        
        # Run audit
        results = self.azure.audit_network()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

    @patch('azure.mgmt.compute.ComputeManagementClient')
    def test_audit_compute(self, mock_compute_client):
        """Test compute audit functionality."""
        # Mock VM
        mock_vm = MagicMock()
        mock_vm.name = 'test-vm'
        mock_vm.storage_profile.os_disk.encryption_settings = None
        mock_vm.tags = {}
        
        mock_compute_client.return_value.virtual_machines.list_all.return_value = [mock_vm]
        
        # Run audit
        results = self.azure.audit_compute()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

if __name__ == '__main__':
    unittest.main() 