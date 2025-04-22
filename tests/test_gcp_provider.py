"""Unit tests for GCP cloud provider."""

import unittest
from unittest.mock import patch, MagicMock
from redclouds.cloud_providers.gcp import GCP
from redclouds.cloud_providers.base import AuditResult, Severity

class TestGCPProvider(unittest.TestCase):
    """Test cases for GCP provider implementation."""

    def setUp(self):
        """Set up test fixtures."""
        self.credentials = {
            'project_id': 'test-project',
            'credentials_path': '/path/to/credentials.json'
        }
        self.gcp = GCP(credentials=self.credentials, region='us-central1')

    @patch('google.cloud.storage.Client')
    @patch('google.cloud.compute.ComputeClient')
    def test_connect_success(self, mock_compute, mock_storage):
        """Test successful GCP connection."""
        mock_storage.return_value = MagicMock()
        mock_compute.return_value = MagicMock()
        self.assertTrue(self.gcp.connect())

    @patch('google.cloud.storage.Client')
    def test_connect_failure(self, mock_storage):
        """Test GCP connection failure."""
        mock_storage.side_effect = Exception("Connection failed")
        self.assertFalse(self.gcp.connect())

    @patch('google.cloud.storage.Client')
    def test_validate_credentials_success(self, mock_storage):
        """Test successful credentials validation."""
        mock_storage.return_value = MagicMock()
        self.assertTrue(self.gcp.validate_credentials())

    @patch('google.cloud.storage.Client')
    def test_validate_credentials_failure(self, mock_storage):
        """Test credentials validation failure."""
        mock_storage.side_effect = Exception("Invalid credentials")
        self.assertFalse(self.gcp.validate_credentials())

    @patch('google.cloud.storage.Client')
    def test_audit_storage(self, mock_storage):
        """Test storage audit functionality."""
        # Mock bucket
        mock_bucket = MagicMock()
        mock_bucket.name = 'test-bucket'
        mock_bucket.iam_configuration.uniform_bucket_level_access_enabled = False
        mock_bucket.public_access_prevention = 'inherited'
        
        mock_storage.return_value.list_buckets.return_value = [mock_bucket]
        
        # Run audit
        results = self.gcp.audit_storage()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

    @patch('google.cloud.compute.ComputeClient')
    def test_audit_compute(self, mock_compute):
        """Test compute audit functionality."""
        # Mock instance
        mock_instance = MagicMock()
        mock_instance.name = 'test-instance'
        mock_instance.network_interfaces = [{
            'accessConfigs': [{
                'natIP': '34.123.123.123'
            }]
        }]
        mock_instance.shielded_instance_config = None
        
        mock_compute.return_value.instances.return_value.list.return_value = [mock_instance]
        
        # Run audit
        results = self.gcp.audit_compute()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

    @patch('google.cloud.compute.ComputeClient')
    def test_audit_network(self, mock_compute):
        """Test network audit functionality."""
        # Mock firewall
        mock_firewall = MagicMock()
        mock_firewall.name = 'test-firewall'
        mock_firewall.allowed = [{
            'IPProtocol': 'tcp',
            'ports': ['22']
        }]
        mock_firewall.source_ranges = ['0.0.0.0/0']
        
        mock_compute.return_value.firewalls.return_value.list.return_value = [mock_firewall]
        
        # Run audit
        results = self.gcp.audit_network()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

    @patch('google.cloud.iam.Client')
    def test_audit_iam(self, mock_iam):
        """Test IAM audit functionality."""
        # Mock service account
        mock_sa = MagicMock()
        mock_sa.email = 'test-sa@test-project.iam.gserviceaccount.com'
        mock_sa.disabled = False
        
        mock_iam.return_value.list_service_accounts.return_value = [mock_sa]
        
        # Run audit
        results = self.gcp.audit_iam()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

if __name__ == '__main__':
    unittest.main() 