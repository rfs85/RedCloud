"""Unit tests for AWS cloud provider."""

import unittest
from unittest.mock import patch, MagicMock
from redclouds.cloud_providers.aws import AWS
from redclouds.cloud_providers.base import AuditResult, Severity

class TestAWSProvider(unittest.TestCase):
    """Test cases for AWS provider implementation."""

    def setUp(self):
        """Set up test fixtures."""
        self.aws = AWS(
            access_key="test_key",
            secret_key="test_secret",
            region="us-east-1"
        )

    @patch('boto3.Session')
    def test_connect_success(self, mock_session):
        """Test successful AWS connection."""
        mock_session.return_value.get_available_regions.return_value = ['us-east-1']
        self.assertTrue(self.aws.connect())

    @patch('boto3.Session')
    def test_connect_failure(self, mock_session):
        """Test AWS connection failure."""
        mock_session.side_effect = Exception("Connection failed")
        self.assertFalse(self.aws.connect())

    @patch('boto3.Session')
    def test_validate_credentials_success(self, mock_session):
        """Test successful credentials validation."""
        mock_sts = MagicMock()
        mock_session.return_value.client.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        self.assertTrue(self.aws.validate_credentials())

    @patch('boto3.Session')
    def test_validate_credentials_failure(self, mock_session):
        """Test credentials validation failure."""
        mock_sts = MagicMock()
        mock_session.return_value.client.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = Exception("Invalid credentials")
        self.assertFalse(self.aws.validate_credentials())

    @patch('boto3.Session')
    def test_audit_iam(self, mock_session):
        """Test IAM audit functionality."""
        # Mock IAM client
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam
        
        # Mock IAM responses
        mock_iam.get_account_password_policy.return_value = {
            'PasswordPolicy': {
                'MinimumPasswordLength': 8,
                'RequireSymbols': True,
                'RequireNumbers': True,
                'RequireUppercaseCharacters': True,
                'RequireLowercaseCharacters': True,
                'AllowUsersToChangePassword': True,
                'MaxPasswordAge': 90,
                'PasswordReusePrevention': 24
            }
        }
        
        mock_iam.list_users.return_value = {
            'Users': [{
                'UserName': 'test_user',
                'PasswordLastUsed': '2023-01-01 00:00:00',
                'CreateDate': '2023-01-01 00:00:00'
            }]
        }
        
        # Run audit
        results = self.aws.audit_iam()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

    @patch('boto3.Session')
    def test_audit_storage(self, mock_session):
        """Test storage audit functionality."""
        # Mock S3 client
        mock_s3 = MagicMock()
        mock_session.return_value.client.return_value = mock_s3
        
        # Mock S3 responses
        mock_s3.list_buckets.return_value = {
            'Buckets': [{
                'Name': 'test-bucket',
                'CreationDate': '2023-01-01 00:00:00'
            }]
        }
        
        mock_s3.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        }
        
        # Run audit
        results = self.aws.audit_storage()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

    @patch('boto3.Session')
    def test_audit_network(self, mock_session):
        """Test network audit functionality."""
        # Mock EC2 client
        mock_ec2 = MagicMock()
        mock_session.return_value.client.return_value = mock_ec2
        
        # Mock EC2 responses
        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [{
                'GroupId': 'sg-123',
                'GroupName': 'test-sg',
                'IpPermissions': [{
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            }]
        }
        
        # Run audit
        results = self.aws.audit_network()
        
        # Verify results
        self.assertIsInstance(results, list)
        self.assertTrue(all(isinstance(r, AuditResult) for r in results))

if __name__ == '__main__':
    unittest.main() 