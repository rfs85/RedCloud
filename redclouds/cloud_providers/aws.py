"""AWS cloud provider implementation."""
import boto3
from typing import Dict, List, Optional
from botocore.exceptions import ClientError
import logging
import requests

from .base import CloudProvider, AuditResult, ResourceType, Severity

logger = logging.getLogger(__name__)


class AWS(CloudProvider):
    """AWS cloud provider implementation."""

    def __init__(self, access_key: Optional[str] = None, secret_key: Optional[str] = None, region: Optional[str] = None):
        """Initialize AWS provider.

        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            region: Optional AWS region
        """
        super().__init__("aws")
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.session = None
        self._clients = {}

    def connect(self) -> bool:
        """Establish connection to AWS."""
        try:
            self.session = boto3.Session(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region or 'us-east-1'  # Default to us-east-1 if no region specified
            )
            # Only test connection if we have credentials
            if self.access_key and self.secret_key:
                self.get_regions()
            return True
        except Exception as e:
            # Don't log connection errors as they're expected in unauthenticated mode
            return False

    def validate_credentials(self) -> bool:
        """Validate AWS credentials."""
        try:
            sts = self._get_client('sts')
            sts.get_caller_identity()
            return True
        except Exception as e:
            logger.error(f"Invalid AWS credentials: {str(e)}")
            return False

    def get_regions(self) -> List[str]:
        """Get list of available AWS regions."""
        try:
            ec2 = self._get_client('ec2')
            regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
            return regions
        except Exception as e:
            logger.error(f"Failed to get AWS regions: {str(e)}")
            return []

    def _get_client(self, service: str):
        """Get or create a boto3 client for the specified service."""
        if service not in self._clients:
            self._clients[service] = self.session.client(service)
        return self._clients[service]

    def audit_iam(self) -> List[AuditResult]:
        """Audit IAM configurations."""
        results = []
        iam = self._get_client('iam')

        try:
            # Check password policy
            try:
                policy = iam.get_account_password_policy()
                if not policy['PasswordPolicy'].get('RequireMFA', False):
                    results.append(AuditResult(
                        provider="aws",
                        service="iam",
                        check_id='AWS_IAM_1',
                        resource_id='aws/account/password-policy',
                        region=self.region or 'global',
                        status='FAIL',
                        severity=Severity.HIGH,
                        message='MFA not required in password policy',
                        resource_type=ResourceType.IAM,
                        details={'current_setting': 'MFA not required'}
                    ))
            except ClientError:
                results.append(AuditResult(
                    provider="aws",
                    service="iam",
                    check_id='AWS_IAM_1',
                    resource_id='aws/account/password-policy',
                    region=self.region or 'global',
                    status='FAIL',
                    severity=Severity.HIGH,
                    message='No password policy configured',
                    resource_type=ResourceType.IAM,
                    details={'error': 'No password policy set'}
                ))

            # Check IAM users
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    # Check access keys age
                    keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                    for key in keys:
                        key_age = (boto3.utils.datetime_now() - key['CreateDate']).days
                        if key_age > 90:
                            results.append(AuditResult(
                                provider="aws",
                                service="iam",
                                check_id='AWS_IAM_2',
                                resource_id=f"aws/iam/user/{user['UserName']}/key/{key['AccessKeyId']}",
                                region=self.region or 'global',
                                status='FAIL',
                                severity=Severity.MEDIUM,
                                message=f'Access key is {key_age} days old',
                                resource_type=ResourceType.IAM,
                                details={'key_age_days': key_age}
                            ))

                    # Check MFA status
                    mfa = iam.list_mfa_devices(UserName=user['UserName'])
                    if not mfa['MFADevices']:
                        results.append(AuditResult(
                            provider="aws",
                            service="iam",
                            check_id='AWS_IAM_3',
                            resource_id=f"aws/iam/user/{user['UserName']}",
                            region=self.region or 'global',
                            status='FAIL',
                            severity=Severity.HIGH,
                            message='MFA not enabled for user',
                            resource_type=ResourceType.IAM,
                            details={'mfa_enabled': False}
                        ))

        except Exception as e:
            logger.error(f"Error during IAM audit: {str(e)}")

        return results

    def audit_storage(self) -> List[AuditResult]:
        """Audit storage configurations."""
        results = []
        s3 = self._get_client('s3')

        try:
            # List all buckets
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']

                try:
                    # Check bucket encryption
                    try:
                        s3.get_bucket_encryption(Bucket=bucket_name)
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                            results.append(AuditResult(
                                provider="aws",
                                service="s3",
                                check_id='AWS_S3_1',
                                resource_id=f"aws/s3/{bucket_name}",
                                region=self.region or 'global',
                                status='FAIL',
                                severity=Severity.HIGH,
                                message='Default encryption not enabled',
                                resource_type=ResourceType.STORAGE,
                                details={'encryption': 'disabled'}
                            ))

                    # Check public access
                    try:
                        public_access = s3.get_public_access_block(Bucket=bucket_name)
                        block_config = public_access['PublicAccessBlockConfiguration']
                        if not all(block_config.values()):
                            results.append(AuditResult(
                                provider="aws",
                                service="s3",
                                check_id='AWS_S3_2',
                                resource_id=f"aws/s3/{bucket_name}",
                                region=self.region or 'global',
                                status='FAIL',
                                severity=Severity.HIGH,
                                message='Public access block settings not fully enabled',
                                resource_type=ResourceType.STORAGE,
                                details={'public_access_config': block_config}
                            ))
                    except ClientError:
                        results.append(AuditResult(
                            provider="aws",
                            service="s3",
                            check_id='AWS_S3_2',
                            resource_id=f"aws/s3/{bucket_name}",
                            region=self.region or 'global',
                            status='FAIL',
                            severity=Severity.HIGH,
                            message='Public access block not configured',
                            resource_type=ResourceType.STORAGE,
                            details={'public_access': 'not configured'}
                        ))

                    # Check bucket versioning
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if 'Status' not in versioning or versioning['Status'] != 'Enabled':
                        results.append(AuditResult(
                            provider="aws",
                            service="s3",
                            check_id='AWS_S3_3',
                            resource_id=f"aws/s3/{bucket_name}",
                            region=self.region or 'global',
                            status='FAIL',
                            severity=Severity.MEDIUM,
                            message='Versioning not enabled',
                            resource_type=ResourceType.STORAGE,
                            details={'versioning': 'disabled'}
                        ))

                except Exception as e:
                    logger.error(f"Error checking bucket {bucket_name}: {str(e)}")

        except Exception as e:
            logger.error(f"Error during storage audit: {str(e)}")

        return results

    def audit_network(self) -> List[AuditResult]:
        """Audit network configurations."""
        results = []
        ec2 = self._get_client('ec2')

        try:
            # Check security groups
            security_groups = ec2.describe_security_groups()['SecurityGroups']
            for sg in security_groups:
                # Check inbound rules
                for rule in sg['IpPermissions']:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port = rule.get('FromPort', 'all')
                            results.append(AuditResult(
                                provider="aws",
                                service="ec2",
                                check_id='AWS_NET_1',
                                resource_id=f"aws/ec2/sg/{sg['GroupId']}",
                                region=self.region or 'global',
                                status='FAIL',
                                severity=Severity.HIGH,
                                message=f'Security group allows inbound access from 0.0.0.0/0 on port {port}',
                                resource_type=ResourceType.NETWORK,
                                details={
                                    'security_group': sg['GroupId'],
                                    'port': port,
                                    'cidr': '0.0.0.0/0'
                                }
                            ))

            # Check VPC flow logs
            vpcs = ec2.describe_vpcs()['Vpcs']
            for vpc in vpcs:
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc['VpcId']]}]
                )['FlowLogs']
                
                if not flow_logs:
                    results.append(AuditResult(
                        provider="aws",
                        service="ec2",
                        check_id='AWS_NET_2',
                        resource_id=f"aws/ec2/vpc/{vpc['VpcId']}",
                        region=self.region or 'global',
                        status='FAIL',
                        severity=Severity.MEDIUM,
                        message='VPC flow logs not enabled',
                        resource_type=ResourceType.NETWORK,
                        details={'vpc_id': vpc['VpcId']}
                    ))

        except Exception as e:
            logger.error(f"Error during network audit: {str(e)}")

        return results

    def audit_compute(self) -> List[AuditResult]:
        """Audit compute configurations."""
        results = []
        ec2 = self._get_client('ec2')

        try:
            # Check EC2 instances
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    # Check for public IP
                    if instance.get('PublicIpAddress'):
                        results.append(AuditResult(
                            provider="aws",
                            service="ec2",
                            check_id='AWS_EC2_1',
                            resource_id=f"aws/ec2/instance/{instance['InstanceId']}",
                            region=self.region or 'global',
                            status='FAIL',
                            severity=Severity.HIGH,
                            message='Instance has public IP address',
                            resource_type=ResourceType.COMPUTE,
                            details={
                                'instance_id': instance['InstanceId'],
                                'public_ip': instance['PublicIpAddress']
                            }
                        ))

                    # Check EBS volume encryption
                    for volume in instance.get('BlockDeviceMappings', []):
                        if 'Ebs' in volume and not volume['Ebs'].get('Encrypted', False):
                            results.append(AuditResult(
                                provider="aws",
                                service="ec2",
                                check_id='AWS_EC2_2',
                                resource_id=f"aws/ec2/volume/{volume['Ebs']['VolumeId']}",
                                region=self.region or 'global',
                                status='FAIL',
                                severity=Severity.HIGH,
                                message='EBS volume not encrypted',
                                resource_type=ResourceType.COMPUTE,
                                details={
                                    'volume_id': volume['Ebs']['VolumeId'],
                                    'instance_id': instance['InstanceId']
                                }
                            ))

        except Exception as e:
            logger.error(f"Error during compute audit: {str(e)}")

        return results

    def audit_database(self) -> List[AuditResult]:
        """Audit database configurations."""
        results = []
        rds = self._get_client('rds')

        try:
            # Check RDS instances
            instances = rds.describe_db_instances()
            for instance in instances['DBInstances']:
                # Check public accessibility
                if instance['PubliclyAccessible']:
                    results.append(AuditResult(
                        provider="aws",
                        service="rds",
                        check_id='AWS_RDS_1',
                        resource_id=f"aws/rds/{instance['DBInstanceIdentifier']}",
                        region=self.region or 'global',
                        status='FAIL',
                        severity=Severity.HIGH,
                        message='RDS instance is publicly accessible',
                        resource_type=ResourceType.DATABASE,
                        details={'instance_id': instance['DBInstanceIdentifier']}
                    ))

                # Check encryption
                if not instance.get('StorageEncrypted', False):
                    results.append(AuditResult(
                        provider="aws",
                        service="rds",
                        check_id='AWS_RDS_2',
                        resource_id=f"aws/rds/{instance['DBInstanceIdentifier']}",
                        region=self.region or 'global',
                        status='FAIL',
                        severity=Severity.HIGH,
                        message='RDS storage not encrypted',
                        resource_type=ResourceType.DATABASE,
                        details={'instance_id': instance['DBInstanceIdentifier']}
                    ))

                # Check backup retention
                if instance['BackupRetentionPeriod'] < 7:
                    results.append(AuditResult(
                        provider="aws",
                        service="rds",
                        check_id='AWS_RDS_3',
                        resource_id=f"aws/rds/{instance['DBInstanceIdentifier']}",
                        region=self.region or 'global',
                        status='FAIL',
                        severity=Severity.MEDIUM,
                        message=f'Backup retention period is only {instance["BackupRetentionPeriod"]} days',
                        resource_type=ResourceType.DATABASE,
                        details={
                            'instance_id': instance['DBInstanceIdentifier'],
                            'retention_days': instance['BackupRetentionPeriod']
                        }
                    ))

        except Exception as e:
            logger.error(f"Error during database audit: {str(e)}")

        return results

    def audit_logging(self) -> List[AuditResult]:
        """Audit logging configurations."""
        results = []
        cloudtrail = self._get_client('cloudtrail')

        try:
            # Check CloudTrail trails
            trails = cloudtrail.describe_trails()
            if not trails['trailList']:
                results.append(AuditResult(
                    provider="aws",
                    service="cloudtrail",
                    check_id='AWS_LOG_1',
                    resource_id='aws/cloudtrail',
                    region=self.region or 'global',
                    status='FAIL',
                    severity=Severity.HIGH,
                    message='No CloudTrail trails configured',
                    resource_type=ResourceType.LOGGING,
                    details={'trails': 0}
                ))
            else:
                for trail in trails['trailList']:
                    # Check if trail is enabled
                    status = cloudtrail.get_trail_status(Name=trail['Name'])
                    if not status['IsLogging']:
                        results.append(AuditResult(
                            provider="aws",
                            service="cloudtrail",
                            check_id='AWS_LOG_2',
                            resource_id=f"aws/cloudtrail/{trail['Name']}",
                            region=self.region or 'global',
                            status='FAIL',
                            severity=Severity.HIGH,
                            message='CloudTrail logging is disabled',
                            resource_type=ResourceType.LOGGING,
                            details={'trail_name': trail['Name']}
                        ))

                    # Check log file validation
                    if not trail.get('LogFileValidationEnabled', False):
                        results.append(AuditResult(
                            provider="aws",
                            service="cloudtrail",
                            check_id='AWS_LOG_3',
                            resource_id=f"aws/cloudtrail/{trail['Name']}",
                            region=self.region or 'global',
                            status='FAIL',
                            severity=Severity.MEDIUM,
                            message='CloudTrail log file validation not enabled',
                            resource_type=ResourceType.LOGGING,
                            details={'trail_name': trail['Name']}
                        ))

        except Exception as e:
            logger.error(f"Error during logging audit: {str(e)}")

        return results

    def audit_monitoring(self) -> List[AuditResult]:
        """Audit monitoring configurations."""
        results = []
        cloudwatch = self._get_client('cloudwatch')

        try:
            # Check CloudWatch alarms
            alarms = cloudwatch.describe_alarms()
            if not alarms['MetricAlarms']:
                results.append(AuditResult(
                    provider="aws",
                    service="cloudwatch",
                    check_id='AWS_MON_1',
                    resource_id='aws/cloudwatch',
                    region=self.region or 'global',
                    status='FAIL',
                    severity=Severity.MEDIUM,
                    message='No CloudWatch alarms configured',
                    resource_type=ResourceType.MONITORING,
                    details={'alarms': 0}
                ))

            # Check SNS topics for alarms
            sns = self._get_client('sns')
            topics = sns.list_topics()
            if not topics.get('Topics', []):
                results.append(AuditResult(
                    provider="aws",
                    service="sns",
                    check_id='AWS_MON_2',
                    resource_id='aws/sns',
                    region=self.region or 'global',
                    status='FAIL',
                    severity=Severity.MEDIUM,
                    message='No SNS topics configured for notifications',
                    resource_type=ResourceType.MONITORING,
                    details={'topics': 0}
                ))

        except Exception as e:
            logger.error(f"Error during monitoring audit: {str(e)}")

        return results

    def enumerate_public_s3_buckets(self, domain=None, company=None):
        """Enumerate potentially public S3 buckets without authentication."""
        found_buckets = []
        search_terms = []
        
        if domain:
            # Try common bucket naming patterns with domain
            domain_parts = domain.split('.')
            search_terms.extend([
                domain.replace('.', '-'),
                domain_parts[0],
                f"{domain_parts[0]}-backup",
                f"{domain_parts[0]}-files",
                f"{domain_parts[0]}-static",
                f"{domain_parts[0]}-media",
                f"{domain_parts[0]}-assets",
                f"{domain_parts[0]}-data",
                f"{domain_parts[0]}-dev",
                f"{domain_parts[0]}-prod",
                f"{domain_parts[0]}-stage",
                f"{domain_parts[0]}-test"
            ])
        
        if company:
            # Try common bucket naming patterns with company name
            company_normalized = company.lower().replace(' ', '-')
            search_terms.extend([
                company_normalized,
                f"{company_normalized}-backup",
                f"{company_normalized}-files",
                f"{company_normalized}-static",
                f"{company_normalized}-media",
                f"{company_normalized}-assets",
                f"{company_normalized}-data",
                f"{company_normalized}-dev",
                f"{company_normalized}-prod",
                f"{company_normalized}-stage",
                f"{company_normalized}-test"
            ])

        for bucket_name in search_terms:
            try:
                # Try to access the bucket
                response = requests.head(f"https://{bucket_name}.s3.amazonaws.com", timeout=3)
                if response.status_code != 404:  # Bucket exists
                    bucket_info = {
                        'name': bucket_name,
                        'exists': True,
                        'public': response.status_code == 200,
                        'status_code': response.status_code
                    }
                    found_buckets.append(bucket_info)
            except requests.exceptions.RequestException:
                continue

        return found_buckets

    def enumerate_public_resources(self, domain=None, company=None):
        """Enumerate public AWS resources without requiring credentials."""
        results = {
            'buckets': self.enumerate_public_s3_buckets(domain, company),
            # Add more public resource enumeration methods here
        }
        return results

    def search_resources(self, domain=None, company=None):
        """Search for AWS resources matching domain or company name."""
        results = []
        
        # First, try unauthenticated enumeration
        try:
            public_resources = self.enumerate_public_resources(domain, company)
            for bucket in public_resources['buckets']:
                results.append({
                    'provider': 'aws',
                    'service': 's3',
                    'resource_type': 'bucket',
                    'name': bucket['name'],
                    'public': bucket['public'],
                    'status': bucket['status_code'],
                    'authenticated': False
                })
        except Exception as e:
            # Don't log errors for unauthenticated enumeration
            pass

        # If we have valid credentials, try authenticated search
        if self.session:
            try:
                # Search S3 buckets
                s3_client = self._get_client('s3')
                if s3_client:
                    try:
                        buckets = s3_client.list_buckets()['Buckets']
                        for bucket in buckets:
                            if (domain and domain.lower() in bucket['Name'].lower()) or \
                               (company and company.lower() in bucket['Name'].lower()):
                                results.append({
                                    'provider': 'aws',
                                    'service': 's3',
                                    'resource_type': 'bucket',
                                    'name': bucket['Name'],
                                    'creation_date': bucket['CreationDate'].isoformat(),
                                    'authenticated': True,
                                    'public': False  # We know it's not public since we found it with credentials
                                })
                    except Exception:
                        # Don't log errors for authenticated search failures
                        pass

            except Exception:
                # Don't log errors for authenticated search failures
                pass

        return results 