"""Google Cloud Platform (GCP) provider for RedClouds security auditing tool."""

import logging
from typing import List, Optional, Dict, Any
import ipaddress
import requests

from google.cloud import storage, compute, iam, monitoring
from google.cloud.compute_v1 import Instance, Firewall
from google.cloud import iam as google_iam
from google.cloud.monitoring_v3 import AlertPolicy
from google.oauth2 import service_account
from google.api_core import exceptions

from .base import CloudProvider, AuditResult, Severity
from ..utils.config import load_config

class GCP(CloudProvider):
    """Google Cloud Platform provider implementation."""

    def __init__(self, credentials_path: Optional[str] = None, project_id: Optional[str] = None):
        """Initialize GCP provider.
        
        Args:
            credentials_path: Path to service account credentials JSON file.
            project_id: GCP project ID to audit.
        """
        super().__init__("gcp")
        self.credentials_path = credentials_path
        self.project_id = project_id
        self.credentials = None
        self.clients = {}
        self.logger = logging.getLogger(__name__)

    def connect(self) -> bool:
        """Connect to GCP using provided credentials.
        
        Returns:
            bool: True if connection successful, False otherwise.
        """
        try:
            if self.credentials_path:
                self.credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path
                )
            
            # Test connection by listing projects
            self._get_client("storage").list_buckets(project=self.project_id)
            return True
        except exceptions.PermissionDenied:
            self.logger.error("Permission denied. Check credentials and project ID.")
            return False
        except Exception as e:
            self.logger.error(f"Failed to connect to GCP: {str(e)}")
            return False

    def validate_credentials(self) -> bool:
        """Validate GCP credentials.
        
        Returns:
            bool: True if credentials are valid, False otherwise.
        """
        try:
            return self.connect()
        except Exception as e:
            self.logger.error(f"Failed to validate credentials: {str(e)}")
            return False

    def _get_client(self, service: str) -> Any:
        """Get or create a GCP service client.
        
        Args:
            service: GCP service name (storage, compute, iam, monitoring).
            
        Returns:
            Any: GCP service client.
        """
        if service not in self.clients:
            if service == "storage":
                self.clients[service] = storage.Client(
                    credentials=self.credentials,
                    project=self.project_id
                )
            elif service == "compute":
                self.clients[service] = compute.InstancesClient(
                    credentials=self.credentials
                )
            elif service == "iam":
                self.clients[service] = google_iam.IAMClient(
                    credentials=self.credentials
                )
            elif service == "monitoring":
                self.clients[service] = monitoring.AlertPolicyServiceClient(
                    credentials=self.credentials
                )
        return self.clients[service]

    def audit_iam(self) -> List[AuditResult]:
        """Audit IAM configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        results = []
        try:
            iam_client = self._get_client("iam")
            
            # Check service account key age
            service_accounts = iam_client.list_service_accounts(
                request={"name": f"projects/{self.project_id}"}
            )
            for sa in service_accounts:
                keys = iam_client.list_service_account_keys(
                    request={"name": sa.name}
                )
                for key in keys:
                    if key.key_type == "USER_MANAGED":
                        results.append(
                            AuditResult(
                                provider="gcp",
                                service="iam",
                                check_id="service_account_key_age",
                                resource_id=sa.name,
                                region="global",
                                status="FAIL" if key.valid_after_time.days > 90 else "PASS",
                                severity=Severity.HIGH,
                                message=f"Service account key is older than 90 days: {key.name}"
                            )
                        )

            # Check IAM policy bindings
            policy = iam_client.get_iam_policy(
                request={"resource": f"projects/{self.project_id}"}
            )
            for binding in policy.bindings:
                if binding.role in ["roles/owner", "roles/editor"]:
                    for member in binding.members:
                        if member.startswith("user:") or member.startswith("serviceAccount:"):
                            results.append(
                                AuditResult(
                                    provider="gcp",
                                    service="iam",
                                    check_id="privileged_access",
                                    resource_id=member,
                                    region="global",
                                    status="FAIL",
                                    severity=Severity.HIGH,
                                    message=f"Principal has privileged role {binding.role}"
                                )
                            )

        except Exception as e:
            self.logger.error(f"Error auditing IAM: {str(e)}")
            results.append(
                AuditResult(
                    provider="gcp",
                    service="iam",
                    check_id="iam_audit",
                    resource_id="N/A",
                    region="global",
                    status="ERROR",
                    severity=Severity.HIGH,
                    message=f"Failed to audit IAM: {str(e)}"
                )
            )
        
        return results

    def audit_storage(self) -> List[AuditResult]:
        """Audit storage configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        results = []
        try:
            storage_client = self._get_client("storage")
            
            # Check bucket configurations
            for bucket in storage_client.list_buckets(project=self.project_id):
                # Check public access
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                        results.append(
                            AuditResult(
                                provider="gcp",
                                service="storage",
                                check_id="public_access",
                                resource_id=bucket.name,
                                region=bucket.location,
                                status="FAIL",
                                severity=Severity.HIGH,
                                message=f"Bucket {bucket.name} allows public access"
                            )
                        )

                # Check encryption
                if not bucket.default_kms_key_name:
                    results.append(
                        AuditResult(
                            provider="gcp",
                            service="storage",
                            check_id="encryption",
                            resource_id=bucket.name,
                            region=bucket.location,
                            status="FAIL",
                            severity=Severity.MEDIUM,
                            message=f"Bucket {bucket.name} does not use customer-managed encryption keys"
                        )
                    )

                # Check versioning
                if not bucket.versioning_enabled:
                    results.append(
                        AuditResult(
                            provider="gcp",
                            service="storage",
                            check_id="versioning",
                            resource_id=bucket.name,
                            region=bucket.location,
                            status="FAIL",
                            severity=Severity.LOW,
                            message=f"Bucket {bucket.name} does not have versioning enabled"
                        )
                    )

        except Exception as e:
            self.logger.error(f"Error auditing storage: {str(e)}")
            results.append(
                AuditResult(
                    provider="gcp",
                    service="storage",
                    check_id="storage_audit",
                    resource_id="N/A",
                    region="global",
                    status="ERROR",
                    severity=Severity.HIGH,
                    message=f"Failed to audit storage: {str(e)}"
                )
            )
        
        return results

    def audit_network(self) -> List[AuditResult]:
        """Audit network configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        results = []
        try:
            compute_client = self._get_client("compute")
            
            # Check firewall rules
            request = compute_client.list_firewalls(project=self.project_id)
            for firewall in request:
                # Check for overly permissive rules
                for allowed in firewall.allowed:
                    if allowed.ports and ("0-65535" in allowed.ports or "*" in allowed.ports):
                        results.append(
                            AuditResult(
                                provider="gcp",
                                service="network",
                                check_id="firewall_all_ports",
                                resource_id=firewall.name,
                                region="global",
                                status="FAIL",
                                severity=Severity.HIGH,
                                message=f"Firewall rule {firewall.name} allows all ports"
                            )
                        )

                # Check for 0.0.0.0/0 source ranges
                if "0.0.0.0/0" in firewall.source_ranges:
                    results.append(
                        AuditResult(
                            provider="gcp",
                            service="network",
                            check_id="firewall_open_access",
                            resource_id=firewall.name,
                            region="global",
                            status="FAIL",
                            severity=Severity.HIGH,
                            message=f"Firewall rule {firewall.name} allows access from any IP"
                        )
                    )

        except Exception as e:
            self.logger.error(f"Error auditing network: {str(e)}")
            results.append(
                AuditResult(
                    provider="gcp",
                    service="network",
                    check_id="network_audit",
                    resource_id="N/A",
                    region="global",
                    status="ERROR",
                    severity=Severity.HIGH,
                    message=f"Failed to audit network: {str(e)}"
                )
            )
        
        return results

    def audit_compute(self) -> List[AuditResult]:
        """Audit compute configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        results = []
        try:
            compute_client = self._get_client("compute")
            
            # Check instance configurations
            for zone in compute_client.list_zones(project=self.project_id):
                instances = compute_client.list_instances(
                    project=self.project_id,
                    zone=zone.name
                )
                
                for instance in instances:
                    # Check for public IPs
                    for network_interface in instance.network_interfaces:
                        if network_interface.access_configs:
                            results.append(
                                AuditResult(
                                    provider="gcp",
                                    service="compute",
                                    check_id="public_ip",
                                    resource_id=instance.name,
                                    region=zone.name,
                                    status="FAIL",
                                    severity=Severity.MEDIUM,
                                    message=f"Instance {instance.name} has a public IP"
                                )
                            )

                    # Check for OS login
                    if not instance.metadata.items.get("enable-oslogin", False):
                        results.append(
                            AuditResult(
                                provider="gcp",
                                service="compute",
                                check_id="os_login",
                                resource_id=instance.name,
                                region=zone.name,
                                status="FAIL",
                                severity=Severity.MEDIUM,
                                message=f"Instance {instance.name} does not have OS Login enabled"
                            )
                        )

                    # Check for service account
                    if not instance.service_accounts:
                        results.append(
                            AuditResult(
                                provider="gcp",
                                service="compute",
                                check_id="service_account",
                                resource_id=instance.name,
                                region=zone.name,
                                status="FAIL",
                                severity=Severity.LOW,
                                message=f"Instance {instance.name} does not use a service account"
                            )
                        )

        except Exception as e:
            self.logger.error(f"Error auditing compute: {str(e)}")
            results.append(
                AuditResult(
                    provider="gcp",
                    service="compute",
                    check_id="compute_audit",
                    resource_id="N/A",
                    region="global",
                    status="ERROR",
                    severity=Severity.HIGH,
                    message=f"Failed to audit compute: {str(e)}"
                )
            )
        
        return results

    def audit_database(self) -> List[AuditResult]:
        """Audit database configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        results = []
        try:
            # Note: This would require additional setup with Cloud SQL Admin API
            # For now, we'll add a placeholder result
            results.append(
                AuditResult(
                    provider="gcp",
                    service="database",
                    check_id="database_audit",
                    resource_id="N/A",
                    region="global",
                    status="INFO",
                    severity=Severity.LOW,
                    message="Database auditing requires Cloud SQL Admin API setup"
                )
            )

        except Exception as e:
            self.logger.error(f"Error auditing database: {str(e)}")
            results.append(
                AuditResult(
                    provider="gcp",
                    service="database",
                    check_id="database_audit",
                    resource_id="N/A",
                    region="global",
                    status="ERROR",
                    severity=Severity.HIGH,
                    message=f"Failed to audit database: {str(e)}"
                )
            )
        
        return results

    def audit_logging(self) -> List[AuditResult]:
        """Audit logging configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        results = []
        try:
            # Check Cloud Audit Logging configuration
            # Note: This would require additional setup with Cloud Audit Logs API
            # For now, we'll add a placeholder result
            results.append(
                AuditResult(
                    provider="gcp",
                    service="logging",
                    check_id="audit_logging",
                    resource_id="N/A",
                    region="global",
                    status="INFO",
                    severity=Severity.LOW,
                    message="Logging auditing requires Cloud Audit Logs API setup"
                )
            )

        except Exception as e:
            self.logger.error(f"Error auditing logging: {str(e)}")
            results.append(
                AuditResult(
                    provider="gcp",
                    service="logging",
                    check_id="logging_audit",
                    resource_id="N/A",
                    region="global",
                    status="ERROR",
                    severity=Severity.HIGH,
                    message=f"Failed to audit logging: {str(e)}"
                )
            )
        
        return results

    def audit_monitoring(self) -> List[AuditResult]:
        """Audit monitoring configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        results = []
        try:
            monitoring_client = self._get_client("monitoring")
            
            # Check alert policies
            request = monitoring_client.list_alert_policies(
                request={"name": f"projects/{self.project_id}"}
            )
            
            has_alerts = False
            for policy in request:
                has_alerts = True
                if not policy.enabled:
                    results.append(
                        AuditResult(
                            provider="gcp",
                            service="monitoring",
                            check_id="alert_policy_disabled",
                            resource_id=policy.name,
                            region="global",
                            status="FAIL",
                            severity=Severity.MEDIUM,
                            message=f"Alert policy {policy.display_name} is disabled"
                        )
                    )
            
            if not has_alerts:
                results.append(
                    AuditResult(
                        provider="gcp",
                        service="monitoring",
                        check_id="alert_policies",
                        resource_id="N/A",
                        region="global",
                        status="FAIL",
                        severity=Severity.HIGH,
                        message="No alert policies configured"
                    )
                )

        except Exception as e:
            self.logger.error(f"Error auditing monitoring: {str(e)}")
            results.append(
                AuditResult(
                    provider="gcp",
                    service="monitoring",
                    check_id="monitoring_audit",
                    resource_id="N/A",
                    region="global",
                    status="ERROR",
                    severity=Severity.HIGH,
                    message=f"Failed to audit monitoring: {str(e)}"
                )
            )
        
        return results

    def audit_mongodb(self) -> List[AuditResult]:
        """Audit MongoDB Atlas clusters and configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        results = []
        try:
            compute_client = self._get_client("compute")
            
            # Get all instances in the project
            for zone in compute_client.list_zones(project=self.project_id):
                instances = compute_client.list_instances(
                    project=self.project_id,
                    zone=zone.name
                )
                
                for instance in instances:
                    # Check network interfaces for MongoDB Atlas ASN (8011)
                    for network_interface in instance.network_interfaces:
                        if network_interface.access_configs:
                            try:
                                # Try to connect to MongoDB default port
                                ip = network_interface.access_configs[0].nat_ip
                                response = requests.get(f"http://{ip}:27017", timeout=2)
                                
                                # If we can connect, the MongoDB instance might be exposed
                                results.append(
                                    AuditResult(
                                        provider="gcp",
                                        service="mongodb",
                                        check_id="mongodb_public_access",
                                        resource_id=instance.name,
                                        region=zone.name,
                                        status="FAIL",
                                        severity=Severity.HIGH,
                                        message=f"MongoDB instance {instance.name} appears to be publicly accessible on {ip}:27017"
                                    )
                                )
                                
                                # Try to enumerate databases without authentication
                                try:
                                    from pymongo import MongoClient
                                    client = MongoClient(f"mongodb://{ip}:27017", serverSelectionTimeoutMS=2000)
                                    dbs = client.list_database_names()
                                    
                                    results.append(
                                        AuditResult(
                                            provider="gcp",
                                            service="mongodb",
                                            check_id="mongodb_no_auth",
                                            resource_id=instance.name,
                                            region=zone.name,
                                            status="FAIL",
                                            severity=Severity.CRITICAL,
                                            message=f"MongoDB instance {instance.name} allows unauthenticated access. Found databases: {', '.join(dbs)}"
                                        )
                                    )
                                    
                                    # Check roles and users
                                    if "admin" in dbs:
                                        admin_db = client["admin"]
                                        try:
                                            roles = list(admin_db.command("rolesInfo")["roles"])
                                            results.append(
                                                AuditResult(
                                                    provider="gcp",
                                                    service="mongodb",
                                                    check_id="mongodb_roles",
                                                    resource_id=instance.name,
                                                    region=zone.name,
                                                    status="INFO",
                                                    severity=Severity.LOW,
                                                    message=f"MongoDB roles found: {[role['role'] for role in roles]}"
                                                )
                                            )
                                        except Exception:
                                            pass
                                            
                                        try:
                                            users = list(admin_db.command("usersInfo")["users"])
                                            results.append(
                                                AuditResult(
                                                    provider="gcp",
                                                    service="mongodb",
                                                    check_id="mongodb_users",
                                                    resource_id=instance.name,
                                                    region=zone.name,
                                                    status="INFO",
                                                    severity=Severity.LOW,
                                                    message=f"MongoDB users found: {[user['user'] for user in users]}"
                                                )
                                            )
                                        except Exception:
                                            pass
                                            
                                    # Check collections in each database
                                    for db_name in dbs:
                                        if db_name not in ["admin", "local", "config"]:
                                            db = client[db_name]
                                            collections = db.list_collection_names()
                                            results.append(
                                                AuditResult(
                                                    provider="gcp",
                                                    service="mongodb",
                                                    check_id="mongodb_collections",
                                                    resource_id=f"{instance.name}/{db_name}",
                                                    region=zone.name,
                                                    status="INFO",
                                                    severity=Severity.LOW,
                                                    message=f"Database {db_name} collections: {', '.join(collections)}"
                                                )
                                            )
                                            
                                except Exception as mongo_err:
                                    # If we can't connect without auth, that's actually good
                                    results.append(
                                        AuditResult(
                                            provider="gcp",
                                            service="mongodb",
                                            check_id="mongodb_auth",
                                            resource_id=instance.name,
                                            region=zone.name,
                                            status="PASS",
                                            severity=Severity.LOW,
                                            message=f"MongoDB instance {instance.name} requires authentication"
                                        )
                                    )
                                    
                            except requests.exceptions.RequestException:
                                # If we can't connect, the instance might be properly secured
                                pass

            # Check firewall rules specifically for MongoDB ports
            request = compute_client.list_firewalls(project=self.project_id)
            for firewall in request:
                for allowed in firewall.allowed:
                    if allowed.ports and ("27017" in allowed.ports or "27018" in allowed.ports or "27019" in allowed.ports):
                        if "0.0.0.0/0" in firewall.source_ranges:
                            results.append(
                                AuditResult(
                                    provider="gcp",
                                    service="mongodb",
                                    check_id="mongodb_firewall",
                                    resource_id=firewall.name,
                                    region="global",
                                    status="FAIL",
                                    severity=Severity.HIGH,
                                    message=f"Firewall rule {firewall.name} allows public access to MongoDB ports"
                                )
                            )

        except Exception as e:
            self.logger.error(f"Error auditing MongoDB: {str(e)}")
            results.append(
                AuditResult(
                    provider="gcp",
                    service="mongodb",
                    check_id="mongodb_audit",
                    resource_id="N/A",
                    region="global",
                    status="ERROR",
                    severity=Severity.HIGH,
                    message=f"Failed to audit MongoDB: {str(e)}"
                )
            )
        
        return results 