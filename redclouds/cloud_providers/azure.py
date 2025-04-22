"""Azure cloud provider implementation."""
import logging
import re
import requests
from typing import Dict, List, Optional, Set, Tuple
from azure.identity import ClientSecretCredential, AzureCliCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.core.exceptions import AzureError, ResourceNotFoundError

from .base import CloudProvider, AuditResult, ResourceType

logger = logging.getLogger(__name__)


class Azure(CloudProvider):
    """Azure cloud provider implementation with enhanced enumeration capabilities."""

    def __init__(self, credentials: Dict[str, str], region: Optional[str] = None):
        """Initialize Azure provider.

        Args:
            credentials: Azure credentials dictionary (can be empty for unauthenticated enumeration)
            region: Optional Azure region (location)
        """
        super().__init__(credentials, region)
        self.subscription_id = credentials.get('subscription_id')
        self._credential = None
        self.clients = {}
        self.discovered_resources = {
            'tenants': set(),
            'subscriptions': set(),
            'storage_accounts': set(),
            'endpoints': set(),
            'credentials': []
        }

    def _discover_tenants(self) -> Set[str]:
        """Attempt to discover Azure tenants through various methods."""
        tenants = set()
        
        # Common Azure endpoints to check
        endpoints = [
            "https://login.microsoftonline.com",
            "https://login.windows.net",
            "https://graph.windows.net",
            "https://management.azure.com"
        ]

        for endpoint in endpoints:
            try:
                response = requests.get(f"{endpoint}/common/discovery/instance", timeout=5)
                if response.status_code == 200:
                    self.discovered_resources['endpoints'].add(endpoint)
                    # Look for tenant IDs in the response
                    tenant_matches = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 
                                             response.text, re.IGNORECASE)
                    tenants.update(tenant_matches)
            except Exception as e:
                logger.debug(f"Error discovering tenants from {endpoint}: {str(e)}")

        self.discovered_resources['tenants'].update(tenants)
        return tenants

    def _discover_storage_accounts(self) -> Set[str]:
        """Attempt to discover Azure storage accounts through DNS enumeration."""
        storage_accounts = set()
        
        # Common storage account patterns
        patterns = [
            "backup", "storage", "data", "prod", "dev", "test", "staging",
            "files", "media", "static", "blob", "assets", "archive"
        ]

        for pattern in patterns:
            try:
                # Try to resolve common storage account names
                url = f"https://{pattern}.blob.core.windows.net"
                response = requests.head(url, timeout=5)
                if response.status_code != 404:  # Any response except 404 might indicate existence
                    storage_accounts.add(pattern)
                    self.discovered_resources['storage_accounts'].add(url)
            except Exception as e:
                logger.debug(f"Error discovering storage account {pattern}: {str(e)}")

        return storage_accounts

    def _check_storage_account_access(self, account: str) -> List[AuditResult]:
        """Check for publicly accessible storage containers."""
        results = []
        
        try:
            url = f"https://{account}.blob.core.windows.net/?comp=list"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                results.append(AuditResult(
                    check_id='AZURE_STORAGE_PUBLIC_1',
                    resource_id=f"azure/storage/{account}",
                    resource_type=ResourceType.STORAGE,
                    status='fail',
                    details={'public_access': True, 'url': url},
                    recommendation='Disable public access to storage account containers'
                ))
        except Exception as e:
            logger.debug(f"Error checking storage account {account}: {str(e)}")

        return results

    def _try_common_credentials(self) -> List[Dict[str, str]]:
        """Attempt to authenticate using common credential patterns."""
        discovered_creds = []
        
        # Common service principal patterns
        common_client_ids = [
            "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
            "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
        ]

        for client_id in common_client_ids:
            try:
                # Try to authenticate with default credentials
                credential = ClientSecretCredential(
                    tenant_id=next(iter(self.discovered_resources['tenants']), None),
                    client_id=client_id,
                    client_secret=""
                )
                # If we get this far without exception, store the credential
                discovered_creds.append({
                    'tenant_id': next(iter(self.discovered_resources['tenants']), None),
                    'client_id': client_id,
                    'type': 'service_principal'
                })
            except Exception:
                continue

        return discovered_creds

    def connect(self) -> bool:
        """Establish connection to Azure with enhanced enumeration."""
        # Start with unauthenticated discovery
        logger.info("Starting unauthenticated Azure enumeration...")
        
        # Discover tenants
        tenants = self._discover_tenants()
        if tenants:
            logger.info(f"Discovered {len(tenants)} potential Azure tenants")

        # Discover storage accounts
        storage_accounts = self._discover_storage_accounts()
        if storage_accounts:
            logger.info(f"Discovered {len(storage_accounts)} potential storage accounts")
            
            # Check storage account access
            for account in storage_accounts:
                results = self._check_storage_account_access(account)
                if results:
                    logger.warning(f"Found publicly accessible storage account: {account}")

        # Try to establish authenticated connection if credentials provided
        if self.credentials:
            try:
                if 'credential' in self.credentials:
                    self._credential = self.credentials['credential']
                else:
                    self._credential = ClientSecretCredential(
                        tenant_id=self.credentials['tenant_id'],
                        client_id=self.credentials['client_id'],
                        client_secret=self.credentials['client_secret']
                    )

                # Test connection
                self._get_client('resource').resource_groups.list()
                logger.info("Successfully authenticated with provided credentials")
                return True
            except Exception as e:
                logger.error(f"Failed to authenticate with provided credentials: {str(e)}")
        
        # If no valid credentials, try common patterns
        if not self._credential:
            discovered_creds = self._try_common_credentials()
            if discovered_creds:
                logger.info(f"Discovered {len(discovered_creds)} potential credential sets")
                self.discovered_resources['credentials'].extend(discovered_creds)

        return bool(self._credential)

    def validate_credentials(self) -> bool:
        """Validate Azure credentials with enhanced checks."""
        if not self._credential:
            return False

        try:
            subscription_client = SubscriptionClient(self._credential)
            subscriptions = list(subscription_client.subscriptions.list())
            
            # Store discovered subscriptions
            for sub in subscriptions:
                self.discovered_resources['subscriptions'].add(sub.subscription_id)
                logger.info(f"Found subscription: {sub.subscription_id} ({sub.display_name})")
            
            return bool(subscriptions)
        except Exception as e:
            logger.error(f"Invalid Azure credentials: {str(e)}")
            return False

    def get_regions(self) -> List[str]:
        """Get available Azure regions."""
        try:
            subscription_client = SubscriptionClient(self._credential)
            locations = subscription_client.subscriptions.list_locations(self.subscription_id)
            return [loc.name for loc in locations]
        except AzureError as e:
            logger.error(f"Failed to get regions: {str(e)}")
            return []

    def _get_client(self, service: str):
        """Get or create an Azure service client."""
        if service not in self.clients:
            try:
                if service == 'resource':
                    self.clients[service] = ResourceManagementClient(self._credential, self.subscription_id)
                elif service == 'storage':
                    self.clients[service] = StorageManagementClient(self._credential, self.subscription_id)
                elif service == 'network':
                    self.clients[service] = NetworkManagementClient(self._credential, self.subscription_id)
                elif service == 'compute':
                    self.clients[service] = ComputeManagementClient(self._credential, self.subscription_id)
                elif service == 'monitor':
                    self.clients[service] = MonitorManagementClient(self._credential, self.subscription_id)
                elif service == 'sql':
                    self.clients[service] = SqlManagementClient(self._credential, self.subscription_id)
                else:
                    raise ValueError(f"Unknown service: {service}")
            except AzureError as e:
                logger.error(f"Failed to create {service} client: {str(e)}")
                raise
        return self.clients[service]

    def audit_iam(self) -> List[AuditResult]:
        """Audit Azure IAM configurations."""
        results = []
        try:
            # Get subscription client
            subscription_client = SubscriptionClient(self._credential)
            
            # List subscriptions
            try:
                subscriptions = list(subscription_client.subscriptions.list())
                for sub in subscriptions:
                    self.discovered_resources['subscriptions'].add(sub.subscription_id)
            except AzureError as e:
                logger.error(f"Failed to list subscriptions: {str(e)}")
                return results

            # Continue with other IAM checks...
            
        except AzureError as e:
            logger.error(f"Error during IAM audit: {str(e)}")
        
        return results

    def audit_storage(self) -> List[AuditResult]:
        """Audit Azure Storage configurations."""
        results = []
        try:
            storage_client = self._get_client('storage')
            
            # List storage accounts
            try:
                storage_accounts = storage_client.storage_accounts.list()
                for account in storage_accounts:
                    try:
                        # Check encryption
                        if not account.encryption.services.blob.enabled:
                            results.append(AuditResult(
                                check_id='AZURE_STORAGE_ENCRYPTION_1',
                                resource_id=account.id,
                                resource_type=ResourceType.STORAGE,
                                status='fail',
                                details={'encryption': False},
                                recommendation='Enable blob encryption for the storage account'
                            ))
                    except (AzureError, ResourceNotFoundError) as e:
                        logger.error(f"Error checking storage account {account.name}: {str(e)}")
                        continue
                        
            except AzureError as e:
                logger.error(f"Failed to list storage accounts: {str(e)}")
                return results
                
        except AzureError as e:
            logger.error(f"Error during storage audit: {str(e)}")
            
        return results

    def audit_network(self) -> List[AuditResult]:
        """Audit network configurations."""
        results = []
        network_client = self._get_client('network')

        try:
            # Check Network Security Groups (NSGs)
            for nsg in network_client.network_security_groups.list_all():
                try:
                    for rule in nsg.security_rules:
                        # Check for overly permissive inbound rules
                        if (rule.direction == 'Inbound' and
                            rule.source_address_prefix in ['*', '0.0.0.0/0', 'Internet'] and
                            rule.access == 'Allow'):
                            
                            # Check common ports
                            ports = rule.destination_port_range.split(',') if rule.destination_port_range else []
                            risky_ports = {'22', '3389', '3306', '1433', '1521'}
                            for port in ports:
                                if port in risky_ports or port == '*':
                                    results.append(AuditResult(
                                        check_id='AZURE_NET_1',
                                        resource_id=f"azure/nsg/{nsg.name}/rule/{rule.name}",
                                        resource_type=ResourceType.NETWORK,
                                        status='fail',
                                        details={
                                            'direction': 'Inbound',
                                            'source': rule.source_address_prefix,
                                            'port': port
                                        },
                                        recommendation='Restrict inbound access to specific IP ranges'
                                    ))

                except Exception as e:
                    logger.error(f"Error checking NSG {nsg.name}: {str(e)}")

            # Check Virtual Networks
            for vnet in network_client.virtual_networks.list_all():
                try:
                    # Check for diagnostic settings
                    monitor_client = self._get_client('monitor')
                    diagnostic_settings = monitor_client.diagnostic_settings.list(
                        resource_uri=vnet.id
                    )
                    if not list(diagnostic_settings):
                        results.append(AuditResult(
                            check_id='AZURE_NET_2',
                            resource_id=f"azure/vnet/{vnet.name}",
                            resource_type=ResourceType.NETWORK,
                            status='warning',
                            details={'diagnostics': 'disabled'},
                            recommendation='Enable diagnostic settings for network monitoring'
                        ))

                except Exception as e:
                    logger.error(f"Error checking VNet {vnet.name}: {str(e)}")

        except Exception as e:
            logger.error(f"Error during network audit: {str(e)}")

        return results

    def audit_compute(self) -> List[AuditResult]:
        """Audit compute configurations."""
        results = []
        compute_client = self._get_client('compute')

        try:
            # Check Virtual Machines
            for vm in compute_client.virtual_machines.list_all():
                try:
                    # Check disk encryption
                    if not vm.storage_profile.os_disk.encryption_settings:
                        results.append(AuditResult(
                            check_id='AZURE_VM_1',
                            resource_id=f"azure/vm/{vm.name}",
                            resource_type=ResourceType.COMPUTE,
                            status='fail',
                            details={'disk_encryption': False},
                            recommendation='Enable disk encryption for the virtual machine'
                        ))

                    # Check backup policy
                    if not any(tag.startswith('backup-policy') for tag in vm.tags or []):
                        results.append(AuditResult(
                            check_id='AZURE_VM_2',
                            resource_id=f"azure/vm/{vm.name}",
                            resource_type=ResourceType.COMPUTE,
                            status='warning',
                            details={'backup': 'not configured'},
                            recommendation='Configure backup policy for the virtual machine'
                        ))

                    # Check for public IP
                    network_client = self._get_client('network')
                    nics = [network_client.network_interfaces.get(
                        vm.resource_group_name,
                        nic.id.split('/')[-1]
                    ) for nic in vm.network_profile.network_interfaces]

                    for nic in nics:
                        for ip_config in nic.ip_configurations:
                            if ip_config.public_ip_address:
                                results.append(AuditResult(
                                    check_id='AZURE_VM_3',
                                    resource_id=f"azure/vm/{vm.name}/nic/{nic.name}",
                                    resource_type=ResourceType.COMPUTE,
                                    status='warning',
                                    details={'public_ip': True},
                                    recommendation='Consider using private IP if public access not required'
                                ))

                except Exception as e:
                    logger.error(f"Error checking VM {vm.name}: {str(e)}")

        except Exception as e:
            logger.error(f"Error during compute audit: {str(e)}")

        return results

    def audit_database(self) -> List[AuditResult]:
        """Audit database configurations."""
        results = []
        sql_client = self._get_client('sql')

        try:
            # Check SQL Servers
            for server in sql_client.servers.list():
                try:
                    # Check firewall rules
                    firewall_rules = sql_client.firewall_rules.list_by_server(
                        server.resource_group_name,
                        server.name
                    )
                    for rule in firewall_rules:
                        if rule.start_ip_address == '0.0.0.0' and rule.end_ip_address == '255.255.255.255':
                            results.append(AuditResult(
                                check_id='AZURE_SQL_1',
                                resource_id=f"azure/sql/{server.name}/firewall/{rule.name}",
                                resource_type=ResourceType.DATABASE,
                                status='fail',
                                details={
                                    'rule': 'Allow all',
                                    'ip_range': f"{rule.start_ip_address}-{rule.end_ip_address}"
                                },
                                recommendation='Restrict SQL Server firewall rules to specific IP ranges'
                            ))

                    # Check auditing settings
                    audit_settings = sql_client.server_blob_auditing_policies.get(
                        server.resource_group_name,
                        server.name
                    )
                    if not audit_settings.state == 'Enabled':
                        results.append(AuditResult(
                            check_id='AZURE_SQL_2',
                            resource_id=f"azure/sql/{server.name}",
                            resource_type=ResourceType.DATABASE,
                            status='fail',
                            details={'auditing': False},
                            recommendation='Enable auditing for SQL Server'
                        ))

                    # Check threat detection
                    threat_detection = sql_client.server_security_alert_policies.get(
                        server.resource_group_name,
                        server.name
                    )
                    if not threat_detection.state == 'Enabled':
                        results.append(AuditResult(
                            check_id='AZURE_SQL_3',
                            resource_id=f"azure/sql/{server.name}",
                            resource_type=ResourceType.DATABASE,
                            status='warning',
                            details={'threat_detection': False},
                            recommendation='Enable threat detection for SQL Server'
                        ))

                except Exception as e:
                    logger.error(f"Error checking SQL Server {server.name}: {str(e)}")

        except Exception as e:
            logger.error(f"Error during database audit: {str(e)}")

        return results

    def audit_logging(self) -> List[AuditResult]:
        """Audit logging configurations."""
        results = []
        monitor_client = self._get_client('monitor')

        try:
            # Check Activity Log settings
            activity_log_settings = monitor_client.diagnostic_settings.list(
                resource_uri='/subscriptions/' + self.subscription_id
            )
            settings_found = False
            for setting in activity_log_settings:
                settings_found = True
                if not any(log.enabled for log in setting.logs):
                    results.append(AuditResult(
                        check_id='AZURE_LOG_1',
                        resource_id=f"azure/activitylog/{setting.name}",
                        resource_type=ResourceType.LOGGING,
                        status='fail',
                        details={'logging': 'disabled'},
                        recommendation='Enable Activity Log collection'
                    ))

            if not settings_found:
                results.append(AuditResult(
                    check_id='AZURE_LOG_2',
                    resource_id='azure/activitylog',
                    resource_type=ResourceType.LOGGING,
                    status='fail',
                    details={'settings': 'none'},
                    recommendation='Configure Activity Log settings'
                ))

        except Exception as e:
            logger.error(f"Error during logging audit: {str(e)}")

        return results

    def audit_monitoring(self) -> List[AuditResult]:
        """Audit monitoring configurations."""
        results = []
        monitor_client = self._get_client('monitor')

        try:
            # Check Alert Rules
            alert_rules = monitor_client.alert_rules.list_by_subscription_id(
                self.subscription_id
            )
            rules_found = False
            for rule in alert_rules:
                rules_found = True
                if not rule.enabled:
                    results.append(AuditResult(
                        check_id='AZURE_MON_1',
                        resource_id=f"azure/alertrule/{rule.name}",
                        resource_type=ResourceType.MONITORING,
                        status='warning',
                        details={'enabled': False},
                        recommendation='Enable alert rule'
                    ))

            if not rules_found:
                results.append(AuditResult(
                    check_id='AZURE_MON_2',
                    resource_id='azure/alertrules',
                    resource_type=ResourceType.MONITORING,
                    status='warning',
                    details={'rules': 'none'},
                    recommendation='Configure monitoring alert rules'
                ))

            # Check Action Groups
            action_groups = monitor_client.action_groups.list_by_subscription_id(
                self.subscription_id
            )
            groups_found = False
            for group in action_groups:
                groups_found = True
                if not group.enabled:
                    results.append(AuditResult(
                        check_id='AZURE_MON_3',
                        resource_id=f"azure/actiongroup/{group.name}",
                        resource_type=ResourceType.MONITORING,
                        status='warning',
                        details={'enabled': False},
                        recommendation='Enable action group for alerts'
                    ))

            if not groups_found:
                results.append(AuditResult(
                    check_id='AZURE_MON_4',
                    resource_id='azure/actiongroups',
                    resource_type=ResourceType.MONITORING,
                    status='warning',
                    details={'groups': 'none'},
                    recommendation='Configure action groups for alert notifications'
                ))

        except Exception as e:
            logger.error(f"Error during monitoring audit: {str(e)}")

        return results 