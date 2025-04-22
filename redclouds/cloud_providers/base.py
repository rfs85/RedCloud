"""Base classes for cloud providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class ResourceType(Enum):
    """Enum defining the types of resources that can be audited."""
    IAM = "iam"
    STORAGE = "storage"
    NETWORK = "network"
    COMPUTE = "compute"
    DATABASE = "database"
    LOGGING = "logging"
    MONITORING = "monitoring"


class Severity(Enum):
    """Severity levels for audit findings."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AuditResult:
    """Result of a security audit check."""
    provider: str
    service: str
    check_id: str
    resource_id: str
    region: str
    status: str
    severity: Severity
    message: str
    resource_type: ResourceType
    details: Optional[Dict] = None


class CloudProvider(ABC):
    """Base class for cloud providers."""

    def __init__(self, provider_name: str):
        """Initialize cloud provider.
        
        Args:
            provider_name: Name of the cloud provider (aws, azure, gcp).
        """
        self.provider_name = provider_name

    @abstractmethod
    def connect(self) -> bool:
        """Connect to the cloud provider.
        
        Returns:
            bool: True if connection successful, False otherwise.
        """
        pass

    @abstractmethod
    def validate_credentials(self) -> bool:
        """Validate cloud provider credentials.
        
        Returns:
            bool: True if credentials are valid, False otherwise.
        """
        pass

    @abstractmethod
    def audit_iam(self) -> List[AuditResult]:
        """Audit IAM configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        pass

    @abstractmethod
    def audit_storage(self) -> List[AuditResult]:
        """Audit storage configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        pass

    @abstractmethod
    def audit_network(self) -> List[AuditResult]:
        """Audit network configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        pass

    @abstractmethod
    def audit_compute(self) -> List[AuditResult]:
        """Audit compute configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        pass

    @abstractmethod
    def audit_database(self) -> List[AuditResult]:
        """Audit database configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        pass

    @abstractmethod
    def audit_logging(self) -> List[AuditResult]:
        """Audit logging configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        pass

    @abstractmethod
    def audit_monitoring(self) -> List[AuditResult]:
        """Audit monitoring configurations.
        
        Returns:
            List[AuditResult]: List of audit results.
        """
        pass

    def audit_all(self) -> List[AuditResult]:
        """Run all available audits.

        Returns:
            List[AuditResult]: Combined list of all audit results
        """
        results = []
        results.extend(self.audit_iam())
        results.extend(self.audit_storage())
        results.extend(self.audit_network())
        results.extend(self.audit_compute())
        results.extend(self.audit_database())
        results.extend(self.audit_logging())
        results.extend(self.audit_monitoring())
        return results 