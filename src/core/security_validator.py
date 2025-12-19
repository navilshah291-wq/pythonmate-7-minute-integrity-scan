"""
Security Validator for SAP RFC connections.

Validates:
- Authorization models (S_TABU_DIS vs S_TABU_NAM)
- Connection security parameters
- RFC_READ_TABLE access compliance
- Read-only operation verification
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import logging


@dataclass
class ValidationResult:
    """Result of security validation."""
    is_compliant: bool
    violations: List[str]
    recommendations: List[str]


@dataclass
class AuthorizationModel:
    """SAP authorization model details."""
    name: str
    allows_ddic_read: bool  # Can read DDIC metadata
    allows_table_read: bool  # Can execute RFC_READ_TABLE
    level: str  # 'N' for names, 'D' for display, etc.


class SecurityValidator:
    """
    Validates SAP RFC security configuration and authorization models.
    
    Ensures compliance with read-only GOS scanning requirements:
    - Verify S_TABU_NAM authorization (table name access)
    - Validate RFC_READ_TABLE permissions
    - Check for binary data access restrictions
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def check_authorization_model(self, required_tables: List[str]) -> ValidationResult:
        """
        Validate SAP authorization model for GOS scanning.
        
        Args:
            required_tables: List of tables the scan will access (SRGBTBREL, SOFFPHIO, SOFFCONT1)
            
        Returns:
            ValidationResult with compliance status
        """
        violations = []
        recommendations = []

        # Default required tables for GOS scanning
        if not required_tables:
            required_tables = ["SRGBTBREL", "SOFFPHIO", "SOFFCONT1"]

        # Verify basic RFC_READ_TABLE permission
        # In a real implementation, this would check actual SAP authorizations
        if not self._has_rfc_read_table_permission():
            violations.append(
                "RFC_READ_TABLE authorization missing - cannot scan tables"
            )
            recommendations.append(
                "Grant RFC_READ_TABLE authorization or equivalent permission"
            )

        # Verify S_TABU_NAM (table name access) instead of S_TABU_DIS (table display)
        if not self._has_tabu_nam_authorization():
            violations.append(
                "S_TABU_NAM authorization missing - cannot access table names"
            )
            recommendations.append(
                "Grant S_TABU_NAM authorization for GOS tables"
            )

        # Ensure no binary data access (CLUSTD column) is attempted
        if self._can_access_binary_data():
            violations.append(
                "Binary data (CLUSTD) access detected - violates security policy"
            )
            recommendations.append(
                "Ensure RFC connection restricts access to binary columns"
            )

        # Check that required GOS tables are accessible
        inaccessible_tables = self._check_table_access(required_tables)
        if inaccessible_tables:
            violations.append(
                f"Cannot access required GOS tables: {inaccessible_tables}"
            )
            recommendations.append(
                f"Grant access to tables: {inaccessible_tables}"
            )

        return ValidationResult(
            is_compliant=len(violations) == 0,
            violations=violations,
            recommendations=recommendations
        )

    def validate_connection_params(self, config: Dict[str, str]) -> ValidationResult:
        """
        Validate RFC connection parameters for security compliance.
        
        Args:
            config: RFC connection parameters
            
        Returns:
            ValidationResult with security assessment
        """
        violations = []
        recommendations = []

        # Check for secure parameter configuration
        if config.get('trace', '0') != '0':
            violations.append("RFC tracing enabled - may log sensitive data")
            recommendations.append("Set trace='0' in production")

        if config.get('passwd').startswith('!'):
            # Encrypted password (as per RFC standards)
            pass  # This is good
        else:
            self.logger.warning("Password not encrypted - consider using RFC encryption")

        # Check for potentially unsafe connection settings
        if config.get('sysnr', '').startswith('0') and int(config.get('sysnr', '0')) < 10:
            # System numbers 00-09 are typically production systems
            recommendations.append(
                "Connection to system number < 10 detected - verify this is intended for scanning"
            )

        return ValidationResult(
            is_compliant=len(violations) == 0,
            violations=violations,
            recommendations=recommendations
        )

    def _has_rfc_read_table_permission(self) -> bool:
        """
        Check if RFC_READ_TABLE permission is granted.
        In a real implementation, this would query SAP authorizations.
        """
        # This is a placeholder implementation
        # The actual check would involve RFC calls to authorization functions
        return True  # Assume true for the example

    def _has_tabu_nam_authorization(self) -> bool:
        """
        Check if S_TABU_NAM authorization is granted for table name access.
        """
        return True  # Assume true for the example

    def _can_access_binary_data(self) -> bool:
        """
        Verify that binary data access is restricted.
        """
        # The 7-minute scan specifically avoids binary data (CLUSTD column)
        # so this should return False to be compliant
        return False

    def _check_table_access(self, tables: List[str]) -> List[str]:
        """
        Check if specific tables are accessible.
        
        Args:
            tables: List of table names to check
            
        Returns:
            List of inaccessible table names
        """
        # Placeholder implementation
        # In real implementation, this would test access to each table
        return []  # Assume all tables accessible for example

    def validate_read_only_compliance(self) -> ValidationResult:
        """
        Ensure all operations are read-only as required for GOS scanning.
        """
        violations = []
        recommendations = []

        # Verify no write operations are attempted
        safe_operations = [
            'RFC_READ_TABLE',  # Read-only table access
            'DDIF_FIELDINFO_GET',  # Read metadata
            'EM_GET_NUMBER_OF_ENTRIES'  # Count entries
        ]

        # Check that only safe operations are used
        # In a real implementation, this would analyze the codebase
        # to ensure no dangerous operations are called

        return ValidationResult(
            is_compliant=len(violations) == 0,
            violations=violations,
            recommendations=recommendations
        )


# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)

    validator = SecurityValidator()

    # Validate authorization model
    auth_result = validator.check_authorization_model(["SRGBTBREL", "SOFFPHIO", "SOFFCONT1"])
    print(f"Authorization Model: {'COMPLIANT' if auth_result.is_compliant else 'NON-COMPLIANT'}")
    print(f"Violations: {len(auth_result.violations)}")
    print(f"Recommendations: {len(auth_result.recommendations)}")

    # Validate connection parameters
    config = {
        'ashost': 'sapserver.local',
        'sysnr': '00',
        'client': '100',
        'user': 'RFC_READ_USER',
        'passwd': 'password',
        'trace': '0'
    }
    conn_result = validator.validate_connection_params(config)
    print(f"\\nConnection Security: {'COMPLIANT' if conn_result.is_compliant else 'NON-COMPLIANT'}")