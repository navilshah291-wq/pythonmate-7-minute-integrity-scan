"""
GOS Integrity Scanner - The 7-Minute SOFFCONT1 Bloat Analysis

Identifies orphaned entries in SOFFCONT1 table by:
1. Tracing SRGBTBREL → SOFFPHIO → SOFFCONT1 relationships
2. Using set theory to detect unmapped physical objects
3. Calculating storage impact and cost projections
4. Generating executive summary

This module implements the core 7-minute scan algorithm that identifies
SOFFCONT1 bloat without touching sensitive binary data (CLUSTD column).
"""

from typing import Dict, List, Set, Tuple, Generator
from datetime import datetime
from dataclasses import dataclass
import logging

from .sap_connector import SapConnector, RFCConfig


@dataclass
class ScanResult:
    """Results of a GOS integrity scan."""
    timestamp: datetime
    system_name: str
    client: str
    total_soffcont1_rows: int
    orphaned_phio_count: int
    orphaned_cont_count: int
    integrity_score: float  # 0-100, higher is better
    estimated_storage_mb: float
    estimated_cost_usd: float
    recommendations: List[str]

    def integrity_score_percent(self) -> float:
        """Returns integrity score as percentage (0-100)"""
        return self.integrity_score

logger = logging.getLogger(__name__)


class GOSIntegrityScanner:
    """
    Enterprise-grade GOS integrity scanner for SOFFCONT1 bloat analysis.

    The 7-Minute Algorithm:
    1. Fetch all PHIO_IDs from SOFFPHIO (Physical Objects)
    2. Fetch all LOIO_IDs referenced in SRGBTBREL (Relationships)
    3. Find PHIO_IDs not present in LOIO_ID set (orphans)
    4. Count corresponding SOFFCONT1 entries
    5. Calculate storage impact and cost projections

    This approach avoids direct access to CLUSTD (binary data) column,
    ensuring compliance with security policies.
    """

    def __init__(self, connector: SapConnector):
        self.connector = connector
        
    def run_integrity_scan(
        self,
        system_name: str,
        batch_size: int = 5000,
        max_rows: int = 50000,
        enable_sampling: bool = True
    ) -> ScanResult:
        """
        Execute the 7-minute GOS integrity scan.

        Args:
            system_name: SAP system identifier (e.g., 'PRD', 'QAS')
            batch_size: Rows per RFC_READ_TABLE call (5000 recommended)
            max_rows: Max rows to process (for sampling)
            enable_sampling: Whether to limit scan duration

        Returns:
            ScanResult with integrity metrics
        """
        start_time = datetime.now()
        logger.info(f"Starting GOS integrity scan for system: {system_name}")

        # Step 1: Get total SOFFCONT1 row count
        total_soffcont1 = self.connector.get_table_row_count("SOFFCONT1")

        # Step 2: Collect all LOIO_IDs referenced in relationships
        logger.info("Collecting active LOIO_IDs from SRGBTBREL...")
        active_loio_ids = self._collect_active_loio_ids(batch_size, max_rows, enable_sampling)

        # Step 3: Collect all PHIO_IDs from SOFFPHIO
        logger.info("Collecting all PHIO_IDs from SOFFPHIO...")
        all_phio_ids = self._collect_all_phio_ids(batch_size, max_rows, enable_sampling)

        # Step 4: Find orphaned PHIO_IDs (present in SOFFPHIO but not referenced)
        orphaned_phio_ids = all_phio_ids - active_loio_ids
        orphaned_phio_count = len(orphaned_phio_ids)

        # Step 5: Count corresponding SOFFCONT1 entries for orphaned PHIOs
        orphaned_cont_count = self._count_orphaned_cont_entries(list(orphaned_phio_ids), batch_size)

        # Step 6: Calculate metrics
        integrity_score = (
            ((len(all_phio_ids) - orphaned_phio_count) / len(all_phio_ids)) * 100
            if all_phio_ids else 100.0
        )

        # Storage estimation (approximate - based on typical record size)
        # Each SOFFCONT1 record ~ 2KB uncompressed average
        estimated_storage_mb = orphaned_cont_count * 0.002  # 2KB = 0.002 MB
        estimated_cost_usd = estimated_storage_mb * 0.05  # $50/GB = $0.05/MB

        # Generate recommendations
        recommendations = self._generate_recommendations(
            orphaned_phio_count,
            estimated_storage_mb,
            integrity_score
        )

        scan_duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"GOS integrity scan completed in {scan_duration:.2f} seconds")

        return ScanResult(
            timestamp=datetime.now(),
            system_name=system_name,
            client=self.connector.config.client,
            total_soffcont1_rows=total_soffcont1,
            orphaned_phio_count=orphaned_phio_count,
            orphaned_cont_count=orphaned_cont_count,
            integrity_score=round(integrity_score, 2),
            estimated_storage_mb=round(estimated_storage_mb, 2),
            estimated_cost_usd=round(estimated_cost_usd, 2),
            recommendations=recommendations
        )

    def _collect_active_loio_ids(
        self,
        batch_size: int,
        max_rows: int,
        enable_sampling: bool
    ) -> Set[str]:
        """Collect all LOIO_IDs referenced in SRGBTBREL relationships."""
        active_loio_ids: Set[str] = set()

        where_clause = "OBJTYPE_B = 'PHIO'"  # Focus on PHIO relationships

        for batch in self.connector.fetch_table_batch(
            "SRGBTBREL",
            ["INSTID_B"],
            where_clause,
            batch_size=batch_size,
            max_rows=max_rows if enable_sampling else None
        ):
            for row in batch:
                loio_id = row["INSTID_B"].strip()
                if loio_id:
                    active_loio_ids.add(loio_id)

        logger.info(f"Collected {len(active_loio_ids)} active LOIO_IDs")
        return active_loio_ids

    def _collect_all_phio_ids(
        self,
        batch_size: int,
        max_rows: int,
        enable_sampling: bool
    ) -> Set[str]:
        """Collect all PHIO_IDs from SOFFPHIO table."""
        all_phio_ids: Set[str] = set()

        for batch in self.connector.fetch_table_batch(
            "SOFFPHIO",
            ["PHIO_ID"],
            batch_size=batch_size,
            max_rows=max_rows if enable_sampling else None
        ):
            for row in batch:
                phio_id = row["PHIO_ID"].strip()
                if phio_id:
                    all_phio_ids.add(phio_id)

        logger.info(f"Collected {len(all_phio_ids)} total PHIO_IDs")
        return all_phio_ids

    def _count_orphaned_cont_entries(self, orphaned_phio_ids: List[str], batch_size: int) -> int:
        """Count SOFFCONT1 entries for orphaned PHIO IDs."""
        if not orphaned_phio_ids:
            return 0

        # Build WHERE clause for PHIO_IDs (batched to avoid exceeding limits)
        count = 0
        batch_size_ids = 1000  # Limit for IN clause

        for i in range(0, len(orphaned_phio_ids), batch_size_ids):
            batch_phio_ids = orphaned_phio_ids[i:i + batch_size_ids]
            where_clause = f"PHIO_ID IN ('{'',''.join(batch_phio_ids)}')"

            for batch in self.connector.fetch_table_batch(
                "SOFFCONT1",
                ["PHIO_ID"],  # Just count rows
                where_clause,
                batch_size=batch_size
            ):
                count += len(batch)

        logger.info(f"Found {count} orphaned SOFFCONT1 entries")
        return count

    def _generate_recommendations(
        self,
        orphaned_phio_count: int,
        estimated_storage_mb: float,
        integrity_score: float
    ) -> List[str]:
        """Generate actionable recommendations based on scan results."""
        recommendations = []

        if integrity_score < 90:
            recommendations.append(
                "CRITICAL: Integrity score below 90%. Immediate cleanup recommended."
            )
        elif integrity_score < 95:
            recommendations.append(
                "WARNING: Integrity score below 95%. Cleanup recommended."
            )

        if estimated_storage_mb > 100:  # More than 100MB
            recommendations.append(
                f"HIGH STORAGE: {estimated_storage_mb:.2f}MB available for cleanup. "
                "Consider Content Server migration."
            )

        if orphaned_phio_count > 1000:
            recommendations.append(
                f"LARGE ORPHAN COUNT: {orphaned_phio_count} orphaned records found. "
                "Run archiving utilities to reclaim space."
            )

        recommendations.extend([
            "Validate findings in non-production system before cleanup",
            "Backup relevant tables before executing cleanup operations",
            "Review relationship mappings to confirm orphans are truly unused"
        ])

        return recommendations


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # Example configuration
    config = RFCConfig(
        ashost="sapserver.local",
        sysnr="00",
        client="100",
        user="RFC_USER",
        passwd="password"
    )

    connector = SapConnector(config)
    scanner = GOSIntegrityScanner(connector)

    try:
        connector.connect()

        # Run the 7-minute scan
        result = scanner.run_integrity_scan(
            system_name="PRD",
            batch_size=5000,
            max_rows=50000,
            enable_sampling=True
        )

        print(f"\\nGOS Integrity Scan Results:")
        print(f"System: {result.system_name}")
        print(f"Timestamp: {result.timestamp}")
        print(f"Total SOFFCONT1 Rows: {result.total_soffcont1_rows:,}")
        print(f"Orphaned PHIO Count: {result.orphaned_phio_count:,}")
        print(f"Orphaned CONT Count: {result.orphaned_cont_count:,}")
        print(f"Integrity Score: {result.integrity_score}%")
        print(f"Estimated Storage Reclaimable: {result.estimated_storage_mb:.2f} MB")
        print(f"Estimated Cost Savings: ${result.estimated_cost_usd:.2f}")
        print(f"\\nRecommendations:")
        for rec in result.recommendations:
            print(f"- {rec}")

    finally:
        connector.disconnect()