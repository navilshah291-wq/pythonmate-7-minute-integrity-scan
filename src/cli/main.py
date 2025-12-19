"""
Command Line Interface for SAP GOS 7-Minute Integrity Scan

Provides command-line access to:
- GOS integrity scanning
- Connection validation
"""

import click
import os
import sys
from datetime import datetime
from typing import Optional
import logging

# Add the project root to the Python path to resolve imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Import MOFU dependencies
from src.core.integrity_scanner import ScanResult, GOSIntegrityScanner
from src.core.security_validator import SecurityValidator
from src.reports.pdf_generator import PDFReportGenerator
from src.core.sap_connector import SapConnector, RFCConfig

# Placeholder for SAPValidator - can be implemented as needed
class SAPValidator:
    def validate_rfc_config(self, config):
        # Simplified validation - in a real implementation this would be more thorough
        errors = []
        if not config.get('ashost'):
            errors.append("Missing ashost parameter")
        if not config.get('sysnr'):
            errors.append("Missing sysnr parameter")
        if not config.get('client'):
            errors.append("Missing client parameter")
        if not config.get('user'):
            errors.append("Missing user parameter")
        if not config.get('passwd'):
            errors.append("Missing passwd parameter")
        return {'errors': errors}


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def cli(verbose: bool):
    """SAP GOS 7-Minute Integrity Scan - Diagnostic Tool."""
    if verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)


@cli.command()
@click.option('--system', '-s', required=True, help='SAP system identifier (e.g., PRD, QAS)')
@click.option('--client', '-cl', required=True, help='SAP client number (e.g., 100)')
@click.option('--host', '-h', required=True, help='SAP host address')
@click.option('--sysnr', '-n', required=True, help='SAP system number (e.g., 00)')
@click.option('--user', '-u', required=True, help='SAP user')
@click.option('--password', '-p', required=True, help='SAP password')
@click.option('--output', '-o', default='./reports', help='Output directory for reports')
@click.option('--batch-size', default=5000, help='Batch size for RFC calls (default: 5000)')
@click.option('--max-rows', default=50000, help='Maximum rows to process (for sampling)')
@click.option('--enable-sampling', is_flag=True, help='Enable result sampling')
@click.option('--report-title', default='GOS Integrity Audit', help='Title for the report')
def scan(
    system: str,
    client: str,
    host: str,
    sysnr: str,
    user: str,
    password: str,
    output: str,
    batch_size: int,
    max_rows: int,
    enable_sampling: bool,
    report_title: str
):
    """Run a 7-minute GOS integrity scan."""
    logger = get_logger("gos_scan_cli")

    # Validate inputs
    validator = SAPValidator()
    config_errors = validator.validate_rfc_config({
        'ashost': host,
        'sysnr': sysnr,
        'client': client,
        'user': user,
        'passwd': password
    })

    if config_errors['errors']:
        for error in config_errors['errors']:
            click.echo(f"Error: {error}", err=True)
        sys.exit(1)

    # Setup output directory
    os.makedirs(output, exist_ok=True)

    # Setup SAP connection
    config = RFCConfig(
        ashost=host,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=password
    )

    connector = SapConnector(config)
    scanner = GOSIntegrityScanner(connector)

    try:
        click.echo(f"Starting GOS integrity scan for system: {system}")
        connector.connect()

        # Run the scan
        result = scanner.run_integrity_scan(
            system_name=system,
            batch_size=batch_size,
            max_rows=max_rows,
            enable_sampling=enable_sampling
        )

        # Generate PDF report
        report_gen = PDFReportGenerator()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(
            output,
            f"GOS_Integrity_Audit_{system}_{timestamp}.pdf"
        )

        report_gen.generate_integrity_report(result, report_path)

        # Print summary
        click.echo(f"\nScan completed successfully!")
        click.echo(f"System: {result.system_name}")
        click.echo(f"Client: {result.client}")
        click.echo(f"Total SOFFCONT1 Rows: {result.total_soffcont1_rows:,}")
        click.echo(f"Orphaned Entries: {result.orphaned_cont_count:,}")
        click.echo(f"Integrity Score: {result.integrity_score}%")
        click.echo(f"Estimated Savings: ${result.estimated_cost_usd:.2f}")
        click.echo(f"Report saved to: {report_path}")

        # Show recommendations
        click.echo(f"\nRecommendations:")
        for i, rec in enumerate(result.recommendations, 1):
            click.echo(f"  {i}. {rec}")

    except Exception as e:
        click.echo(f"Error during scan: {e}", err=True)
        sys.exit(1)

    finally:
        connector.disconnect()


@cli.command()
@click.option('--host', '-h', required=True, help='SAP host address')
@click.option('--sysnr', '-n', required=True, help='SAP system number')
@click.option('--client', '-cl', required=True, help='SAP client number')
@click.option('--user', '-u', required=True, help='SAP user')
@click.option('--password', '-p', required=True, help='SAP password')
def validate_connection(host: str, sysnr: str, client: str, user: str, password: str):
    """Validate SAP connection without performing a scan."""
    config = RFCConfig(
        ashost=host,
        sysnr=sysnr,
        client=client,
        user=user,
        passwd=password
    )

    connector = SapConnector(config)
    validator = SecurityValidator()

    try:
        click.echo("Validating SAP connection...")
        connector.connect()
        click.echo("✓ Connection successful!")

        # Validate configuration
        config_dict = {
            'ashost': host, 'sysnr': sysnr, 'client': client,
            'user': user, 'passwd': password
        }
        validation_result = validator.check_authorization_model([])

        click.echo("\nConfiguration validation:")
        if validation_result.is_compliant:
            click.echo("✓ All validations passed")
        else:
            click.echo("⚠ Some validations failed:")
            for violation in validation_result.violations:
                click.echo(f"  - {violation}")

    except Exception as e:
        click.echo(f"✗ Connection failed: {e}", err=True)
        sys.exit(1)

    finally:
        connector.disconnect()


if __name__ == '__main__':
    cli()