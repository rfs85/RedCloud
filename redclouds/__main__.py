"""Main entry point for the RedClouds CLI."""
import os
import sys
import click
import logging
from typing import List, Optional
from dotenv import load_dotenv

from .cloud_providers.base import ResourceType
from .utils.config import load_config
from .utils.credentials import get_credentials
from .reporting.report_generator import generate_report


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def validate_providers(ctx, param, value):
    """Validate the provided cloud providers."""
    valid_providers = {'aws', 'azure', 'gcp'}
    if not value:
        return []
    providers = [p.lower() for p in value]
    invalid = set(providers) - valid_providers
    if invalid:
        raise click.BadParameter(
            f"Invalid provider(s): {', '.join(invalid)}. "
            f"Valid providers are: {', '.join(valid_providers)}"
        )
    return providers


def validate_output_format(ctx, param, value):
    """Validate the output format."""
    valid_formats = {'json', 'csv', 'md', 'txt'}
    if value.lower() not in valid_formats:
        raise click.BadParameter(
            f"Invalid format: {value}. "
            f"Valid formats are: {', '.join(valid_formats)}"
        )
    return value.lower()


@click.group()
@click.version_option(version='0.1.0')
def cli():
    """RedClouds - Multi-Cloud Security Auditing Tool.

    Audit security configurations across AWS, Azure, and GCP cloud providers.
    """
    # Load environment variables from .env file if it exists
    load_dotenv()


@cli.command()
@click.option(
    '--providers',
    multiple=True,
    callback=validate_providers,
    help='Cloud providers to audit (aws, azure, gcp)'
)
@click.option(
    '--region',
    multiple=True,
    help='Regions to audit (can specify multiple)'
)
@click.option(
    '--checks',
    multiple=True,
    type=click.Choice([r.value for r in ResourceType], case_sensitive=False),
    help='Types of checks to run'
)
@click.option(
    '--output-format',
    default='json',
    callback=validate_output_format,
    help='Output format (json, csv, md, txt)'
)
@click.option(
    '--output-file',
    type=click.Path(dir_okay=False, writable=True),
    help='Output file path'
)
@click.option(
    '--verbose',
    is_flag=True,
    help='Enable verbose logging'
)
def audit(
    providers: List[str],
    region: Optional[List[str]],
    checks: Optional[List[str]],
    output_format: str,
    output_file: Optional[str],
    verbose: bool
):
    """Run security audit on specified cloud providers."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not providers:
        providers = ['aws', 'azure', 'gcp']
        logger.info("No providers specified, will attempt to audit all providers")

    # Load configuration
    config = load_config()

    all_results = []
    for provider in providers:
        try:
            # Get provider-specific credentials
            credentials = get_credentials(provider)
            if not credentials:
                logger.warning(f"No credentials found for {provider}, skipping...")
                continue

            # Import the appropriate provider class
            provider_module = __import__(
                f'redclouds.cloud_providers.{provider}',
                fromlist=[provider.upper()]
            )
            provider_class = getattr(provider_module, provider.upper())

            # Initialize provider
            cloud_provider = provider_class(credentials=credentials)
            if not cloud_provider.validate_credentials():
                logger.error(f"Invalid credentials for {provider}, skipping...")
                continue

            # Connect to the provider
            if not cloud_provider.connect():
                logger.error(f"Failed to connect to {provider}, skipping...")
                continue

            # Get available regions if none specified
            regions = region or cloud_provider.get_regions()

            # Run audits for each region
            for r in regions:
                cloud_provider.region = r
                logger.info(f"Auditing {provider} in region {r}...")

                if not checks:
                    # Run all checks
                    results = cloud_provider.audit_all()
                else:
                    # Run specific checks
                    results = []
                    for check in checks:
                        check_method = f'audit_{check}'
                        if hasattr(cloud_provider, check_method):
                            results.extend(
                                getattr(cloud_provider, check_method)()
                            )

                all_results.extend(results)

        except Exception as e:
            logger.error(f"Error auditing {provider}: {str(e)}")
            if verbose:
                logger.exception(e)

    # Generate report
    if all_results:
        generate_report(
            results=all_results,
            output_format=output_format,
            output_file=output_file
        )
    else:
        logger.warning("No audit results generated")


if __name__ == '__main__':
    cli() 