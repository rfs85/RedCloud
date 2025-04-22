#!/usr/bin/env python3
"""RedClouds - Multi-Cloud Security Auditing Tool."""

import os
import sys
import click
import logging
from typing import List, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import json
import pandas as pd
from datetime import datetime
import re
import requests
from urllib.parse import urlparse
from rich.layout import Layout
from rich.spinner import Spinner
from rich.text import Text
from rich import box

from redclouds.cloud_providers.aws import AWS
from redclouds.cloud_providers.azure import Azure
from redclouds.cloud_providers.gcp import GCP
from redclouds.cloud_providers.base import AuditResult, Severity
from redclouds.utils.config import load_config

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress unnecessary warnings
logging.getLogger('google.auth').setLevel(logging.ERROR)
logging.getLogger('google.auth.compute_engine._metadata').setLevel(logging.ERROR)
logging.getLogger('redclouds.cloud_providers').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)
logging.getLogger('boto3').setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.ERROR)
logging.getLogger('azure').setLevel(logging.ERROR)

# Create a global console instance
console = Console()

def handle_error(message: str, exit_code: int = 1):
    """Handle errors consistently throughout the application."""
    console.print(f"[red]Error: {message}[/red]")
    if exit_code:
        sys.exit(exit_code)

def enumerate_aws_resources(domain: str, company: str) -> List[dict]:
    """Enumerate AWS resources without authentication."""
    results = []
    
    try:
        # Common S3 bucket patterns
        bucket_patterns = [
            f"{domain}",
            f"{domain}-backup",
            f"{domain}-dev",
            f"{domain}-prod",
            f"{domain}-stage",
            f"{domain}-staging",
            f"{domain}-test",
            f"{domain}-data",
            f"{domain}-assets",
            f"{domain}-media",
            f"{domain}-static",
            f"{domain}-files",
            f"{company}",
            f"{company}-backup",
            f"{company}-dev",
            f"{company}-prod",
            f"{company}-stage",
            f"{company}-staging",
            f"{company}-test",
            f"{company}-data",
            f"{company}-assets",
            f"{company}-media",
            f"{company}-static",
            f"{company}-files"
        ]

        console.print("[cyan]Enumerating S3 buckets...[/cyan]")
        
        # Try to access each potential bucket
        for pattern in bucket_patterns:
            if not pattern:  # Skip empty patterns
                continue
            pattern = pattern.lower().replace('_', '-')  # S3 buckets can't have underscores
            url = f"https://{pattern}.s3.amazonaws.com"
            try:
                response = requests.head(url, timeout=3)
                if response.status_code in [200, 403]:  # 403 means bucket exists but is private
                    results.append({
                        'provider': 'aws',
                        'service': 's3',
                        'resource_type': 'bucket',
                        'name': pattern,
                        'url': url,
                        'status': 'public' if response.status_code == 200 else 'private'
                    })
                    console.print(f"[green]Found bucket: {pattern} ({results[-1]['status']})[/green]")
            except requests.exceptions.RequestException:
                continue
            
        console.print("[cyan]Enumerating AWS services...[/cyan]")
        
        # Try common AWS service endpoints
        services = ['ec2', 'rds', 'elasticbeanstalk', 'elb', 'cloudfront']
        regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1']
        
        for service in services:
            for region in regions:
                patterns = [p for p in [domain, company] if p]  # Filter out empty values
                patterns.extend([
                    f"{domain}-{service}" if domain else None,
                    f"{company}-{service}" if company else None
                ])
                patterns = [p for p in patterns if p]  # Filter out None values
                
                for pattern in patterns:
                    pattern = pattern.lower().replace('_', '-')
                    # Skip service enumeration as it produces too many false positives
                    continue
                        
    except Exception as e:
        logger.error(f"Error enumerating AWS resources: {str(e)}")
    
    return results

def enumerate_azure_resources(domain: str, company: str) -> List[dict]:
    """Enumerate Azure resources without authentication."""
    results = []
    
    try:
        # Common Azure patterns
        patterns = []
        if domain:
            patterns.extend([
                f"{domain}",
                f"{domain}-webapp",
                f"{domain}-storage",
                f"{domain}-function",
                f"{domain}-app",
                f"{domain}-api"
            ])
        if company:
            patterns.extend([
                f"{company}",
                f"{company}-webapp",
                f"{company}-storage",
                f"{company}-function",
                f"{company}-app",
                f"{company}-api"
            ])
        
        # Try common Azure storage accounts
        for pattern in patterns:
            pattern = pattern.lower().replace('_', '').replace('-', '')[:24]  # Azure storage name restrictions
            url = f"https://{pattern}.blob.core.windows.net"
            try:
                response = requests.head(url, timeout=3)
                # Only report 200 (public) or 403 (exists but private)
                if response.status_code in [200, 403]:
                    results.append({
                        'provider': 'azure',
                        'service': 'storage',
                        'resource_type': 'blob',
                        'name': pattern,
                        'url': url,
                        'status': 'public' if response.status_code == 200 else 'private'
                    })
                    console.print(f"[green]Found storage account: {pattern} ({results[-1]['status']})[/green]")
            except requests.exceptions.RequestException:
                continue
                
        # Try Azure Web Apps
        for pattern in patterns:
            pattern = pattern.lower().replace('_', '-')
            urls = [
                f"https://{pattern}.azurewebsites.net",
                f"https://{pattern}-dev.azurewebsites.net",
                f"https://{pattern}-prod.azurewebsites.net"
            ]
            for url in urls:
                try:
                    response = requests.head(url, timeout=3)
                    # Only report 200 (exists) or specific Azure error codes
                    if response.status_code in [200, 403, 404]:
                        results.append({
                            'provider': 'azure',
                            'service': 'webapp',
                            'resource_type': 'website',
                            'name': pattern,
                            'url': url,
                            'status': 'public' if response.status_code == 200 else 'private'
                        })
                        if response.status_code == 200:
                            console.print(f"[green]Found web app: {pattern}[/green]")
                except requests.exceptions.RequestException:
                    continue
                    
    except Exception as e:
        logger.error(f"Error enumerating Azure resources: {str(e)}")
    
    return results

def enumerate_gcp_resources(domain: str, company: str) -> List[dict]:
    """Enumerate GCP resources without authentication."""
    results = []
    
    try:
        # Common GCP patterns
        patterns = []
        if domain:
            patterns.extend([
                f"{domain}",
                f"{domain}-storage",
                f"{domain}-app",
                f"{domain}-function",
                f"{domain}-bucket",
                f"{domain}-data"
            ])
        if company:
            patterns.extend([
                f"{company}",
                f"{company}-storage",
                f"{company}-app",
                f"{company}-function",
                f"{company}-bucket",
                f"{company}-data"
            ])
        
        # Try GCP Storage buckets
        for pattern in patterns:
            if not pattern:  # Skip empty patterns
                continue
            pattern = pattern.lower().replace('_', '-')
            url = f"https://storage.googleapis.com/{pattern}"
            try:
                response = requests.head(url, timeout=3)
                # Only report 200 (public) or 403 (exists but private)
                if response.status_code in [200, 403]:
                    results.append({
                        'provider': 'gcp',
                        'service': 'storage',
                        'resource_type': 'bucket',
                        'name': pattern,
                        'url': url,
                        'status': 'public' if response.status_code == 200 else 'private'
                    })
                    console.print(f"[green]Found bucket: {pattern} ({results[-1]['status']})[/green]")
            except requests.exceptions.RequestException:
                continue
                
        # Try App Engine apps
        for pattern in patterns:
            if not pattern:  # Skip empty patterns
                continue
            pattern = pattern.lower().replace('_', '-')
            urls = [
                f"https://{pattern}.appspot.com",
                f"https://{pattern}-dev.appspot.com",
                f"https://{pattern}-prod.appspot.com"
            ]
            for url in urls:
                try:
                    response = requests.head(url, timeout=3)
                    # Only report 200 (exists) or specific GCP error codes
                    if response.status_code == 200:
                        results.append({
                            'provider': 'gcp',
                            'service': 'appengine',
                            'resource_type': 'app',
                            'name': pattern,
                            'url': url,
                            'status': 'public'
                        })
                        console.print(f"[green]Found App Engine app: {pattern}[/green]")
                except requests.exceptions.RequestException:
                    continue
                    
    except Exception as e:
        logger.error(f"Error enumerating GCP resources: {str(e)}")
    
    return results

def search_resources(provider_instance, company=None, domain=None):
    """Search for resources across cloud providers."""
    try:
        if hasattr(provider_instance, 'search_resources'):
            results = provider_instance.search_resources(domain=domain, company=company)
            return results
        return []
    except Exception:
        return []  # Return empty list on any error

def setup_cloud_provider(provider: str, config: dict) -> Optional[AWS | Azure | GCP]:
    """Initialize cloud provider based on configuration."""
    try:
        if provider == "aws":
            return AWS(
                access_key=config.get("aws", {}).get("access_key"),
                secret_key=config.get("aws", {}).get("secret_key"),
                region=config.get("aws", {}).get("region")
            )
        elif provider == "azure":
            azure_config = config.get("azure", {})
            credentials = {}
            if azure_config:
                credentials = {
                    'subscription_id': azure_config.get('subscription_id'),
                    'client_id': azure_config.get('client_id'),
                    'client_secret': azure_config.get('client_secret')
                }
            return Azure(credentials=credentials)
        elif provider == "gcp":
            return GCP(
                credentials_path=config.get("gcp", {}).get("credentials_path"),
                project_id=config.get("gcp", {}).get("project_id")
            )
    except Exception:
        return None  # Silently fail and return None

def generate_report(results: List[AuditResult], format: str, output: str):
    """Generate audit report in specified format.
    
    Args:
        results: List of audit results
        format: Output format (text, json, csv, markdown, html)
        output: Output file path
    """
    if format == "html":
        # Generate HTML report with CSS styling
        html_content = """
        <html>
        <head>
            <title>RedClouds Security Audit Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #2c3e50; }
                .summary { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
                .summary h2 { color: #34495e; }
                table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #34495e; color: white; }
                tr:nth-child(even) { background-color: #f8f9fa; }
                .pass { color: #27ae60; }
                .fail { color: #e74c3c; }
                .error { color: #f39c12; }
                .info { color: #3498db; }
                .critical { background-color: #ffebee; }
                .high { background-color: #fff3e0; }
            </style>
        </head>
        <body>
            <h1>RedClouds Security Audit Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Total findings: {total}</p>
                <p>Failed checks: <span class="fail">{fails}</span></p>
                <p>Critical severity: <span class="fail">{criticals}</span></p>
                <p>High severity: <span class="fail">{highs}</span></p>
                <p>Generated on: {date}</p>
            </div>
            <table>
                <tr>
                    <th>Provider</th>
                    <th>Service</th>
                    <th>Check</th>
                    <th>Resource</th>
                    <th>Region</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Message</th>
                </tr>
        """

        # Add rows for each result
        for result in results:
            status_class = result.status.lower()
            severity_class = result.severity.name.lower()
            
            html_content += f"""
                <tr class="{severity_class}">
                    <td>{result.provider}</td>
                    <td>{result.service}</td>
                    <td>{result.check_id}</td>
                    <td>{result.resource_id}</td>
                    <td>{result.region}</td>
                    <td class="{status_class}">{result.status}</td>
                    <td>{result.severity.name}</td>
                    <td>{result.message}</td>
                </tr>
            """

        html_content += """
            </table>
        </body>
        </html>
        """

        # Add summary statistics
        total = len(results)
        fails = len([r for r in results if r.status == "FAIL"])
        criticals = len([r for r in results if r.severity == Severity.CRITICAL])
        highs = len([r for r in results if r.severity == Severity.HIGH])
        date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_content = html_content.format(
            total=total,
            fails=fails,
            criticals=criticals,
            highs=highs,
            date=date
        )

        if output:
            with open(output, "w", encoding='utf-8') as f:
                f.write(html_content)
        else:
            print(html_content)

    elif format == "text":
        # Create rich table
        table = Table(show_header=True, header_style="bold")
        table.add_column("Provider")
        table.add_column("Service")
        table.add_column("Check")
        table.add_column("Resource")
        table.add_column("Region")
        table.add_column("Status")
        table.add_column("Severity")
        table.add_column("Message")

        for result in results:
            status_color = {
                "PASS": "green",
                "FAIL": "red",
                "ERROR": "yellow",
                "INFO": "blue"
            }.get(result.status, "white")

            severity_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "green"
            }.get(result.severity, "white")

            table.add_row(
                result.provider,
                result.service,
                result.check_id,
                result.resource_id,
                result.region,
                f"[{status_color}]{result.status}[/{status_color}]",
                f"[{severity_color}]{result.severity.name}[/{severity_color}]",
                result.message
            )

        if output:
            with open(output, "w") as f:
                console = Console(file=f)
                console.print(table)
        else:
            console.print(table)

    elif format == "json":
        json_data = [result.__dict__ for result in results]
        if output:
            with open(output, "w") as f:
                json.dump(json_data, f, indent=2)
        else:
            print(json.dumps(json_data, indent=2))

    elif format == "csv":
        df = pd.DataFrame([result.__dict__ for result in results])
        if output:
            df.to_csv(output, index=False)
        else:
            print(df.to_csv(index=False))

    elif format == "markdown":
        md_lines = ["| Provider | Service | Check | Resource | Region | Status | Severity | Message |",
                   "|----------|----------|--------|-----------|---------|---------|-----------|---------|"]
        
        for result in results:
            md_lines.append(
                f"| {result.provider} | {result.service} | {result.check_id} | "
                f"{result.resource_id} | {result.region} | {result.status} | "
                f"{result.severity.name} | {result.message} |"
            )
        
        md_content = "\n".join(md_lines)
        if output:
            with open(output, "w") as f:
                f.write(md_content)
        else:
            print(md_content)

@click.group()
def cli():
    """RedClouds - Multi-Cloud Security Auditing Tool.
    
    Audit security configurations across AWS, Azure, and GCP.
    """
    pass

@cli.command()
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "gcp", "all"]),
    required=True,
    help="Cloud provider to audit"
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    default="config.yaml",
    help="Path to configuration file"
)
@click.option(
    "--format",
    type=click.Choice(["text", "json", "csv", "markdown", "html"]),
    default="text",
    help="Output format"
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output file path"
)
@click.option(
    "--service",
    multiple=True,
    help="Specific services to audit (e.g., iam, storage, network)"
)
def audit(provider: str, config: str, format: str, output: str, service: tuple):
    """Run security audit on specified cloud provider(s)."""
    all_results = []
    
    try:
        # Load configuration
        config_data = load_config(config)
        
        # Determine providers to audit
        providers = ["aws", "azure", "gcp"] if provider == "all" else [provider]
        
        with Progress() as progress:
            for cloud_provider in providers:
                task = progress.add_task(f"[cyan]Auditing {cloud_provider}...", total=100)
                
                # Initialize provider
                provider_instance = setup_cloud_provider(cloud_provider, config_data)
                if not provider_instance:
                    progress.update(task, completed=100)
                    continue

                # Connect to provider
                if not provider_instance.connect():
                    logger.error(f"Failed to connect to {cloud_provider}")
                    progress.update(task, completed=100)
                    continue

                progress.update(task, advance=20)

                # Run audits
                try:
                    if not service:  # If no specific services specified, audit all
                        results = []
                        if hasattr(provider_instance, "audit_iam"):
                            results.extend(provider_instance.audit_iam())
                        if hasattr(provider_instance, "audit_storage"):
                            results.extend(provider_instance.audit_storage())
                        if hasattr(provider_instance, "audit_network"):
                            results.extend(provider_instance.audit_network())
                        if hasattr(provider_instance, "audit_compute"):
                            results.extend(provider_instance.audit_compute())
                        if hasattr(provider_instance, "audit_database"):
                            results.extend(provider_instance.audit_database())
                        if hasattr(provider_instance, "audit_logging"):
                            results.extend(provider_instance.audit_logging())
                        if hasattr(provider_instance, "audit_monitoring"):
                            results.extend(provider_instance.audit_monitoring())
                        if hasattr(provider_instance, "audit_mongodb"):
                            results.extend(provider_instance.audit_mongodb())
                    else:
                        results = []
                        for svc in service:
                            method = getattr(provider_instance, f"audit_{svc}", None)
                            if method:
                                results.extend(method())
                            else:
                                logger.warning(f"Service '{svc}' not supported for {cloud_provider}")

                    all_results.extend(results)
                    progress.update(task, completed=100)

                except Exception as e:
                    logger.error(f"Error auditing {cloud_provider}: {str(e)}")
                    progress.update(task, completed=100)

    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        sys.exit(1)

    # Generate report
    if all_results:
        generate_report(all_results, format, output)
        
        # Print summary
        total = len(all_results)
        fails = len([r for r in all_results if r.status == "FAIL"])
        criticals = len([r for r in all_results if r.severity == Severity.CRITICAL])
        highs = len([r for r in all_results if r.severity == Severity.HIGH])
        
        console.print("\n[bold]Audit Summary:[/bold]")
        console.print(f"Total findings: {total}")
        console.print(f"Failed checks: [red]{fails}[/red]")
        console.print(f"Critical severity: [red]{criticals}[/red]")
        console.print(f"High severity: [red]{highs}[/red]")
        
        if output:
            console.print(f"\nReport saved to: {output}")
    else:
        console.print("[yellow]No audit results found.[/yellow]")

@cli.command()
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "gcp", "all"]),
    required=True,
    help="Cloud provider to search"
)
@click.option(
    "--company",
    help="Company name to search for"
)
@click.option(
    "--domain",
    help="Domain name to search for"
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    default="config.yaml",
    help="Path to configuration file"
)
@click.option(
    "--format",
    type=click.Choice(["text", "json", "csv", "html"]),
    default="text",
    help="Output format"
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output file path"
)
def search(provider: str, company: str, domain: str, config: str, format: str, output: str):
    """Search for resources across cloud providers."""
    if not company and not domain:
        console.print("[red]Error: Either --company or --domain must be specified[/red]")
        return

    # Clean up domain input if provided
    if domain:
        domain = urlparse(domain).netloc or domain  # Extract domain from URL if provided
        domain = domain.lower().replace('www.', '')  # Remove www if present

    # Suppress all logging
    for logger_name in ['', 'redclouds', 'google', 'azure', 'boto3', 'botocore', 'urllib3']:
        logging.getLogger(logger_name).setLevel(logging.CRITICAL)

    try:
        # Load configuration but don't fail if it doesn't exist
        config_data = {}
        try:
            config_data = load_config(config)
        except Exception:
            pass

        results = []
        providers_to_search = ['aws', 'azure', 'gcp'] if provider == 'all' else [provider]

        with console.status("[bold blue]Searching for resources...", spinner="dots") as status:
            for p in providers_to_search:
                try:
                    status.update(f"[bold blue]Searching {p.upper()} resources...")
                    provider_instance = setup_cloud_provider(p, config_data.get(p, {}))
                    if provider_instance:
                        try:
                            provider_instance.connect()
                            provider_results = search_resources(provider_instance, company, domain)
                            if provider_results:
                                results.extend(provider_results)
                                status.update(f"[green]Found {len(provider_results)} resources in {p.upper()}[/green]")
                        except Exception:
                            pass
                except Exception:
                    pass

        # Display results summary
        if results:
            console.print(f"\n[bold green]Found {len(results)} resources:[/bold green]")
            
            # Count resources by provider and type
            by_provider = {}
            for r in results:
                provider_name = r['provider'].upper()
                if provider_name not in by_provider:
                    by_provider[provider_name] = {'total': 0, 'public': 0, 'private': 0}
                by_provider[provider_name]['total'] += 1
                if r.get('public', False):
                    by_provider[provider_name]['public'] += 1
                else:
                    by_provider[provider_name]['private'] += 1

            # Display summary by provider
            for prov, counts in by_provider.items():
                console.print(f"\n[bold]{prov}[/bold]:")
                console.print(f"  Total: {counts['total']}")
                if counts['public'] > 0:
                    console.print(f"  [yellow]Public: {counts['public']}[/yellow]")
                if counts['private'] > 0:
                    console.print(f"  Private: {counts['private']}")

            console.print("\n[bold]Detailed Results:[/bold]")
            
            # Format and output detailed results
            if format == 'text':
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Provider", style="cyan")
                table.add_column("Service", style="green")
                table.add_column("Resource Type", style="yellow")
                table.add_column("Resource Name/ID", style="blue")
                table.add_column("Status", style="white")
                table.add_column("Details", style="white")

                for result in results:
                    # Handle dictionary results
                    details = []
                    for key, value in result.items():
                        if key not in ['provider', 'service', 'resource_type', 'name', 'status', 'url']:
                            details.append(f"{key}: {str(value)}")
                    
                    table.add_row(
                        str(result['provider']).upper(),
                        str(result['service']),
                        str(result['resource_type']),
                        str(result['name']),
                        str(result.get('status', 'N/A')),
                        str("\n".join(details) if details else result.get('url', 'N/A'))
                    )

                if output:
                    with open(output, 'w') as f:
                        f.write(str(table))
                else:
                    console.print(table)

            elif format == 'json':
                output_data = json.dumps(results, indent=2)
                if output:
                    with open(output, 'w') as f:
                        f.write(output_data)
                    console.print(f"\nResults saved to: [blue]{output}[/blue]")
                else:
                    print(output_data)

            elif format == 'csv':
                import csv
                import io

                # Flatten the results for CSV output
                flattened_results = []
                for result in results:
                    flat_result = {
                        'provider': result['provider'].upper(),
                        'service': result['service'],
                        'resource_type': result['resource_type'],
                        'name': result['name'],
                        'public': result.get('public', False)
                    }
                    # Add any additional fields
                    for key, value in result.items():
                        if key not in flat_result:
                            flat_result[key] = value
                    flattened_results.append(flat_result)

                # Get all unique fields for headers
                headers = set()
                for result in flattened_results:
                    headers.update(result.keys())
                headers = sorted(list(headers))

                # Write CSV
                output_buffer = io.StringIO() if not output else open(output, 'w', newline='')
                writer = csv.DictWriter(output_buffer, fieldnames=headers)
                writer.writeheader()
                writer.writerows(flattened_results)

                if output:
                    output_buffer.close()
                    console.print(f"\nResults saved to: [blue]{output}[/blue]")
                else:
                    print(output_buffer.getvalue())
                    output_buffer.close()

            elif format == 'html':
                # Generate HTML report for search results
                html_content = """
                <html>
                <head>
                    <title>RedClouds Resource Search Results</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        h1 { color: #2c3e50; }
                        .summary { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
                        .summary h2 { color: #34495e; }
                        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                        th { background-color: #34495e; color: white; }
                        tr:nth-child(even) { background-color: #f8f9fa; }
                        .public { color: #e74c3c; }
                        .private { color: #27ae60; }
                    </style>
                </head>
                <body>
                    <h1>RedClouds Resource Search Results</h1>
                    <div class="summary">
                        <h2>Summary</h2>
                """

                # Add provider summaries
                for prov, counts in by_provider.items():
                    html_content += f"""
                        <h3>{prov}</h3>
                        <p>Total resources: {counts['total']}</p>
                        <p>Public resources: <span class="public">{counts['public']}</span></p>
                        <p>Private resources: <span class="private">{counts['private']}</span></p>
                    """

                html_content += """
                    </div>
                    <table>
                        <tr>
                            <th>Provider</th>
                            <th>Service</th>
                            <th>Resource Type</th>
                            <th>Resource Name/ID</th>
                            <th>Status</th>
                            <th>Details</th>
                        </tr>
                """

                for result in results:
                    status = result.get('status', 'N/A')
                    status_class = 'public' if status == 'public' else 'private'
                    details = []
                    for key, value in result.items():
                        if key not in ['provider', 'service', 'resource_type', 'name', 'status', 'url']:
                            details.append(f"{key}: {str(value)}")

                    html_content += f"""
                        <tr>
                            <td>{str(result['provider']).upper()}</td>
                            <td>{str(result['service'])}</td>
                            <td>{str(result['resource_type'])}</td>
                            <td>{str(result['name'])}</td>
                            <td class="{status_class}">{str(status)}</td>
                            <td>{str("\n".join(details) if details else result.get('url', 'N/A'))}</td>
                        </tr>
                    """

                html_content += """
                    </table>
                </body>
                </html>
                """

                if output:
                    with open(output, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                else:
                    print(html_content)

        else:
            console.print("\n[yellow]No resources found matching the search criteria.[/yellow]")

    except Exception as e:
        console.print(f"[red]Error during search: {str(e)}[/red]")
    finally:
        # Restore logging level
        for logger_name in ['', 'redclouds', 'google', 'azure', 'boto3', 'botocore', 'urllib3']:
            logging.getLogger(logger_name).setLevel(logging.INFO)

@cli.command()
def version():
    """Display version information."""
    console.print("RedClouds v1.0.0")

if __name__ == "__main__":
    cli() 