"""Report generation utilities."""
import json
import csv
import sys
from typing import List, Optional, TextIO
import pandas as pd
from tabulate import tabulate
from datetime import datetime

from ..cloud_providers.base import AuditResult


def generate_report(
    results: List[AuditResult],
    output_format: str = 'json',
    output_file: Optional[str] = None
) -> None:
    """Generate a report from audit results.

    Args:
        results: List of AuditResult objects
        output_format: Format of the report (json, csv, md, txt)
        output_file: Optional file path to write the report to
    """
    if not results:
        return

    # Convert results to a list of dictionaries for easier processing
    report_data = [
        {
            'provider': result.resource_id.split('/')[0],
            'check_id': result.check_id,
            'resource_id': result.resource_id,
            'resource_type': result.resource_type.value,
            'status': result.status,
            'details': result.details,
            'recommendation': result.recommendation
        }
        for result in results
    ]

    # Generate report in specified format
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            _write_report(report_data, output_format, f)
    else:
        _write_report(report_data, output_format, sys.stdout)


def _write_report(data: List[dict], format: str, output: TextIO) -> None:
    """Write report in specified format to output stream.

    Args:
        data: List of dictionaries containing report data
        format: Output format (json, csv, md, txt)
        output: Output stream to write to
    """
    if format == 'json':
        _write_json(data, output)
    elif format == 'csv':
        _write_csv(data, output)
    elif format == 'md':
        _write_markdown(data, output)
    else:  # txt
        _write_text(data, output)


def _write_json(data: List[dict], output: TextIO) -> None:
    """Write report in JSON format."""
    report = {
        'metadata': {
            'generated_at': datetime.utcnow().isoformat(),
            'total_checks': len(data),
            'summary': {
                'pass': len([r for r in data if r['status'] == 'pass']),
                'fail': len([r for r in data if r['status'] == 'fail']),
                'warning': len([r for r in data if r['status'] == 'warning'])
            }
        },
        'results': data
    }
    json.dump(report, output, indent=2)


def _write_csv(data: List[dict], output: TextIO) -> None:
    """Write report in CSV format."""
    if not data:
        return

    # Flatten the details dictionary into separate columns
    flattened_data = []
    for item in data:
        flat_item = item.copy()
        details = flat_item.pop('details', {})
        for k, v in details.items():
            flat_item[f'detail_{k}'] = str(v)
        flattened_data.append(flat_item)

    writer = csv.DictWriter(output, fieldnames=flattened_data[0].keys())
    writer.writeheader()
    writer.writerows(flattened_data)


def _write_markdown(data: List[dict], output: TextIO) -> None:
    """Write report in Markdown format."""
    # Write report header
    output.write("# Cloud Security Audit Report\n\n")
    output.write(f"Generated at: {datetime.utcnow().isoformat()}\n\n")

    # Write summary
    total = len(data)
    passed = len([r for r in data if r['status'] == 'pass'])
    failed = len([r for r in data if r['status'] == 'fail'])
    warnings = len([r for r in data if r['status'] == 'warning'])

    output.write("## Summary\n\n")
    output.write(f"- Total Checks: {total}\n")
    output.write(f"- Passed: {passed}\n")
    output.write(f"- Failed: {failed}\n")
    output.write(f"- Warnings: {warnings}\n\n")

    # Group results by provider and resource type
    df = pd.DataFrame(data)
    for provider in df['provider'].unique():
        output.write(f"## {provider.upper()}\n\n")
        provider_data = df[df['provider'] == provider]
        
        for res_type in provider_data['resource_type'].unique():
            output.write(f"### {res_type.upper()}\n\n")
            type_data = provider_data[df['resource_type'] == res_type]
            
            # Create a table for this resource type
            table_data = type_data[[
                'check_id', 'resource_id', 'status', 'recommendation'
            ]].values.tolist()
            
            output.write(tabulate(
                table_data,
                headers=['Check ID', 'Resource ID', 'Status', 'Recommendation'],
                tablefmt='pipe'
            ))
            output.write("\n\n")


def _write_text(data: List[dict], output: TextIO) -> None:
    """Write report in plain text format."""
    # Write header
    output.write("Cloud Security Audit Report\n")
    output.write("=" * 30 + "\n\n")
    output.write(f"Generated at: {datetime.utcnow().isoformat()}\n\n")

    # Write summary
    total = len(data)
    passed = len([r for r in data if r['status'] == 'pass'])
    failed = len([r for r in data if r['status'] == 'fail'])
    warnings = len([r for r in data if r['status'] == 'warning'])

    output.write("Summary:\n")
    output.write("-" * 8 + "\n")
    output.write(f"Total Checks: {total}\n")
    output.write(f"Passed: {passed}\n")
    output.write(f"Failed: {failed}\n")
    output.write(f"Warnings: {warnings}\n\n")

    # Group results by provider
    df = pd.DataFrame(data)
    for provider in df['provider'].unique():
        output.write(f"\n{provider.upper()}\n")
        output.write("=" * len(provider) + "\n\n")
        
        provider_data = df[df['provider'] == provider]
        for _, row in provider_data.iterrows():
            output.write(f"Check ID: {row['check_id']}\n")
            output.write(f"Resource: {row['resource_id']}\n")
            output.write(f"Type: {row['resource_type']}\n")
            output.write(f"Status: {row['status']}\n")
            
            if row['details']:
                output.write("Details:\n")
                for k, v in row['details'].items():
                    output.write(f"  {k}: {v}\n")
            
            output.write(f"Recommendation: {row['recommendation']}\n")
            output.write("-" * 50 + "\n\n") 