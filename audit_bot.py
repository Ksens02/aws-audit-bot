"""
AWS Security Audit Bot
Comprehensive security audit tool for AWS resources

This tool performs read-only security audits across multiple AWS services:
- IAM (Identity and Access Management)
- S3 (Simple Storage Service)
- EC2 (Elastic Compute Cloud)

Usage:
    python audit_bot.py

Requirements:
    - AWS credentials configured (aws configure or environment variables)
    - Appropriate IAM permissions for read-only access to AWS services

Output:
    - JSON report: output/audit_results.json
    - CSV report: output/audit_results.csv
    - Summary report: output/audit_summary.txt
"""

import json
import csv
import os
import sys
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path

# Import audit modules
from modules.iam_audit import check_iam_policies
from modules.s3_audit import check_s3_buckets
from modules.ec2_audit import check_ec2_security_groups

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('output/audit.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class AWSAuditBot:
    """
    AWS Security Audit Bot
    
    Performs comprehensive security audits across AWS services
    and generates detailed reports with findings and recommendations.
    """
    
    def __init__(self):
        """Initialize the audit bot"""
        self.output_dir = Path("output")
        self.output_dir.mkdir(exist_ok=True)
        
        # Audit modules and their display names
        self.audit_modules = {
            "IAM": {
                "function": check_iam_policies,
                "description": "Identity and Access Management"
            },
            "S3": {
                "function": check_s3_buckets,
                "description": "Simple Storage Service"
            },
            "EC2": {
                "function": check_ec2_security_groups,
                "description": "Elastic Compute Cloud"
            }
        }
        
        self.results = {}
        self.summary = {
            "total_findings": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "services_audited": 0,
            "audit_timestamp": None
        }
    
    def run_audit(self) -> Dict[str, Any]:
        """
        Run comprehensive AWS security audit
        
        Returns:
            Dict containing audit results for all services
        """
        logger.info("Starting AWS Security Audit...")
        logger.info("=" * 50)
        
        start_time = datetime.now(timezone.utc)
        
        for service_name, service_info in self.audit_modules.items():
            logger.info(f"Auditing {service_name} ({service_info['description']})...")
            
            try:
                findings = service_info['function']()
                self.results[service_name] = findings
                self.summary["services_audited"] += 1
                
                # Count findings by severity
                for finding in findings:
                    self.summary["total_findings"] += 1
                    severity = finding.get("Severity", "Unknown").lower()
                    
                    if severity == "critical":
                        self.summary["critical_findings"] += 1
                    elif severity == "high":
                        self.summary["high_findings"] += 1
                    elif severity == "medium":
                        self.summary["medium_findings"] += 1
                    elif severity == "low":
                        self.summary["low_findings"] += 1
                
                logger.info(f"[SUCCESS] {service_name} audit completed - {len(findings)} findings")
                
            except Exception as e:
                logger.error(f"[ERROR] Error auditing {service_name}: {str(e)}")
                self.results[service_name] = [{
                    "Resource": service_name,
                    "Issue": f"Audit failed: {str(e)}",
                    "Severity": "Critical",
                    "Recommendation": "Check logs and AWS credentials"
                }]
        
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()
        
        self.summary["audit_timestamp"] = start_time.isoformat()
        self.summary["duration_seconds"] = duration
        
        logger.info("=" * 50)
        logger.info(f"Audit completed in {duration:.2f} seconds")
        logger.info(f"Total findings: {self.summary['total_findings']}")
        logger.info(f"Critical: {self.summary['critical_findings']}, "
                   f"High: {self.summary['high_findings']}, "
                   f"Medium: {self.summary['medium_findings']}, "
                   f"Low: {self.summary['low_findings']}")
        
        return self.results
    
    def generate_json_report(self) -> str:
        """
        Generate JSON report with detailed findings
        
        Returns:
            Path to the generated JSON file
        """
        report_data = {
            "audit_summary": self.summary,
            "findings": self.results,
            "metadata": {
                "tool": "AWS Security Audit Bot",
                "version": "2.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
        }
        
        json_file = self.output_dir / "audit_results.json"
        
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report saved to: {json_file}")
            return str(json_file)
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            raise
    
    def generate_csv_report(self) -> str:
        """
        Generate CSV report with findings
        
        Returns:
            Path to the generated CSV file
        """
        csv_file = self.output_dir / "audit_results.csv"
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    "Service", "Resource", "Issue", "Severity", "Recommendation"
                ])
                
                # Write findings
                for service, findings in self.results.items():
                    for finding in findings:
                        writer.writerow([
                            service,
                            finding.get("Resource", ""),
                            finding.get("Issue", ""),
                            finding.get("Severity", ""),
                            finding.get("Recommendation", "")
                        ])
            
            logger.info(f"CSV report saved to: {csv_file}")
            return str(csv_file)
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {str(e)}")
            raise
    
    def generate_summary_report(self) -> str:
        """
        Generate human-readable summary report
        
        Returns:
            Path to the generated summary file
        """
        summary_file = self.output_dir / "audit_summary.txt"
        
        try:
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("AWS Security Audit Summary\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Audit Date: {self.summary['audit_timestamp']}\n")
                f.write(f"Duration: {self.summary.get('duration_seconds', 0):.2f} seconds\n")
                f.write(f"Services Audited: {self.summary['services_audited']}\n\n")
                
                f.write("Findings Summary:\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Findings: {self.summary['total_findings']}\n")
                f.write(f"Critical: {self.summary['critical_findings']}\n")
                f.write(f"High: {self.summary['high_findings']}\n")
                f.write(f"Medium: {self.summary['medium_findings']}\n")
                f.write(f"Low: {self.summary['low_findings']}\n\n")
                
                # Service-specific summaries
                for service, findings in self.results.items():
                    f.write(f"{service} Findings:\n")
                    f.write("-" * (len(service) + 10) + "\n")
                    
                    if not findings:
                        f.write("No findings.\n\n")
                        continue
                    
                    # Group by severity
                    by_severity = {}
                    for finding in findings:
                        severity = finding.get("Severity", "Unknown")
                        if severity not in by_severity:
                            by_severity[severity] = []
                        by_severity[severity].append(finding)
                    
                    for severity in ["Critical", "High", "Medium", "Low"]:
                        if severity in by_severity:
                            f.write(f"\n{severity} Issues:\n")
                            for finding in by_severity[severity]:
                                f.write(f"  • {finding.get('Resource', 'Unknown')}: "
                                       f"{finding.get('Issue', 'Unknown issue')}\n")
                    
                    f.write("\n")
                
                f.write("\nRecommendations:\n")
                f.write("-" * 15 + "\n")
                f.write("1. Address Critical and High severity findings immediately\n")
                f.write("2. Review Medium severity findings within 30 days\n")
                f.write("3. Consider Low severity findings for future improvements\n")
                f.write("4. Implement continuous monitoring and regular audits\n")
                f.write("5. Follow AWS security best practices and compliance frameworks\n")
            
            logger.info(f"Summary report saved to: {summary_file}")
            return str(summary_file)
            
        except Exception as e:
            logger.error(f"Error generating summary report: {str(e)}")
            raise
    
    def generate_reports(self) -> Dict[str, str]:
        """
        Generate all audit reports
        
        Returns:
            Dict with paths to generated reports
        """
        logger.info("Generating audit reports...")
        
        reports = {}
        
        try:
            reports['json'] = self.generate_json_report()
            reports['csv'] = self.generate_csv_report()
            reports['summary'] = self.generate_summary_report()
            
            logger.info("[SUCCESS] All reports generated successfully")
            return reports
            
        except Exception as e:
            logger.error(f"Error generating reports: {str(e)}")
            raise


def main():
    """
    Main entry point for the AWS Security Audit Bot
    """
    try:
        # Initialize and run audit
        bot = AWSAuditBot()
        results = bot.run_audit()
        
        # Generate reports
        reports = bot.generate_reports()
        
        # Print summary
        print("\n" + "=" * 60)
        print("AWS SECURITY AUDIT COMPLETED")
        print("=" * 60)
        print(f"Total Findings: {bot.summary['total_findings']}")
        print(f"Critical: {bot.summary['critical_findings']}")
        print(f"High: {bot.summary['high_findings']}")
        print(f"Medium: {bot.summary['medium_findings']}")
        print(f"Low: {bot.summary['low_findings']}")
        print("\nReports generated:")
        for report_type, path in reports.items():
            print(f"  {report_type.upper()}: {path}")
        print("\n[SUCCESS] Audit complete!")
        
        # Exit with appropriate code
        if bot.summary['critical_findings'] > 0:
            sys.exit(1)  # Critical findings found
        else:
            sys.exit(0)  # No critical findings
            
    except KeyboardInterrupt:
        logger.info("Audit interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Audit failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
