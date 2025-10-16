# aws-audit-bot
AWS Security Audit Bot --
A comprehensive, read-only security audit tool for AWS resources that helps identify security
misconfigurations and compliance issues across multiple AWS services.
Features
Comprehensive Security Audits
- **IAM (Identity and Access Management)**: User policies, MFA enforcement, password policies,
access keys, roles, and permissions
- **S3 (Simple Storage Service)**: Bucket policies, encryption, public access, versioning, logging, and
lifecycle policies
- **EC2 (Elastic Compute Cloud)**: Security groups, instances, EBS volumes, snapshots, VPC flow
logs, and network ACLs
Multiple Output Formats
- **JSON Report**: Detailed structured data for programmatic analysis
- **CSV Report**: Spreadsheet-compatible format for data analysis
- **Summary Report**: Human-readable text summary with recommendations
- **Log File**: Detailed audit logs for troubleshooting
Security Best Practices
- Read-only operations (no modifications to AWS resources)
- Comprehensive error handling and logging
- Severity-based findings classification (Critical, High, Medium, Low)
- Detailed recommendations for each finding
Installation
Prerequisites
- Python 3.7 or higher
- AWS credentials configured (via `aws configure` or environment variables)
- Appropriate IAM permissions for read-only access
Setup
1. Clone the repository:
```
git clone https://github.com/yourusername/aws-security-audit-bot.git
cd aws-security-audit-bot
```
2. Install dependencies:
```
pip install -r requirements.txt
```
3. Configure AWS credentials:
```
aws configure
```
Usage
Before running, activate your Python virtual environment if you are using one:
```
Windows
venv\Scripts\activate
Mac/Linux
source venv/bin/activate
```
Once activated, run the audit using:
```
python audit_bot.py
```
All reports will be saved automatically in the `output/` directory.
Output Files
The tool generates the following files in the `output/` directory:
- `audit_results.json` - Detailed JSON report
- `audit_results.csv` - CSV report for analysis
- `audit_summary.txt` - Human-readable summary
- `audit.log` - Detailed audit logs
Disclaimer
This tool is for educational and security assessment purposes only. Always ensure you have proper
authorization before running security audits on AWS resources. The tool performs read-only operations
but may generate logs and reports that could contain sensitive information.
Support
For issues and questions:
- Check the logs in `output/audit.log` for detailed error information
- Ensure your AWS credentials and permissions are properly configured

Changelog: 
Version 2.0.0
- Enhanced EC2 audit with comprehensive security checks
- Improved main audit bot with professional structure
- Added severity levels and detailed recommendations
- Enhanced output formats (JSON, CSV, Summary)
- Added comprehensive logging and error handling
- Improved documentation and GitHub readiness
