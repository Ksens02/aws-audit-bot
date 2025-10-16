"""
Enhanced S3 Security Audit Module
Comprehensive S3 security checks for AWS resources
"""

import boto3
import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logger = logging.getLogger(__name__)


def check_s3_buckets() -> List[Dict[str, Any]]:
    """
    Comprehensive S3 security audit including:
    - Public bucket access
    - Bucket policies
    - Server-side encryption
    - Versioning
    - Logging
    - MFA delete
    - Lifecycle policies
    """
    findings = []
    
    try:
        s3 = boto3.client("s3")
        
        # List all buckets
        buckets = s3.list_buckets().get("Buckets", [])
        
        for bucket in buckets:
            bucket_name = bucket.get("Name")
            findings.extend(_check_bucket_public_access(bucket_name, s3))
            findings.extend(_check_bucket_encryption(bucket_name, s3))
            findings.extend(_check_bucket_versioning(bucket_name, s3))
            findings.extend(_check_bucket_logging(bucket_name, s3))
            findings.extend(_check_bucket_lifecycle(bucket_name, s3))
            findings.extend(_check_bucket_policy(bucket_name, s3))
            
    except NoCredentialsError:
        findings.append({
            "Resource": "S3",
            "Issue": "No AWS credentials found",
            "Severity": "Critical",
            "Recommendation": "Configure AWS credentials using aws configure or environment variables"
        })
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            findings.append({
                "Resource": "S3",
                "Issue": "Insufficient permissions to audit S3 resources",
                "Severity": "High",
                "Recommendation": "Ensure the audit role has S3 read permissions"
            })
        else:
            findings.append({
                "Resource": "S3",
                "Issue": f"Error accessing S3: {str(e)}",
                "Severity": "Medium",
                "Recommendation": "Check AWS credentials and permissions"
            })
    except Exception as e:
        logger.error(f"Unexpected error in S3 audit: {str(e)}")
        findings.append({
            "Resource": "S3",
            "Issue": f"Unexpected error: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check logs for more details"
        })
    
    return findings


def _check_bucket_public_access(bucket_name: str, s3) -> List[Dict[str, Any]]:
    """Check for public bucket access"""
    findings = []
    
    try:
        # Check bucket ACL
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            permission = grant.get("Permission", "")
            
            # Check for public read access
            if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                if permission in ["READ", "FULL_CONTROL"]:
                    findings.append({
                        "Resource": f"S3 Bucket: {bucket_name}",
                        "Issue": f"Public read access via ACL (Permission: {permission})",
                        "Severity": "High",
                        "Recommendation": "Remove public read access from bucket ACL"
                    })
            
            # Check for public write access
            if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                if permission in ["WRITE", "WRITE_ACP", "FULL_CONTROL"]:
                    findings.append({
                        "Resource": f"S3 Bucket: {bucket_name}",
                        "Issue": f"Public write access via ACL (Permission: {permission})",
                        "Severity": "Critical",
                        "Recommendation": "Remove public write access from bucket ACL"
                    })
        
        # Check bucket policy for public access
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = policy.get('Policy')
            if policy_doc:
                # This is a simplified check - in production, you'd want to parse the JSON
                if "Principal" in policy_doc and ("*" in policy_doc or "AWS" in policy_doc):
                    findings.append({
                        "Resource": f"S3 Bucket: {bucket_name}",
                        "Issue": "Bucket policy may allow public access",
                        "Severity": "Medium",
                        "Recommendation": "Review bucket policy for public access patterns"
                    })
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                logger.warning(f"Error checking bucket policy for {bucket_name}: {str(e)}")
        
        # Check public access block settings
        try:
            public_access_block = s3.get_public_access_block(Bucket=bucket_name)
            settings = public_access_block.get('PublicAccessBlockConfiguration', {})
            
            if not settings.get('BlockPublicAcls', False):
                findings.append({
                    "Resource": f"S3 Bucket: {bucket_name}",
                    "Issue": "Public access block does not block public ACLs",
                    "Severity": "Medium",
                    "Recommendation": "Enable 'Block public ACLs' in public access block settings"
                })
            
            if not settings.get('IgnorePublicAcls', False):
                findings.append({
                    "Resource": f"S3 Bucket: {bucket_name}",
                    "Issue": "Public access block does not ignore public ACLs",
                    "Severity": "Medium",
                    "Recommendation": "Enable 'Ignore public ACLs' in public access block settings"
                })
            
            if not settings.get('BlockPublicPolicy', False):
                findings.append({
                    "Resource": f"S3 Bucket: {bucket_name}",
                    "Issue": "Public access block does not block public policies",
                    "Severity": "Medium",
                    "Recommendation": "Enable 'Block public policies' in public access block settings"
                })
            
            if not settings.get('RestrictPublicBuckets', False):
                findings.append({
                    "Resource": f"S3 Bucket: {bucket_name}",
                    "Issue": "Public access block does not restrict public buckets",
                    "Severity": "Medium",
                    "Recommendation": "Enable 'Restrict public buckets' in public access block settings"
                })
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                logger.warning(f"Error checking public access block for {bucket_name}: {str(e)}")
        
    except ClientError as e:
        logger.warning(f"Error checking public access for bucket {bucket_name}: {str(e)}")
        findings.append({
            "Resource": f"S3 Bucket: {bucket_name}",
            "Issue": f"Error checking public access: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check bucket permissions"
        })
    
    return findings


def _check_bucket_encryption(bucket_name: str, s3) -> List[Dict[str, Any]]:
    """Check bucket encryption settings"""
    findings = []
    
    try:
        # Check default encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            
            if not rules:
                findings.append({
                    "Resource": f"S3 Bucket: {bucket_name}",
                    "Issue": "No default encryption configured",
                    "Severity": "High",
                    "Recommendation": "Enable default server-side encryption"
                })
            else:
                for rule in rules:
                    sse_algorithm = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
                    if sse_algorithm not in ['AES256', 'aws:kms']:
                        findings.append({
                            "Resource": f"S3 Bucket: {bucket_name}",
                            "Issue": f"Unsupported encryption algorithm: {sse_algorithm}",
                            "Severity": "Medium",
                            "Recommendation": "Use AES256 or aws:kms encryption"
                        })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append({
                    "Resource": f"S3 Bucket: {bucket_name}",
                    "Issue": "No default encryption configured",
                    "Severity": "High",
                    "Recommendation": "Enable default server-side encryption"
                })
            else:
                logger.warning(f"Error checking encryption for bucket {bucket_name}: {str(e)}")
        
    except Exception as e:
        logger.warning(f"Error checking encryption for bucket {bucket_name}: {str(e)}")
    
    return findings


def _check_bucket_versioning(bucket_name: str, s3) -> List[Dict[str, Any]]:
    """Check bucket versioning settings"""
    findings = []
    
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        status = versioning.get('Status')
        
        if status != 'Enabled':
            findings.append({
                "Resource": f"S3 Bucket: {bucket_name}",
                "Issue": f"Versioning is {status or 'Disabled'}",
                "Severity": "Medium",
                "Recommendation": "Enable versioning for data protection"
            })
        
        # Check MFA delete
        mfa_delete = versioning.get('MFADelete')
        if mfa_delete != 'Enabled':
            findings.append({
                "Resource": f"S3 Bucket: {bucket_name}",
                "Issue": "MFA delete is not enabled",
                "Severity": "Low",
                "Recommendation": "Consider enabling MFA delete for additional security"
            })
            
    except ClientError as e:
        logger.warning(f"Error checking versioning for bucket {bucket_name}: {str(e)}")
    
    return findings


def _check_bucket_logging(bucket_name: str, s3) -> List[Dict[str, Any]]:
    """Check bucket logging settings"""
    findings = []
    
    try:
        logging_config = s3.get_bucket_logging(Bucket=bucket_name)
        logging_enabled = logging_config.get('LoggingEnabled')
        
        if not logging_enabled:
            findings.append({
                "Resource": f"S3 Bucket: {bucket_name}",
                "Issue": "Access logging is not enabled",
                "Severity": "Medium",
                "Recommendation": "Enable access logging for audit trail"
            })
            
    except ClientError as e:
        logger.warning(f"Error checking logging for bucket {bucket_name}: {str(e)}")
    
    return findings


def _check_bucket_lifecycle(bucket_name: str, s3) -> List[Dict[str, Any]]:
    """Check bucket lifecycle policies"""
    findings = []
    
    try:
        lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        rules = lifecycle.get('Rules', [])
        
        if not rules:
            findings.append({
                "Resource": f"S3 Bucket: {bucket_name}",
                "Issue": "No lifecycle policy configured",
                "Severity": "Low",
                "Recommendation": "Consider implementing lifecycle policies for cost optimization"
            })
        else:
            # Check for transition to IA
            has_ia_transition = False
            for rule in rules:
                transitions = rule.get('Transitions', [])
                for transition in transitions:
                    if transition.get('StorageClass') == 'STANDARD_IA':
                        has_ia_transition = True
                        break
            
            if not has_ia_transition:
                findings.append({
                    "Resource": f"S3 Bucket: {bucket_name}",
                    "Issue": "No transition to IA storage class",
                    "Severity": "Low",
                    "Recommendation": "Consider transitioning objects to IA for cost optimization"
                })
                
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchLifecycleConfiguration':
            logger.warning(f"Error checking lifecycle for bucket {bucket_name}: {str(e)}")
    
    return findings


def _check_bucket_policy(bucket_name: str, s3) -> List[Dict[str, Any]]:
    """Check bucket policy for security issues"""
    findings = []
    
    try:
        policy = s3.get_bucket_policy(Bucket=bucket_name)
        policy_doc = policy.get('Policy')
        
        if policy_doc:
            # This is a simplified check - in production, you'd want to parse the JSON properly
            if "s3:GetObject" in policy_doc and "Principal" in policy_doc:
                if "*" in policy_doc or "AWS" in policy_doc:
                    findings.append({
                        "Resource": f"S3 Bucket: {bucket_name}",
                        "Issue": "Bucket policy may allow public object access",
                        "Severity": "High",
                        "Recommendation": "Review bucket policy for public access patterns"
                    })
                    
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
            logger.warning(f"Error checking bucket policy for {bucket_name}: {str(e)}")
    
    return findings
