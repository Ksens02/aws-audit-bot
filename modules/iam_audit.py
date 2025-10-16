"""
Enhanced IAM Security Audit Module
Comprehensive IAM security checks for AWS resources
"""

import boto3
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logger = logging.getLogger(__name__)


def check_iam_policies() -> List[Dict[str, Any]]:
    """
    Comprehensive IAM security audit including:
    - MFA enforcement
    - Password policies
    - Access key age and rotation
    - Root account usage
    - Inline policies
    - Overly permissive policies
    - Unused access keys
    """
    findings = []
    
    try:
        iam = boto3.client("iam")
        
        # Check for root account usage
        findings.extend(_check_root_account_usage(iam))
        
        # Check password policy
        findings.extend(_check_password_policy(iam))
        
        # Check users
        findings.extend(_check_users(iam))
        
        # Check roles
        findings.extend(_check_roles(iam))
        
        # Check policies
        findings.extend(_check_policies(iam))
        
        # Check access keys
        findings.extend(_check_access_keys(iam))
        
    except NoCredentialsError:
        findings.append({
            "Resource": "IAM",
            "Issue": "No AWS credentials found",
            "Severity": "Critical",
            "Recommendation": "Configure AWS credentials using aws configure or environment variables"
        })
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            findings.append({
                "Resource": "IAM",
                "Issue": "Insufficient permissions to audit IAM resources",
                "Severity": "High",
                "Recommendation": "Ensure the audit role has IAM read permissions"
            })
        else:
            findings.append({
                "Resource": "IAM",
                "Issue": f"Error accessing IAM: {str(e)}",
                "Severity": "Medium",
                "Recommendation": "Check AWS credentials and permissions"
            })
    except Exception as e:
        logger.error(f"Unexpected error in IAM audit: {str(e)}")
        findings.append({
            "Resource": "IAM",
            "Issue": f"Unexpected error: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check logs for more details"
        })
    
    return findings


def _check_root_account_usage(iam) -> List[Dict[str, Any]]:
    """Check for root account usage and MFA"""
    findings = []
    
    try:
        # Check if root has MFA enabled
        mfa_devices = iam.list_mfa_devices()
        if not mfa_devices.get('MFADevices'):
            findings.append({
                "Resource": "Root Account",
                "Issue": "Root account does not have MFA enabled",
                "Severity": "Critical",
                "Recommendation": "Enable MFA for root account"
            })
        
        # Check for root access keys
        try:
            access_keys = iam.list_access_keys(UserName='root')
            if access_keys.get('AccessKeyMetadata'):
                findings.append({
                    "Resource": "Root Account",
                    "Issue": "Root account has access keys",
                    "Severity": "Critical",
                    "Recommendation": "Delete root access keys and use IAM users"
                })
        except ClientError:
            # Root access keys check might fail if not root user
            pass
            
    except Exception as e:
        logger.warning(f"Error checking root account: {str(e)}")
    
    return findings


def _check_password_policy(iam) -> List[Dict[str, Any]]:
    """Check password policy compliance"""
    findings = []
    
    try:
        policy = iam.get_account_password_policy()
        pw_policy = policy.get('PasswordPolicy', {})
        
        if not pw_policy.get('MinimumPasswordLength', 0) >= 14:
            findings.append({
                "Resource": "Password Policy",
                "Issue": f"Password minimum length is {pw_policy.get('MinimumPasswordLength', 0)} (should be >= 14)",
                "Severity": "Medium",
                "Recommendation": "Increase minimum password length to 14 characters"
            })
        
        if not pw_policy.get('RequireUppercaseCharacters', False):
            findings.append({
                "Resource": "Password Policy",
                "Issue": "Password policy does not require uppercase characters",
                "Severity": "Medium",
                "Recommendation": "Enable uppercase character requirement"
            })
        
        if not pw_policy.get('RequireLowercaseCharacters', False):
            findings.append({
                "Resource": "Password Policy",
                "Issue": "Password policy does not require lowercase characters",
                "Severity": "Medium",
                "Recommendation": "Enable lowercase character requirement"
            })
        
        if not pw_policy.get('RequireNumbers', False):
            findings.append({
                "Resource": "Password Policy",
                "Issue": "Password policy does not require numbers",
                "Severity": "Medium",
                "Recommendation": "Enable number requirement"
            })
        
        if not pw_policy.get('RequireSymbols', False):
            findings.append({
                "Resource": "Password Policy",
                "Issue": "Password policy does not require symbols",
                "Severity": "Medium",
                "Recommendation": "Enable symbol requirement"
            })
        
        if not pw_policy.get('MaxPasswordAge', 0) <= 90:
            findings.append({
                "Resource": "Password Policy",
                "Issue": f"Password max age is {pw_policy.get('MaxPasswordAge', 0)} days (should be <= 90)",
                "Severity": "Medium",
                "Recommendation": "Set password max age to 90 days or less"
            })
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            findings.append({
                "Resource": "Password Policy",
                "Issue": "No password policy configured",
                "Severity": "High",
                "Recommendation": "Configure a strong password policy"
            })
    
    return findings


def _check_users(iam) -> List[Dict[str, Any]]:
    """Check IAM users for security issues"""
    findings = []
    
    try:
        users = iam.list_users()["Users"]
        
        for user in users:
            username = user["UserName"]
            
            # Skip root user
            if username == "root":
                continue
            
            # Check MFA
            try:
                mfa_devices = iam.list_mfa_devices(UserName=username)
                if not mfa_devices.get("MFADevices"):
                    findings.append({
                        "Resource": f"User: {username}",
                        "Issue": "No MFA device configured",
                        "Severity": "High",
                        "Recommendation": "Enable MFA for this user"
                    })
            except ClientError as e:
                logger.warning(f"Error checking MFA for user {username}: {str(e)}")
            
            # Check access keys
            try:
                access_keys = iam.list_access_keys(UserName=username)
                for key in access_keys.get('AccessKeyMetadata', []):
                    key_id = key['AccessKeyId']
                    created_date = key['CreateDate']
                    days_old = (datetime.now(timezone.utc) - created_date).days
                    
                    if days_old > 90:
                        findings.append({
                            "Resource": f"User: {username}",
                            "Issue": f"Access key {key_id} is {days_old} days old",
                            "Severity": "Medium",
                            "Recommendation": "Rotate access keys older than 90 days"
                        })
                    
                    # Check if key is active
                    try:
                        last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                        if 'LastUsedDate' not in last_used.get('AccessKeyLastUsed', {}):
                            findings.append({
                                "Resource": f"User: {username}",
                                "Issue": f"Access key {key_id} has never been used",
                                "Severity": "Low",
                                "Recommendation": "Consider removing unused access keys"
                            })
                    except ClientError:
                        pass
                        
            except ClientError as e:
                logger.warning(f"Error checking access keys for user {username}: {str(e)}")
            
            # Check for inline policies
            try:
                inline_policies = iam.list_user_policies(UserName=username)
                if inline_policies.get('PolicyNames'):
                    findings.append({
                        "Resource": f"User: {username}",
                        "Issue": f"Has {len(inline_policies['PolicyNames'])} inline policies",
                        "Severity": "Medium",
                        "Recommendation": "Use managed policies instead of inline policies"
                    })
            except ClientError as e:
                logger.warning(f"Error checking inline policies for user {username}: {str(e)}")
                
    except ClientError as e:
        logger.error(f"Error listing users: {str(e)}")
        findings.append({
            "Resource": "IAM Users",
            "Issue": f"Error listing users: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check IAM permissions"
        })
    
    return findings


def _check_roles(iam) -> List[Dict[str, Any]]:
    """Check IAM roles for security issues"""
    findings = []
    
    try:
        roles = iam.list_roles()["Roles"]
        
        for role in roles:
            role_name = role["RoleName"]
            
            # Check for overly permissive trust policies
            trust_policy = role.get("AssumeRolePolicyDocument", {})
            statements = trust_policy.get("Statement", [])
            
            for statement in statements:
                if statement.get("Effect") == "Allow":
                    principal = statement.get("Principal", {})
                    if principal.get("AWS") == "*":
                        findings.append({
                            "Resource": f"Role: {role_name}",
                            "Issue": "Trust policy allows any AWS principal",
                            "Severity": "High",
                            "Recommendation": "Restrict trust policy to specific principals"
                        })
            
            # Check for inline policies
            try:
                inline_policies = iam.list_role_policies(RoleName=role_name)
                if inline_policies.get('PolicyNames'):
                    findings.append({
                        "Resource": f"Role: {role_name}",
                        "Issue": f"Has {len(inline_policies['PolicyNames'])} inline policies",
                        "Severity": "Medium",
                        "Recommendation": "Use managed policies instead of inline policies"
                    })
            except ClientError as e:
                logger.warning(f"Error checking inline policies for role {role_name}: {str(e)}")
                
    except ClientError as e:
        logger.error(f"Error listing roles: {str(e)}")
        findings.append({
            "Resource": "IAM Roles",
            "Issue": f"Error listing roles: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check IAM permissions"
        })
    
    return findings


def _check_policies(iam) -> List[Dict[str, Any]]:
    """Check for overly permissive policies"""
    findings = []
    
    try:
        # Check customer managed policies
        policies = iam.list_policies(Scope='Local')["Policies"]
        
        for policy in policies:
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]
            
            try:
                policy_doc = iam.get_policy(PolicyArn=policy_arn)
                version_id = policy_doc['Policy']['DefaultVersionId']
                policy_version = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )
                
                statements = policy_version['PolicyVersion']['Document'].get('Statement', [])
                
                for statement in statements:
                    if statement.get("Effect") == "Allow":
                        # Check for wildcard actions
                        actions = statement.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        for action in actions:
                            if action == "*" or action.endswith("*"):
                                findings.append({
                                    "Resource": f"Policy: {policy_name}",
                                    "Issue": f"Policy allows wildcard action: {action}",
                                    "Severity": "High",
                                    "Recommendation": "Use specific actions instead of wildcards"
                                })
                        
                        # Check for wildcard resources
                        resources = statement.get("Resource", [])
                        if isinstance(resources, str):
                            resources = [resources]
                        
                        for resource in resources:
                            if resource == "*":
                                findings.append({
                                    "Resource": f"Policy: {policy_name}",
                                    "Issue": f"Policy allows wildcard resource: {resource}",
                                    "Severity": "High",
                                    "Recommendation": "Use specific resources instead of wildcards"
                                })
                                
            except ClientError as e:
                logger.warning(f"Error checking policy {policy_name}: {str(e)}")
                
    except ClientError as e:
        logger.error(f"Error listing policies: {str(e)}")
        findings.append({
            "Resource": "IAM Policies",
            "Issue": f"Error listing policies: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check IAM permissions"
        })
    
    return findings


def _check_access_keys(iam) -> List[Dict[str, Any]]:
    """Check for unused and old access keys"""
    findings = []
    
    try:
        users = iam.list_users()["Users"]
        
        for user in users:
            username = user["UserName"]
            
            try:
                access_keys = iam.list_access_keys(UserName=username)
                
                for key in access_keys.get('AccessKeyMetadata', []):
                    key_id = key['AccessKeyId']
                    
                    try:
                        last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                        last_used_info = last_used.get('AccessKeyLastUsed', {})
                        
                        if 'LastUsedDate' in last_used_info:
                            last_used_date = last_used_info['LastUsedDate']
                            days_since_used = (datetime.now(timezone.utc) - last_used_date).days
                            
                            if days_since_used > 90:
                                findings.append({
                                    "Resource": f"User: {username}",
                                    "Issue": f"Access key {key_id} not used for {days_since_used} days",
                                    "Severity": "Medium",
                                    "Recommendation": "Consider removing unused access keys"
                                })
                        else:
                            findings.append({
                                "Resource": f"User: {username}",
                                "Issue": f"Access key {key_id} has never been used",
                                "Severity": "Low",
                                "Recommendation": "Consider removing unused access keys"
                            })
                            
                    except ClientError as e:
                        logger.warning(f"Error checking last used for key {key_id}: {str(e)}")
                        
            except ClientError as e:
                logger.warning(f"Error checking access keys for user {username}: {str(e)}")
                
    except ClientError as e:
        logger.error(f"Error checking access keys: {str(e)}")
    
    return findings