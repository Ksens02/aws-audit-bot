"""
Enhanced EC2 Security Audit Module
Comprehensive EC2 security checks for AWS resources
"""

import boto3
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logger = logging.getLogger(__name__)


def check_ec2_security_groups() -> List[Dict[str, Any]]:
    """
    Comprehensive EC2 security audit including:
    - Security groups with overly permissive rules
    - EC2 instances with public IPs
    - Unencrypted EBS volumes
    - Public snapshots
    - Unused security groups
    - Instance metadata service access
    - VPC flow logs
    - Network ACLs
    """
    findings = []
    
    try:
        ec2 = boto3.client("ec2")
        
        # Check security groups
        findings.extend(_check_security_groups(ec2))
        
        # Check EC2 instances
        findings.extend(_check_ec2_instances(ec2))
        
        # Check EBS volumes
        findings.extend(_check_ebs_volumes(ec2))
        
        # Check snapshots
        findings.extend(_check_snapshots(ec2))
        
        # Check VPC flow logs
        findings.extend(_check_vpc_flow_logs(ec2))
        
        # Check network ACLs
        findings.extend(_check_network_acls(ec2))
        
    except NoCredentialsError:
        findings.append({
            "Resource": "EC2",
            "Issue": "No AWS credentials found",
            "Severity": "Critical",
            "Recommendation": "Configure AWS credentials using aws configure or environment variables"
        })
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            findings.append({
                "Resource": "EC2",
                "Issue": "Insufficient permissions to audit EC2 resources",
                "Severity": "High",
                "Recommendation": "Ensure the audit role has EC2 read permissions"
            })
        else:
            findings.append({
                "Resource": "EC2",
                "Issue": f"Error accessing EC2: {str(e)}",
                "Severity": "Medium",
                "Recommendation": "Check AWS credentials and permissions"
            })
    except Exception as e:
        logger.error(f"Unexpected error in EC2 audit: {str(e)}")
        findings.append({
            "Resource": "EC2",
            "Issue": f"Unexpected error: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check logs for more details"
        })
    
    return findings


def _check_security_groups(ec2) -> List[Dict[str, Any]]:
    """Check security groups for overly permissive rules"""
    findings = []
    
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        
        for sg in sgs:
            sg_id = sg.get("GroupId")
            sg_name = sg.get("GroupName")
            
            # Check inbound rules
            for rule in sg.get("IpPermissions", []):
                protocol = rule.get("IpProtocol", "")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                
                # Check for 0.0.0.0/0 access
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        port_info = f"port {from_port}" if from_port == to_port else f"ports {from_port}-{to_port}"
                        protocol_info = f" {protocol}" if protocol != "-1" else ""
                        
                        findings.append({
                            "Resource": f"Security Group: {sg_id} ({sg_name})",
                            "Issue": f"Allows 0.0.0.0/0 access on {port_info}{protocol_info}",
                            "Severity": "High",
                            "Recommendation": "Restrict CIDR blocks to specific IP ranges"
                        })
                
                # Check for ::/0 access (IPv6)
                for ipv6_range in rule.get("Ipv6Ranges", []):
                    cidr = ipv6_range.get("CidrIpv6", "")
                    if cidr == "::/0":
                        port_info = f"port {from_port}" if from_port == to_port else f"ports {from_port}-{to_port}"
                        protocol_info = f" {protocol}" if protocol != "-1" else ""
                        
                        findings.append({
                            "Resource": f"Security Group: {sg_id} ({sg_name})",
                            "Issue": f"Allows ::/0 access on {port_info}{protocol_info}",
                            "Severity": "High",
                            "Recommendation": "Restrict IPv6 CIDR blocks to specific IP ranges"
                        })
                
                # Check for SSH (port 22) open to world
                if from_port == 22 and to_port == 22:
                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        if cidr == "0.0.0.0/0":
                            findings.append({
                                "Resource": f"Security Group: {sg_id} ({sg_name})",
                                "Issue": "SSH (port 22) open to 0.0.0.0/0",
                                "Severity": "Critical",
                                "Recommendation": "Restrict SSH access to specific IP ranges"
                            })
                
                # Check for RDP (port 3389) open to world
                if from_port == 3389 and to_port == 3389:
                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        if cidr == "0.0.0.0/0":
                            findings.append({
                                "Resource": f"Security Group: {sg_id} ({sg_name})",
                                "Issue": "RDP (port 3389) open to 0.0.0.0/0",
                                "Severity": "Critical",
                                "Recommendation": "Restrict RDP access to specific IP ranges"
                            })
                
                # Check for all ports open
                if from_port == 0 and to_port == 65535:
                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        if cidr == "0.0.0.0/0":
                            findings.append({
                                "Resource": f"Security Group: {sg_id} ({sg_name})",
                                "Issue": "All ports (0-65535) open to 0.0.0.0/0",
                                "Severity": "Critical",
                                "Recommendation": "Restrict to specific ports and IP ranges"
                            })
        
        # Check for unused security groups
        findings.extend(_check_unused_security_groups(ec2, sgs))
        
    except ClientError as e:
        logger.error(f"Error checking security groups: {str(e)}")
        findings.append({
            "Resource": "Security Groups",
            "Issue": f"Error checking security groups: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check EC2 permissions"
        })
    
    return findings


def _check_unused_security_groups(ec2, sgs) -> List[Dict[str, Any]]:
    """Check for unused security groups"""
    findings = []
    
    try:
        # Get all network interfaces
        network_interfaces = ec2.describe_network_interfaces().get("NetworkInterfaces", [])
        used_sg_ids = set()
        
        for ni in network_interfaces:
            for sg in ni.get("Groups", []):
                used_sg_ids.add(sg.get("GroupId"))
        
        # Check for unused security groups
        for sg in sgs:
            sg_id = sg.get("GroupId")
            sg_name = sg.get("GroupName")
            
            # Skip default security groups
            if sg_name == "default":
                continue
                
            if sg_id not in used_sg_ids:
                findings.append({
                    "Resource": f"Security Group: {sg_id} ({sg_name})",
                    "Issue": "Security group is not attached to any network interface",
                    "Severity": "Low",
                    "Recommendation": "Consider removing unused security groups"
                })
                
    except ClientError as e:
        logger.warning(f"Error checking unused security groups: {str(e)}")
    
    return findings


def _check_ec2_instances(ec2) -> List[Dict[str, Any]]:
    """Check EC2 instances for security issues"""
    findings = []
    
    try:
        instances = ec2.describe_instances().get("Reservations", [])
        
        for reservation in instances:
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId")
                state = instance.get("State", {}).get("Name", "")
                
                # Skip terminated instances
                if state == "terminated":
                    continue
                
                # Check for public IP
                public_ip = instance.get("PublicIpAddress")
                if public_ip:
                    findings.append({
                        "Resource": f"EC2 Instance: {instance_id}",
                        "Issue": f"Instance has public IP: {public_ip}",
                        "Severity": "Medium",
                        "Recommendation": "Consider using private instances with NAT gateway for outbound access"
                    })
                
                # Check for public DNS
                public_dns = instance.get("PublicDnsName")
                if public_dns:
                    findings.append({
                        "Resource": f"EC2 Instance: {instance_id}",
                        "Issue": f"Instance has public DNS: {public_dns}",
                        "Severity": "Medium",
                        "Recommendation": "Consider using private instances with NAT gateway for outbound access"
                    })
                
                # Check instance metadata service
                metadata_options = instance.get("MetadataOptions", {})
                http_tokens = metadata_options.get("HttpTokens")
                if http_tokens != "required":
                    findings.append({
                        "Resource": f"EC2 Instance: {instance_id}",
                        "Issue": "Instance metadata service does not require IMDSv2",
                        "Severity": "Medium",
                        "Recommendation": "Enable IMDSv2 for enhanced security"
                    })
                
                # Check for user data
                user_data = instance.get("UserData")
                if user_data:
                    # This is a basic check - in production, you'd want to decode and analyze the user data
                    findings.append({
                        "Resource": f"EC2 Instance: {instance_id}",
                        "Issue": "Instance has user data configured",
                        "Severity": "Low",
                        "Recommendation": "Review user data for sensitive information"
                    })
                
                # Check security groups
                security_groups = instance.get("SecurityGroups", [])
                if not security_groups:
                    findings.append({
                        "Resource": f"EC2 Instance: {instance_id}",
                        "Issue": "Instance has no security groups attached",
                        "Severity": "High",
                        "Recommendation": "Attach appropriate security groups"
                    })
                
    except ClientError as e:
        logger.error(f"Error checking EC2 instances: {str(e)}")
        findings.append({
            "Resource": "EC2 Instances",
            "Issue": f"Error checking instances: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check EC2 permissions"
        })
    
    return findings


def _check_ebs_volumes(ec2) -> List[Dict[str, Any]]:
    """Check EBS volumes for encryption"""
    findings = []
    
    try:
        volumes = ec2.describe_volumes().get("Volumes", [])
        
        for volume in volumes:
            volume_id = volume.get("VolumeId")
            encrypted = volume.get("Encrypted", False)
            
            if not encrypted:
                findings.append({
                    "Resource": f"EBS Volume: {volume_id}",
                    "Issue": "Volume is not encrypted",
                    "Severity": "High",
                    "Recommendation": "Enable encryption for EBS volumes"
                })
            
            # Check for public snapshots
            snapshots = volume.get("Snapshots", [])
            for snapshot in snapshots:
                snapshot_id = snapshot.get("SnapshotId")
                try:
                    snapshot_attrs = ec2.describe_snapshot_attribute(
                        SnapshotId=snapshot_id,
                        Attribute='createVolumePermission'
                    )
                    
                    for perm in snapshot_attrs.get('CreateVolumePermissions', []):
                        if perm.get('Group') == 'all':
                            findings.append({
                                "Resource": f"EBS Snapshot: {snapshot_id}",
                                "Issue": "Snapshot is publicly accessible",
                                "Severity": "Critical",
                                "Recommendation": "Remove public access from snapshot"
                            })
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidSnapshot.NotFound':
                        logger.warning(f"Error checking snapshot {snapshot_id}: {str(e)}")
        
    except ClientError as e:
        logger.error(f"Error checking EBS volumes: {str(e)}")
        findings.append({
            "Resource": "EBS Volumes",
            "Issue": f"Error checking volumes: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check EC2 permissions"
        })
    
    return findings


def _check_snapshots(ec2) -> List[Dict[str, Any]]:
    """Check for public snapshots"""
    findings = []
    
    try:
        snapshots = ec2.describe_snapshots(OwnerIds=['self']).get("Snapshots", [])
        
        for snapshot in snapshots:
            snapshot_id = snapshot.get("SnapshotId")
            
            try:
                snapshot_attrs = ec2.describe_snapshot_attribute(
                    SnapshotId=snapshot_id,
                    Attribute='createVolumePermission'
                )
                
                for perm in snapshot_attrs.get('CreateVolumePermissions', []):
                    if perm.get('Group') == 'all':
                        findings.append({
                            "Resource": f"EBS Snapshot: {snapshot_id}",
                            "Issue": "Snapshot is publicly accessible",
                            "Severity": "Critical",
                            "Recommendation": "Remove public access from snapshot"
                        })
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidSnapshot.NotFound':
                    logger.warning(f"Error checking snapshot {snapshot_id}: {str(e)}")
        
    except ClientError as e:
        logger.error(f"Error checking snapshots: {str(e)}")
        findings.append({
            "Resource": "EBS Snapshots",
            "Issue": f"Error checking snapshots: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check EC2 permissions"
        })
    
    return findings


def _check_vpc_flow_logs(ec2) -> List[Dict[str, Any]]:
    """Check for VPC flow logs"""
    findings = []
    
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        
        for vpc in vpcs:
            vpc_id = vpc.get("VpcId")
            
            try:
                flow_logs = ec2.describe_flow_logs(
                    Filter=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                ).get("FlowLogs", [])
                
                if not flow_logs:
                    findings.append({
                        "Resource": f"VPC: {vpc_id}",
                        "Issue": "VPC flow logs are not enabled",
                        "Severity": "Medium",
                        "Recommendation": "Enable VPC flow logs for network monitoring"
                    })
            except ClientError as e:
                logger.warning(f"Error checking flow logs for VPC {vpc_id}: {str(e)}")
        
    except ClientError as e:
        logger.error(f"Error checking VPC flow logs: {str(e)}")
        findings.append({
            "Resource": "VPC Flow Logs",
            "Issue": f"Error checking flow logs: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check EC2 permissions"
        })
    
    return findings


def _check_network_acls(ec2) -> List[Dict[str, Any]]:
    """Check network ACLs for overly permissive rules"""
    findings = []
    
    try:
        network_acls = ec2.describe_network_acls().get("NetworkAcls", [])
        
        for nacl in network_acls:
            nacl_id = nacl.get("NetworkAclId")
            
            for entry in nacl.get("Entries", []):
                rule_number = entry.get("RuleNumber")
                protocol = entry.get("Protocol")
                rule_action = entry.get("RuleAction")
                cidr_block = entry.get("CidrBlock")
                
                # Check for overly permissive rules
                if rule_action == "allow" and cidr_block == "0.0.0.0/0":
                    if protocol == "-1":  # All protocols
                        findings.append({
                            "Resource": f"Network ACL: {nacl_id}",
                            "Issue": f"Rule {rule_number} allows all traffic from 0.0.0.0/0",
                            "Severity": "High",
                            "Recommendation": "Restrict network ACL rules to specific IP ranges"
                        })
                    elif protocol == "6":  # TCP
                        findings.append({
                            "Resource": f"Network ACL: {nacl_id}",
                            "Issue": f"Rule {rule_number} allows all TCP traffic from 0.0.0.0/0",
                            "Severity": "High",
                            "Recommendation": "Restrict network ACL rules to specific IP ranges"
                        })
                    elif protocol == "17":  # UDP
                        findings.append({
                            "Resource": f"Network ACL: {nacl_id}",
                            "Issue": f"Rule {rule_number} allows all UDP traffic from 0.0.0.0/0",
                            "Severity": "High",
                            "Recommendation": "Restrict network ACL rules to specific IP ranges"
                        })
        
    except ClientError as e:
        logger.error(f"Error checking network ACLs: {str(e)}")
        findings.append({
            "Resource": "Network ACLs",
            "Issue": f"Error checking network ACLs: {str(e)}",
            "Severity": "Medium",
            "Recommendation": "Check EC2 permissions"
        })
    
    return findings
