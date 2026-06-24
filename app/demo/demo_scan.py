"""
Demo scan data generator for Portfolio Demo Mode.
Returns a ScanResponse-compatible object with realistic AWS security findings.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from app.models.scan import ScanResponse


def generate_demo_scan() -> ScanResponse:
    """
    Generate a realistic demo scan response that matches the ScanResponse schema.
    Includes predefined findings for demonstration purposes.
    """
    # Generate a fixed scan ID for consistency in demo (optional, can be random)
    scan_id = str(uuid.uuid4())
    scan_timestamp = datetime.now(timezone.utc).isoformat()

    # Define demo findings matching the expected schema from existing scanners
    findings = [
        {
            "issue": "S3 Bucket Publicly Accessible",
            "description": "S3 bucket 'company-public-backups' is publicly accessible allowing anyone to read/list objects.",
            "remediation": "Remove public read/write permissions and consider using bucket policies or ACLs to restrict access.",
            "explanation": "Public S3 buckets can lead to data exposure and potential compliance violations.",
            "resource_id": "arn:aws:s3:::company-public-backups",
            "resource_type": "AWS::S3::Bucket",
            "region": "us-east-1",
            "severity": "high",
            "scanner": "s3",
            "timestamp": scan_timestamp
        },
        {
            "issue": "Security Group Allows SSH from Internet",
            "description": "Security group 'web-sg' allows inbound SSH (port 22) from 0.0.0.0/0.",
            "remediation": "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager.",
            "explanation": "Exposing SSH to the internet increases the attack surface for brute force attacks.",
            "resource_id": "sg-0a1b2c3d4e5f6g7h8",
            "resource_type": "AWS::EC2::SecurityGroup",
            "region": "us-east-1",
            "severity": "high",
            "scanner": "security_group",
            "timestamp": scan_timestamp
        },
        {
            "issue": "Security Group Allows All Traffic",
            "description": "Security group 'db-sg' allows all inbound traffic (0.0.0.0/0) on all ports.",
            "remediation": "Restrict inbound traffic to only necessary ports and sources.",
            "explanation": "Overly permissive security groups expose resources to unnecessary risks.",
            "resource_id": "sg-0a1b2c3d4e5f6g7h9",
            "resource_type": "AWS::EC2::SecurityGroup",
            "region": "us-east-1",
            "severity": "critical",
            "scanner": "security_group",
            "timestamp": scan_timestamp
        },
        {
            "issue": "IAM User Missing MFA",
            "description": "IAM user 'john.doe' does not have multi-factor authentication enabled.",
            "remediation": "Enable MFA for all IAM users with console access.",
            "explanation": "Without MFA, compromised credentials can lead to full account takeover.",
            "resource_id": "john.doe",
            "resource_type": "AWS::IAM::User",
            "region": "us-east-1",
            "severity": "medium",
            "scanner": "iam",
            "timestamp": scan_timestamp
        },
        {
            "issue": "IAM User with AdministratorAccess",
            "description": "IAM user 'dev.admin' has AdministratorAccess policy attached.",
            "remediation": "Apply principle of least privilege: replace with specific permissions needed.",
            "explanation": "AdministratorAccess provides unlimited privileges, increasing risk if credentials are compromised.",
            "resource_id": "dev.admin",
            "resource_type": "AWS::IAM::User",
            "region": "us-east-1",
            "severity": "high",
            "scanner": "iam",
            "timestamp": scan_timestamp
        }
    ]

    # Calculate severity breakdown
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding["severity"]
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Calculate security score (0-100) based on findings
    # Simple scoring: 100 minus penalties for findings
    # Critical: 25 points each, High: 15, Medium: 10, Low: 5
    penalties = {
        "critical": 25,
        "high": 15,
        "medium": 10,
        "low": 5
    }
    total_penalty = sum(penalties[f["severity"]] for f in findings)
    security_score = max(0, 100 - total_penalty)

    # Determine risk level based on score
    if security_score >= 80:
        risk_level = "Low Risk"
    elif security_score >= 60:
        risk_level = "Medium Risk"
    elif security_score >= 40:
        risk_level = "High Risk"
    else:
        risk_level = "Critical Risk"

    # Construct response matching ScanResponse schema
    response: ScanResponse = {
        "scan_id": scan_id,
        "status": "completed",
        "findings_count": len(findings),
        "findings": findings,
        "security_score": security_score,
        "risk_level": risk_level,
        "severity_breakdown": severity_counts
    }

    return response