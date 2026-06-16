"""
Centralized constants for vulnerability types in the AWS Security Auditor.
Using constants instead of string literals prevents typos and makes the code more maintainable.
"""

# S3 Vulnerabilities
S3_PUBLIC_BUCKET = "Publicly accessible S3 bucket"

# Security Group Vulnerabilities
SG_SSH_OPEN = "SSH open to 0.0.0.0/0"
SG_RDP_OPEN = "RDP open to 0.0.0.0/0"
SG_ALL_TRAFFIC_OPEN = "All Traffic open to 0.0.0.0/0"

# IAM Vulnerabilities
IAM_NO_MFA = "User does not have MFA enabled"
IAM_OLD_KEY = "Access key older than 90 days"
IAM_ADMIN_ACCESS = "User has AdministratorAccess privileges"

# Error findings that should be ignored in scoring
SCANNER_ERROR_FINDINGS = {
    "Scan failed",
    "AWS API error",
    "Unable to check bucket ACL",
    "IAM scan failed due to AWS API error",
    "Unexpected error during IAM scan"
}