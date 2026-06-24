"""
Demo remediation generator for portfolio mode.
"""

from typing import Dict, Any


def generate_demo_remediation(scan_id: str) -> Dict[str, Any]:
    return {
        "scan_id": scan_id,
        "generated_at": "2026-06-24T00:00:00Z",
        "findings_total": 5,
        "findings_remediated": 2,
        "findings_manual_guidance": 3,
        "remediation": {
            "ai_explanations": [
                {
                    "issue_type": "Public S3 Bucket",
                    "explanation": "Anyone on the internet can read this bucket. Remove public access and enable Block Public Access."
                },
                {
                    "issue_type": "Open SSH Port",
                    "explanation": "Port 22 is exposed to the internet. Restrict access to trusted IPs or use AWS Systems Manager Session Manager."
                },
                {
                    "issue_type": "IAM User Without MFA",
                    "explanation": "Users without MFA are significantly easier to compromise through stolen passwords."
                }
            ],
            "terraform": [
                {
                    "filename": "s3_public_bucket.tf",
                    "service": "s3",
                    "content": """resource "aws_s3_bucket_public_access_block" "example" {
  bucket = "company-public-backups"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}"""
                }
            ],
            "manual_guidance": [
                {
                    "issue_type": "AdministratorAccess Policy",
                    "guidance": "Replace AdministratorAccess with least-privilege IAM policies.",
                    "priority": "high"
                },
                {
                    "issue_type": "Security Group Allows All Traffic",
                    "guidance": "Restrict inbound rules to only required ports and trusted CIDRs.",
                    "priority": "high"
                }
            ]
        },
        "metadata": {
            "review_required": True,
            "terraform_version_required": ">=1.0.0",
            "generated_resources": [
                "s3_public_bucket.tf"
            ]
        }
    }