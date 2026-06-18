"""
Terraform remediation generation service.
"""
import json
import logging
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from sqlalchemy.orm import Session

from app.crud.scan import get_scan_by_scan_id
from app.models.db import Scan, Finding
from app import constants

logger = logging.getLogger(__name__)

# Jinja2 environment setup
template_env = Environment(
    loader=FileSystemLoader('app/templates/terraform'),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True
)

# Map issue types to template paths
TEMPLATE_MAP = {
    constants.S3_PUBLIC_BUCKET: "s3/public_bucket.j2",
    constants.SG_SSH_OPEN: "security_group/ssh_open.j2",
    constants.SG_RDP_OPEN: "security_group/rdp_open.j2",
    constants.IAM_OLD_KEY: "iam/old_key.j2",
    # Note: SG_ALL_TRAFFIC_OPEN, IAM_NO_MFA, IAM_ADMIN_ACCESS do not have templates
    # and will generate manual guidance instead.
}

def generate_remediation(db: Session, scan_id: str) -> Dict[str, Any]:
    """
    Generate Terraform remediation for a given scan.

    Args:
        db: Database session
        scan_id: Unique scan identifier

    Returns:
        Dictionary containing generated Terraform, manual guidance, and metadata.

    Raises:
        ValueError: If scan is not found.
    """
    # Retrieve the scan from the database
    db_scan = get_scan_by_scan_id(db, scan_id)
    if db_scan is None:
        raise ValueError(f"Scan with ID {scan_id} not found")

    # Extract findings from the scan
    findings = []
    for finding in db_scan.findings:
        finding_dict = finding.to_dict()
        findings.append(finding_dict)

    # Initialize response containers
    terraform_blocks = []
    manual_guidance_list = []
    processed_findings = 0
    remediated_count = 0
    manual_count = 0

    # Process each finding
    for finding in findings:
        processed_findings += 1
        issue_type = finding.get("issue_type")

        # Check if we have a template for this issue type
        template_path = TEMPLATE_MAP.get(issue_type)

        if template_path:
            # Attempt to generate Terraform for this finding
            try:
                # Extract and validate variables
                vars_dict = _extract_and_validate_vars(finding, issue_type)
                if vars_dict is None:
                    # Validation failed, generate manual guidance
                    guidance = _generate_manual_guidance(finding, issue_type,
                                                       "Required variables could not be extracted or validated")
                    manual_guidance_list.append(guidance)
                    manual_count += 1
                    continue

                # Render the template
                template = template_env.get_template(template_path)
                rendered = template.render(**vars_dict)

                # Generate a filename based on the finding and issue type
                filename = _generate_filename(finding, issue_type)

                terraform_blocks.append({
                    "filename": filename,
                    "service": _get_service_from_issue_type(issue_type),
                    "content": rendered
                })
                remediated_count += 1

            except TemplateNotFound:
                logger.warning(f"Template not found for issue type: {issue_type}")
                guidance = _generate_manual_guidance(finding, issue_type,
                                                   "No Terraform template available")
                manual_guidance_list.append(guidance)
                manual_count += 1
            except Exception as e:
                logger.error(f"Error generating Terraform for finding {finding.get('id')}: {e}")
                guidance = _generate_manual_guidance(finding, issue_type,
                                                   f"Error during Terraform generation: {str(e)}")
                manual_guidance_list.append(guidance)
                manual_count += 1
        else:
            # No template available, generate manual guidance
            guidance = _generate_manual_guidance(finding, issue_type,
                                               "No automated remediation available")
            manual_guidance_list.append(guidance)
            manual_count += 1

    # Prepare the response
    return {
        "scan_id": scan_id,
        "generated_at": _get_current_timestamp(),
        "findings_total": processed_findings,
        "findings_remediated": remediated_count,
        "findings_manual_guidance": manual_count,
        "remediation": {
            "terraform": terraform_blocks,
            "manual_guidance": manual_guidance_list
        },
        "metadata": {
            "review_required": True,
            "terraform_version_required": ">=1.0.0",
            "generated_resources": [block["filename"] for block in terraform_blocks],
            "warnings": [
                "Always review generated Terraform before applying.",
                "Manual guidance findings require human intervention."
            ]
        }
    }

def _extract_and_validate_vars(finding: Dict[str, Any], issue_type: str) -> Optional[Dict[str, Any]]:
    """
    Extract and validate variables from a finding based on issue type.

    Args:
        finding: The finding dictionary
        issue_type: The issue type string

    Returns:
        Dictionary of variables if successful, None if validation fails.
    """
    try:
        # Extract finding_data from the finding
        finding_data = finding.get("finding_data", {})

        if issue_type == constants.S3_PUBLIC_BUCKET:
            # Extract bucket name with fallback (all from finding_data)
            bucket_name = (
                finding_data.get("bucket_name") or
                finding_data.get("bucket") or
                finding_data.get("resource_name")
            )
            if not bucket_name:
                logger.warning(f"Could not extract bucket name from finding: {finding}")
                return None

            # Basic validation: S3 bucket name rules
            if not _is_valid_s3_bucket_name(bucket_name):
                logger.warning(f"Invalid S3 bucket name: {bucket_name}")
                return None

            return {
                "bucket_name": bucket_name,
                "region": finding_data.get("region", "us-east-1"),  # Default region
                "account_id": finding_data.get("account_id")  # Optional
            }

        elif issue_type in (constants.SG_SSH_OPEN, constants.SG_RDP_OPEN):
            # Extract group ID with fallback (all from finding_data)
            group_id = (
                finding_data.get("group_id") or
                finding_data.get("security_group_id") or
                finding_data.get("resource_id")
            )
            if not group_id:
                logger.warning(f"Could not extract group ID from finding: {finding}")
                return None

            # Validate security group ID format
            if not _is_valid_sg_id(group_id):
                logger.warning(f"Invalid security group ID: {group_id}")
                return None

            # Determine port and protocol based on issue type
            if issue_type == constants.SG_SSH_OPEN:
                port = 22
                protocol = "tcp"
            else:  # SG_RDP_OPEN
                port = 3389
                protocol = "tcp"

            # For these templates, we are removing the rule, so we don't need a CIDR to allow.
            # However, we might want to allow a specific CIDR in the future, so we leave it as optional.
            # We'll not include any variables for allowed CIDR in the template for now.
            # The template currently removes the rule and has commented-out code for allowing a CIDR.
            return {
                "group_id": group_id,
                "port": port,
                "protocol": protocol
            }

        elif issue_type == constants.IAM_OLD_KEY:
            # Extract user name with fallback (all from finding_data)
            user_name = (
                finding_data.get("user_name") or
                finding_data.get("user") or
                finding_data.get("username")
            )
            if not user_name:
                logger.warning(f"Could not extract user name from finding: {finding}")
                return None

            # Extract access key ID from finding_data if not directly available
            access_key_id = (
                finding_data.get("access_key_id") or
                finding_data.get("key_id")
            )

            # If not found directly, try to parse from details in finding_data
            if not access_key_id:
                details = finding_data.get("details", "")
                # Example details: "Access key 'AKIAIOSFODNN7EXAMPLE' created 95 days ago (created: 2023-01-01)"
                import re
                match = re.search(r"Access key '([^']+)'", details)
                if match:
                    access_key_id = match.group(1)
                else:
                    logger.warning(f"Could not extract access key ID from details: {details}")
                    return None

            # Validate access key ID format (should start with AKIA or ASIA and be 16 or 20 alphanumeric chars)
            if not _is_valid_aws_access_key_id(access_key_id):
                logger.warning(f"Invalid access key ID: {access_key_id}")
                return None

            return {
                "user_name": user_name,
                "access_key_id": access_key_id
            }


        else:
            # This should not happen because we only call this for issue types in TEMPLATE_MAP
            logger.warning(f"_extract_and_validate_vars called for unmapped issue type: {issue_type}")
            return None

    except Exception as e:
        logger.error(f"Error extracting variables for finding {finding.get('id')}: {e}")
        return None

def _is_valid_s3_bucket_name(name: str) -> bool:
    """Validate S3 bucket name according to AWS rules."""
    if not name or len(name) < 3 or len(name) > 63:
        return False
    # Must consist of lowercase letters, numbers, dots, and hyphens
    # Must start and end with a letter or number
    if not name[0].isalnum() or not name[-1].isalnum():
        return False
    # No consecutive periods
    if '..' in name:
        return False
    # Only allowed characters
    allowed_chars = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    return all(c in allowed_chars for c in name)

def _is_valid_sg_id(sg_id: str) -> bool:
    """Validate security group ID format."""
    if not sg_id:
        return False
    # Security group ID pattern: sg- followed by 8 or 17 alphanumeric characters
    import re
    return bool(re.match(r'^sg-[0-9a-f]{8}$', sg_id)) or bool(re.match(r'^sg-[0-9a-f]{17}$', sg_id))

def _is_valid_aws_access_key_id(key_id: str) -> bool:
    """Validate AWS access key ID format."""
    if not key_id:
        return False
    # Access key ID: AKIA or ASIA followed by 16 alphanumeric characters
    import re
    return bool(re.match(r'^(AKIA|ASIA)[0-9A-Z]{16}$', key_id))

def _get_service_from_issue_type(issue_type: str) -> str:
    """
    Map issue type to AWS service name.

    Args:
        issue_type: The issue type string

    Returns:
        Service name (s3, security_group, iam)
    """
    issue_lower = issue_type.lower()
    if "s3" in issue_lower or "bucket" in issue_lower:
        return "s3"
    elif "ssh" in issue_lower or "rdp" in issue_lower or "all traffic" in issue_lower:
        return "security_group"
    elif "iam" in issue_lower or "user" in issue_lower or "mfa" in issue_lower or "access key" in issue_lower or "administratoraccess" in issue_lower:
        return "iam"
    else:
        return "unknown"

def _generate_manual_guidance(finding: Dict[str, Any], issue_type: str, extra_info: str = "") -> Dict[str, Any]:
    """
    Generate manual guidance for a finding that cannot be remediated via Terraform.

    Args:
        finding: The finding dictionary
        issue_type: The issue type string
        extra_info: Additional information to include in the guidance

    Returns:
        Dictionary representing the manual guidance.
    """
    guidance_text = ""
    priority = "medium"

    # Extract finding_data from the finding
    finding_data = finding.get("finding_data", {})

    if issue_type == constants.SG_ALL_TRAFFIC_OPEN:
        guidance_text = "Security group allows all traffic (0.0.0.0/0:0-65535). Replace with minimum required ports and protocols."
        priority = "high"
    elif issue_type == constants.IAM_NO_MFA:
        user_name = (
            finding_data.get("user_name") or
            finding_data.get("user") or
            finding_data.get("username") or
            "unknown user"
        )
        guidance_text = f"Enable MFA for IAM user '{user_name}' via AWS Console, CLI, or API."
        priority = "high"
    elif issue_type == constants.IAM_ADMIN_ACCESS:
        user_name = (
            finding_data.get("user_name") or
            finding_data.get("user") or
            finding_data.get("username") or
            "unknown user"
        )
        guidance_text = f"Review IAM user '{user_name}' permissions. Replace AdministratorAccess with least-privilege policy."
        priority = "high"
    else:
        guidance_text = f"No automated remediation available for issue type: {issue_type}"
        if extra_info:
            guidance_text += f" ({extra_info})"
        priority = "low"

    # If we have extra info, append it
    if extra_info and extra_info not in guidance_text:
        guidance_text += f" - {extra_info}"

    return {
        "finding_id": finding.get("id"),
        "issue_type": issue_type,
        "guidance": guidance_text,
        "priority": priority
    }

def _get_findings_from_scan(db_scan: Scan) -> List[Dict[str, Any]]:
    """
    Extract findings from a Scan object.

    Args:
        db_scan: The Scan object from the database

    Returns:
        List of finding dictionaries.
    """
    findings = []
    for finding in db_scan.findings:
        findings.append(finding.to_dict())
    return findings

def _generate_filename(finding: Dict[str, Any], issue_type: str) -> str:
    """
    generate a filename for the Terraform block.

    Args:
        finding: The finding dictionary
        issue_type: The issue type string

    Returns:
        A filename string.
    """
    # Create a safe filename based on the issue type and identifying information
    service = _get_service_from_issue_type(issue_type)

    # Extract finding_data from the finding
    finding_data = finding.get("finding_data", {})

    # Try to get an identifier
    identifier = "unknown"
    if issue_type == constants.S3_PUBLIC_BUCKET:
        identifier = (
            finding_data.get("bucket_name") or
            finding_data.get("bucket") or
            finding_data.get("resource_name") or
            "bucket"
        )
    elif issue_type in (constants.SG_SSH_OPEN, constants.SG_RDP_OPEN):
        identifier = (
            finding_data.get("group_id") or
            finding_data.get("security_group_id") or
            finding_data.get("resource_id") or
            "sg"
        )
    elif issue_type == constants.IAM_OLD_KEY:
        identifier = (
            finding_data.get("user_name") or
            finding_data.get("user") or
            finding_data.get("username") or
            "user"
        )
        # Also include part of the access key ID if available
        access_key_id = (
            finding_data.get("access_key_id") or
            finding_data.get("key_id") or
            ""
        )
        if access_key_id:
            # Use last 4 characters of the access key ID for brevity
            identifier += f"_{access_key_id[-4:]}"

    # sanitize identifier for filename
    import re
    safe_identifier = re.sub(r'[^a-zA-Z0-9_-]', '_', identifier)
    # Limit length
    if len(safe_identifier) > 30:
        safe_identifier = safe_identifier[:30]

    return f"{service}_{issue_type.lower().replace(' ', '_')}_{safe_identifier}.tf"

def _get_current_timestamp() -> str:
    """Get current timestamp in ISO format."""
    from datetime import datetime, timezone
    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")