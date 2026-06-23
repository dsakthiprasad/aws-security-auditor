import uuid
import logging
from datetime import datetime
from app.services.scanner import scan_aws_account
from app.services.security_group_scanner import scan_security_groups
from app.services.iam_scanner import scan_iam
from app.services.scoring import compute_scan_results
from app.crud.scan import create_scan

logger = logging.getLogger(__name__)


def run_full_scan(request, db=None):
    """
    Orchestrator function that runs S3, Security Group, and IAM scanners
    and combines their results into a unified response.

    Args:
        request: The incoming request object (ScanRequest)
        db: Database session (optional, for persistence)

    Returns:
        A dictionary containing:
            - scan_id: A unique identifier for this combined scan (UUID string).
            - status: Either 'completed', 'partial_failure', or 'failed'.
            - findings_count: The total number of findings from all scanners.
            - findings: A list of finding dictionaries from all scanners,
                       with error findings enhanced to include scanner identification.
            - security_score: Calculated compliance score (0-100)
            - risk_level: Risk level derived from score
            - severity_breakdown: Count of findings by severity level
    """
    # Generate a single master scan ID for the entire combined operation
    master_scan_id = str(uuid.uuid4())
    # Get current timestamp for the scan
    scan_timestamp = datetime.utcnow()

    # Initialize result tracking for each scanner
    s3_result = None
    sg_result = None
    iam_result = None
    s3_status = 'unknown'
    sg_status = 'unknown'
    iam_status = 'unknown'

    # Run S3 scanner
    try:
        s3_result = scan_aws_account(request)
        s3_status = s3_result.get('status', 'unknown')
    except Exception as e:
        # If the scanner itself throws an exception, create a failed result
        s3_result = {
            "scan_id": str(uuid.uuid4()),
            "status": "failed",
            "findings_count": 0,
            "findings": [{
                "issue": "Scan failed",
                "details": str(e)
            }]
        }
        s3_status = 'failed'

    # Run Security Group scanner
    try:
        sg_result = scan_security_groups(request)
        sg_status = sg_result.get('status', 'unknown')
    except Exception as e:
        # If the scanner itself throws an exception, create a failed result
        sg_result = {
            "scan_id": str(uuid.uuid4()),
            "status": "failed",
            "findings_count": 0,
            "findings": [{
                "issue": "Scan failed",
                "details": str(e)
            }]
        }
        sg_status = 'failed'

    # Run IAM scanner
    try:
        iam_result = scan_iam(request)
        iam_status = iam_result.get('status', 'unknown')
    except Exception as e:
        # If the scanner itself throws an exception, create a failed result
        iam_result = {
            "scan_id": str(uuid.uuid4()),
            "status": "failed",
            "findings_count": 0,
            "findings": [{
                "issue": "Scan failed",
                "details": str(e)
            }]
        }
        iam_status = 'failed'

    # Process findings to add scanner identification for error findings
    all_findings = []

    # Process S3 findings
    if s3_result and 'findings' in s3_result:
        for finding in s3_result['findings']:
            # Add scanner identification to all findings
            finding = finding.copy()  # Don't modify original
            finding['scanner'] = 's3'
            all_findings.append(finding)

    # Process Security Group findings
    if sg_result and 'findings' in sg_result:
        for finding in sg_result['findings']:
            # Add scanner identification to all findings
            finding = finding.copy()  # Don't modify original
            finding['scanner'] = 'security_group'
            all_findings.append(finding)

    # Process IAM findings
    if iam_result and 'findings' in iam_result:
        for finding in iam_result['findings']:
            # Add scanner identification to all findings
            finding = finding.copy()  # Don't modify original
            finding['scanner'] = 'iam'
            all_findings.append(finding)

    # Calculate total findings count
    total_findings_count = len(all_findings)

    # Determine overall status based on the statuses of all three scanners
    statuses = [s3_status, sg_status, iam_status]
    if all(status == 'completed' for status in statuses):
        overall_status = 'completed'
    elif all(status == 'failed' for status in statuses):
        overall_status = 'failed'
    else:
        # At least one scanner has a different status (mixed success/failure)
        overall_status = 'partial_failure'

    # Compute compliance scoring results
    scoring_results = compute_scan_results(all_findings)

    # Persist to database if session is provided
    if db is not None:
        try:
            # Extract AWS account ID from request if available
            aws_account_id = getattr(request, 'aws_account_id', None)

            # Create scan record with findings
            create_scan(
                db=db,
                scan_id=master_scan_id,
                status=overall_status,
                scan_timestamp=scan_timestamp,
                aws_account_id=aws_account_id,
                findings_count=total_findings_count,
                security_score=scoring_results["security_score"],
                risk_level=scoring_results["risk_level"],
                findings=all_findings
            )
        except Exception as e:
            # Log the error but don't break the scan execution
            logger.error(f"Failed to persist scan results to database: {e}")
            # Continue to return the scan results to the user

    # Return unified response matching ScanResponse schema
    return {
        "scan_id": master_scan_id,
        "status": overall_status,
        "findings_count": total_findings_count,
        "findings": all_findings,
        "security_score": scoring_results["security_score"],
        "risk_level": scoring_results["risk_level"],
        "severity_breakdown": scoring_results["severity_breakdown"]
    }