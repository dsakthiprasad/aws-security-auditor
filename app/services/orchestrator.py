import uuid
from app.services.scanner import scan_aws_account
from app.services.security_group_scanner import scan_security_groups
from app.services.iam_scanner import scan_iam


def run_full_scan(request):
    """
    Orchestrator function that runs S3, Security Group, and IAM scanners
    and combines their results into a unified response.

    Args:
        request: The incoming request object (ScanRequest)

    Returns:
        A dictionary containing:
            - scan_id: A unique identifier for this combined scan (UUID string).
            - status: Either 'completed', 'partial_failure', or 'failed'.
            - findings_count: The total number of findings from all scanners.
            - findings: A list of finding dictionaries from all scanners,
                       with error findings enhanced to include scanner identification.
    """
    # Generate a single master scan ID for the entire combined operation
    master_scan_id = str(uuid.uuid4())

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
            # If this is an error finding (indicated by issue being 'Scan failed' or similar),
            # add scanner identification
            if s3_status == 'failed' and finding.get('issue') == 'Scan failed':
                finding = finding.copy()  # Don't modify original
                finding['scanner'] = 's3'
            all_findings.append(finding)

    # Process Security Group findings
    if sg_result and 'findings' in sg_result:
        for finding in sg_result['findings']:
            # If this is an error finding, add scanner identification
            if sg_status == 'failed' and finding.get('issue') in ['Scan failed', 'AWS API error']:
                finding = finding.copy()  # Don't modify original
                finding['scanner'] = 'security_group'
            all_findings.append(finding)

    # Process IAM findings
    if iam_result and 'findings' in iam_result:
        for finding in iam_result['findings']:
            # If this is an error finding, add scanner identification
            if iam_status == 'failed' and finding.get('issue') in ['IAM scan failed due to AWS API error', 'Unexpected error during IAM scan']:
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

    # Return unified response matching ScanResponse schema
    return {
        "scan_id": master_scan_id,
        "status": overall_status,
        "findings_count": total_findings_count,
        "findings": all_findings
    }