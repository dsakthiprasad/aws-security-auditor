"""
History API endpoints for AWS Security Auditor.

This module provides endpoints to retrieve historical scan data.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.crud.scan import get_scan_by_scan_id, get_all_scans
from app.db.session import get_db
from app.models.scan import ScanResponse

router = APIRouter()


@router.get("/scans", response_model=List[dict])
def get_scans(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """
    Retrieve historical scans with pagination.

    Returns the latest scans (limited to 50 by default) with basic information.
    """
    scans = get_all_scans(db, skip=skip, limit=limit)

    # Convert to dictionary format for API response
    result = []
    for scan in scans:
        result.append({
            "scan_id": scan.scan_id,
            "status": scan.status,
            "timestamp": scan.scan_timestamp.isoformat() if scan.scan_timestamp else None,
            "findings_count": scan.findings_count,
            "security_score": scan.security_score,
            "risk_level": scan.risk_level
        })

    return result


@router.get("/scans/{scan_id}", response_model=dict)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    Retrieve a specific scan by its scan_id, including all findings.

    Args:
        scan_id: The unique scan identifier (UUID)

    Returns:
        Dictionary containing scan details and all associated findings

    Raises:
        HTTPException: 404 if scan is not found
    """
    db_scan = get_scan_by_scan_id(db, scan_id)
    if db_scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Build response with scan details and findings
    findings = []
    for finding in db_scan.findings:
        finding_dict = finding.to_dict()
        findings.append({
            "id": finding_dict["id"],
            "scanner": finding_dict["scanner"],
            "issue_type": finding_dict["issue_type"],
            "finding_data": finding_dict["finding_data"],
            "discovered_at": finding_dict["discovered_at"]
        })

    return {
        "scan_id": db_scan.scan_id,
        "status": db_scan.status,
        "timestamp": db_scan.scan_timestamp.isoformat() if db_scan.scan_timestamp else None,
        "aws_account_id": db_scan.aws_account_id,
        "findings_count": db_scan.findings_count,
        "security_score": db_scan.security_score,
        "risk_level": db_scan.risk_level,
        "findings": findings
    }