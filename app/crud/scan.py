"""
CRUD operations for Scan model.

This module contains database helper functions for creating and retrieving
scan records. These functions are isolated from routers and services as per
the architecture requirements.
"""

import json
from sqlalchemy.orm import Session
from app.models.db import Scan, Finding
from typing import List, Optional


def create_scan(db: Session, scan_id: str, status: str, scan_timestamp: str,
                aws_account_id: Optional[str], findings_count: int,
                security_score: Optional[int], risk_level: Optional[str],
                findings: List[dict]) -> Scan:
    """
    Create a new scan record with associated findings.

    Args:
        db: Database session
        scan_id: Unique scan identifier (UUID)
        status: Overall scan status
        scan_timestamp: Timestamp when scan was initiated
        aws_account_id: AWS account identifier (optional)
        findings_count: Total number of findings
        security_score: Calculated compliance score (optional)
        risk_level: Risk level derived from score (optional)
        findings: List of finding dictionaries from scanners

    Returns:
        Scan: The created scan object with assigned ID
    """
    # Create the scan record
    db_scan = Scan(
        scan_id=scan_id,
        status=status,
        scan_timestamp=scan_timestamp,
        aws_account_id=aws_account_id,
        findings_count=findings_count,
        security_score=security_score,
        risk_level=risk_level
    )
    db.add(db_scan)
    db.flush()  # Flush to get the ID without committing

    # Create finding records
    for finding in findings:
        db_finding = Finding(
            scan_id=db_scan.id,
            scanner=finding.get("scanner", "unknown"),
            issue_type=finding.get("issue", "Unknown Issue"),
            finding_data=json.dumps(finding)  # Store as JSON string
        )
        db.add(db_finding)

    db.commit()
    db.refresh(db_scan)
    return db_scan


def get_scan_by_scan_id(db: Session, scan_id: str) -> Optional[Scan]:
    """
    Retrieve a scan by its scan_id (UUID).

    Args:
        db: Database session
        scan_id: Unique scan identifier (UUID)

    Returns:
        Optional[Scan]: The scan object if found, None otherwise
    """
    return db.query(Scan).filter(Scan.scan_id == scan_id).first()


def get_all_scans(db: Session, skip: int = 0, limit: int = 100) -> List[Scan]:
    """
    Retrieve all scans with pagination.

    Args:
        db: Database session
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return

    Returns:
        List[Scan]: List of scan objects
    """
    return db.query(Scan).offset(skip).limit(limit).all()