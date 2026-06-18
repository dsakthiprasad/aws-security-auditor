"""
Terraform remediation API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.services.remediation import generate_remediation
from app.db.session import get_db

router = APIRouter()


@router.get("/{scan_id}", response_model=Dict[str, Any])
def get_remediation(
    scan_id: str = Path(..., description="The scan ID to generate remediation for"),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Generate Terraform remediation for a specific scan.

    Args:
        scan_id: The unique scan identifier (UUID)
        db: Database session

    Returns:
        Dictionary containing generated Terraform, manual guidance, and metadata.

    Raises:
        HTTPException: 404 if scan is not found, 500 for internal errors.
    """
    try:
        remediation_data = generate_remediation(db, scan_id)
        return remediation_data
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        # Log the error (in a real app, use logging)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")