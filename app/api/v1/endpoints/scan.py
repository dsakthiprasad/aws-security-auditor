from fastapi import APIRouter, Depends
from app.models.scan import ScanRequest, ScanResponse
from app.services.orchestrator import run_full_scan
from app.db.session import get_db
from sqlalchemy.orm import Session

router = APIRouter()


@router.post("", response_model=ScanResponse)
async def initiate_scan(scan_request: ScanRequest, db: Session = Depends(get_db)):
    """
    Endpoint to initiate a full AWS security scan.
    This orchestrator calls both S3 and Security Group scanners
    and returns unified results.
    """
    # Run the full scan orchestrator with database session
    result = run_full_scan(scan_request, db)
    return result