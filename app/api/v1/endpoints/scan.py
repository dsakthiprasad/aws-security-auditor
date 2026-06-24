from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
import os
import logging
from app.models.scan import ScanRequest, ScanResponse
from app.services.orchestrator import run_full_scan
from app.db.session import get_db
from app.demo.demo_scan import generate_demo_scan

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("", response_model=ScanResponse)
async def initiate_scan(scan_request: ScanRequest, db: Session = Depends(get_db)):
    """
    Endpoint to initiate a full AWS security scan.
    This orchestrator calls both S3 and Security Group scanners
    and returns unified results.

    When DEMO_MODE=true, returns pre-generated demo data instead of making AWS API calls.
    """
    # Check if demo mode is enabled
    demo_mode = os.getenv("DEMO_MODE", "false").lower() == "true"

    if demo_mode:
        logger.info("DEMO_MODE enabled - returning demo scan data")
        return generate_demo_scan()

    # Run the full scan orchestrator with database session
    result = run_full_scan(scan_request, db)
    return result