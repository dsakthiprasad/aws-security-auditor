from pydantic import BaseModel
from typing import List, Optional


class ScanRequest(BaseModel):
    aws_account_id: str
    # Optional: list of AWS regions to scan, empty means all
    regions: Optional[List[str]] = None
    # Optional: specific compliance frameworks to check (e.g., ['cis', 'gdpr'])
    frameworks: Optional[List[str]] = None


class ScanResponse(BaseModel):
    scan_id: str
    status: str  # e.g., "completed", "failed", "in_progress"
    findings_count: int
    # Optional: list of findings (we'll define a Finding model later if needed)
    # For now, we can leave it as a placeholder
    findings: Optional[List[dict]] = None