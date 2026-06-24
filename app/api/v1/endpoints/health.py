from fastapi import APIRouter
import os

router = APIRouter()

@router.get("")
async def health_check():
    """
    Health check endpoint that returns application status and mode.
    """
    demo_mode = os.getenv("DEMO_MODE", "false").lower() == "true"
    mode = "demo" if demo_mode else "live"

    return {
        "status": "healthy",
        "mode": mode,
        "version": "1.0.0"
    }