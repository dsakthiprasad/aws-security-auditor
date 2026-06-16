from fastapi import FastAPI
from app.api.v1.endpoints import health, scan

app = FastAPI(title="AWS Security & Compliance Auditor", version="0.1.0")

# Include routers
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(scan.router, prefix="/scan", tags=["scan"])