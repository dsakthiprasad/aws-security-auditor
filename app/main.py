from fastapi import FastAPI
from app.api.v1.endpoints import health, scan, history, remediation
from app.db.session import engine
from app.models.db import Base

app = FastAPI(title="AWS Security & Compliance Auditor", version="0.1.0")


@app.on_event("startup")
def startup_event():
    """
    Initialize the database on application startup.
    """
    Base.metadata.create_all(bind=engine)


# Include routers
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(scan.router, prefix="/scan", tags=["scan"])
app.include_router(
    history.router,
    prefix="/history",
    tags=["history"]
)
app.include_router(
    remediation.router,
    prefix="/remediate",
    tags=["remediation"]
)