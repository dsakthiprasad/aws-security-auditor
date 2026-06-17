"""
SQLAlchemy models for AWS Security Auditor persistence layer.

This module defines the ORM models for storing scan results and findings.
These models are completely separate from the Pydantic models in app/models/scan.py
as per the architecture requirements.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, func
from sqlalchemy.orm import relationship
from app.db.session import Base


class Scan(Base):
    """
    SQLAlchemy model representing a security scan.

    Stores metadata and aggregated results for each security scan execution.
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(36), unique=True, index=True, nullable=False)  # UUID
    status = Column(String(20), nullable=False)  # completed, failed, partial_failure
    scan_timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    aws_account_id = Column(String(12), nullable=True)  # AWS account ID
    findings_count = Column(Integer, nullable=False, default=0)
    security_score = Column(Integer, nullable=True)  # 0-100
    risk_level = Column(String(15), nullable=True)  # Low Risk, Medium Risk, High Risk, Critical Risk
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationship to findings
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self):
        """
        Convert the Scan model to a dictionary.

        Returns:
            dict: Dictionary representation of the scan
        """
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "status": self.status,
            "scan_timestamp": self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            "aws_account_id": self.aws_account_id,
            "findings_count": self.findings_count,
            "security_score": self.security_score,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class Finding(Base):
    """
    SQLAlchemy model representing an individual security finding.

    Stores the original finding data from scanners as JSON text.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    scanner = Column(String(20), nullable=False)  # s3, security_group, iam
    issue_type = Column(String(100), nullable=False, index=True)
    finding_data = Column(Text, nullable=False)  # JSON stored as text
    discovered_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationship to scan
    scan = relationship("Scan", back_populates="findings")

    def to_dict(self):
        """
        Convert the Finding model to a dictionary.

        Returns:
            dict: Dictionary representation of the finding
        """
        import json
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "scanner": self.scanner,
            "issue_type": self.issue_type,
            "finding_data": json.loads(self.finding_data) if self.finding_data else {},
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }