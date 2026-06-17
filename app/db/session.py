"""
Database session management for AWS Security Auditor.

This module sets up the SQLAlchemy engine, session factory, and base class
for ORM models. It also provides a dependency for FastAPI to inject database
sessions.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLAlchemy database URL (SQLite)
SQLALCHEMY_DATABASE_URL = "sqlite:///./audit.db"

# Create SQLAlchemy engine
# connect_args={"check_same_thread": False} is needed for SQLite
# when using it with multiple threads (FastAPI default)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Create SessionLocal class
# Each instance of SessionLocal will be a database session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base class for declarative models
Base = declarative_base()


def get_db():
    """
    Dependency that provides a database session.

    Yields:
        Session: SQLAlchemy database session

    Note:
        The session is always closed after use, even if an exception occurs.
        This prevents database locking issues in SQLite.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()