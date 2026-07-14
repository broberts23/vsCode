"""SQLite database engine and session management."""

import os
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from scim_gateway.models import Base

DB_PATH = os.environ.get("SCIM_DB_PATH", "scim_store.db")

engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
_SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def init_db() -> None:
    """Create all tables if they do not exist."""
    Base.metadata.create_all(bind=engine)


def get_db_session() -> Generator[Session, None, None]:
    """Yield a database session, ensuring clean connection closure."""
    session = _SessionLocal()
    try:
        yield session
    finally:
        session.close()
