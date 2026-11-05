"""Database engine, session factory and the reusable `get_db` dependency."""
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings


class Base(DeclarativeBase):
    """Parent class of all SQLAlchemy models."""


def _create_engine():
    url = settings.sqlalchemy_url
    if url.startswith("sqlite"):  # only used by the automated tests
        kwargs = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
        return create_engine(url, **kwargs)
    # pool_pre_ping drops dead connections, pool_recycle avoids MySQL "gone away" errors
    return create_engine(url, pool_pre_ping=True, pool_recycle=3600)


engine = _create_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, always closed afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
