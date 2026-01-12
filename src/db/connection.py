"""
Database connection management.
"""
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.config.settings import get_settings


@lru_cache
def get_engine():
    """Get cached database engine."""
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )


@lru_cache
def get_session_factory():
    """Get cached session factory."""
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_session() -> Session:
    """Create a new database session."""
    factory = get_session_factory()
    return factory()


@contextmanager
def get_db_session():
    """Context manager for database sessions with automatic cleanup."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    """Initialize database tables and run migrations."""
    from src.db.models import Base
    from sqlalchemy import text

    engine = get_engine()
    Base.metadata.create_all(bind=engine)

    # Run migrations for schema changes added after initial release
    _run_migrations(engine)


def _run_migrations(engine):
    """Run database migrations for schema changes.

    This handles adding new columns/tables to existing databases.
    SQLAlchemy's create_all only creates new tables, not new columns.
    """
    from sqlalchemy import text

    migrations = [
        # (description, check_query, migration_query)
        (
            "Add management_subnet column to devices",
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='devices' AND column_name='management_subnet'",
            "ALTER TABLE devices ADD COLUMN management_subnet VARCHAR(50)",
        ),
        # Add future migrations here as tuples:
        # ("Description", "SELECT check query", "ALTER/CREATE migration query"),
    ]

    with engine.connect() as conn:
        for description, check_query, migration_query in migrations:
            result = conn.execute(text(check_query))
            if not result.fetchone():
                conn.execute(text(migration_query))
                conn.commit()
