"""
Database connection and session management.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..config import get_settings
from .models import Base


class Database:
    """Async database manager."""

    def __init__(self, url: str | None = None):
        """
        Initialize database.

        Args:
            url: Database URL (default: from settings)
        """
        settings = get_settings()
        self.url = url or settings.database_url

        self.engine = create_async_engine(
            self.url,
            echo=settings.debug,
            future=True,
        )

        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def init_db(self) -> None:
        """Create all tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_db(self) -> None:
        """Drop all tables (use with caution!)."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def execute_raw(self, sql: str) -> list[dict]:
        """
        Execute raw SQL query (SELECT only for safety).

        Args:
            sql: SQL query string

        Returns:
            List of result dictionaries
        """
        # Safety check
        sql_upper = sql.strip().upper()
        if not (sql_upper.startswith("SELECT") or sql_upper.startswith("WITH")):
            raise ValueError("Only SELECT queries are allowed")

        async with self.session() as session:
            result = await session.execute(text(sql))
            rows = result.fetchall()
            columns = result.keys()
            return [dict(zip(columns, row)) for row in rows]

    async def close(self) -> None:
        """Close database connections."""
        await self.engine.dispose()


# Global database instance
_db: Database | None = None


def get_db() -> Database:
    """Get or create global database instance."""
    global _db
    if _db is None:
        _db = Database()
    return _db


async def init_database() -> None:
    """Initialize database tables."""
    db = get_db()
    await db.init_db()
