"""
Database connection and session management for AdversarialShield.
Supports PostgreSQL (SQLAlchemy), Redis, and MongoDB.
"""
from typing import AsyncGenerator

from motor.motor_asyncio import AsyncIOMotorClient
from redis import asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from backend.core.config import settings

# SQLAlchemy Base
Base = declarative_base()

# PostgreSQL Engine
engine = create_async_engine(
    settings.database_url.replace("postgresql://", "postgresql+asyncpg://"),
    echo=settings.is_development,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Async Session Factory
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting async database sessions.

    Usage:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Redis Connection
class RedisClient:
    """Redis client wrapper for connection management."""

    def __init__(self):
        self.client: aioredis.Redis | None = None

    async def connect(self):
        """Establish Redis connection."""
        self.client = await aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )

    async def disconnect(self):
        """Close Redis connection."""
        if self.client:
            await self.client.close()

    async def get_client(self) -> aioredis.Redis:
        """Get Redis client instance."""
        if not self.client:
            await self.connect()
        return self.client


redis_client = RedisClient()


async def get_redis() -> aioredis.Redis:
    """
    Dependency for getting Redis client.

    Usage:
        @app.get("/cache")
        async def get_cache(redis: aioredis.Redis = Depends(get_redis)):
            ...
    """
    return await redis_client.get_client()


# MongoDB Connection
class MongoDBClient:
    """MongoDB client wrapper for connection management."""

    def __init__(self):
        self.client: AsyncIOMotorClient | None = None
        self.db = None

    async def connect(self):
        """Establish MongoDB connection."""
        self.client = AsyncIOMotorClient(settings.mongodb_url)
        # Extract database name from URL
        db_name = settings.mongodb_url.split("/")[-1]
        self.db = self.client[db_name]

    async def disconnect(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()

    async def get_database(self):
        """Get MongoDB database instance."""
        if not self.db:
            await self.connect()
        return self.db


mongodb_client = MongoDBClient()


async def get_mongodb():
    """
    Dependency for getting MongoDB database.

    Usage:
        @app.get("/documents")
        async def get_documents(db = Depends(get_mongodb)):
            ...
    """
    return await mongodb_client.get_database()


async def init_db():
    """Initialize database connections and create tables."""
    # Create PostgreSQL tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Initialize Redis connection
    await redis_client.connect()

    # Initialize MongoDB connection
    await mongodb_client.connect()


async def close_db():
    """Close all database connections."""
    # Close PostgreSQL
    await engine.dispose()

    # Close Redis
    await redis_client.disconnect()

    # Close MongoDB
    await mongodb_client.disconnect()
