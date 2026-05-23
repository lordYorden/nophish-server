import asyncio
import os
import time
from sqlmodel import create_engine, SQLModel, Session
from sqlalchemy import text
from arq import create_pool
from arq.connections import RedisSettings

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        url = os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://nophish:nophish@localhost:5432/nophish",
        )
        _engine = create_engine(url, echo=True)
    return _engine


def init_db():
    engine = get_engine()
    # Enable pgvector extension before creating tables that use the Vector type
    with engine.connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        conn.commit()
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(get_engine()) as session:
        yield session


redis_pool = None
redis_settings = RedisSettings(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
)


async def set_redis_settings(host: str, port: int = 6379):
    global redis_settings
    redis_settings = RedisSettings(host, port)


async def get_redis_pool():
    global redis_pool
    global redis_settings
    if redis_pool is None:
        redis_pool = await create_pool(redis_settings)
    return redis_pool


async def close_redis_pool():
    global redis_pool
    if redis_pool:
        await redis_pool.close()
        redis_pool = None


async def wait_for_redis(timeout_seconds: int = 60, interval_seconds: int = 1):
    deadline = time.monotonic() + timeout_seconds
    last_error = None

    while time.monotonic() < deadline:
        try:
            pool = await get_redis_pool()
            await pool.ping()
            return
        except Exception as exc:
            last_error = exc
            await close_redis_pool()
            await asyncio.sleep(interval_seconds)

    raise RuntimeError("Redis did not become available") from last_error


async def wait_for_postgres(timeout_seconds: int = 60, interval_seconds: int = 1):
    deadline = time.monotonic() + timeout_seconds
    last_error = None

    while time.monotonic() < deadline:
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception as exc:
            last_error = exc
            await asyncio.sleep(interval_seconds)

    raise RuntimeError("Postgres did not become available") from last_error
