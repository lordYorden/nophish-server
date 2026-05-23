import os
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
        _engine = create_engine(url, echo=False)
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
redis_settings = None


async def set_redis_settings(host: str, port: int):
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
