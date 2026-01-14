from sqlmodel import create_engine, SQLModel, Session
from arq import create_pool
from arq.connections import RedisSettings
import os

DATABASE_URL = 'sqlite:///db.sqlite'

engine = create_engine(DATABASE_URL, echo=True)

def init_db():
    SQLModel.metadata.create_all(engine)
    
def get_session():
    with Session(engine) as session:
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
        redis_pool = await create_pool(
            redis_settings
        )
    return redis_pool

async def close_redis_pool():
    global redis_pool
    if redis_pool:
        await redis_pool.close()
        redis_pool = None