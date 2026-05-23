import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi_pagination import add_pagination
from app.routers import messages, notifications
from fcm.firebase import initialize_firebase
from app.database import (
    close_redis_pool,
    init_db,
    set_redis_settings,
    wait_for_postgres,
    wait_for_redis,
)
import logging

# Import all SQLModel table classes so their metadata is registered
# before init_db() calls SQLModel.metadata.create_all()
import app.scheme.message          # noqa: F401
import app.scheme.notification     # noqa: F401
import app.scheme.malicious_url    # noqa: F401

logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.debug("Starting up FastAPI server")

    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", "6379"))
    await set_redis_settings(host=redis_host, port=redis_port)
    logger.info("Redis configured on %s:%s", redis_host, redis_port)

    await wait_for_redis()
    await wait_for_postgres()
    init_db()
    logger.info("Postgres initialized from DATABASE_URL")

    yield

    await close_redis_pool()

    logger.debug("FastAPI server stopped")


app = FastAPI(lifespan=lifespan)
add_pagination(app)

app.include_router(messages.router)
app.include_router(notifications.router)


@app.get("/")
async def root():
    return {"Hello": "World"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="localhost", port=8000, log_level="debug")
