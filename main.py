import os
from contextlib import asynccontextmanager
from logging.config import dictConfig
from fastapi import FastAPI
from fastapi_pagination import add_pagination
from app.routers import messages, notifications
from fcm.firebase import initialize_firebase
from app.database import close_redis_pool, set_redis_settings, init_db
from app.logging_config import LOGGING_CONFIG
import logging

dictConfig(LOGGING_CONFIG)

# Import all SQLModel table classes so their metadata is registered
# before init_db() calls SQLModel.metadata.create_all()
import app.scheme.message          # noqa: F401
import app.scheme.notification     # noqa: F401
import app.scheme.malicious_url    # noqa: F401

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.debug("Starting up application")

    # Redis
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", "6379"))
    await set_redis_settings(host=redis_host, port=redis_port)
    logger.info(f"Redis on {redis_host}:{redis_port}")

    # Postgres must be configured before get_engine() is called anywhere.
    init_db()
    logger.info("Postgres initialized")

    yield

    await close_redis_pool()

    logger.debug("Application stopped")


app = FastAPI(lifespan=lifespan)
add_pagination(app)

app.include_router(messages.router)
app.include_router(notifications.router)


@app.get("/")
async def root():
    return {"Hello": "World"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="localhost",
        port=8000,
        log_level="debug",
        log_config=LOGGING_CONFIG,
    )
