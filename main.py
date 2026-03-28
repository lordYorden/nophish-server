import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi_pagination import add_pagination
from app.routers import messages, notifications
from fcm.firebase import initialize_firebase
from app.database import close_redis_pool, set_redis_settings, init_db
from testcontainers.compose import DockerCompose
import logging

# Import all SQLModel table classes so their metadata is registered
# before init_db() calls SQLModel.metadata.create_all()
import app.scheme.message          # noqa: F401
import app.scheme.notification     # noqa: F401
import app.scheme.malicious_url    # noqa: F401

compose = DockerCompose(".", compose_file_name="compose.yml")
logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.debug("Starting up Postgres, Redis, and workers")

    compose.start()

    # Redis
    redis_host = compose.get_service_host("redis", 6379)
    redis_port = compose.get_service_port("redis", 6379)
    await set_redis_settings(host=redis_host, port=int(redis_port))
    logger.info(f"Redis on {redis_host}:{redis_port}")

    # Postgres — must be set before get_engine() is called anywhere
    pg_host = compose.get_service_host("postgres", 5432)
    pg_port = compose.get_service_port("postgres", 5432)
    os.environ["DATABASE_URL"] = (
        f"postgresql+psycopg://nophish:nophish@{pg_host}:{pg_port}/nophish"
    )
    init_db()
    logger.info(f"Postgres on {pg_host}:{pg_port}")

    yield

    await close_redis_pool()
    compose.stop()

    logger.debug("Postgres, Redis, and workers stopped")


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
