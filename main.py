import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi_pagination import add_pagination
from app.routers import messages, notifications
from fcm.firebase import initialize_firebase
from app.database import close_redis_pool, set_redis_settings
from testcontainers.compose import DockerCompose
import logging

compose = DockerCompose(".", compose_file_name="compose.yml")
logger = logging.getLogger("uvicorn.error")

@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.debug("Starting up redis and workers")

    compose.start()
    
    redis_host = compose.get_service_host("redis", 6379)
    redis_port = compose.get_service_port("redis", 6379)

    await set_redis_settings(host=redis_host, port=redis_port)

    logger.info(f"DB initialized on {redis_host}:{redis_port}")

    yield

    await close_redis_pool()

    compose.stop()
    
    logger.debug("redis and workers stopped")

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


