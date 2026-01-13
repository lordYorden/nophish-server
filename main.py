from fastapi import FastAPI
from fastapi_pagination import add_pagination
from app.routers import messages, notifications

app = FastAPI()
add_pagination(app)

app.include_router(messages.router)
app.include_router(notifications.router)

@app.get("/")
async def root():
    return {"Hello": "World"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="localhost", port=8000, log_level="debug", reload=True)


