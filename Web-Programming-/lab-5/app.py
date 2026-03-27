from fastapi import FastAPI
from db import database
from routes.auth_routes import router as auth_router

app = FastAPI()
app.include_router(auth_router)


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()