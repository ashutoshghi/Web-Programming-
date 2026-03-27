from fastapi import HTTPException
from passlib.context import CryptContext

from db import database
from models import users
from schema import UserCreate, UserLogin

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def register_user(user: UserCreate):
    query = users.select().where(users.c.username == user.username)
    existing_user = await database.fetch_one(query)

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = pwd_context.hash(user.password[:72])
    query = users.insert().values(username=user.username, password=hashed_password)
    await database.execute(query)

    return {"message": "User created successfully!"}


async def login_user(user: UserLogin):
    query = users.select().where(users.c.username == user.username)
    db_user = await database.fetch_one(query)

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    if not pwd_context.verify(user.password[:72], db_user.password):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    return {"message": "Login successful!"}
