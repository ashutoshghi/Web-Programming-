from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from passlib.context import CryptContext

from db import database, engine, metadata
from models import todos, users
from schema import TodoCreate, TodoResponse, TodoUpdate, UserCreate, UserLogin

app = FastAPI()
metadata.create_all(engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
BASE_DIR = Path(__file__).resolve().parent


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.get("/")
async def root():
    return FileResponse(BASE_DIR / "index.html")


@app.post("/register")
async def register_user(user: UserCreate):
    query = users.select().where(users.c.username == user.username)
    existing_user = await database.fetch_one(query)

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = pwd_context.hash(user.password[:72])
    query = users.insert().values(username=user.username, password=hashed_password)
    user_id = await database.execute(query)

    return {"message": "User created successfully!", "user_id": user_id}


@app.post("/login")
async def login_user(user: UserLogin):
    query = users.select().where(users.c.username == user.username)
    db_user = await database.fetch_one(query)

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    if not pwd_context.verify(user.password[:72], db_user.password):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    return {"message": "Login successful!", "user_id": db_user.id}


@app.get("/todos/{user_id}", response_model=List[TodoResponse])
async def get_todos(user_id: int):
    user_exists_query = users.select().where(users.c.id == user_id)
    user_row = await database.fetch_one(user_exists_query)
    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")

    query = todos.select().where(todos.c.user_id == user_id).order_by(todos.c.id.desc())
    return await database.fetch_all(query)


@app.post("/todos/{user_id}", response_model=TodoResponse)
async def create_todo(user_id: int, todo: TodoCreate):
    user_exists_query = users.select().where(users.c.id == user_id)
    user_row = await database.fetch_one(user_exists_query)
    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")

    insert_query = todos.insert().values(
        text=todo.text,
        completed=False,
        user_id=user_id,
    )
    todo_id = await database.execute(insert_query)

    fetch_query = todos.select().where(todos.c.id == todo_id)
    created_todo = await database.fetch_one(fetch_query)
    return created_todo


@app.put("/todos/{todo_id}", response_model=TodoResponse)
async def update_todo(todo_id: int, payload: TodoUpdate):
    fetch_query = todos.select().where(todos.c.id == todo_id)
    existing_todo = await database.fetch_one(fetch_query)
    if not existing_todo:
        raise HTTPException(status_code=404, detail="Todo not found")

    new_text = existing_todo.text if payload.text is None else payload.text

    if payload.completed is None and payload.text is None:
        new_completed = not existing_todo.completed
    elif payload.completed is None:
        new_completed = existing_todo.completed
    else:
        new_completed = payload.completed

    update_query = (
        todos.update()
        .where(todos.c.id == todo_id)
        .values(text=new_text, completed=new_completed)
    )
    await database.execute(update_query)

    updated_todo = await database.fetch_one(fetch_query)
    return updated_todo


@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: int):
    fetch_query = todos.select().where(todos.c.id == todo_id)
    existing_todo = await database.fetch_one(fetch_query)
    if not existing_todo:
        raise HTTPException(status_code=404, detail="Todo not found")

    delete_query = todos.delete().where(todos.c.id == todo_id)
    await database.execute(delete_query)

    return {"message": "Todo deleted successfully!"}