from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Table
from db import metadata

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, unique=True, nullable=False, index=True),
    Column("password", String, unique=True, nullable=False),
)

todos = Table(
    "todos",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("text", String, nullable=False),
    Column("completed", Boolean, nullable=False, default=False),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
)