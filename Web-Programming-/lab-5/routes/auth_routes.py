from fastapi import APIRouter

from controllers.auth_controller import login_user, register_user
from schema import UserCreate, UserLogin

router = APIRouter()


@router.post("/register")
async def register(user: UserCreate):
    return await register_user(user)


@router.post("/login")
async def login(user: UserLogin):
    return await login_user(user)
