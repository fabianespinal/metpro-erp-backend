from pydantic import BaseModel, EmailStr
from typing import Optional

class UserCreate(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    password: str
    role: Optional[str] = "user"

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

class User(BaseModel):
    id: int
    username: str
    email: Optional[EmailStr]
    role: str
    is_active: bool
    created_at: str