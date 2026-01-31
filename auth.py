from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
import os
import psycopg
from psycopg.rows import dict_row

router = APIRouter(prefix="/auth", tags=["auth"])

SECRET_KEY = os.getenv("SECRET_KEY", "metpro-erp-secret-key-change-in-production-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
security = HTTPBearer()


class LoginRequest(BaseModel):
    username: str
    password: str


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@router.post("/login")
def login(payload: LoginRequest):
    conn = psycopg.connect(os.getenv("DATABASE_URL"), row_factory=dict_row)
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username = %s", (payload.username,))
    user = cur.fetchone()

    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    # IMPORTANT: Supabase column is hashed_password
    if not pwd_context.verify(payload.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect password")

    token = create_access_token({"sub": payload.username})
    return {"access_token": token, "token_type": "bearer"}


# ⭐⭐⭐ TOKEN VERIFICATION ADDED HERE ⭐⭐⭐
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # contains "sub" (username)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")