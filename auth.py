from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
import os


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
    try:
        # Get DATABASE_URL from environment
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise HTTPException(status_code=500, detail="Database configuration missing")
        
        # Connect to database
        conn = psycopg.connect(db_url, row_factory=dict_row)
        cur = conn.cursor()
        
        # Query user
        cur.execute("SELECT * FROM users WHERE username = %s", (payload.username,))
        user = cur.fetchone()
        
        # Close connection
        cur.close()
        conn.close()
        
        # Validate user exists
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        # Verify password
        if not pwd_context.verify(payload.password, user["hashed_password"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        # Create token
        token = create_access_token({"sub": payload.username})
        
        return {"access_token": token, "token_type": "bearer"}
    
    except psycopg.Error as db_error:
        print(f"Database error: {db_error}")
        raise HTTPException(status_code=500, detail="Database connection failed")
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Token verification
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # contains "sub" (username)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
