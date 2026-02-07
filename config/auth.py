from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer
import jwt
from config.settings import JWT_SECRET

security = HTTPBearer()

def verify_token(credentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")