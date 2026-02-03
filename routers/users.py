from fastapi import APIRouter, Depends, HTTPException
from typing import List
from models.user_models import User, UserCreate, UserUpdate
from services.user_service import verify_token
from db.connection import get_db_connection
from passlib.context import CryptContext
import psycopg2.extras

router = APIRouter(prefix="/users", tags=["Users"])
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


@router.post('/register')
def register_user(user: UserCreate, current_user: dict = Depends(verify_token)):
    """
    Register new user (admin-only endpoint)
    """
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail='Only admins can create users')

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Check username
        cursor.execute('SELECT 1 FROM users WHERE username = %s', (user.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail='Username already exists')

        # Check email
        if user.email:
            cursor.execute('SELECT 1 FROM users WHERE email = %s', (user.email,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail='Email already registered')

        hashed_password = pwd_context.hash(user.password)

        cursor.execute('''
            INSERT INTO users (username, email, hashed_password, role, is_active)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, username, email, role, is_active, created_at
        ''', (
            user.username,
            user.email,
            hashed_password,
            user.role or 'user',
            True
        ))

        new_user = cursor.fetchone()
        conn.commit()

        return {
            'message': 'User created successfully',
            'user': {
                'id': new_user['id'],
                'username': new_user['username'],
                'email': new_user['email'],
                'role': new_user['role'],
                'is_active': new_user['is_active'],
                'created_at': new_user['created_at'].isoformat()
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f'Registration failed: {str(e)}')
    finally:
        if conn:
            conn.close()
