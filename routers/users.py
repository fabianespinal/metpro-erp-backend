import os
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from config.database import get_db_connection
from models.user_models import User, UserCreate, UserUpdate
from services.user_service import verify_token
from passlib.context import CryptContext

router = APIRouter(prefix="/users", tags=["Users"])
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


# -----------------------------
# CREATE USER (ADMIN ONLY)
# -----------------------------
@router.post("/register")
def register_user(user: UserCreate, current_user: dict = Depends(verify_token)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can create users")

    with get_db_connection() as conn:
        cur = conn.cursor()

        # Check username
        cur.execute("SELECT 1 FROM users WHERE username = ?", (user.username,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Username already exists")

        # Check email
        if user.email:
            cur.execute("SELECT 1 FROM users WHERE email = ?", (user.email,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Email already registered")

        hashed_password = pwd_context.hash(user.password)

        cur.execute(
            """
            INSERT INTO users (username, email, hashed_password, role, is_active)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user.username,
                user.email,
                hashed_password,
                user.role or "user",
                True,
            ),
        )
        conn.commit()

        new_id = cur.lastrowid

        cur.execute(
            "SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ?",
            (new_id,),
        )
        new_user = cur.fetchone()

        return {
            "message": "User created successfully",
            "user": {
                "id": new_user["id"],
                "username": new_user["username"],
                "email": new_user["email"],
                "role": new_user["role"],
                "is_active": new_user["is_active"],
                "created_at": new_user["created_at"],
            },
        }


# -----------------------------
# GET ALL USERS (ADMIN ONLY)
# -----------------------------
@router.get("/", response_model=List[User])
def get_users(current_user: dict = Depends(verify_token)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can view users")

    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, email, role, is_active, created_at FROM users ORDER BY created_at DESC"
        )
        rows = cur.fetchall()

        return [
            User(
                id=row["id"],
                username=row["username"],
                email=row["email"],
                role=row["role"],
                is_active=row["is_active"],
                created_at=row["created_at"],
            )
            for row in rows
        ]


# -----------------------------
# GET SINGLE USER
# -----------------------------
@router.get("/{user_id}", response_model=User)
def get_user(user_id: int, current_user: dict = Depends(verify_token)):
    with get_db_connection() as conn:
        cur = conn.cursor()

        if current_user.get("user_id") != user_id and current_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Access denied")

        cur.execute(
            "SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ?",
            (user_id,),
        )
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        return User(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            role=row["role"],
            is_active=row["is_active"],
            created_at=row["created_at"],
        )


# -----------------------------
# UPDATE USER
# -----------------------------
@router.put("/{user_id}")
def update_user(user_id: int, user_update: UserUpdate, current_user: dict = Depends(verify_token)):
    with get_db_connection() as conn:
        cur = conn.cursor()

        cur.execute("SELECT role, is_active FROM users WHERE id = ?", (user_id,))
        existing = cur.fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="User not found")

        # Permission checks
        if current_user.get("role") != "admin":
            if current_user.get("user_id") != user_id:
                raise HTTPException(status_code=403, detail="Access denied")

            if user_update.role or user_update.is_active is not None:
                raise HTTPException(status_code=403, detail="Only admins can modify role or active status")

        update_fields = []
        update_values = []

        if user_update.email is not None:
            update_fields.append("email = ?")
            update_values.append(user_update.email)

        if user_update.role is not None and current_user.get("role") == "admin":
            update_fields.append("role = ?")
            update_values.append(user_update.role)

        if user_update.is_active is not None and current_user.get("role") == "admin":
            update_fields.append("is_active = ?")
            update_values.append(user_update.is_active)

        if not update_fields:
            raise HTTPException(status_code=400, detail="No valid fields to update")

        update_values.append(user_id)
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"

        cur.execute(query, update_values)
        conn.commit()

        return {"message": "User updated successfully"}


# -----------------------------
# DELETE USER (ADMIN ONLY)
# -----------------------------
@router.delete("/{user_id}")
def delete_user(user_id: int, current_user: dict = Depends(verify_token)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete users")

    if current_user.get("user_id") == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    with get_db_connection() as conn:
        cur = conn.cursor()

        cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

        return {"message": f"User {row['username']} deleted successfully"}


# -----------------------------
# CHANGE PASSWORD
# -----------------------------
@router.post("/{user_id}/change-password")
def change_password(user_id: int, password_data: dict, current_user: dict = Depends(verify_token)):
    with get_db_connection() as conn:
        cur = conn.cursor()

        if current_user.get("user_id") != user_id and current_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Access denied")

        current_password = password_data.get("current_password")
        new_password = password_data.get("new_password")

        if not new_password or len(new_password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

        # Non-admins must verify current password
        if current_user.get("role") != "admin":
            if not current_password:
                raise HTTPException(status_code=400, detail="Current password required")

            cur.execute("SELECT hashed_password FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()

            if not row or not pwd_context.verify(current_password, row["hashed_password"]):
                raise HTTPException(status_code=400, detail="Current password is incorrect")

        hashed_password = pwd_context.hash(new_password)

        cur.execute(
            "UPDATE users SET hashed_password = ? WHERE id = ?",
            (hashed_password, user_id),
        )
        conn.commit()

        return {"message": "Password changed successfully"}