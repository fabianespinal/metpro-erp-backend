from config.database import get_db_connection
from fastapi import HTTPException
from backend.models.client_models import ClientCreate, ClientUpdate


# -----------------------------
# CREATE CLIENT
# -----------------------------
def create_client(data: ClientCreate):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()

            # Check duplicate name
            cur.execute("SELECT 1 FROM clients WHERE name = ?", (data.name,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Client name already exists")

            cur.execute(
                """
                INSERT INTO clients (name, email, phone, address, notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (data.name, data.email, data.phone, data.address, data.notes),
            )
            conn.commit()

            new_id = cur.lastrowid

            cur.execute(
                "SELECT id, name, email, phone, address, notes, created_at FROM clients WHERE id = ?",
                (new_id,),
            )
            row = cur.fetchone()

            return {
                "id": row["id"],
                "name": row["name"],
                "email": row["email"],
                "phone": row["phone"],
                "address": row["address"],
                "notes": row["notes"],
                "created_at": row["created_at"],
            }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Client creation failed: {str(e)}")


# -----------------------------
# GET ALL CLIENTS
# -----------------------------
def get_all_clients():
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, email, phone, address, notes, created_at FROM clients ORDER BY created_at DESC"
        )
        rows = cur.fetchall()

        return [
            {
                "id": row["id"],
                "name": row["name"],
                "email": row["email"],
                "phone": row["phone"],
                "address": row["address"],
                "notes": row["notes"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]


# -----------------------------
# GET SINGLE CLIENT
# -----------------------------
def get_client(client_id: int):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, email, phone, address, notes, created_at FROM clients WHERE id = ?",
            (client_id,),
        )
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Client not found")

        return {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "phone": row["phone"],
            "address": row["address"],
            "notes": row["notes"],
            "created_at": row["created_at"],
        }


# -----------------------------
# UPDATE CLIENT
# -----------------------------
def update_client(client_id: int, data: ClientUpdate):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()

            cur.execute("SELECT id FROM clients WHERE id = ?", (client_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Client not found")

            update_fields = []
            update_values = []

            if data.name is not None:
                update_fields.append("name = ?")
                update_values.append(data.name)

            if data.email is not None:
                update_fields.append("email = ?")
                update_values.append(data.email)

            if data.phone is not None:
                update_fields.append("phone = ?")
                update_values.append(data.phone)

            if data.address is not None:
                update_fields.append("address = ?")
                update_values.append(data.address)

            if data.notes is not None:
                update_fields.append("notes = ?")
                update_values.append(data.notes)

            if not update_fields:
                raise HTTPException(status_code=400, detail="No valid fields to update")

            update_values.append(client_id)

            query = f"UPDATE clients SET {', '.join(update_fields)} WHERE id = ?"
            cur.execute(query, update_values)
            conn.commit()

            return {"message": "Client updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Client update failed: {str(e)}")


# -----------------------------
# DELETE CLIENT
# -----------------------------
def delete_client(client_id: int):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()

            cur.execute("SELECT name FROM clients WHERE id = ?", (client_id,))
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Client not found")

            cur.execute("DELETE FROM clients WHERE id = ?", (client_id,))
            conn.commit()

            return {"message": f"Client '{row['name']}' deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Client deletion failed: {str(e)}")