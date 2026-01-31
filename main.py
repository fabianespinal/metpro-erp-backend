import os
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    Header,
    File,
    UploadFile,
    Form
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel
from typing import List, Optional

import psycopg  # psycopg3
from psycopg.rows import dict_row  # row factory for dict-style rows

import json
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt

from supabase import create_client, Client

import csv
import io
from fpdf import FPDF
import re

# Import your authentication utilities (NOT routers)
from auth import verify_token


def sanitize_text(text):
    """Remove emojis and non-ASCII characters that FPDF can't handle"""
    if text is None:
        return ''
    
    # Convert to string
    text = str(text)
    
    # Remove emojis and other unsupported Unicode characters
    # Keep only ASCII printable characters plus basic Latin extended
    text = re.sub(r'[^\x00-\x7F\xA0-\xFF]+', '', text)
    
    # Remove any remaining problematic characters
    text = text.encode('latin-1', errors='ignore').decode('latin-1')
    
    return text

# Debugging output for DATABASE_URL
dsn = os.environ.get("DATABASE_URL", "")
print("DSN length:", len(dsn))
print("DSN contains dot at end:", dsn.rstrip().endswith("."))
print("DSN host:", dsn.split("@")[1].split("/")[0] if "@" in dsn else "MISSING")

# Database configuration from .env
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL not found in .env file!")

# JWT Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "metpro-erp-secret-key-change-in-production-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing setup (Argon2)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# JWT Authentication setup
security = HTTPBearer()

app = FastAPI(title='METPRO ERP API')

# Supabase Storage configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://qbyectandmkdmajzolzb.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_KEY else None

def get_db_connection():
    """Get a new database connection to Supabase PostgreSQL (IPv4 only)"""
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=10,
        options='-c statement_timeout=5000'
    )

# CORS Configuration - Allow frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        'http://localhost:3000',           # Local development
        'http://127.0.0.1:3000',           # Local development alternative
        'https://metpro-erp-frontend.vercel.app',  # Production Vercel
        'https://*.vercel.app'             # All Vercel preview deployments
    ],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
    expose_headers=['*']
)


# Simple health check endpoint
@app.get("/health")
def health():
    return {"status": "ok"}

def verify_token(
    authorization: str = Header(None),
    token: str = None  # Accept token from query string for iframe
):
    """Verify JWT token from Authorization header or query string"""
    if authorization:
        try:
            scheme, token = authorization.split()
            if scheme.lower() != 'bearer':
                raise HTTPException(status_code=401, detail='Invalid authorization scheme')
        except ValueError:
            raise HTTPException(status_code=401, detail='Invalid authorization header format')
    elif token:
        pass  # token provided via query string
    else:
        raise HTTPException(status_code=401, detail='Missing authorization token')
    
    if not token:
        raise HTTPException(status_code=401, detail='Token is empty')
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token expired')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail='Invalid token')

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Pydantic models
class ClientBase(BaseModel):
    company_name: str
    contact_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    tax_id: Optional[str] = None
    notes: Optional[str] = None

class Client(ClientBase):
    id: int
    
    class Config:
        from_attributes = True

class ProductBase(BaseModel):
    name: str
    description: Optional[str] = None
    unit_price: float

class Product(ProductBase):
    id: int
    
    class Config:
        from_attributes = True

class IncludedCharges(BaseModel):
    supervision: bool = True
    supervision_percentage: float = 10.0
    admin: bool = True
    admin_percentage: float = 4.0
    insurance: bool = True
    insurance_percentage: float = 1.0
    transport: bool = True
    transport_percentage: float = 3.0
    contingency: bool = True
    contingency_percentage: float = 3.0

class QuoteItemBase(BaseModel):
    product_name: str
    quantity: float
    unit_price: float
    discount_type: str = 'none'
    discount_value: float = 0.0

class QuoteBase(BaseModel):
    client_id: int
    project_name: Optional[str] = None
    notes: Optional[str] = None
    items: List[QuoteItemBase]  # ← FIXED
    included_charges: IncludedCharges = IncludedCharges()

class QuoteCreate(QuoteBase):
    items: List[QuoteItemBase]

class StatusUpdate(BaseModel):
    status: str

class LoginRequest(BaseModel):
    username: str
    password: str

# Root endpoints
@app.get('/')
def read_root():
    return {'message': 'METPRO ERP API is running!', 'version': '1.0.0'}

@app.get('/health')
def health_check():
    return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}



# Client endpoints
@app.post('/clients/', response_model=Client)
def create_client(client: ClientBase, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO clients
            (company_name, contact_name, email, phone, address, tax_id, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            client.company_name,
            client.contact_name,
            client.email,
            client.phone,
            client.address,
            client.tax_id,
            client.notes
        ))
        client_id = cursor.fetchone()['id']
        conn.commit()

        cursor.execute('SELECT * FROM clients WHERE id = %s', (client_id,))
        new_client = cursor.fetchone()

        return Client(**new_client)

    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            conn.close()


@app.get('/clients/', response_model=List[Client])
def get_clients(current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM clients ORDER BY company_name')
        rows = cursor.fetchall()
        return [Client(**row) for row in rows]
    finally:
        if conn:
            conn.close()


@app.get('/clients/{client_id}', response_model=Client)
def get_client(client_id: int, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM clients WHERE id = %s', (client_id,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Client not found')
        return Client(**row)
    finally:
        if conn:
            conn.close()


# ⭐ CSV Import Endpoint — FINAL FIX ⭐
@app.post('/clients/bulk-import')
async def import_clients_csv(
    file: UploadFile = File(...),
    skip_duplicates: bool = True,
    current_user: dict = Depends(verify_token)
):
    try:
        contents = await file.read()
        text = contents.decode('utf-8')
        rows = text.splitlines()
        return {"message": "CSV received", "rows": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSV import failed: {str(e)}")

        # You can add your CSV parsing logic here
        return {"message": "CSV received", "rows": len(rows)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSV import failed: {str(e)}")

# Example fix for get_client
@app.get('/clients/{client_id}', response_model=Client)
def get_client(client_id: int, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM clients WHERE id = %s', (client_id,))  # ← %s NOT ?
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Client not found')
        return Client(**row)  # Simplified using dict_row
    finally:
        if conn: conn.close()

# Example fix for get_client
@app.get('/clients/{client_id}', response_model=Client)
def get_client(client_id: int, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM clients WHERE id = %s', (client_id,))  # ← %s NOT ?
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Client not found')
        return Client(**row)  # Simplified using dict_row
    finally:
        if conn: conn.close()

# Example fix for get_client
@app.get('/clients/{client_id}', response_model=Client)
def get_client(client_id: int, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM clients WHERE id = %s', (client_id,))  # ← %s NOT ?
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Client not found')
        return Client(**row)  # Simplified using dict_row
    finally:
        if conn: conn.close()

# Quote calculation helper (supports dynamic percentages)
def calculate_quote_totals(items: List[dict], charges: dict):
    items_total = sum(item['quantity'] * item['unit_price'] for item in items)
    total_discounts = 0
    for item in items:
        subtotal = item['quantity'] * item['unit_price']
        if item['discount_type'] == 'percentage':
            total_discounts += subtotal * (item['discount_value'] / 100)
        elif item['discount_type'] == 'fixed':
            total_discounts += item['discount_value']
    items_after_discount = items_total - total_discounts
    
    # Get percentages with backwards-compatible defaults
    supervision_pct = charges.get('supervision_percentage', 10.0)
    admin_pct = charges.get('admin_percentage', 4.0)
    insurance_pct = charges.get('insurance_percentage', 1.0)
    transport_pct = charges.get('transport_percentage', 3.0)
    contingency_pct = charges.get('contingency_percentage', 3.0)
    
    # Get percentages with safe defaults (for old quotes without percentage fields)
    supervision_pct = charges.get('supervision_percentage', 10.0) if charges.get('supervision') else 0
    admin_pct = charges.get('admin_percentage', 4.0) if charges.get('admin') else 0
    insurance_pct = charges.get('insurance_percentage', 1.0) if charges.get('insurance') else 0
    transport_pct = charges.get('transport_percentage', 3.0) if charges.get('transport') else 0
    contingency_pct = charges.get('contingency_percentage', 3.0) if charges.get('contingency') else 0
    
    supervision = items_after_discount * (supervision_pct / 100) if charges.get('supervision') else 0
    admin = items_after_discount * (admin_pct / 100) if charges.get('admin') else 0
    insurance = items_after_discount * (insurance_pct / 100) if charges.get('insurance') else 0
    transport = items_after_discount * (transport_pct / 100) if charges.get('transport') else 0
    contingency = items_after_discount * (contingency_pct / 100) if charges.get('contingency') else 0
    
    subtotal_general = items_after_discount + supervision + admin + insurance + transport + contingency
    itbis = subtotal_general * 0.18
    grand_total = subtotal_general + itbis
    
    return {
        'items_total': round(items_total, 2),
        'total_discounts': round(total_discounts, 2),
        'items_after_discount': round(items_after_discount, 2),
        'supervision': round(supervision, 2),
        'admin': round(admin, 2),
        'insurance': round(insurance, 2),
        'transport': round(transport, 2),
        'contingency': round(contingency, 2),
        'subtotal_general': round(subtotal_general, 2),
        'itbis': round(itbis, 2),
        'grand_total': round(grand_total, 2)
    }

# Quote endpoints (same as before - no changes needed)
@app.post('/quotes/', response_model=dict)
def create_quote(quote_data: QuoteCreate, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Verify client exists (PostgreSQL uses %s not ?)
        cursor.execute('SELECT * FROM clients WHERE id = %s', (quote_data.client_id,))
        client = cursor.fetchone()
        if not client:
            raise HTTPException(status_code=404, detail='Client not found')
        
        # Calculate totals
        totals = calculate_quote_totals(
            [item.model_dump() for item in quote_data.items],
            quote_data.included_charges.model_dump()
        )
        
        # Generate quote ID
        year = datetime.now().year
        cursor.execute(
            'SELECT quote_id FROM quotes WHERE quote_id LIKE %s ORDER BY quote_id DESC LIMIT 1',
            (f'COT-{year}-%',)
        )
        last_quote = cursor.fetchone()
        if last_quote:
            num = int(last_quote['quote_id'].split('-')[-1])
            quote_id = f'COT-{year}-{num+1:03d}'
        else:
            quote_id = f'COT-{year}-001'
        
        # Insert quote (PostgreSQL uses %s not ?)
        cursor.execute('''
            INSERT INTO quotes (quote_id, client_id, project_name, date, total_amount, status, notes, included_charges)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            quote_id,
            quote_data.client_id,
            quote_data.project_name,
            datetime.now().strftime('%Y-%m-%d'),
            totals['grand_total'],
            'Draft',
            quote_data.notes,
            json.dumps(quote_data.included_charges.model_dump())
        ))
        
        # Insert items (PostgreSQL uses %s not ?)
        for item in quote_data.items:
            cursor.execute('''
                INSERT INTO quote_items (quote_id, product_name, quantity, unit_price, discount_type, discount_value)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                quote_id,
                item.product_name,
                item.quantity,
                item.unit_price,
                item.discount_type,
                item.discount_value
            ))
        
        conn.commit()
        return {
            'quote_id': quote_id,
            'totals': totals,
            'message': 'Quote created successfully'
        }
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            conn.close()

@app.get('/quotes/', response_model=List[dict])
def get_quotes(current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT q.quote_id, q.client_id, q.project_name, q.date, q.total_amount, q.status,
            c.company_name, q.notes, q.included_charges
            FROM quotes q
            JOIN clients c ON q.client_id = c.id
            ORDER BY q.date DESC
        ''')
        rows = cursor.fetchall()
        return [{
            'quote_id': row['quote_id'],
            'client_id': row['client_id'],
            'client_name': row['company_name'],
            'project_name': row['project_name'],
            'date': row['date'],
            'total_amount': row['total_amount'],
            'status': row['status'],
            'notes': row['notes']
        } for row in rows]
    finally:
        if conn:
            conn.close()

@app.get('/quotes/{quote_id}', response_model=dict)
def get_quote(quote_id: str, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        quote = cursor.execute(
            'SELECT * FROM quotes WHERE quote_id = ?',
            (quote_id,)
        ).fetchone()
        if not quote:
            raise HTTPException(status_code=404, detail='Quote not found')
        items = cursor.execute(
            'SELECT * FROM quote_items WHERE quote_id = ?',
            (quote_id,)
        ).fetchall()
        items_list = []
        for item in items:
            items_list.append({
                'id': item[0],
                'quote_id': item[1],
                'product_name': item[2],
                'quantity': item[3],
                'unit_price': item[4],
                'discount_type': item[5],
                'discount_value': item[6]
            })
        return {
            'quote_id': quote[1],
            'client_id': quote[2],
            'project_name': quote[3],
            'date': quote[4],
            'total_amount': quote[5],
            'status': quote[6],
            'notes': quote[7],
            'included_charges': json.loads(quote[8]),
            'items': items_list
        }
    finally:
        conn.close()

@app.delete('/quotes/{quote_id}')
def delete_quote(quote_id: str, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Check if quote exists
        cursor.execute('SELECT * FROM quotes WHERE quote_id = %s', (quote_id,))
        quote = cursor.fetchone()
        if not quote:
            raise HTTPException(status_code=404, detail='Quote not found')
        
        # PREVENT DELETING INVOICED QUOTES (critical business rule)
        if quote['status'] == 'Invoiced':
            raise HTTPException(
                status_code=403, 
                detail='Cannot delete invoiced quotes. Invoices must be cancelled through accounting procedures.'
            )
        
        # Delete items first (foreign key constraint)
        cursor.execute('DELETE FROM quote_items WHERE quote_id = %s', (quote_id,))

        # Delete quote
        cursor.execute('DELETE FROM quotes WHERE quote_id = %s', (quote_id,))
        conn.commit()
        return {'message': 'Quote deleted successfully', 'quote_id': quote_id}
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f'Failed to delete quote: {str(e)}')
    finally:
        if conn:
            conn.close()

@app.put('/quotes/{quote_id}')
def update_quote(quote_id: str, quote_data: QuoteCreate, current_user: dict = Depends(verify_token)):
    """Update quote details (only for Draft status)"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify quote exists and is Draft
        cursor.execute('SELECT * FROM quotes WHERE quote_id = %s', (quote_id,))
        quote = cursor.fetchone()
        if not quote:
            raise HTTPException(status_code=404, detail='Quote not found')
        if quote['status'] != 'Draft':
            raise HTTPException(
                status_code=400, 
                detail=f'Only Draft quotes can be edited. Current status: {quote["status"]}'
            )
        
        # Calculate new totals
        totals = calculate_quote_totals(
            [item.model_dump() for item in quote_data.items],
            quote_data.included_charges.model_dump()
        )
        
        # Update quote (KEEP EXISTING client_id - don't allow changing client)
        cursor.execute('''
            UPDATE quotes 
            SET project_name = %s, notes = %s, total_amount = %s, included_charges = %s
            WHERE quote_id = %s
        ''', (
            quote_data.project_name,
            quote_data.notes,
            totals['grand_total'],
            json.dumps(quote_data.included_charges.model_dump()),
            quote_id
        ))
        
        # Delete old items
        cursor.execute('DELETE FROM quote_items WHERE quote_id = %s', (quote_id,))
        
        # Insert new items
        for item in quote_data.items:
            cursor.execute('''
                INSERT INTO quote_items (quote_id, product_name, quantity, unit_price, discount_type, discount_value)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                quote_id,
                item.product_name,
                item.quantity,
                item.unit_price,
                item.discount_type,
                item.discount_value
            ))
        
        conn.commit()
        return {
            'quote_id': quote_id,
            'message': 'Quote updated successfully',
            'totals': totals
        }
    except HTTPException:
        raise
    except Exception as e:
        if conn: conn.rollback()
        raise HTTPException(status_code=500, detail=f'Update failed: {str(e)}')
    finally:
        if conn: conn.close()

@app.post('/quotes/{quote_id}/duplicate')
def duplicate_quote(quote_id: str, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Get quote
        cursor.execute('SELECT * FROM quotes WHERE quote_id = %s', (quote_id,))
        quote = cursor.fetchone()
        if not quote:
            raise HTTPException(status_code=404, detail='Quote not found')
        # Get items
        cursor.execute('SELECT * FROM quote_items WHERE quote_id = %s', (quote_id,))
        items = cursor.fetchall()
        # Generate new ID
        year = datetime.now().year
        cursor.execute('SELECT quote_id FROM quotes WHERE quote_id LIKE %s ORDER BY quote_id DESC LIMIT 1', (f'COT-{year}-%',))
        last_quote = cursor.fetchone()
        new_quote_id = f'COT-{year}-{int(last_quote["quote_id"].split("-")[-1]) + 1:03d}' if last_quote else f'COT-{year}-001'
        # Insert new quote
        cursor.execute('''
            INSERT INTO quotes (quote_id, client_id, project_name, date, total_amount, status, notes, included_charges)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            new_quote_id,
            quote['client_id'],
            quote['project_name'],
            datetime.now().strftime('%Y-%m-%d'),
            quote['total_amount'],
            'Draft',
            quote['notes'],
            quote['included_charges']
        ))
        # Insert items
        for item in items:
            cursor.execute('''
                INSERT INTO quote_items (quote_id, product_name, quantity, unit_price, discount_type, discount_value)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                new_quote_id,
                item['product_name'],
                item['quantity'],
                item['unit_price'],
                item['discount_type'],
                item['discount_value']
            ))
        conn.commit()
        return {'quote_id': new_quote_id, 'message': 'Quote duplicated successfully'}
    except HTTPException:
        raise
    except Exception as e:
        if conn: conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn: conn.close()

@app.post('/quotes/{quote_id}/convert-to-invoice')
def convert_to_invoice(quote_id: str, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM quotes WHERE quote_id = %s', (quote_id,))
        quote = cursor.fetchone()
        if not quote:
            raise HTTPException(status_code=404, detail='Quote not found')
        if quote['status'] != 'Approved':  # ✅ FIXED: Was checking 'Draft' before
            raise HTTPException(status_code=400, detail=f'Only Approved quotes can be converted (current: {quote["status"]})')
        
        invoice_id = quote_id.replace('COT-', 'INV-', 1)  # ✅ COT → INV conversion
        
        cursor.execute('UPDATE quotes SET status = %s, quote_id = %s WHERE quote_id = %s', 
                      ('Invoiced', invoice_id, quote_id))
        cursor.execute('UPDATE quote_items SET quote_id = %s WHERE quote_id = %s', 
                      (invoice_id, quote_id))
        conn.commit()
        
        return {'invoice_id': invoice_id, 'message': 'Converted to invoice'}
    except Exception as e:
        if conn: conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn: conn.close()

@app.put('/quotes/{quote_id}/status')
def update_quote_status(quote_id: str, status_update: StatusUpdate, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Verify quote exists
        cursor.execute('SELECT * FROM quotes WHERE quote_id = %s', (quote_id,))
        quote = cursor.fetchone()
        if not quote:
            raise HTTPException(status_code=404, detail='Quote not found')
        # Update status
        cursor.execute(
            'UPDATE quotes SET status = %s WHERE quote_id = %s',
            (status_update.status, quote_id)
        )
        conn.commit()
        return {'message': 'Status updated successfully', 'quote_id': quote_id, 'status': status_update.status}
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f'Failed to update status: {str(e)}')
    finally:
        if conn:
            conn.close()

@app.get('/quotes/{quote_id}/download')
def download_quote_pdf(quote_id: str, current_user: dict = Depends(verify_token)):
    """Download PDF from Supabase Storage (if exists)"""
    if not supabase:
        raise HTTPException(status_code=500, detail='Storage not configured')
    try:
        file_path = f"{quote_id}.pdf"
        # Check if file exists in storage
        try:
            file_data = supabase.storage.from_("pdfs").download(file_path)
            return StreamingResponse(
                io.BytesIO(file_data),
                media_type='application/pdf',
                headers={'Content-Disposition': f'attachment; filename={quote_id}_cotizacion.pdf'}
            )
        except Exception as e:
            # File doesn't exist - generate it
            print(f"PDF not in storage, generating: {str(e)}")
            raise HTTPException(status_code=404, detail='PDF not found - please generate it first')
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Download failed: {str(e)}')
    

@app.get('/quotes/{quote_id}/pdf')
def get_quote_pdf(quote_id: str, current_user: dict = Depends(verify_token)):
    """Generate professional METPRO PDF with exact branding and layout"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get quote
        cursor.execute('SELECT * FROM quotes WHERE quote_id = %s', (quote_id,))
        quote = cursor.fetchone()
        if not quote:
            raise HTTPException(status_code=404, detail='Quote not found')
        
        # Get client
        cursor.execute('SELECT * FROM clients WHERE id = %s', (quote['client_id'],))
        client = cursor.fetchone()
        if not client:
            raise HTTPException(status_code=404, detail='Client not found')
        
        # Get items
        cursor.execute('SELECT * FROM quote_items WHERE quote_id = %s', (quote_id,))
        items = cursor.fetchall()
        
        # Parse charges with backwards-compatible defaults
        try:
            charges = json.loads(quote['included_charges'])
            defaults = {
                'supervision_percentage': 10.0,
                'admin_percentage': 4.0,
                'insurance_percentage': 1.0,
                'transport_percentage': 3.0,
                'contingency_percentage': 3.0
            }
            for key, default in defaults.items():
                if key not in charges:
                    charges[key] = default
        except:
            charges = {
                'supervision': True, 'supervision_percentage': 10.0,
                'admin': True, 'admin_percentage': 4.0,
                'insurance': True, 'insurance_percentage': 1.0,
                'transport': True, 'transport_percentage': 3.0,
                'contingency': True, 'contingency_percentage': 3.0
            }
        
        # Calculate totals
        items_total = sum(float(item['quantity'] or 0) * float(item['unit_price'] or 0) for item in items)
        
        total_discounts = 0
        for item in items:
            subtotal = float(item['quantity'] or 0) * float(item['unit_price'] or 0)
            if item.get('discount_type') == 'percentage':
                total_discounts += subtotal * (float(item.get('discount_value', 0)) / 100)
            elif item.get('discount_type') == 'fixed':
                total_discounts += float(item.get('discount_value', 0))
        
        items_after_discount = items_total - total_discounts
        
        # Get percentages safely
        supervision_pct = float(charges.get('supervision_percentage', 10.0))
        admin_pct = float(charges.get('admin_percentage', 4.0))
        insurance_pct = float(charges.get('insurance_percentage', 1.0))
        transport_pct = float(charges.get('transport_percentage', 3.0))
        contingency_pct = float(charges.get('contingency_percentage', 3.0))
        
        supervision = items_after_discount * (supervision_pct / 100) if charges.get('supervision') else 0
        admin = items_after_discount * (admin_pct / 100) if charges.get('admin') else 0
        insurance = items_after_discount * (insurance_pct / 100) if charges.get('insurance') else 0
        transport = items_after_discount * (transport_pct / 100) if charges.get('transport') else 0
        contingency = items_after_discount * (contingency_pct / 100) if charges.get('contingency') else 0
        
        subtotal_general = items_after_discount + supervision + admin + insurance + transport + contingency
        itbis = subtotal_general * 0.18
        grand_total = subtotal_general + itbis
        
        # Create PDF with modernized design
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # ==================== HEADER: METPRO BRANDING (MODERNIZED) ====================
        pdf.set_font('Arial', 'B', 20)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, 'METPRO', 0, 1, 'L')
        
        pdf.set_font('Arial', '', 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 4, 'ESTRUCTURAS METALICAS & OBRAS CIVILES', 0, 1, 'L')
        
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 3, 'Calle Principal #123, Ensanche La Fe, Santo Domingo, Republica Dominicana', 0, 1, 'L')
        pdf.cell(0, 3, 'Tel: (809) 555-1234 | RNC: 1-23-45678-9', 0, 1, 'L')
        
        pdf.ln(8)
        
        # ==================== TITLE: COTIZACIÓN (REFINED) ====================
        pdf.set_font('Arial', 'B', 14)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 7, 'COTIZACION', 0, 1, 'L')
        pdf.set_draw_color(220, 220, 220)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)
        
        # ==================== QUOTE INFO & CLIENT (TWO COLUMNS) ====================
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(100, 100, 100)
        
        # Left column: Quote info
        left_x = 10
        right_x = 110
        start_y = pdf.get_y()
        
        pdf.set_xy(left_x, start_y)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(35, 4, 'Numero de Cotizacion:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, sanitize_text(quote["quote_id"]), 0, 1)
        
        pdf.set_x(left_x)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(35, 4, 'Fecha:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, sanitize_text(quote["date"]), 0, 1)
        
        if quote.get('project_name'):
            pdf.set_x(left_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(35, 4, 'Proyecto:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(quote["project_name"])[:60], 0, 1)
        
        # Right column: Client info
        pdf.set_xy(right_x, start_y)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(25, 4, 'Cliente:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, sanitize_text(client["company_name"])[:40], 0, 1)
        
        if client.get('contact_name'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Contacto:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["contact_name"])[:40], 0, 1)
        
        if client.get('email'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Email:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["email"])[:40], 0, 1)
        
        if client.get('phone'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Telefono:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["phone"])[:30], 0, 1)
        
        if client.get('address'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Direccion:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["address"])[:40], 0, 1)
        
        if client.get('tax_id'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'RNC:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["tax_id"])[:30], 0, 1)
        
        pdf.ln(8)
        
        # ==================== SECTION: ITEMS TABLE (MODERN DESIGN) ====================
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 5, 'Detalle de Items', 0, 1, 'L')
        pdf.ln(2)
        
        # Table headers with subtle background
        pdf.set_fill_color(245, 245, 245)
        pdf.set_draw_color(220, 220, 220)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(85, 6, 'DESCRIPCION', 1, 0, 'L', True)
        pdf.cell(25, 6, 'CANTIDAD', 1, 0, 'C', True)
        pdf.cell(35, 6, 'PRECIO UNIT.', 1, 0, 'R', True)
        pdf.cell(45, 6, 'TOTAL', 1, 1, 'R', True)
        
        # Table rows with alternating colors
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        row_color = True
        
        for item in items:
            qty = float(item['quantity'] or 0)
            price = float(item['unit_price'] or 0)
            subtotal = qty * price
            product_name = sanitize_text(item.get('product_name', 'Item'))[:50]
            
            if row_color:
                pdf.set_fill_color(252, 252, 252)
            else:
                pdf.set_fill_color(255, 255, 255)
            
            pdf.cell(85, 5, product_name, 1, 0, 'L', True)
            pdf.cell(25, 5, f'{qty:.2f}', 1, 0, 'C', True)
            pdf.cell(35, 5, f'${price:,.2f}', 1, 0, 'R', True)
            pdf.cell(45, 5, f'${subtotal:,.2f}', 1, 1, 'R', True)
            
            row_color = not row_color
        
        pdf.ln(6)
        
        # ==================== SECTION: FINANCIAL SUMMARY (CLEAN LAYOUT) ====================
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 5, 'Resumen Financiero', 0, 1, 'L')
        pdf.ln(2)
        
        # Financial summary table with right alignment
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(60, 60, 60)
        summary_x = 120
        
        # Subtotal de Items
        pdf.set_x(summary_x)
        pdf.cell(45, 4, 'Subtotal de Items:', 0, 0, 'L')
        pdf.set_text_color(30, 30, 30)
        pdf.cell(25, 4, f'${items_total:,.2f}', 0, 1, 'R')
        
        # Discounts if applicable
        if total_discounts > 0:
            pdf.set_x(summary_x)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(45, 4, 'Total Descuentos:', 0, 0, 'L')
            pdf.set_text_color(200, 50, 50)
            pdf.cell(25, 4, f'-${total_discounts:,.2f}', 0, 1, 'R')
            
            pdf.set_x(summary_x)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(45, 4, 'Despues de Descuentos:', 0, 0, 'L')
            pdf.set_text_color(30, 30, 30)
            pdf.cell(25, 4, f'${items_after_discount:,.2f}', 0, 1, 'R')
            pdf.ln(1)
        
        # Surcharges with smaller, lighter text
        pdf.set_font('Arial', '', 7)
        if charges.get('supervision'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Supervision ({supervision_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${supervision:,.2f}', 0, 1, 'R')
        if charges.get('admin'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Administracion ({admin_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${admin:,.2f}', 0, 1, 'R')
        if charges.get('insurance'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Seguro ({insurance_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${insurance:,.2f}', 0, 1, 'R')
        if charges.get('transport'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Transporte ({transport_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${transport:,.2f}', 0, 1, 'R')
        if charges.get('contingency'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Contingencia ({contingency_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${contingency:,.2f}', 0, 1, 'R')
        
        pdf.ln(2)
        
        # Subtotal line separator
        pdf.set_draw_color(220, 220, 220)
        pdf.line(summary_x, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(2)
        
        # SUBTOTAL GENERAL
        pdf.set_x(summary_x)
        pdf.set_font('Arial', 'B', 8)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(45, 5, 'Subtotal General:', 0, 0, 'L')
        pdf.cell(25, 5, f'${subtotal_general:,.2f}', 0, 1, 'R')
        
        # ITBIS (18%)
        pdf.set_x(summary_x)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(45, 4, 'ITBIS (18%):', 0, 0, 'L')
        pdf.set_text_color(30, 30, 30)
        pdf.cell(25, 4, f'${itbis:,.2f}', 0, 1, 'R')
        
        pdf.ln(1)
        
        # Total line separator
        pdf.set_draw_color(200, 200, 200)
        pdf.line(summary_x, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(2)
        
        # TOTAL GENERAL (emphasized)
        pdf.set_x(summary_x)
        pdf.set_font('Arial', 'B', 11)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(45, 7, 'TOTAL GENERAL:', 0, 0, 'L')
        pdf.cell(25, 7, f'${grand_total:,.2f}', 0, 1, 'R')
        
        pdf.ln(12)
        
        # ==================== SECTION: NOTES (FROM UI FORM) ====================
        if quote.get('notes') and quote['notes'].strip():
            pdf.set_font('Arial', 'B', 8)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 5, 'NOTAS / NOTES', 0, 1, 'L')
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(60, 60, 60)
            # Handle multi-line notes properly with word wrap
            pdf.multi_cell(0, 4, quote['notes'].strip(), border=0, align='L', fill=False)
            pdf.ln(3)
        pdf.ln(5)  # Add space before signatures
        
        # ==================== SECTION: SIGNATURES (MINIMALIST) ====================
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(100, 100, 100)
        
        sig_y = pdf.get_y()
        pdf.set_xy(20, sig_y + 15)
        pdf.set_draw_color(180, 180, 180)
        pdf.line(20, sig_y + 15, 80, sig_y + 15)
        pdf.set_xy(20, sig_y + 16)
        pdf.cell(60, 4, 'Autorizado Por', 0, 0, 'C')
        
        pdf.set_xy(130, sig_y + 15)
        pdf.line(130, sig_y + 15, 190, sig_y + 15)
        pdf.set_xy(130, sig_y + 16)
        pdf.cell(60, 4, 'Firma Cliente', 0, 0, 'C')
        
        # ==================== FOOTER: COMPACT INFO ====================
        pdf.set_y(-20)
        pdf.set_font('Arial', '', 6)
        pdf.set_text_color(140, 140, 140)
        pdf.cell(0, 3, 'METPRO - ESTRUCTURAS METALICAS & OBRAS CIVILES', 0, 1, 'C')
        pdf.cell(0, 3, 'Calle Principal #123, Ensanche La Fe, Santo Domingo | Tel: (809) 555-1234 | RNC: 1-23-45678-9', 0, 1, 'C')
        pdf.set_font('Arial', 'I', 6)
        pdf.cell(0, 3, f'Cotizacion {sanitize_text(quote["quote_id"])} | {sanitize_text(quote["date"])} | Pagina 1 de 1', 0, 1, 'C')
        
        pdf_bytes = pdf.output()
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={quote_id}_cotizacion.pdf'}
        )
    
    except Exception as e:
        print(f"PDF GENERATION ERROR for quote {quote_id}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f'PDF generation failed: {str(e)}')
    finally:
        if conn:
            conn.close()


@app.get('/invoices/{invoice_id}/pdf')
def get_invoice_pdf(invoice_id: str, current_user: dict = Depends(verify_token)):
    """Generate professional METPRO Invoice PDF with exact branding and layout"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get invoice (from quotes table - invoices are quotes with INV- prefix and Invoiced status)
        cursor.execute('SELECT * FROM quotes WHERE quote_id = %s AND status = %s', (invoice_id, 'Invoiced'))
        invoice = cursor.fetchone()
        if not invoice:
            raise HTTPException(status_code=404, detail='Invoice not found')
        
        # Get client
        cursor.execute('SELECT * FROM clients WHERE id = %s', (invoice['client_id'],))
        client = cursor.fetchone()
        if not client:
            raise HTTPException(status_code=404, detail='Client not found')
        
        # Get items (from quote_items table)
        cursor.execute('SELECT * FROM quote_items WHERE quote_id = %s', (invoice_id,))
        items = cursor.fetchall()
        
        # Parse charges with backwards-compatible defaults
        try:
            charges = json.loads(invoice['included_charges'])
            defaults = {
                'supervision_percentage': 10.0,
                'admin_percentage': 4.0,
                'insurance_percentage': 1.0,
                'transport_percentage': 3.0,
                'contingency_percentage': 3.0
            }
            for key, default in defaults.items():
                if key not in charges:
                    charges[key] = default
        except:
            charges = {
                'supervision': True, 'supervision_percentage': 10.0,
                'admin': True, 'admin_percentage': 4.0,
                'insurance': True, 'insurance_percentage': 1.0,
                'transport': True, 'transport_percentage': 3.0,
                'contingency': True, 'contingency_percentage': 3.0
            }
        
        # Calculate totals
        items_total = sum(float(item['quantity'] or 0) * float(item['unit_price'] or 0) for item in items)
        
        total_discounts = 0
        for item in items:
            subtotal = float(item['quantity'] or 0) * float(item['unit_price'] or 0)
            if item.get('discount_type') == 'percentage':
                total_discounts += subtotal * (float(item.get('discount_value', 0)) / 100)
            elif item.get('discount_type') == 'fixed':
                total_discounts += float(item.get('discount_value', 0))
        
        items_after_discount = items_total - total_discounts
        
        # Get percentages safely
        supervision_pct = float(charges.get('supervision_percentage', 10.0))
        admin_pct = float(charges.get('admin_percentage', 4.0))
        insurance_pct = float(charges.get('insurance_percentage', 1.0))
        transport_pct = float(charges.get('transport_percentage', 3.0))
        contingency_pct = float(charges.get('contingency_percentage', 3.0))
        
        supervision = items_after_discount * (supervision_pct / 100) if charges.get('supervision') else 0
        admin = items_after_discount * (admin_pct / 100) if charges.get('admin') else 0
        insurance = items_after_discount * (insurance_pct / 100) if charges.get('insurance') else 0
        transport = items_after_discount * (transport_pct / 100) if charges.get('transport') else 0
        contingency = items_after_discount * (contingency_pct / 100) if charges.get('contingency') else 0
        
        subtotal_general = items_after_discount + supervision + admin + insurance + transport + contingency
        itbis = subtotal_general * 0.18
        grand_total = subtotal_general + itbis
        
        # Create PDF with modernized design
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # ==================== HEADER: METPRO BRANDING (MODERNIZED) ====================
        pdf.set_font('Arial', 'B', 20)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, 'METPRO', 0, 1, 'L')
        
        pdf.set_font('Arial', '', 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 4, 'ESTRUCTURAS METALICAS & OBRAS CIVILES', 0, 1, 'L')
        
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 3, 'Calle Principal #123, Ensanche La Fe, Santo Domingo, Republica Dominicana', 0, 1, 'L')
        pdf.cell(0, 3, 'Tel: (809) 555-1234 | RNC: 1-23-45678-9', 0, 1, 'L')
        
        pdf.ln(8)
        
        # ==================== TITLE: FACTURA (REFINED) ====================
        pdf.set_font('Arial', 'B', 14)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 7, 'FACTURA', 0, 1, 'L')
        pdf.set_draw_color(220, 220, 220)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)
        
        # ==================== INVOICE INFO & CLIENT (TWO COLUMNS) ====================
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(100, 100, 100)
        
        # Left column: Invoice info
        left_x = 10
        right_x = 110
        start_y = pdf.get_y()
        
        pdf.set_xy(left_x, start_y)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(35, 4, 'Numero de Factura:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, sanitize_text(invoice["quote_id"]), 0, 1)
        
        pdf.set_x(left_x)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(35, 4, 'Fecha de Emision:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, sanitize_text(invoice["date"]), 0, 1)
        
        if invoice.get('project_name'):
            pdf.set_x(left_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(35, 4, 'Proyecto:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(invoice["project_name"])[:60], 0, 1)
        
        # Right column: Client info
        pdf.set_xy(right_x, start_y)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(25, 4, 'Cliente:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, sanitize_text(client["company_name"])[:40], 0, 1)
        
        if client.get('contact_name'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Contacto:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["contact_name"])[:40], 0, 1)
        
        if client.get('email'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Email:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["email"])[:40], 0, 1)
        
        if client.get('phone'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Telefono:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["phone"])[:30], 0, 1)
        
        if client.get('address'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Direccion:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["address"])[:40], 0, 1)
        
        if client.get('tax_id'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'RNC:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["tax_id"])[:30], 0, 1)
        
        pdf.ln(8)
        
        # ==================== SECTION: ITEMS TABLE (MODERN DESIGN) ====================
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 5, 'Detalle de Items', 0, 1, 'L')
        pdf.ln(2)
        
        # Table headers with subtle background
        pdf.set_fill_color(245, 245, 245)
        pdf.set_draw_color(220, 220, 220)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(85, 6, 'DESCRIPCION', 1, 0, 'L', True)
        pdf.cell(25, 6, 'CANTIDAD', 1, 0, 'C', True)
        pdf.cell(35, 6, 'PRECIO UNIT.', 1, 0, 'R', True)
        pdf.cell(45, 6, 'TOTAL', 1, 1, 'R', True)
        
        # Table rows with alternating colors
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        row_color = True
        
        for item in items:
            qty = float(item['quantity'] or 0)
            price = float(item['unit_price'] or 0)
            subtotal = qty * price
            product_name = sanitize_text(item.get('product_name', 'Item'))[:50]
            
            if row_color:
                pdf.set_fill_color(252, 252, 252)
            else:
                pdf.set_fill_color(255, 255, 255)
            
            pdf.cell(85, 5, product_name, 1, 0, 'L', True)
            pdf.cell(25, 5, f'{qty:.2f}', 1, 0, 'C', True)
            pdf.cell(35, 5, f'${price:,.2f}', 1, 0, 'R', True)
            pdf.cell(45, 5, f'${subtotal:,.2f}', 1, 1, 'R', True)
            
            row_color = not row_color
        
        pdf.ln(6)
        
        # ==================== SECTION: FINANCIAL SUMMARY (CLEAN LAYOUT) ====================
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 5, 'Resumen Financiero', 0, 1, 'L')
        pdf.ln(2)
        
        # Financial summary table with right alignment
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(60, 60, 60)
        summary_x = 120
        
        # Subtotal de Items
        pdf.set_x(summary_x)
        pdf.cell(45, 4, 'Subtotal de Items:', 0, 0, 'L')
        pdf.set_text_color(30, 30, 30)
        pdf.cell(25, 4, f'${items_total:,.2f}', 0, 1, 'R')
        
        # Discounts if applicable
        if total_discounts > 0:
            pdf.set_x(summary_x)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(45, 4, 'Total Descuentos:', 0, 0, 'L')
            pdf.set_text_color(200, 50, 50)
            pdf.cell(25, 4, f'-${total_discounts:,.2f}', 0, 1, 'R')
            
            pdf.set_x(summary_x)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(45, 4, 'Despues de Descuentos:', 0, 0, 'L')
            pdf.set_text_color(30, 30, 30)
            pdf.cell(25, 4, f'${items_after_discount:,.2f}', 0, 1, 'R')
            pdf.ln(1)
        
        # Surcharges with smaller, lighter text
        pdf.set_font('Arial', '', 7)
        if charges.get('supervision'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Supervision ({supervision_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${supervision:,.2f}', 0, 1, 'R')
        if charges.get('admin'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Administracion ({admin_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${admin:,.2f}', 0, 1, 'R')
        if charges.get('insurance'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Seguro ({insurance_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${insurance:,.2f}', 0, 1, 'R')
        if charges.get('transport'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Transporte ({transport_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${transport:,.2f}', 0, 1, 'R')
        if charges.get('contingency'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Contingencia ({contingency_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${contingency:,.2f}', 0, 1, 'R')
        
        pdf.ln(2)
        
        # Subtotal line separator
        pdf.set_draw_color(220, 220, 220)
        pdf.line(summary_x, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(2)
        
        # SUBTOTAL GENERAL
        pdf.set_x(summary_x)
        pdf.set_font('Arial', 'B', 8)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(45, 5, 'Subtotal General:', 0, 0, 'L')
        pdf.cell(25, 5, f'${subtotal_general:,.2f}', 0, 1, 'R')
        
        # ITBIS (18%)
        pdf.set_x(summary_x)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(45, 4, 'ITBIS (18%):', 0, 0, 'L')
        pdf.set_text_color(30, 30, 30)
        pdf.cell(25, 4, f'${itbis:,.2f}', 0, 1, 'R')
        
        pdf.ln(1)
        
        # Total line separator
        pdf.set_draw_color(200, 200, 200)
        pdf.line(summary_x, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(2)
        
        # TOTAL GENERAL (emphasized)
        pdf.set_x(summary_x)
        pdf.set_font('Arial', 'B', 11)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(45, 7, 'TOTAL A PAGAR:', 0, 0, 'L')
        pdf.cell(25, 7, f'${grand_total:,.2f}', 0, 1, 'R')
        
        pdf.ln(8)
        
                # ==================== SECTION: NOTES (FROM UI FORM) ====================
        if invoice.get('notes') and invoice['notes'].strip():
            pdf.set_font('Arial', 'B', 8)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 5, 'NOTAS / NOTES', 0, 1, 'L')
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(60, 60, 60)
            # Handle multi-line notes properly with word wrap
            pdf.multi_cell(0, 4, invoice['notes'].strip(), border=0, align='L', fill=False)
            pdf.ln(3)
        pdf.ln(5)  # Add space before signatures
        
        # ==================== SECTION: SIGNATURES (MINIMALIST) ====================
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(100, 100, 100)
        
        sig_y = pdf.get_y()
        pdf.set_xy(20, sig_y + 15)
        pdf.set_draw_color(180, 180, 180)
        pdf.line(20, sig_y + 15, 80, sig_y + 15)
        pdf.set_xy(20, sig_y + 16)
        pdf.cell(60, 4, 'Autorizado Por', 0, 0, 'C')
        
        pdf.set_xy(130, sig_y + 15)
        pdf.line(130, sig_y + 15, 190, sig_y + 15)
        pdf.set_xy(130, sig_y + 16)
        pdf.cell(60, 4, 'Recibido Por Cliente', 0, 0, 'C')
        
        # ==================== FOOTER: COMPACT INFO ====================
        pdf.set_y(-20)
        pdf.set_font('Arial', '', 6)
        pdf.set_text_color(140, 140, 140)
        pdf.cell(0, 3, 'METPRO - ESTRUCTURAS METALICAS & OBRAS CIVILES', 0, 1, 'C')
        pdf.cell(0, 3, 'Calle Principal #123, Ensanche La Fe, Santo Domingo | Tel: (809) 555-1234 | RNC: 1-23-45678-9', 0, 1, 'C')
        pdf.set_font('Arial', 'I', 6)
        pdf.cell(0, 3, f'Factura {sanitize_text(invoice["quote_id"])} | {sanitize_text(invoice["date"])} | Pagina 1 de 1', 0, 1, 'C')
        
        pdf_bytes = pdf.output()
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={invoice_id}_factura.pdf'}
        )
    
    except Exception as e:
        print(f"PDF GENERATION ERROR for invoice {invoice_id}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f'Invoice PDF generation failed: {str(e)}')
    finally:
        if conn:
            conn.close()


@app.get('/invoices/{invoice_id}/conduce/pdf')
def get_conduce_pdf(invoice_id: str, current_user: dict = Depends(verify_token)):
    """Generate professional METPRO CONDUCE (Delivery Note) PDF"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get invoice (from quotes table - invoices are quotes with INV- prefix and Invoiced status)
        cursor.execute('SELECT * FROM quotes WHERE quote_id = %s AND status = %s', (invoice_id, 'Invoiced'))
        invoice = cursor.fetchone()
        if not invoice:
            raise HTTPException(status_code=404, detail='Invoice not found')
        
        # Get client
        cursor.execute('SELECT * FROM clients WHERE id = %s', (invoice['client_id'],))
        client = cursor.fetchone()
        if not client:
            raise HTTPException(status_code=404, detail='Client not found')
        
        # Get items (from quote_items table)
        cursor.execute('SELECT * FROM quote_items WHERE quote_id = %s', (invoice_id,))
        items = cursor.fetchall()
        
        # Create PDF with modernized design
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # ==================== HEADER: LOGO SPACE + METPRO BRANDING ====================
        # Logo placeholder (add actual logo with pdf.image() if you have the file)
        # pdf.image('path/to/logo.png', 10, 10, 30)  # Uncomment and set path when logo is available
        
        # Company info aligned to the right
        pdf.set_font('Arial', 'B', 20)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, 'METPRO', 0, 1, 'R')
        
        pdf.set_font('Arial', '', 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 4, 'ESTRUCTURAS METALICAS & OBRAS CIVILES', 0, 1, 'R')
        
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 3, 'Calle Principal #123, Ensanche La Fe', 0, 1, 'R')
        pdf.cell(0, 3, 'Santo Domingo, Republica Dominicana', 0, 1, 'R')
        pdf.cell(0, 3, 'Tel: (809) 555-1234', 0, 1, 'R')
        pdf.cell(0, 3, 'RNC: 1-23-45678-9', 0, 1, 'R')
        
        pdf.ln(8)
        
        # ==================== TITLE: CONDUCE (REFINED) ====================
        pdf.set_font('Arial', 'B', 16)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, 'CONDUCE', 0, 1, 'C')
        pdf.set_font('Arial', '', 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 4, 'Nota de Entrega / Delivery Note', 0, 1, 'C')
        
        pdf.set_draw_color(220, 220, 220)
        pdf.line(10, pdf.get_y() + 2, 200, pdf.get_y() + 2)
        pdf.ln(6)
        
        # ==================== DOCUMENT INFO & CLIENT (TWO COLUMNS) ====================
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(100, 100, 100)
        
        # Left column: Document info
        left_x = 10
        right_x = 110
        start_y = pdf.get_y()
        
        pdf.set_xy(left_x, start_y)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(35, 4, 'Numero de Conduce:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        conduce_number = f"CD-{sanitize_text(invoice['quote_id'])}"
        pdf.cell(0, 4, conduce_number, 0, 1)
        
        pdf.set_x(left_x)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(35, 4, 'Factura Relacionada:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, sanitize_text(invoice["quote_id"]), 0, 1)
        
        pdf.set_x(left_x)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(35, 4, 'Fecha de Entrega:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, sanitize_text(invoice["date"]), 0, 1)
        
        if invoice.get('project_name'):
            pdf.set_x(left_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(35, 4, 'Proyecto:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(invoice["project_name"])[:60], 0, 1)
        
        # Right column: Client info
        pdf.set_xy(right_x, start_y)
        pdf.set_font('Arial', 'B', 8)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, 4, 'ENTREGAR A:', 0, 1)
        pdf.ln(1)
        
        pdf.set_x(right_x)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(25, 4, 'Cliente:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, sanitize_text(client["company_name"])[:40], 0, 1)
        
        if client.get('contact_name'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Contacto:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["contact_name"])[:40], 0, 1)
        
        if client.get('phone'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Telefono:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["phone"])[:30], 0, 1)
        
        if client.get('address'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Direccion:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["address"])[:40], 0, 1)
        
        if client.get('tax_id'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'RNC:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, sanitize_text(client["tax_id"])[:30], 0, 1)
        
        pdf.ln(10)
        
        # ==================== SECTION: ITEMS TABLE (SIMPLIFIED - NO PRICES) ====================
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 5, 'Detalle de Mercancia', 0, 1, 'L')
        pdf.ln(2)
        
        # Table headers with subtle background
        pdf.set_fill_color(245, 245, 245)
        pdf.set_draw_color(220, 220, 220)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(30, 6, 'CANTIDAD', 1, 0, 'C', True)
        pdf.cell(40, 6, 'UNIDAD', 1, 0, 'C', True)
        pdf.cell(120, 6, 'DESCRIPCION', 1, 1, 'L', True)
        
        # Table rows with alternating colors
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        row_color = True
        
        for item in items:
            qty = float(item['quantity'] or 0)
            product_name = sanitize_text(item.get('product_name', 'Item'))[:70]
            unit = 'UND'
            
            if row_color:
                pdf.set_fill_color(252, 252, 252)
            else:
                pdf.set_fill_color(255, 255, 255)
            
            pdf.cell(30, 5, f'{qty:.2f}', 1, 0, 'C', True)
            pdf.cell(40, 5, unit, 1, 0, 'C', True)
            pdf.cell(120, 5, product_name, 1, 1, 'L', True)
            
            row_color = not row_color
        
        pdf.ln(10)
        
        # ==================== SECTION: DELIVERY CONDITIONS ====================
        pdf.set_font('Arial', 'B', 8)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 5, 'Condiciones de Entrega', 0, 1, 'L')
        pdf.ln(1)
        
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 4, 'La mercancia descrita en este conduce ha sido entregada en perfectas condiciones. El receptor confirma haber recibido los articulos listados y acepta que estan completos y en buen estado.', 0, 'L')
        
        pdf.ln(8)
        
        # ==================== SECTION: SIGNATURE AREA ====================
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 5, 'Firmas y Confirmacion', 0, 1, 'L')
        pdf.ln(3)
        
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(100, 100, 100)
        
        sig_y = pdf.get_y()
        
        # Left signature: Delivered by
        pdf.set_xy(15, sig_y + 15)
        pdf.set_draw_color(180, 180, 180)
        pdf.line(15, sig_y + 15, 90, sig_y + 15)
        
        pdf.set_xy(15, sig_y + 17)
        pdf.set_font('Arial', 'B', 7)
        pdf.cell(75, 4, 'ENTREGADO POR', 0, 1, 'C')
        
        pdf.set_x(15)
        pdf.set_font('Arial', '', 6)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(75, 3, 'Nombre:', 0, 1, 'L')
        pdf.set_x(15)
        pdf.cell(75, 3, 'Fecha:', 0, 1, 'L')
        pdf.set_x(15)
        pdf.cell(75, 3, 'Hora:', 0, 1, 'L')
        
        # Right signature: Received by
        pdf.set_xy(115, sig_y + 15)
        pdf.line(115, sig_y + 15, 190, sig_y + 15)
        
        pdf.set_xy(115, sig_y + 17)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(75, 4, 'RECIBIDO POR', 0, 1, 'C')
        
        pdf.set_x(115)
        pdf.set_font('Arial', '', 6)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(75, 3, 'Nombre:', 0, 1, 'L')
        pdf.set_x(115)
        pdf.cell(75, 3, 'Cedula:', 0, 1, 'L')
        pdf.set_x(115)
        pdf.cell(75, 3, 'Fecha:', 0, 1, 'L')
        pdf.set_x(115)
        pdf.cell(75, 3, 'Hora:', 0, 1, 'L')
        
        pdf.ln(8)
        
        # ==================== SECTION: NOTES ====================
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, 4, 'OBSERVACIONES:', 0, 1, 'L')
        pdf.ln(1)
        
        # Draw observation box
        pdf.set_draw_color(220, 220, 220)
        pdf.rect(10, pdf.get_y(), 190, 20)
        
        pdf.ln(22)
        
        # ==================== FOOTER: COMPACT INFO ====================
        pdf.set_y(-20)
        pdf.set_font('Arial', '', 6)
        pdf.set_text_color(140, 140, 140)
        pdf.cell(0, 3, 'METPRO - ESTRUCTURAS METALICAS & OBRAS CIVILES', 0, 1, 'C')
        pdf.cell(0, 3, 'Calle Principal #123, Ensanche La Fe, Santo Domingo | Tel: (809) 555-1234 | RNC: 1-23-45678-9', 0, 1, 'C')
        pdf.set_font('Arial', 'I', 6)
        pdf.cell(0, 3, f'Conduce {conduce_number} | Factura {sanitize_text(invoice["quote_id"])} | {sanitize_text(invoice["date"])} | Pagina 1 de 1', 0, 1, 'C')
        
        pdf_bytes = pdf.output()
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={conduce_number}_conduce.pdf'}
        )
    
    except Exception as e:
        print(f"PDF GENERATION ERROR for conduce {invoice_id}: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f'Conduce PDF generation failed: {str(e)}')
    finally:
        if conn:
            conn.close()

@app.put('/clients/{client_id}')
def update_client(
    client_id: int, 
    client: ClientBase, 
    current_user: dict = Depends(verify_token)
):
    """Update an existing client"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if client exists
        cursor.execute('SELECT id FROM clients WHERE id = %s', (client_id,))
        existing = cursor.fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail=f'Client with ID {client_id} not found')
        
        # Validate email format if provided
        if client.email and '@' not in client.email:
            raise HTTPException(status_code=400, detail='Invalid email format')
        
        # Check for duplicate email (excluding current client)
        if client.email:
            cursor.execute(
                'SELECT id FROM clients WHERE email = %s AND id != %s',
                (client.email, client_id)
            )
            if cursor.fetchone():
                raise HTTPException(
                    status_code=400, 
                    detail=f'Email {client.email} is already in use by another client'
                )
        
        # Check for duplicate tax_id (excluding current client)
        if client.tax_id:
            cursor.execute(
                'SELECT id FROM clients WHERE tax_id = %s AND id != %s',
                (client.tax_id, client_id)
            )
            if cursor.fetchone():
                raise HTTPException(
                    status_code=400, 
                    detail=f'Tax ID {client.tax_id} is already in use by another client'
                )
        
        # Update client
        cursor.execute('''
            UPDATE clients 
            SET 
                company_name = %s, 
                contact_name = %s, 
                email = %s, 
                phone = %s, 
                address = %s, 
                tax_id = %s,
                notes = %s
            WHERE id = %s
            RETURNING id, company_name, contact_name, email, phone, address, tax_id, notes, updated_at
        ''', (
            client.company_name,
            client.contact_name,
            client.email,
            client.phone,
            client.address,
            client.tax_id,
            client.notes,
            client_id
        ))
        
        updated_client = cursor.fetchone()
        
        if not updated_client:
            raise HTTPException(status_code=404, detail='Client not found')
        
        conn.commit()
        
        return {
            'id': updated_client['id'],
            'company_name': updated_client['company_name'],
            'contact_name': updated_client['contact_name'],
            'email': updated_client['email'],
            'phone': updated_client['phone'],
            'address': updated_client['address'],
            'tax_id': updated_client['tax_id'],
            'notes': updated_client['notes'],
            'updated_at': updated_client['updated_at'].isoformat() if updated_client['updated_at'] else None
        }
        
        
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except psycopg.errors.UniqueViolation as e:
        if conn:
            conn.rollback()
        error_msg = str(e).lower()
        if 'email' in error_msg:
            raise HTTPException(status_code=400, detail='Email already exists')
        elif 'tax_id' in error_msg:
            raise HTTPException(status_code=400, detail='Tax ID already exists')
        else:
            raise HTTPException(status_code=400, detail='Duplicate entry detected')

    except psycopg.errors.IntegrityError as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=400, detail=f'Database integrity error: {str(e)}')
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Update Client Error (ID {client_id}): {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500, 
            detail=f'Failed to update client: {str(e)}'
        )
    finally:
        if conn:
            conn.close()

     # ← FIXED all at once 
     