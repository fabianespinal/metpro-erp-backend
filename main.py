import os
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file
from fastapi import FastAPI, Depends, HTTPException, status, Header, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
import psycopg  # psycopg3
from psycopg.rows import dict_row  # replacement for RealDictCursor
import json
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from supabase import create_client, Client
import csv
import io
from fpdf import FPDF

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

# Client endpoints (same as before - no changes needed)
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
        # Fetch the created client
        cursor.execute('SELECT * FROM clients WHERE id = %s', (client_id,))
        new_client = cursor.fetchone()
        return Client(
            id=new_client['id'],
            company_name=new_client['company_name'],
            contact_name=new_client['contact_name'],
            email=new_client['email'],
            phone=new_client['phone'],
            address=new_client['address'],
            tax_id=new_client['tax_id'],
            notes=new_client['notes']
        )
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
        return [
            Client(
                id=row['id'],
                company_name=row['company_name'],
                contact_name=row['contact_name'],
                email=row['email'],
                phone=row['phone'],
                address=row['address'],
                tax_id=row['tax_id'],
                notes=row['notes']
            ) for row in rows
        ]
    finally:
        if conn:
            conn.close()

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
        pdf.cell(0, 4, 'ESTRUCTURAS METÁLICAS & OBRAS CIVILES', 0, 1, 'L')
        
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 3, 'Calle Principal #123, Ensanche La Fe, Santo Domingo, República Dominicana', 0, 1, 'L')
        pdf.cell(0, 3, 'Tel: (809) 555-1234 | RNC: 1-23-45678-9', 0, 1, 'L')
        
        pdf.ln(8)
        
        # ==================== TITLE: COTIZACIÓN (REFINED) ====================
        pdf.set_font('Arial', 'B', 14)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 7, 'COTIZACIÓN', 0, 1, 'L')
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
        pdf.cell(35, 4, 'Número de Cotización:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, f'{quote["quote_id"]}', 0, 1)
        
        pdf.set_x(left_x)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(35, 4, 'Fecha:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, f'{quote["date"]}', 0, 1)
        
        if quote.get('project_name'):
            pdf.set_x(left_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(35, 4, 'Proyecto:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, f'{quote["project_name"]}', 0, 1)
        
        # Right column: Client info
        pdf.set_xy(right_x, start_y)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(25, 4, 'Cliente:', 0, 0)
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 4, f'{client["company_name"]}', 0, 1)
        
        if client.get('contact_name'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Contacto:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, f'{client["contact_name"]}', 0, 1)
        
        if client.get('email'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Email:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, f'{client["email"]}', 0, 1)
        
        if client.get('phone'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Teléfono:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, f'{client["phone"]}', 0, 1)
        
        if client.get('address'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'Dirección:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, f'{client["address"]}', 0, 1)
        
        if client.get('tax_id'):
            pdf.set_x(right_x)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(25, 4, 'RNC:', 0, 0)
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 4, f'{client["tax_id"]}', 0, 1)
        
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
        pdf.cell(85, 6, 'DESCRIPCIÓN', 1, 0, 'L', True)
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
            product_name = str(item['product_name'])[:50] if item.get('product_name') else 'Item'
            
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
            pdf.cell(45, 4, 'Después de Descuentos:', 0, 0, 'L')
            pdf.set_text_color(30, 30, 30)
            pdf.cell(25, 4, f'${items_after_discount:,.2f}', 0, 1, 'R')
            pdf.ln(1)
        
        # Surcharges with smaller, lighter text
        pdf.set_font('Arial', '', 7)
        if charges.get('supervision'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Supervisión ({supervision_pct:.1f}%):', 0, 0, 'L')
            pdf.set_text_color(60, 60, 60)
            pdf.cell(25, 4, f'${supervision:,.2f}', 0, 1, 'R')
        if charges.get('admin'):
            pdf.set_x(summary_x)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(45, 4, f'Administración ({admin_pct:.1f}%):', 0, 0, 'L')
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

        # ==================== SECTION: NOTES (PROJECT & DATE) ====================
        if quote.get('project_name'):
            pdf.set_font('Arial', 'B', 8)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 5, 'PROYECTO / PROJECT', 0, 1, 'L')
            pdf.set_font('Arial', '', 7)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(0, 4, f'Nombre: {quote["project_name"]}', 0, 1, 'L')
            pdf.ln(2)
        
        pdf.set_font('Arial', '', 7)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 4, f'Fecha / Date: {quote["date"]}', 0, 1, 'L')
        pdf.ln(8)
        
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
        pdf.cell(0, 3, 'METPRO - ESTRUCTURAS METÁLICAS & OBRAS CIVILES', 0, 1, 'C')
        pdf.cell(0, 3, 'Calle Principal #123, Ensanche La Fe, Santo Domingo | Tel: (809) 555-1234 | RNC: 1-23-45678-9', 0, 1, 'C')
        pdf.set_font('Arial', 'I', 6)
        pdf.cell(0, 3, f'Cotización {quote["quote_id"]} | {quote["date"]} | Página 1 de 1', 0, 1, 'C')
        
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

# Authentication endpoint - REAL database authentication
@app.post('/auth/login')
def login(login_data: LoginRequest):
    """Login endpoint that checks Supabase database"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Get user from database
        cursor.execute(
            'SELECT id, username, email, hashed_password, role, is_active FROM users WHERE username = %s',
            (login_data.username,)
        )
        user = cursor.fetchone()
        # Check if user exists
        if not user:
            raise HTTPException(status_code=401, detail='Invalid username or password')
        # Check if user is active
        if not user['is_active']:
            raise HTTPException(status_code=403, detail='Account is deactivated')
        # Verify password
        if not pwd_context.verify(login_data.password, user['hashed_password']):
            raise HTTPException(status_code=401, detail='Invalid username or password')
        # Create JWT token
        access_token = create_access_token(data={
            'sub': user['username'],
            'user_id': user['id'],
            'role': user['role']
        })
        return {
            'access_token': access_token,
            'token_type': 'bearer',
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'message': 'Login successful'
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail='Internal server error')
    finally:
        if conn:
            conn.close()

    # Product Endpoints - POSTGRESQL SYNTAX (NOT SQLite)
@app.post('/products/', response_model=Product)
def create_product(product: ProductBase, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO products (name, description, unit_price)
            VALUES (%s, %s, %s)
            RETURNING id
        ''', (product.name, product.description, product.unit_price))
        product_id = cursor.fetchone()['id']
        conn.commit()
        return Product(
            id=product_id,
            name=product.name,
            description=product.description,
            unit_price=product.unit_price
        )
    except psycopg2.IntegrityError as e:
        if conn: conn.rollback()
        if 'unique' in str(e).lower() or 'duplicate' in str(e).lower():
            raise HTTPException(status_code=400, detail='Product name already exists')
        raise HTTPException(status_code=400, detail='Database integrity error')
    except Exception as e:
        if conn: conn.rollback()
        raise HTTPException(status_code=500, detail=f'Failed to create product: {str(e)}')
    finally:
        if conn: conn.close()

@app.get('/products/', response_model=List[Product])
def get_products(current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, description, unit_price FROM products ORDER BY name')
        rows = cursor.fetchall()
        return [
            Product(
                id=row['id'],
                name=row['name'],
                description=row['description'],
                unit_price=float(row['unit_price']) if row['unit_price'] is not None else 0.0
            )
            for row in rows
        ]
    finally:
        if conn: conn.close()

@app.get('/products/{product_id}', response_model=Product)
def get_product(product_id: int, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, description, unit_price FROM products WHERE id = %s', (product_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Product not found')
        return Product(
            id=row['id'],
            name=row['name'],
            description=row['description'],
            unit_price=float(row['unit_price']) if row['unit_price'] is not None else 0.0
        )
    finally:
        if conn: conn.close()

@app.put('/products/{product_id}', response_model=Product)
def update_product(product_id: int, product: ProductBase, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE products 
            SET name = %s, description = %s, unit_price = %s 
            WHERE id = %s
            RETURNING id, name, description, unit_price
        ''', (product.name, product.description, product.unit_price, product_id))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Product not found')
        conn.commit()
        return Product(
            id=row['id'],
            name=row['name'],
            description=row['description'],
            unit_price=float(row['unit_price']) if row['unit_price'] is not None else 0.0
        )
    except Exception as e:
        if conn: conn.rollback()
        raise HTTPException(status_code=500, detail=f'Failed to update product: {str(e)}')
    finally:
        if conn: conn.close()

@app.delete('/products/{product_id}')
def delete_product(product_id: int, current_user: dict = Depends(verify_token)):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM products WHERE id = %s', (product_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail='Product not found')
        conn.commit()
        return {'message': 'Product deleted successfully'}
    except Exception as e:
        if conn: conn.rollback()
        raise HTTPException(status_code=500, detail=f'Failed to delete product: {str(e)}')
    finally:
        if conn: conn.close()

@app.post('/products/import-csv')
async def import_products_csv(file: UploadFile = File(...), current_user: dict = Depends(verify_token)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail='File must be CSV')
    
    conn = None
    try:
        content = await file.read()
        csv_text = content.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(csv_text))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        imported = 0
        skipped = 0
        
        for row in csv_reader:
            try:
                name = row.get('name', '').strip()
                if not name:
                    skipped += 1
                    continue
                
                description = row.get('description', '').strip()
                unit_price = float(row.get('unit_price', 0))
                
                cursor.execute('''
                    INSERT INTO products (name, description, unit_price)
                    VALUES (%s, %s, %s)
                ''', (name, description, unit_price))
                
                imported += 1
            except Exception as e:
                skipped += 1
        
        conn.commit()
        
        return {
            'imported': imported,
            'skipped': skipped,
            'message': f'Successfully imported {imported} products, skipped {skipped}'
        }
    except Exception as e:
        if conn: conn.rollback()
        raise HTTPException(status_code=500, detail=f'CSV import failed: {str(e)}')
    finally:
        if conn: conn.close()
        
     # redeploy after removing env
     # redeploy trigger 
     # ← FIXED
     