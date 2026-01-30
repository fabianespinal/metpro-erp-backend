import os
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file
from fastapi import FastAPI, Depends, HTTPException, status, Header
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

@app.get('/clients/{client_id}', response_model=Client)
def get_client(client_id: int, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM clients WHERE id = ?', (client_id,))
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='Client not found')
        return Client(
            id=row[0],
            company_name=row[1],
            contact_name=row[2],
            email=row[3],
            phone=row[4],
            address=row[5],
            tax_id=row[6],
            notes=row[7]
        )
    finally:
        conn.close()

@app.put('/clients/{client_id}', response_model=Client)
def update_client(client_id: int, client: ClientBase, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE clients
            SET company_name = ?, contact_name = ?, email = ?, phone = ?, address = ?, tax_id = ?, notes = ?
            WHERE id = ?
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
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail='Client not found')
        conn.commit()
        cursor.execute('SELECT * FROM clients WHERE id = ?', (client_id,))
        row = cursor.fetchone()
        return Client(
            id=row[0],
            company_name=row[1],
            contact_name=row[2],
            email=row[3],
            phone=row[4],
            address=row[5],
            tax_id=row[6],
            notes=row[7]
        )
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.delete('/clients/{client_id}')
def delete_client(client_id: int, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM clients WHERE id = ?', (client_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail='Client not found')
        conn.commit()
        return {'message': 'Client deleted successfully'}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

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
        cursor.execute('SELECT 1 FROM quotes WHERE quote_id = %s', (quote_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail='Quote not found')
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
        # Verify quote exists and is Draft
        cursor.execute('SELECT * FROM quotes WHERE quote_id = %s', (quote_id,))
        quote = cursor.fetchone()
        if not quote:
            raise HTTPException(status_code=404, detail='Quote not found')
        if quote['status'] != 'Draft':
            raise HTTPException(status_code=400, detail=f'Only Draft quotes can be converted. Current status: {quote["status"]}')
        # Generate invoice ID
        invoice_id = quote_id.replace('COT-', 'INV-')
        # Check if invoice exists
        cursor.execute('SELECT 1 FROM quotes WHERE quote_id = %s', (invoice_id,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail=f'Invoice {invoice_id} already exists')
        # Update status first
        cursor.execute('UPDATE quotes SET status = %s WHERE quote_id = %s', ('Invoiced', quote_id))
        # Update quote_id
        cursor.execute('UPDATE quotes SET quote_id = %s WHERE quote_id = %s', (invoice_id, quote_id))
        # Update items
        cursor.execute('UPDATE quote_items SET quote_id = %s WHERE quote_id = %s', (invoice_id, quote_id))
        conn.commit()
        return {'invoice_id': invoice_id, 'message': 'Quote converted to invoice successfully', 'status': 'Invoiced'}
    except HTTPException:
        if conn: conn.rollback()
        raise
    except Exception as e:
        if conn: conn.rollback()
        print(f"Conversion error: {str(e)}")
        raise HTTPException(status_code=500, detail=f'Conversion failed: {str(e)}')
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
    """Generate PDF with surcharge breakdown (supports old and new quotes)"""
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
            # Add missing percentage fields for old quotes
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
            # Fallback for completely broken data
            charges = {
                'supervision': True, 'supervision_percentage': 10.0,
                'admin': True, 'admin_percentage': 4.0,
                'insurance': True, 'insurance_percentage': 1.0,
                'transport': True, 'transport_percentage': 3.0,
                'contingency': True, 'contingency_percentage': 3.0
            }
        
        # Calculate surcharges
        items_total = sum(float(item['quantity'] or 0) * float(item['unit_price'] or 0) for item in items)
        
        # Calculate discounts
        total_discounts = 0
        for item in items:
            subtotal = float(item['quantity'] or 0) * float(item['unit_price'] or 0)
            if item.get('discount_type') == 'percentage':
                total_discounts += subtotal * (float(item.get('discount_value', 0)) / 100)
            elif item.get('discount_type') == 'fixed':
                total_discounts += float(item.get('discount_value', 0))
        
        items_after_discount = items_total - total_discounts
        
        # Get percentages safely (works for old AND new quotes)
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
        
        # Calculate base amounts
        items_total = sum(float(item['quantity'] or 0) * float(item['unit_price'] or 0) for item in items)
        
        # Calculate discounts
        total_discounts = 0
        for item in items:
            subtotal = float(item['quantity'] or 0) * float(item['unit_price'] or 0)
            if item.get('discount_type') == 'percentage':
                total_discounts += subtotal * (float(item.get('discount_value', 0)) / 100)
            elif item.get('discount_type') == 'fixed':
                total_discounts += float(item.get('discount_value', 0))
        
        items_after_discount = items_total - total_discounts
        
        # Get percentages with SAFER defaults (works for old quotes without percentage fields)
        supervision_pct = float(charges.get('supervision_percentage', 10.0)) if charges.get('supervision') else 0
        admin_pct = float(charges.get('admin_percentage', 4.0)) if charges.get('admin') else 0
        insurance_pct = float(charges.get('insurance_percentage', 1.0)) if charges.get('insurance') else 0
        transport_pct = float(charges.get('transport_percentage', 3.0)) if charges.get('transport') else 0
        contingency_pct = float(charges.get('contingency_percentage', 3.0)) if charges.get('contingency') else 0
        
        # Calculate surcharges
        supervision = items_after_discount * (supervision_pct / 100) if charges.get('supervision') else 0
        admin = items_after_discount * (admin_pct / 100) if charges.get('admin') else 0
        insurance = items_after_discount * (insurance_pct / 100) if charges.get('insurance') else 0
        transport = items_after_discount * (transport_pct / 100) if charges.get('transport') else 0
        contingency = items_after_discount * (contingency_pct / 100) if charges.get('contingency') else 0
        
        subtotal_general = items_after_discount + supervision + admin + insurance + transport + contingency
        itbis = subtotal_general * 0.18
        grand_total = subtotal_general + itbis
        
        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'COTIZACION / QUOTE', 0, 1, 'C')
        pdf.ln(5)
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, f'ID: {quote["quote_id"]}', 0, 1)
        pdf.ln(5)
        
        # Client info
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 8, 'CLIENTE / CLIENT', 0, 1)
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 6, f'Empresa: {client["company_name"]}', 0, 1)
        if client.get('contact_name'): pdf.cell(0, 6, f'Contacto: {client["contact_name"]}', 0, 1)
        if client.get('email'): pdf.cell(0, 6, f'Email: {client["email"]}', 0, 1)
        if client.get('phone'): pdf.cell(0, 6, f'Telefono: {client["phone"]}', 0, 1)
        if client.get('address'): pdf.cell(0, 6, f'Direccion: {client["address"]}', 0, 1)
        if client.get('tax_id'): pdf.cell(0, 6, f'RNC: {client["tax_id"]}', 0, 1)
        pdf.ln(5)
        
        # Project & date
        if quote.get('project_name'):
            pdf.set_font('Arial', 'B', 10)
            pdf.cell(0, 8, 'PROYECTO / PROJECT', 0, 1)
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f'Nombre: {quote["project_name"]}', 0, 1)
            pdf.ln(3)
        
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 6, f'Fecha / Date: {quote["date"]}', 0, 1)
        pdf.ln(8)
        
        # Items table
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 8, 'ITEMS / PRODUCTOS', 0, 1)
        pdf.ln(2)
        pdf.set_font('Arial', 'B', 9)
        pdf.cell(20, 8, 'Qty', 1, 0, 'C')
        pdf.cell(85, 8, 'Descripcion', 1, 0)
        pdf.cell(25, 8, 'Precio', 1, 0, 'R')
        pdf.cell(25, 8, 'Total', 1, 1, 'R')
        
        pdf.set_font('Arial', '', 9)
        for item in items:
            qty = float(item['quantity'] or 0)
            price = float(item['unit_price'] or 0)
            subtotal = qty * price
            product_name = str(item['product_name'])[:40] if item.get('product_name') else 'Item'
            pdf.cell(20, 6, str(qty), 1, 0, 'C')
            pdf.cell(85, 6, product_name, 1, 0)
            pdf.cell(25, 6, f'${price:.2f}', 1, 0, 'R')
            pdf.cell(25, 6, f'${subtotal:.2f}', 1, 1, 'R')
        
        pdf.ln(8)
        
        # Show surcharge breakdown BEFORE subtotal
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(120, 6, 'SUBTOTAL ITEMS:', 0, 0)
        pdf.cell(45, 6, f'${items_after_discount:.2f}', 0, 1, 'R')
        pdf.ln(2)
        
        # Display ONLY enabled surcharges
        if charges.get('supervision'):
            pdf.set_font('Arial', '', 10)
            pdf.cell(120, 6, f'Supervision ({supervision_pct:.1f}%):', 0, 0)
            pdf.cell(45, 6, f'${supervision:.2f}', 0, 1, 'R')
        if charges.get('admin'):
            pdf.set_font('Arial', '', 10)
            pdf.cell(120, 6, f'Administracion ({admin_pct:.1f}%):', 0, 0)
            pdf.cell(45, 6, f'${admin:.2f}', 0, 1, 'R')
        if charges.get('insurance'):
            pdf.set_font('Arial', '', 10)
            pdf.cell(120, 6, f'Seguro ({insurance_pct:.1f}%):', 0, 0)
            pdf.cell(45, 6, f'${insurance:.2f}', 0, 1, 'R')
        if charges.get('transport'):
            pdf.set_font('Arial', '', 10)
            pdf.cell(120, 6, f'Transporte ({transport_pct:.1f}%):', 0, 0)
            pdf.cell(45, 6, f'${transport:.2f}', 0, 1, 'R')
        if charges.get('contingency'):
            pdf.set_font('Arial', '', 10)
            pdf.cell(120, 6, f'Contingencia ({contingency_pct:.1f}%):', 0, 0)
            pdf.cell(45, 6, f'${contingency:.2f}', 0, 1, 'R')
        
        pdf.ln(2)
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(120, 6, 'SUBTOTAL:', 0, 0)
        pdf.cell(45, 6, f'${subtotal_general:.2f}', 0, 1, 'R')
        pdf.cell(120, 6, 'ITBIS (18%):', 0, 0)
        pdf.cell(45, 6, f'${itbis:.2f}', 0, 1, 'R')
        pdf.ln(2)
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(120, 10, 'TOTAL:', 0, 0)
        pdf.cell(45, 10, f'${grand_total:.2f}', 0, 1, 'R')
        
        pdf.ln(15)
        pdf.set_font('Arial', 'I', 8)
        pdf.cell(0, 6, 'METPRO ERP - Sistema de Gestion Empresarial', 0, 1, 'C')
        pdf.cell(0, 6, f'Generado: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 0, 1, 'C')
        
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

# Product Endpoints (same as before - no changes needed)
@app.post('/products/', response_model=Product)
def create_product(product: ProductBase, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO products (name, description, unit_price)
            VALUES (?, ?, ?)
        ''', (product.name, product.description, product.unit_price))
        product_id = cursor.lastrowid
        conn.commit()
        return Product(id=product_id, **product.model_dump())
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail='Product name already exists')
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get('/products/', response_model=List[Product])
def get_products(current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM products ORDER BY name')
        rows = cursor.fetchall()
        return [
            Product(id=row[0], name=row[1], description=row[2], unit_price=row[3])
            for row in rows
        ]
    finally:
        conn.close()

@app.get('/products/{product_id}', response_model=Product)
def get_product(product_id: int, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        row = cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Product not found')
        return Product(id=row[0], name=row[1], description=row[2], unit_price=row[3])
    finally:
        conn.close()

@app.put('/products/{product_id}', response_model=Product)
def update_product(product_id: int, product: ProductBase, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE products SET name = ?, description = ?, unit_price = ? WHERE id = ?
        ''', (product.name, product.description, product.unit_price, product_id))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail='Product not found')
        conn.commit()
        row = cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
        return Product(id=row[0], name=row[1], description=row[2], unit_price=row[3])
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.delete('/products/{product_id}')
def delete_product(product_id: int, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail='Product not found')
        conn.commit()
        return {'message': 'Product deleted successfully'}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post('/products/import-csv')
async def import_products_csv(file: UploadFile = File(...), current_user: dict = Depends(verify_token)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail='File must be CSV')
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        content = await file.read()
        csv_text = content.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(csv_text))
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
                    VALUES (?, ?, ?)
                ''', (name, description, unit_price))
                imported += 1
            except:
                skipped += 1
        conn.commit()
        return {
            'imported': imported,
            'skipped': skipped,
            'message': f'Successfully imported {imported} products, skipped {skipped}'
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
        
     # redeploy after removing env
     # redeploy trigger 
     # ← FIXED
     