import sqlite3
from passlib.context import CryptContext

# Setup password hashing with Argon2 (works reliably on Windows)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

# Connect to database
conn = sqlite3.connect('rigc_app.db')
cursor = conn.cursor()

# Create admin user
username = "admin"
email = "admin@metpro.com"
password = "AdminPass123!"  # ⚠️ CHANGE THIS LATER IN PRODUCTION!
role = "admin"

try:
    # Check if user already exists
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        print(f"\nℹ️  User '{username}' already exists. Skipping creation.\n")
    else:
        hashed_password = get_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, email, hashed_password, role, is_active)
            VALUES (?, ?, ?, ?, 1)
        ''', (username, email, hashed_password, role))
        
        conn.commit()
        print(f"\n✅ SUCCESS! Created user:")
        print(f"   Username: {username}")
        print(f"   Email: {email}")
        print(f"   Role: {role}")
        print(f"   Password: {password}")
        print(f"\n⚠️  SAVE THESE CREDENTIALS! You'll need them to login.\n")
    
except Exception as e:
    print(f"\n❌ ERROR: {str(e)}\n")
    conn.rollback()
finally:
    conn.close()