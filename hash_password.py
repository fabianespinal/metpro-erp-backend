from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
password = "AdminPass123!"  # Your actual password
hashed = pwd_context.hash(password)
print("\n" + "="*60)
print("✅ COPY THIS HASH FOR YOUR ADMIN USER:")
print("="*60)
print(hashed)
print("="*60)
print(f"Password: {password}")
print("="*60 + "\n")