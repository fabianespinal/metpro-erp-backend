from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
password = "AdminPass123!"  # Same password as before
hashed = pwd_context.hash(password)
print("\n✅ COPY THIS HASH:")
print(hashed)
print(f"\n✅ For password: {password}\n")