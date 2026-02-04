import os
from dotenv import load_dotenv

from psycopg import connect
from psycopg.rows import dict_row

load_dotenv()

print("\n" + "=" * 60)
print("🔍 TESTING SUPABASE DATABASE CONNECTION")
print("=" * 60)
print(f"Using DATABASE_URL: {os.environ.get('DATABASE_URL', 'NOT FOUND')[:60]}...")
print("=" * 60 + "\n")

try:
    conn = connect(
        os.environ.get("DATABASE_URL"),
        row_factory=dict_row,
        connect_timeout=10,
        options='-c statement_timeout=5000',
    )
    print("✅ SUCCESS! Database connection established.\n")

    cursor = conn.cursor()
    cursor.execute("SELECT version();")
    version = cursor.fetchone()["version"]
    print(f"📡 PostgreSQL Version: {version.split()[0]}\n")

    cursor.execute("SELECT COUNT(*) AS count FROM users;")
    user_count = cursor.fetchone()["count"]
    print(f"👥 Users in database: {user_count}\n")

    if user_count > 0:
        cursor.execute(
            "SELECT username, role, is_active FROM users ORDER BY id LIMIT 3;"
        )
        users = cursor.fetchall()
        print("📋 Sample users:")
        for user in users:
            status = "✅ active" if user["is_active"] else "❌ inactive"
            print(f"   • {user['username']} ({user['role']}) - {status}")

    conn.close()
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED! Your app can connect to Supabase.")
    print("=" * 60 + "\n")

except Exception as e:
    print(f"❌ CONNECTION FAILED: {type(e).__name__}")
    print(f"   Error details: {str(e)}")
    print("\n" + "=" * 60)
    print("💡 TROUBLESHOOTING:")
    print("   1. Check DATABASE_URL starts with 'postgresql://'")
    print("   2. Verify no extra spaces in the URL")
    print("   3. Confirm 'users' table exists in Supabase Table Editor")
    print("   4. Ensure Supabase project is not paused")
    print("=" * 60 + "\n")