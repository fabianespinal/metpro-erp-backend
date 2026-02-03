import os
import psycopg
from psycopg.rows import dict_row

def get_db_connection():
    return psycopg.connect(os.getenv("DATABASE_URL"), row_factory=dict_row)