#!/usr/bin/env python3
"""Test PostgreSQL connection"""
import psycopg2
import sys

def test_connection(host='127.0.0.1', port=5432, user='postgres', password='postgres', dbname='postgres'):
    """Test PostgreSQL connection"""
    try:
        print(f"Testing connection to {host}:{port}...")
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=dbname,
            connect_timeout=3
        )
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print("Connection successful!")
        print(f"  PostgreSQL version: {version[:50]}...")
        cursor.close()
        conn.close()
        return True
    except psycopg2.OperationalError as e:
        print(f"Connection failed: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    password = sys.argv[1] if len(sys.argv) > 1 else 'postgres'
    success = test_connection(password=password)
    sys.exit(0 if success else 1)

