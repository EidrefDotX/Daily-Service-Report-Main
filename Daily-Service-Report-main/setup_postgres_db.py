#!/usr/bin/env python3
"""Setup PostgreSQL database for DSR Backend"""
import psycopg2
import sys

def setup_database(host='127.0.0.1', port=5432, user='postgres', password='postgres', dbname='dsr'):
    """Create database if it doesn't exist"""
    try:
        # Connect to PostgreSQL server (use default 'postgres' database)
        print(f"Connecting to PostgreSQL at {host}:{port}...")
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database='postgres'  # Connect to default database first
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute(f"SELECT 1 FROM pg_database WHERE datname='{dbname}'")
        exists = cursor.fetchone()
        
        if not exists:
            print(f"Creating database '{dbname}'...")
            cursor.execute(f'CREATE DATABASE "{dbname}"')
            print(f"Database '{dbname}' created successfully!")
        else:
            print(f"Database '{dbname}' already exists")
        
        cursor.close()
        conn.close()
        return True
        
    except psycopg2.OperationalError as e:
        print(f"PostgreSQL connection failed: {e}")
        print("\nPlease make sure:")
        print("  1. PostgreSQL service is running")
        print("  2. Credentials are correct (user: postgres, password: postgres)")
        print("  3. PostgreSQL is listening on port 5432")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("PostgreSQL Database Setup")
    print("=" * 50)
    print()
    
    # Use default credentials or command line args
    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        password = 'postgres'
    
    success = setup_database(password=password)
    sys.exit(0 if success else 1)

