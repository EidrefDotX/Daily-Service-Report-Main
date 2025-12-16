# PostgreSQL Integration Guide

## Current Status
- ✅ PostgreSQL Service: Running (version 13)
- ✅ PostgreSQL Port: **5433** (not default 5432)
- ⚠️ Database Password: Needs to be configured

## Quick Setup Steps

### 1. Update .env file

Edit your `.env` file and uncomment/update the DATABASE_URL line:

```env
DATABASE_URL=postgresql+psycopg2://postgres:YOUR_PASSWORD@127.0.0.1:5433/dsr
```

**Important:** Replace `YOUR_PASSWORD` with your actual PostgreSQL password.

### 2. Create the database

Run this command (replace `YOUR_PASSWORD` with your PostgreSQL password):

```powershell
python setup_postgres_db.py YOUR_PASSWORD
```

Or manually connect to PostgreSQL and run:
```sql
CREATE DATABASE dsr;
```

### 3. Restart the backend server

Stop the current server (Ctrl+C) and restart:
```powershell
python app.py
```

Or use:
```powershell
.\start_backend.bat
```

## Testing Connection

Test your PostgreSQL connection:
```powershell
python test_postgres_connection.py YOUR_PASSWORD
```

## Common PostgreSQL Passwords

If you don't remember your PostgreSQL password, you may need to:
1. Reset it in pgAdmin
2. Or check if you set it during installation

Default passwords are often:
- `postgres`
- `admin`
- `root`
- Or the password you set during PostgreSQL installation

## Current Backend Status

The backend is currently running and using **SQLite** database.
After configuring PostgreSQL and restarting, it will automatically switch to PostgreSQL.







