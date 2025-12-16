### DSR (Daily Service Report)

A small Flask app that serves the static frontend and provides APIs for authentication and daily service report submissions. Uses SQLite by default (file at `backend/dsr.sqlite3`) and can optionally connect to PostgreSQL via `DATABASE_URL`.

## Requirements
- **Python 3.11+** and **pip**
- Windows PowerShell (commands below use PowerShell syntax)

## 1) Clone or download
Place the project in a directory such as `C:\Users\<you>\Desktop\DSR`.

## 2) Create your environment file
Copy the example env and adjust values as needed:

```powershell
Copy-Item env.example .env
```

Key variables in `.env`:
- `FLASK_HOST`, `FLASK_PORT`, `FLASK_DEBUG`
- `SECRET_KEY`, `JWT_SECRET` (set strong values in non-dev)
- `JWT_EXPIRE_MINUTES`
- `DATABASE_URL` (optional; leave unset to use SQLite at `dsr.sqlite3`)
- `ADMIN_USERNAME`, `ADMIN_PASSWORD` (optional seed on first start)

## 3) Create and activate a virtual environment
It's recommended to create your own venv rather than using a checked-in one.

```powershell
py -3.11 -m venv .venv
./.venv/Scripts/Activate.ps1
# If script execution is blocked:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## 4) Install dependencies
```powershell
pip install -r requirements.txt
```

## 5) Run the server
```powershell
python app.py
```

By default the server starts at `http://127.0.0.1:5000`.

## 6) Open the app
- Main app: `http://127.0.0.1:5000/`
- 
Tables are auto-created on first run. If `DEFAULT_ADMIN_*` is set in `.env`, an admin user is ensured/seeded on startup.

## 7) Quick health check
```powershell
Invoke-WebRequest http://127.0.0.1:5000/health | Select-Object -ExpandProperty Content
```
Expected: `{ "status": "ok" }`

## Deploying to Vercel

### Prerequisites
- Vercel account (free tier available)
- External database (PostgreSQL, Neon, Supabase, etc.) - **SQLite will NOT work on Vercel**

### Steps

1. **Connect Repository**
   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click "Add New" → "Project"
   - Import your GitHub repository

2. **Configure Project**
   - Framework Preset: **Other** or **Flask** (if available)
   - Root Directory: (leave blank)
   - Build Command: (leave blank - Vercel auto-detects)
   - Output Directory: (leave blank)
   - Install Command: `pip install -r requirements.txt`

3. **Set Environment Variables**
   In Vercel Dashboard → Your Project → Settings → Environment Variables, add:
   - `SECRET_KEY` - Generate: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
   - `JWT_SECRET` - Generate: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
   - `FLASK_DEBUG=false`
   - `FLASK_ENV=production`
   - `DATABASE_URL` - Your external PostgreSQL connection string (required!)
   - `CORS_ORIGINS` - Your Vercel domain (e.g., `https://your-app.vercel.app`)

4. **Deploy**
   - Click "Deploy"
   - Vercel will automatically install dependencies and deploy your Flask app

### Important Notes
- **PostgreSQL is REQUIRED in production** - The app will fail to start if `DATABASE_URL` is not set
- **No SQLite fallback in production** - The app fails fast if PostgreSQL is unavailable (prevents data loss)
- **SQLite will NOT work on Vercel** - Vercel's serverless runtime has no persistent disk
- The app is deployed as a serverless function at `api/index.py`
- All routes are handled by the Flask app via `vercel.json`
- Static files (HTML, CSS, JS) are served through Flask routes

## Notes
- **Local Development:** If `DATABASE_URL` is not set, the app uses SQLite automatically. If PostgreSQL connection fails, it falls back to SQLite.
- **Production:** PostgreSQL is REQUIRED. The app will fail to start if `DATABASE_URL` is missing or if PostgreSQL connection fails. No SQLite fallback in production (prevents data loss).
- To use PostgreSQL locally, set `DATABASE_URL` in `.env` (format: `postgresql+psycopg2://user:pass@host:5432/dbname`).
- If the port is in use, change `FLASK_PORT` in `.env`.
- Service workers may cache assets. If the UI seems stale, hard-refresh or try an incognito window.
- For production, disable debug, set strong secrets, and use PostgreSQL (required).



