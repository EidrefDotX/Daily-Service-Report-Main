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

## Deploying to Render
1. Commit this repository (including `render.yaml`) and connect it to a new **Web Service** on Render.
2. Render will automatically detect `render.yaml` and use the configured build and start commands.
3. Set required environment variables in Render Dashboard (see `DEPLOYMENT.md` for details):
   - `SECRET_KEY` (required)
   - `JWT_SECRET` (required)
   - `FLASK_DEBUG=false`
   - `FLASK_ENV=production`
   - `DATABASE_URL` (from Render PostgreSQL service)
   - `CORS_ORIGINS` (your Render URL, not `*`)
4. Create a PostgreSQL database in Render and use its Internal Database URL for `DATABASE_URL`.
5. No extra port configuration is required—the app uses Waitress which respects the `$PORT` value that Render provides automatically.

## Notes
- To use PostgreSQL instead of SQLite, set `DATABASE_URL` in `.env` (format: `postgresql+psycopg2://user:pass@host:5432/dbname`). If connection fails, the app falls back to SQLite automatically.
- If the port is in use, change `FLASK_PORT` in `.env`.
- Service workers may cache assets. If the UI seems stale, hard-refresh or try an incognito window.
- For production, disable debug, set strong secrets, and use a real database.
- See `DEPLOYMENT.md` for detailed Render deployment instructions.



