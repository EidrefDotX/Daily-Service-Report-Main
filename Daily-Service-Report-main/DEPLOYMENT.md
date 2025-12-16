# Deployment Guide for Vercel

## Quick Setup on Vercel

### 1. Prerequisites
- GitHub repository with your code
- Vercel account (free tier available)
- **External database** (PostgreSQL, Neon, Supabase, etc.) - SQLite will NOT work on Vercel

### 2. Create External Database
**Important:** Vercel's serverless runtime does not provide persistent disk access. You MUST use an external database.

**Recommended options:**
- **Neon** (free PostgreSQL): https://neon.tech
- **Supabase** (free PostgreSQL): https://supabase.com
- **Railway** (PostgreSQL): https://railway.app
- **Render PostgreSQL** (separate service)

### 3. Connect Repository to Vercel
1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click **"Add New"** → **"Project"**
3. Import your GitHub repository
4. Vercel will auto-detect `vercel.json`

### 4. Configure Project Settings
In Vercel project settings:
- **Framework Preset:** Other (or Flask if available)
- **Root Directory:** (leave blank)
- **Build Command:** (leave blank - Vercel handles this)
- **Output Directory:** (leave blank)
- **Install Command:** `pip install -r requirements.txt`

### 5. Set Environment Variables
In Vercel Dashboard → Your Project → **Settings** → **Environment Variables**, add:

#### Required:
```
SECRET_KEY=<generate using: python -c "import secrets; print(secrets.token_urlsafe(32))">
JWT_SECRET=<generate using: python -c "import secrets; print(secrets.token_urlsafe(32))">
FLASK_DEBUG=false
FLASK_ENV=production
DATABASE_URL=<your external PostgreSQL connection string>
CORS_ORIGINS=https://your-app.vercel.app
```

#### Optional:
```
JWT_EXPIRE_MINUTES=120
SUBMISSION_REQUIRE_AUTH=false
```

### 6. Deploy
1. Click **"Deploy"**
2. Vercel will automatically:
   - Install dependencies from `requirements.txt`
   - Build your Flask app
   - Deploy as serverless functions
3. Your app will be live at: `https://your-app.vercel.app`

## Generating Strong Secrets

Run this locally to generate secure secrets:
```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(32))"
```

## Database Setup

### Using Neon (Recommended - Free)
1. Sign up at https://neon.tech
2. Create a new project
3. Copy the connection string
4. Format: `postgresql+psycopg2://user:password@host/database?sslmode=require`
5. Set as `DATABASE_URL` in Vercel

### Using Supabase (Free)
1. Sign up at https://supabase.com
2. Create a new project
3. Go to Settings → Database
4. Copy the connection string
5. Set as `DATABASE_URL` in Vercel

## How It Works

- Your Flask app is deployed as a serverless function at `api/index.py`
- All routes (including static files) are handled by Flask via `vercel.json`
- Vercel automatically handles routing and scaling
- No port configuration needed - Vercel handles this automatically

## Troubleshooting

### Build Fails
- Check build logs in Vercel Dashboard
- Verify `requirements.txt` is in root directory
- Ensure Python version is compatible (3.11+)

### App Won't Start
- Verify all environment variables are set
- Check `DATABASE_URL` is correct and database is accessible
- Review function logs in Vercel Dashboard

### Database Connection Issues
- **Critical:** PostgreSQL is REQUIRED in production - the app will fail to start without it
- **No SQLite fallback in production** - The app will fail fast if PostgreSQL is unavailable (prevents data loss)
- Verify `DATABASE_URL` connection string is correct
- Ensure database allows connections from Vercel's IPs
- Check database is running and accessible
- If you see "DATABASE_URL environment variable must be set in production" - you must set `DATABASE_URL` in Vercel environment variables

### Static Files Not Loading
- Static files are served through Flask routes, not as static assets
- Verify routes in `app.py` are correct
- Check browser console for 404 errors

## Post-Deployment Checklist

- [ ] App is accessible at Vercel URL
- [ ] Can log in as admin
- [ ] Database connection working (external database)
- [ ] No security warnings in logs
- [ ] CORS is restricted to your domain
- [ ] Debug mode is disabled (`FLASK_DEBUG=false`)

## Health Check

Visit: `https://your-app.vercel.app/health`

Should return: `{"status": "ok"}`

## Important Warnings

⚠️ **SQLite will NOT work on Vercel** - The filesystem is read-only and ephemeral. You MUST use an external database.

⚠️ **File uploads/storage** - Vercel serverless functions have limited storage. Use external storage (S3, Cloudinary, etc.) for file uploads.

⚠️ **Cold starts** - Serverless functions may have cold start delays. Consider using Vercel Pro for better performance.

