# Deployment Guide for Render

## Quick Setup on Render

### 1. Prerequisites
- GitHub repository with your code
- Render account (free tier available)

### 2. Create PostgreSQL Database
1. In Render Dashboard, click **"New +"** → **"PostgreSQL"**
2. Name it (e.g., `dsr-db`)
3. Copy the **Internal Database URL** (you'll need this)

### 3. Create Web Service
1. Click **"New +"** → **"Web Service"**
2. Connect your GitHub repository
3. Render will auto-detect `render.yaml` - verify these settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `waitress-serve --port=$PORT --call app:create_app`
   - **Root Directory:** (leave blank)

### 4. Set Environment Variables
In your Web Service → **Environment** tab, add:

#### Required for Production:
```
SECRET_KEY=<generate using: python -c "import secrets; print(secrets.token_urlsafe(32))">
JWT_SECRET=<generate using: python -c "import secrets; print(secrets.token_urlsafe(32))">
FLASK_DEBUG=false
FLASK_ENV=production
```

#### Database:
```
DATABASE_URL=<paste the Internal Database URL from your PostgreSQL service>
```

#### CORS (Important!):
```
CORS_ORIGINS=https://your-app-name.onrender.com
```
**Note:** Replace with your actual Render URL. Do NOT use `*` in production!

#### Optional:
```
JWT_EXPIRE_MINUTES=120
SUBMISSION_REQUIRE_AUTH=false
```

### 5. Deploy
1. Click **"Manual Deploy"** → **"Deploy latest commit"**
2. Wait for build to complete
3. Your app will be live at: `https://your-app-name.onrender.com`

## Generating Strong Secrets

Run this locally to generate secure secrets:
```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(32))"
```

## Troubleshooting

### Build Fails
- Check build logs in Render Dashboard
- Verify `requirements.txt` is in root directory
- Ensure Python version is compatible (3.11+)

### App Won't Start
- Check start command: `waitress-serve --port=$PORT --call app:create_app`
- Verify all environment variables are set
- Check logs for error messages

### Database Connection Issues
- Verify `DATABASE_URL` is set correctly
- Use **Internal Database URL** (not External)
- Check PostgreSQL service is running

### Security Warnings
- If you see warnings about `SECRET_KEY` or `CORS_ORIGINS`, set them in Environment variables
- The app will fail to start in production if `SECRET_KEY` is missing

## Post-Deployment Checklist

- [ ] App is accessible at Render URL
- [ ] Can log in as admin
- [ ] Database connection working
- [ ] No security warnings in logs
- [ ] CORS is restricted to your domain (not `*`)
- [ ] Debug mode is disabled (`FLASK_DEBUG=false`)

## Health Check

Visit: `https://your-app-name.onrender.com/health`

Should return: `{"status": "ok"}`

