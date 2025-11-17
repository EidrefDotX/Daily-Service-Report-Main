# Troubleshooting Guide - "Failing to Fetch" Error

## Quick Fix Steps

### Step 1: Restart the Backend
The backend needs to be restarted to create the default engineer users.

**Windows:**
```bash
# Stop the current server (Ctrl+C if running)
# Then start it again:
python app.py
```

**Or use the startup script:**
```bash
start.bat
```

**Linux/Mac:**
```bash
./start.sh
```

You should see these messages when users are created:
```
[backend] Created default user: EN001 (Reherns)
[backend] Created default user: EN002 (Sam)
[backend] Created default user: EN003 (Ramil)
... etc
```

### Step 2: Clear Browser Cache
1. Open browser DevTools (F12)
2. Go to Application/Storage tab
3. Clear localStorage
4. Refresh the page

### Step 3: Login Again
1. Go to `login.html`
2. Login with:
   - Username: `EN001` (or any EN001-EN009)
   - Password: `#DotXsolutions.opc`
3. Check browser console for these messages:
   - "Attempting backend authentication for: EN001"
   - "Backend authentication successful!"
   - "JWT token length: [some number]"

### Step 4: Submit a Report
1. Fill out the report form
2. Check browser console for:
   - "Submitting report to: [URL]"
   - "Response status: 200"
   - "Response data: {ok: true, ...}"

## Common Issues and Solutions

### Issue 1: "Please login first to submit reports"
**Cause:** No JWT token found in localStorage

**Solution:**
1. Go to login page and login again
2. Make sure you see "Backend authentication successful!" in console
3. Check localStorage has `dsr_jwt_token` key

### Issue 2: "Authentication required" from backend
**Cause:** JWT token is invalid or expired

**Solution:**
1. Logout and login again
2. Check if backend is running
3. Make sure default users were created (check backend console)

### Issue 3: "Cannot reach backend"
**Cause:** Backend server is not running

**Solution:**
1. Start the backend: `python app.py`
2. Verify it's running at http://127.0.0.1:5000
3. Check health endpoint: http://127.0.0.1:5000/health

### Issue 4: Backend authentication fails during login
**Cause:** Users not created in database OR wrong password

**Solution:**
1. Restart backend to trigger user creation
2. Check backend logs for "Created default user" messages
3. Verify password is exactly: `#DotXsolutions.opc` (case-sensitive)

### Issue 5: CORS errors
**Cause:** Accessing from wrong origin

**Solution:**
- Access the app through the backend server: http://127.0.0.1:5000/
- Don't use file:// protocol

## Debugging Checklist

Use browser DevTools Console (F12) to check:

✅ **During Login:**
- [ ] "Attempting backend authentication for: [username]"
- [ ] "Backend authentication successful!"
- [ ] "JWT token length: [number]"
- [ ] localStorage contains `dsr_jwt_token`
- [ ] localStorage contains `dsr_session`

✅ **During Submit:**
- [ ] "Submitting report to: http://127.0.0.1:5000/submit_report"
- [ ] Headers include Authorization
- [ ] "Response status: 200"
- [ ] "Submitted successfully" message appears

✅ **Backend Logs:**
- [ ] "[backend] Created default user:" messages on startup
- [ ] No error messages about database or authentication
- [ ] POST /auth/login returns 200
- [ ] POST /submit_report returns 200

## Manual Testing

### Test 1: Check if backend is running
```bash
curl http://127.0.0.1:5000/health
```
Expected: `{"status":"ok"}`

### Test 2: Check if user exists
Open browser console and run:
```javascript
localStorage.getItem('dsr_jwt_token')
```
Expected: A long string (JWT token)

### Test 3: Test login manually
```bash
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"EN001","password":"#DotXsolutions.opc"}'
```
Expected: `{"ok":true,"token":"...","user":{...}}`

## Still Having Issues?

1. **Check backend logs** for error messages
2. **Check browser console** for JavaScript errors
3. **Clear all localStorage** and try again
4. **Verify backend URL** in browser console:
   ```javascript
   console.log('API Base:', localStorage.getItem('dsr_api_config'))
   ```
5. **Delete the database file** and restart:
   ```bash
   rm dsr.sqlite3
   python app.py
   ```

## Contact Information

If none of these solutions work, provide:
- Browser console logs (full output)
- Backend server logs (terminal output)
- Error messages (exact text)

