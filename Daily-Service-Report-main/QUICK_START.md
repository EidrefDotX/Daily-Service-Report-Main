# Quick Start Guide

## ✅ Backend is Now Running!

The Flask backend server is currently running at: **http://127.0.0.1:5000**

## How to Use the Application

### 1. **Access the Application**
Open your browser and go to:
```
http://127.0.0.1:5000/
```

Or directly to the login page:
```
http://127.0.0.1:5000/login.html
```

### 2. **Login**
Use any of these engineer credentials:

| Username | Password | Engineer Name |
|----------|----------|---------------|
| EN001 | #DotXsolutions.opc | Reherns |
| EN002 | #DotXsolutions.opc | Sam |
| EN003 | #DotXsolutions.opc | Ramil |
| EN004 | #DotXsolutions.opc | Vin |
| EN005 | #DotXsolutions.opc | Renz |
| EN006 | #DotXsolutions.opc | Brent |
| EN007 | #DotXsolutions.opc | Anwil |
| EN008 | #DotXsolutions.opc | Issa |
| EN009 | #DotXsolutions.opc | Ana |

### 3. **Submit Reports**
After logging in:
- Fill out the Daily Service Report form
- Sign the signature pads
- Click "Submit report"
- You should see "Submitted successfully" message

## Starting the Server in the Future

### Windows:
**Option 1:** Double-click `start.bat`

**Option 2:** Run in terminal:
```bash
py app.py
```

### Linux/Mac:
```bash
./start.sh
```
or
```bash
python app.py
```

## Stopping the Server

Press `Ctrl+C` in the terminal where the server is running.

## Checking if Server is Running

Open your browser and visit:
```
http://127.0.0.1:5000/health
```

You should see: `{"status": "ok"}`

## Troubleshooting

### "Cannot reach backend" error
1. Make sure the server is running (check terminal)
2. Verify http://127.0.0.1:5000/health works
3. Clear browser cache and localStorage
4. Login again

### "Authentication required" error
1. Make sure you're logged in
2. Check browser console (F12) for JWT token
3. If no token, logout and login again

### Port 5000 already in use
1. Find and stop the other process using port 5000
2. Or change the port in `.env` file:
   ```
   FLASK_PORT=5001
   ```

## Next Steps

- Submit test reports to verify everything works
- Check backend terminal for any error messages
- Use browser DevTools (F12) to see detailed logs

## Default Configuration

- **Backend URL:** http://127.0.0.1:5000
- **Database:** `dsr.sqlite3` (created automatically)
- **JWT Token Expiry:** 120 minutes
- **Debug Mode:** Enabled (development only)

---

**Need Help?** Check `TROUBLESHOOTING.md` for detailed solutions.

