# Notification System - Troubleshooting Guide

## ✅ Backend Status
The backend is **WORKING CORRECTLY**:
- `login_events` table exists
- 2 login events already recorded
- 23 reports in database
- API endpoint `/api/notifications` is ready

## 🔧 Testing the Frontend

### Step 1: Open Admin Dashboard
1. Make sure Flask server is running: `python app.py`
2. Open browser: http://127.0.0.1:5000/admin.html
3. Log in as admin (username: `admin`, password: check your env or default)

### Step 2: Open Browser Console
- Press **F12** to open Developer Tools
- Click on the **Console** tab
- You should see logs like:
  ```
  ✓ Multi-user session active: admin (admin)
  [Notifications] Starting notification system, checking since: ...
  ```

### Step 3: Refresh Notifications
- Open the notification dropdown and click the **Refresh** button
- Check the console for detailed diagnostic information (you should see `[Notifications]` logs)

### Step 4: What to Look For in Console

#### ✅ GOOD - If you see:
```
[Notifications] API response: {ok: true, notifications: [...]}
[Notifications] Found X total notifications
[Notifications] X are new
[Notifications] Added: EN005 logged in
[Notifications] Badge updated, total notifications: X
[Notifications] Badge activated
```

#### ❌ BAD - If you see:
```
[Notifications] API error: 403 {ok: false, error: "Admin access required"}
```
**FIX**: You're not logged in as admin. Log out and log back in.

```
[Notifications] API error: 401 {...}
```
**FIX**: Your session expired. Refresh the page and log in again.

```
[Notifications] Error checking for notifications: Failed to fetch
```
**FIX**: Flask server is not running or wrong URL. Check server is running on port 5000.

### Step 5: Test Login Notification
1. Keep admin dashboard open with console visible
2. Open a **new browser profile/device** (incognito windows reuse storage, so prefer a separate profile)
3. Go to: http://127.0.0.1:5000/login.html
4. Log in as engineer: EN001, password: `#DotXsolutions.opc`
5. Wait a few seconds, then click **Refresh** in the notification dropdown
6. Check console - should show "EN001 logged in"

### Step 6: Test Report Notification
1. As engineer, go to DSR.html
2. Fill out and submit a report
3. In admin dashboard, click **Refresh** in the notification dropdown
4. You should see the new report notification within a few seconds

## Common Issues & Fixes

### Issue 1: "Badge element not found!"
**Symptom**: Console shows `[Notifications] Badge element not found!`
**Fix**: 
- Refresh the page (Ctrl+F5)
- Clear browser cache
- Check if you're on the correct page (admin.html not login.html)

### Issue 2: Badge not showing even with notifications
**Symptom**: Console shows notifications array has items, but no red dot on bell
**Fix**:
1. Open console
2. Type: `document.getElementById('notificationBadge')`
3. Should return an HTML element, not null
4. Type: `updateNotificationBadge()`
5. Check if badge appears

### Issue 3: API returns empty notifications
**Symptom**: `[Notifications] Found 0 total notifications`
**Possible Causes**:
- No one has logged in yet - try logging in as an engineer in another window
- `lastCheckTime` is too recent - clear localStorage:
  1. Open console
  2. Type: `localStorage.clear()`
  3. Refresh page
  4. Open notifications and click **Refresh**

### Issue 4: Notifications not updating automatically
**Symptom**: Manual refresh works, but auto-updates stop
**Fix**:
- Ensure polling is running: call `startNotificationPolling()` in console and confirm logs every ~2 seconds
- Verify the tab is focused/visible (browsers throttle background tabs)
- If errors appear, run `realtimeTick()` to surface details in the console

## Manual Console Tests

Open browser console (F12) and try these commands:

### Test 1: Check if authenticated
```javascript
fetch('/auth/me', {
  headers: { 'Authorization': 'Bearer ' + localStorage.getItem('jwt_token') }
})
.then(r => r.json())
.then(d => console.log('Auth Status:', d))
```
Should show: `{ok: true, authenticated: true, user: {username: "admin", role: "admin"}}`

### Test 2: Check API directly
```javascript
fetch('/api/notifications?since=2025-01-01T00:00:00Z', {
  headers: { 'Authorization': 'Bearer ' + localStorage.getItem('jwt_token') }
})
.then(r => r.json())
.then(d => console.log('Notifications:', d))
```
Should show: `{ok: true, notifications: [...]}`

### Test 3: Manually trigger notification
```javascript
notifications.push({
  id: 'test-123',
  type: 'login',
  message: 'Test notification',
  time: new Date(),
  unread: true
});
updateNotificationBadge();
```
Should make the red badge appear!

### Test 4: Check lastCheckTime
```javascript
console.log('Last Check:', localStorage.getItem('admin_last_check'));
console.log('Current:', new Date().toISOString());
```

### Test 5: Run built-in diagnostics
```javascript
window.testNotifications && window.testNotifications();
```
Provides DOM checks, auth status, and live API results.

## Still Not Working?

### Nuclear Option - Complete Reset
1. Open console
2. Run: `localStorage.clear()`
3. Close all browser tabs for this site
4. Restart Flask server
5. Open fresh browser window
6. Log in as admin
7. Open notifications and click **Refresh** immediately

### Check Flask Server Logs
When someone logs in, you should see in Flask console:
```
127.0.0.1 - - [date] "POST /auth/login HTTP/1.1" 200 -
```

### Database Check
- Inspect the `login_events` and `reports` tables directly (SQLite browser, `sqlite3`, or your configured database client)
- Confirm recent logins and submissions exist and timestamps are in UTC
- If tables are empty, trigger fresh logins/submissions and retry the refresh test

## Success Criteria
✅ Refresh button shows notifications in console
✅ Badge appears when unread notifications exist
✅ Clicking bell opens dropdown with notifications
✅ Login notifications appear after engineer logs in (within a few seconds)
✅ Report notifications appear after report submission (within a few seconds)

## Need More Help?
1. Share your browser console logs (after clicking Refresh)
2. Share Flask server console output
3. Share any database inspection output for `login_events` and `reports`

