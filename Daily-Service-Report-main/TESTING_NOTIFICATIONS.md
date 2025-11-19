# Testing the Notification System

## Quick Start Guide

### Prerequisites
1. Restart the Flask server to create the new `login_events` table
2. Have two browser windows/tabs ready (or use incognito mode)

## Test Scenario 1: Login Notifications

### Steps:
1. **Window 1**: Log in as admin and go to admin dashboard
2. **Window 2**: Log in as engineer (e.g., EN001 with password `#DotXsolutions.opc`)
3. **Window 1**: Within 30 seconds, you should see:
   - Red badge appears on the bell icon
   - Click bell to see: "👤 EN001 logged in"
4. **Window 2**: Log out and log back in
5. **Window 1**: Another login notification should appear

### What to Look For:
- ✅ Red badge appears automatically
- ✅ Login notification shows username
- ✅ Notification shows "Just now" or "Xm ago"
- ✅ Clicking notification marks it as read
- ✅ Badge disappears when all notifications are read

## Test Scenario 2: Report Submission Notifications

### Steps:
1. **Window 1**: Admin logged into admin dashboard
2. **Window 2**: Engineer logged into DSR.html
3. **Window 2**: Fill out and submit a report
4. **Window 1**: Within 30 seconds, you should see:
   - Bell icon badge appears/updates
   - New notification: "📄 New report submitted by [Engineer Name]"
5. **Window 1**: Click the report notification
   - Should open the full report details modal

### What to Look For:
- ✅ Report notification appears after submission
- ✅ Shows engineer name correctly
- ✅ Clicking opens report details
- ✅ Time is accurate

## Test Scenario 3: Multiple Notifications

### Steps:
1. Admin dashboard open
2. Have 2-3 engineers log in (different windows/browsers)
3. Have 1-2 engineers submit reports
4. Check admin notification panel

### What to Look For:
- ✅ All notifications appear in chronological order (newest first)
- ✅ Login and report notifications are mixed properly
- ✅ Each notification has correct icon (👤 or 📄)
- ✅ "Clear All" button removes all notifications

## Test Scenario 4: Persistence

### Steps:
1. Admin dashboard with some notifications
2. Close the browser tab completely
3. Reopen browser and log in as admin
4. Go to admin dashboard

### What to Look For:
- ✅ Previous notifications should still be visible
- ✅ Badge state is maintained
- ✅ No duplicate notifications appear

## Test Scenario 5: Multi-Admin Support

### Steps:
1. **Window 1**: Admin A logs into admin dashboard
2. **Window 2**: Admin B logs into admin dashboard (different browser/incognito)
3. **Window 3**: Engineer submits a report
4. Check both admin windows

### What to Look For:
- ✅ Both admins receive the notification (within 30 seconds)
- ✅ Each admin can mark their own notifications as read independently
- ✅ No conflicts or logout issues

## Troubleshooting

### Notifications Not Appearing
- **Check**: Is admin dashboard open for at least 30 seconds?
- **Check**: Is the polling working? Open browser console, should see no errors
- **Check**: Is the user actually logged in? Check network tab for 401 errors

### Login Not Being Tracked
- **Check**: Did you restart Flask after adding the LoginEvent model?
- **Check**: Look in browser console for any API errors
- **Check**: Verify the login was successful (not a failed login attempt)

### Badge Not Updating
- **Check**: Clear browser localStorage and refresh
- **Check**: Open browser console and manually call `updateNotificationBadge()`

## Console Verification

### Backend Logs (Flask Console)
When server starts, you should see:
```
[backend] Created default admin user: admin
[backend] Created default user: EN001 (Reherns)
...
```

When someone logs in:
```
[DEBUG] Saving report for authenticated user: 'EN001 - Reherns'
```

### Frontend Logs (Browser Console)
When admin dashboard loads:
```
✓ Multi-user session active: admin (admin)
✓ Each user has their own JWT token - multiple users can work simultaneously
```

If polling fails:
```
Error checking for notifications: [error details]
```

## Manual API Testing

### Using Browser DevTools Console:
```javascript
// Check current notifications
fetch('/api/notifications?since=2025-01-01T00:00:00Z', {
  headers: { 'Authorization': 'Bearer ' + localStorage.getItem('jwt_token') }
})
.then(r => r.json())
.then(d => console.log(d))

// Check if logged in
fetch('/auth/me', {
  headers: { 'Authorization': 'Bearer ' + localStorage.getItem('jwt_token') }
})
.then(r => r.json())
.then(d => console.log(d))
```

## Expected Results Summary

✅ Admins see notifications for:
- Any engineer login (👤 icon)
- Any report submission (📄 icon)

✅ Notifications include:
- Who performed the action
- When it happened (relative time)
- Ability to click and view details (reports only)

✅ System handles:
- Multiple admins simultaneously
- Persistence across page refreshes
- Real-time updates every 30 seconds
- No duplicate notifications

## Common Issues

1. **"No notifications yet"**: This is normal if no one has logged in or submitted reports since you opened the dashboard
2. **Delay in notifications**: Polling happens every 30 seconds, so there can be up to 30s delay
3. **Old notifications**: The system keeps up to 50 of each type - older ones are automatically filtered out

## Success Criteria
- [ ] Login notifications appear within 30 seconds
- [ ] Report notifications appear within 30 seconds  
- [ ] Clicking report notification opens details modal
- [ ] Badge shows correct unread count
- [ ] "Clear All" removes all notifications
- [ ] Notifications persist after page refresh
- [ ] Multiple admins can use system simultaneously
- [ ] No JavaScript errors in console

