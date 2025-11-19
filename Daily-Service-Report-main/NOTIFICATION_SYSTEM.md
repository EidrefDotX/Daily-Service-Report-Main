# Admin Notification System

## Overview
The admin notification system tracks and displays real-time notifications for:
- **User Logins**: When any engineer or user logs into the system
- **Report Submissions**: When any engineer submits a daily service report

## How It Works

### Backend (app.py)

#### 1. LoginEvent Model
A new database table `login_events` tracks all user logins:
```python
class LoginEvent(Base):
    id: int (primary key)
    username: str (user who logged in)
    role: str (user's role: admin/client)
    login_time: datetime (UTC timestamp)
```

#### 2. Login Event Tracking
When a user logs in via `/auth/login`, a login event is automatically recorded:
- Logs username, role, and timestamp
- Stored in the database for persistence
- Accessible to admins via the notifications API

#### 3. Unified Notifications API
**Endpoint**: `GET /api/notifications?since=<ISO_TIMESTAMP>`
- **Auth**: Requires admin role
- **Query Param**: `since` - ISO timestamp to get notifications after this time
- **Response**: Combined list of login events and report submissions
- **Limit**: Returns up to 500 recent login events and 500 report submissions (100 each when `since` is provided)

Response format:
```json
{
  "ok": true,
  "notifications": [
    {
      "id": "login-123",
      "type": "login",
      "message": "EN001 logged in",
      "time": "2025-10-24T10:30:00.000Z",
      "username": "EN001",
      "role": "client"
    },
    {
      "id": "report-456",
      "type": "report", 
      "message": "New report submitted by EN001 - Reherns",
      "time": "2025-10-24T10:35:00.000Z",
      "reportId": 456
    }
  ]
}
```

### Frontend (admin.html)

#### 1. Real-time Polling
- Polls `/api/notifications` roughly every **2 seconds** and on focus/interaction
- Only fetches notifications newer than `lastCheckTime`
- Stores timing and read-state metadata in `localStorage` to avoid duplicate alerts

#### 2. Notification Badge
- Red dot badge appears when there are unread notifications
- Shows on the bell icon in the header
- Updates automatically when new notifications arrive

#### 3. Notification Dropdown
- Click the bell icon to open/close the notification panel
- Shows up to 50 recent notifications
- Visual indicators:
  - 👤 icon for login events
  - 📄 icon for report submissions
  - Blue background for unread notifications
- Time displayed as relative ("Just now", "5m ago", "2h ago", etc.)

#### 4. Notification Actions
- **Click on report notification**: Opens the full report details modal
- **Click on login notification**: Marks as read
- **Clear All button**: Removes all notifications from the list
- **ESC key**: Closes the dropdown
- **Click outside**: Closes the dropdown

#### 5. Persistence
- Notification entries are re-fetched from the backend on each load
- `localStorage` keeps `lastCheckTime`, `admin_notifications_cleared_at`, and read-state so badges stay accurate
- If the backend is unavailable, previously fetched notifications are not cached locally

## User Experience

### For Admin Users
1. Admin opens the dashboard
2. Bell icon shows red badge if there are unread notifications
3. Click bell to see notification list
4. Login notifications show which engineers are active
5. Report notifications allow quick access to submitted reports
6. Mark all as read with "Clear All" button

### For Engineers
- No changes to their workflow
- Their logins are automatically tracked
- Their report submissions trigger notifications to admins

## Multi-User Support
✅ **Fully Supported**: Multiple admins can be logged in simultaneously
- Each admin has their own JWT token
- Each admin maintains their own notification state
- No conflicts between concurrent users
- Each admin's `lastCheckTime` is stored independently in their browser

## Security
- ✅ Admin-only access to notification endpoint
- ✅ JWT token validation on all API requests
- ✅ Role-based access control
- ✅ No sensitive data exposed in notifications
- ✅ SQL injection prevention via SQLAlchemy ORM

## Testing the System

### Test Login Notifications
1. Log in as admin and open admin dashboard
2. In another browser or profile, log in as an engineer (e.g., EN001)
3. Within a few seconds, admin should see notification: "EN001 logged in"

### Test Report Notifications
1. Admin opens admin dashboard
2. Engineer submits a report via DSR.html
3. Within a few seconds, admin should see notification: "Report submitted by EN001 - Reherns"
4. Click the notification to open the full report details

### Test Persistence
1. Receive some notifications
2. Close the browser tab
3. Reopen admin dashboard
4. Confirm the badge/count reflects unread items (state restored from `localStorage` metadata while notifications reload from the API)

## Performance Considerations
- **Polling interval**: ~2 seconds (configurable)
- **Database queries**: Optimized with indexed timestamps
- **API response**: Limited to 500 notifications per type (100 with `since`)
- **Frontend storage**: Metadata only (`localStorage` caches read state/timestamps)

## Future Enhancements
Potential features to add:
- Push notifications (via Web Push API or WebSockets)
- Sound alerts for new notifications
- Email/SMS notifications for critical events
- Filtering notifications by type
- Search within notifications
- Export notification history
- Custom notification preferences per admin

