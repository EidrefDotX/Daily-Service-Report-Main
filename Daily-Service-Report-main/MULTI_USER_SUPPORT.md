# Multi-User Support Documentation

## ✅ The System Already Supports Multiple Concurrent Users!

The Daily Service Report application uses **JWT (JSON Web Token) authentication**, which inherently supports multiple users working simultaneously without interfering with each other.

---

## How It Works

### 1. **Each User Gets Their Own Token**
When a user logs in:
- Admin logs in → Gets a unique JWT token stored in **their browser**
- Engineer 1 logs in on their device → Gets their own JWT token
- Engineer 2 logs in on another device → Gets their own JWT token

**Each token is completely independent and identifies that specific user.**

### 2. **Tokens Are Stored Locally**
- JWT tokens are stored in `localStorage` in each user's browser
- **Different browsers = Different storage = No conflicts**
- **Different devices = Different storage = No conflicts**
- **Separate browser profiles** keep storage isolated (needed for simultaneous sessions on one machine)

### 3. **Backend Validates Each Request**
Every API request includes the user's JWT token:
```
Authorization: Bearer <user's-unique-token>
```

The backend:
- ✅ Validates the token for each request
- ✅ Identifies which user made the request
- ✅ Applies appropriate permissions (admin vs engineer)
- ✅ Processes requests independently

---

## Usage Scenarios

### ✅ **Scenario 1: Admin and Multiple Engineers**
```
Admin (Chrome, Desktop)     → Admin Token → Full access
Engineer 1 (Firefox, Laptop) → Engineer Token 1 → Can submit reports
Engineer 2 (Chrome, Mobile)  → Engineer Token 2 → Can submit reports
Engineer 3 (Safari, iPad)    → Engineer Token 3 → Can submit reports
```

**Result: All work simultaneously without any conflicts!**

### ✅ **Scenario 2: Multiple Admins**
```
Admin 1 (Desktop)  → Admin Token 1 → Can view/delete reports
Admin 2 (Laptop)   → Admin Token 2 → Can view/delete reports
```

**Result: Both admins can work at the same time!**

### ✅ **Scenario 3: Same Device, Different Browsers/Profiles**
```
Admin (Chrome – Profile A)     → Admin Token
Engineer (Firefox – Profile B) → Engineer Token
```

**Result: No conflicts — each browser profile keeps its own storage.**

---

## Verification

When you log in, check the browser console (F12). You'll see:
```
✓ Multi-user session active: EN001 (engineer)
✓ Each user has their own JWT token - multiple users can work simultaneously
```

This confirms your session is working correctly.

---

## Important Notes

### ✅ **What Works:**
- Multiple users on different devices ✓
- Multiple users on different browsers ✓
- Multiple users on the same browser using separate profiles ✓
- Admin and engineers simultaneously ✓
- Multiple admins simultaneously ✓
- Multiple engineers simultaneously ✓

### ⚠️ **Same Browser Profile**
All tabs/windows inside a single browser profile share `localStorage`, so the most recent login replaces earlier tokens:
- Person 1 logs in → Token stored in profile storage
- Person 2 logs in (same profile, any tab/window) → Token is replaced
- Person 1 must log in again to continue

**Solution:** When different users need simultaneous sessions, use separate devices, distinct browser profiles, or completely different browsers.

---

## Technical Details

### JWT Token Structure
```json
{
  "sub": "user_id",
  "username": "EN001",
  "role": "engineer",
  "exp": 1234567890
}
```

Each token:
- Is cryptographically signed
- Contains user identity
- Has an expiration time (2 hours by default)
- Cannot be forged or modified

### API Request Flow
```
User Action → Frontend sends request with JWT token
            → Backend validates token
            → Backend identifies user from token
            → Backend processes request
            → Returns response to that specific user
```

---

## Database Integrity

The system ensures data integrity:
- ✅ Each report submission is atomic (all-or-nothing)
- ✅ Database handles concurrent writes properly
- ✅ SQLite/PostgreSQL backend manages locks automatically
- ✅ No data corruption from simultaneous access

---

## Troubleshooting

### Problem: "I get logged out when someone else logs in"
**Solution:** You're sharing the same browser profile. Switch to separate devices, different browsers, or distinct profiles.

### Problem: "My changes don't appear for other users"
**Solution:** Each user needs to refresh their view. The notification system alerts admins about new reports automatically.

### Problem: "Session expired"
**Solution:** JWT tokens expire after 2 hours. Simply log in again to get a new token.

---

## Conclusion

**The system is already designed for multi-user access!** 

Just ensure each user has their own:
- ✅ Device (computer, tablet, phone), OR
- ✅ Browser (Chrome, Firefox, Safari, Edge) or a distinct browser profile, OR  
- ✅ Dedicated session that isn't shared within the same profile/tab

Multiple users can work simultaneously without any issues. The JWT-based authentication ensures each user's session is completely independent.

---

**Last Updated:** October 2025

