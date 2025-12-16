/* DSR Authentication Helper */
(function () {
  const STORAGE_KEYS = {
    token: 'dsr_jwt_token', // Legacy key for backward compatibility
    tokenAdmin: 'dsr_jwt_token_admin',
    tokenEngineer: 'dsr_jwt_token_engineer',
    apiConfig: 'dsr_api_config',
    redirect: 'dsr_redirect_to'
  };

  // Helper to detect if we're on admin page
  function isAdminPage() {
    try {
      return window.location.pathname.includes('admin.html') || 
             window.location.href.includes('admin.html');
    } catch (_) {
      return false;
    }
  }

  // JWT decoding functions (needed for role detection)
  function base64UrlDecode(input) {
    try {
      input = input.replace(/-/g, '+').replace(/_/g, '/');
      const pad = input.length % 4;
      if (pad) input += '='.repeat(4 - pad);
      const decoded = atob(input);
      const bytes = Uint8Array.from(decoded, c => c.charCodeAt(0));
      const decoder = new TextDecoder('utf-8');
      return decoder.decode(bytes);
    } catch (_) {
      return '';
    }
  }

  function decodeJwt(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const payloadJson = base64UrlDecode(parts[1]);
      return JSON.parse(payloadJson);
    } catch (_) {
      return null;
    }
  }

  // Helper to get role from token
  function getRoleFromToken(token) {
    if (!token) return null;
    try {
      const payload = decodeJwt(token);
      return payload ? (payload.role || null) : null;
    } catch (_) {
      return null;
    }
  }

  function isExpired(token) {
    const payload = decodeJwt(token);
    if (!payload || !payload.exp) return true;
    const nowSec = Math.floor(Date.now() / 1000);
    return payload.exp <= nowSec;
  }

  // Migrate legacy token to role-based storage (runs on every load to ensure tokens are in right place)
  function migrateLegacyToken() {
    try {
      const legacyToken = localStorage.getItem(STORAGE_KEYS.token);
      if (!legacyToken) return;
      
      const role = getRoleFromToken(legacyToken);
      if (!role) return;
      
      // Migrate to role-based key (only if role-specific key doesn't exist or is expired)
      if (role === 'admin') {
        const existingAdminToken = localStorage.getItem(STORAGE_KEYS.tokenAdmin);
        if (!existingAdminToken || isExpired(existingAdminToken)) {
          localStorage.setItem(STORAGE_KEYS.tokenAdmin, legacyToken);
          console.log('auth.js: Migrated legacy token to admin token');
        }
      } else if (role === 'client') {
        const existingEngineerToken = localStorage.getItem(STORAGE_KEYS.tokenEngineer);
        if (!existingEngineerToken || isExpired(existingEngineerToken)) {
          localStorage.setItem(STORAGE_KEYS.tokenEngineer, legacyToken);
          console.log('auth.js: Migrated legacy token to engineer token');
        }
      }
      
      // Keep legacy token for backward compatibility
    } catch (_) {}
  }

  // Initialize migration on load (runs every time to ensure tokens are properly migrated)
  try {
    migrateLegacyToken();
  } catch (_) {}

  function getStoredConfig() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.apiConfig);
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  function getApiBase() {
    const cfg = getStoredConfig();
    // Only use stored config if it's a valid non-empty string
    if (cfg && typeof cfg.base === 'string' && cfg.base && cfg.base.trim() !== '' && cfg.base !== '.') {
      return cfg.base.trim();
    }
    try {
      if (location.protocol === 'file:') return 'http://127.0.0.1:5000';
      if (location.hostname === '127.0.0.1' || location.hostname === 'localhost') {
        // If running from any dev server port that's not 5000, point to Flask on 5000
        if (String(location.port) !== '5000') return 'http://127.0.0.1:5000';
        // If already on port 5000, use current origin
        return location.origin;
      }
      // For other cases, default to localhost:5000
      return 'http://127.0.0.1:5000';
    } catch (_) {
      // Fallback to default if anything fails
      return 'http://127.0.0.1:5000';
    }
  }

  function setToken(token) {
    if (!token) {
      clearToken();
      return;
    }
    
    try {
      // Determine role from token - optimized path
      const role = getRoleFromToken(token);
      
      if (role === 'admin') {
        localStorage.setItem(STORAGE_KEYS.tokenAdmin, token);
        const existingLegacy = localStorage.getItem(STORAGE_KEYS.token);
        const existingLegacyRole = existingLegacy ? getRoleFromToken(existingLegacy) : null;
        if (!existingLegacy || existingLegacyRole === 'admin') {
          localStorage.setItem(STORAGE_KEYS.token, token);
        }
      } else if (role === 'client') {
        localStorage.setItem(STORAGE_KEYS.tokenEngineer, token);
        const existingLegacy = localStorage.getItem(STORAGE_KEYS.token);
        const existingLegacyRole = existingLegacy ? getRoleFromToken(existingLegacy) : null;
        if (!existingLegacy || existingLegacyRole === 'client') {
          localStorage.setItem(STORAGE_KEYS.token, token);
        }
      } else {
        // Unknown role - store in legacy key only if empty
        const existingLegacy = localStorage.getItem(STORAGE_KEYS.token);
        if (!existingLegacy) {
          localStorage.setItem(STORAGE_KEYS.token, token);
        }
      }
    } catch (_) {
      // Fallback to legacy storage if anything fails
      try {
        const existingLegacy = localStorage.getItem(STORAGE_KEYS.token);
        if (!existingLegacy) {
          localStorage.setItem(STORAGE_KEYS.token, token || '');
        }
      } catch (_) {}
    }
  }

  function getToken() {
    try {
      // Determine which token to return based on page context
      if (isAdminPage()) {
        // On admin page, ONLY return admin tokens - never engineer tokens
        // First, check role-specific admin token (highest priority)
        const adminToken = localStorage.getItem(STORAGE_KEYS.tokenAdmin);
        if (adminToken && !isExpired(adminToken)) {
          const role = getRoleFromToken(adminToken);
          if (role === 'admin') {
            return adminToken;
          }
          // If admin token exists but role is wrong, clear it
          console.warn('auth.js: Admin token storage contains non-admin token, clearing');
          localStorage.removeItem(STORAGE_KEYS.tokenAdmin);
        }
        
        // Fallback to legacy token ONLY if it's an admin token
        const legacyToken = localStorage.getItem(STORAGE_KEYS.token);
        if (legacyToken) {
          const role = getRoleFromToken(legacyToken);
          if (role === 'admin' && !isExpired(legacyToken)) {
            // Auto-migrate to role-specific key for future use
            try {
              localStorage.setItem(STORAGE_KEYS.tokenAdmin, legacyToken);
            } catch (_) {}
            return legacyToken;
          }
          // If legacy token is not admin, don't return it (preserve it for engineer pages)
        }
        
        // No valid admin token found
        return '';
      } else {
        // On engineer pages (DSR.html, etc.), prefer engineer token
        const engineerToken = localStorage.getItem(STORAGE_KEYS.tokenEngineer);
        if (engineerToken && !isExpired(engineerToken)) {
          const role = getRoleFromToken(engineerToken);
          if (role === 'client') {
            return engineerToken;
          }
          // If engineer token exists but role is wrong, clear it
          localStorage.removeItem(STORAGE_KEYS.tokenEngineer);
        }
        
        // Fallback to legacy token if engineer token not found - check if it's an engineer token
        const legacyToken = localStorage.getItem(STORAGE_KEYS.token);
        if (legacyToken) {
          const role = getRoleFromToken(legacyToken);
          if (role === 'client' && !isExpired(legacyToken)) {
            // Auto-migrate to role-specific key for future use
            try {
              localStorage.setItem(STORAGE_KEYS.tokenEngineer, legacyToken);
            } catch (_) {}
            return legacyToken;
          }
          // If legacy token is admin, don't return it (preserve it for admin page)
        }
        return '';
      }
    } catch (_) {
      // Fallback to legacy token (but don't return it if it's for wrong role)
      try {
        const legacyToken = localStorage.getItem(STORAGE_KEYS.token);
        if (legacyToken) {
          const role = getRoleFromToken(legacyToken);
          // Only return if role matches page context
          if (isAdminPage() && role === 'admin') return legacyToken;
          if (!isAdminPage() && role === 'client') return legacyToken;
        }
        return '';
      } catch (_) { 
        return ''; 
      }
    }
  }

  function clearToken(roleToClear) {
    try {
      if (roleToClear === 'admin') {
        // Clear only admin tokens
        localStorage.removeItem(STORAGE_KEYS.tokenAdmin);
        const legacyToken = localStorage.getItem(STORAGE_KEYS.token);
        if (legacyToken && getRoleFromToken(legacyToken) === 'admin') {
          localStorage.removeItem(STORAGE_KEYS.token);
        }
        console.log('auth.js: Cleared admin tokens');
      } else if (roleToClear === 'client') {
        // Clear only engineer tokens
        localStorage.removeItem(STORAGE_KEYS.tokenEngineer);
        const legacyToken = localStorage.getItem(STORAGE_KEYS.token);
        if (legacyToken && getRoleFromToken(legacyToken) === 'client') {
          localStorage.removeItem(STORAGE_KEYS.token);
        }
        console.log('auth.js: Cleared engineer tokens');
      } else {
        // Clear all tokens (default behavior for explicit logout)
        localStorage.removeItem(STORAGE_KEYS.token);
        localStorage.removeItem(STORAGE_KEYS.tokenAdmin);
        localStorage.removeItem(STORAGE_KEYS.tokenEngineer);
        console.log('auth.js: Cleared all tokens');
      }
    } catch (_) {
      // Fallback: clear legacy token only
      try { localStorage.removeItem(STORAGE_KEYS.token); } catch (_) {}
    }
  }

  function authHeader() {
    const token = getToken();
    if (!token || isExpired(token)) return {};
    return { 'Authorization': 'Bearer ' + token };
  }

  async function httpJson(path, options) {
    const base = getApiBase();
    const url = base + path;
    try {
      // Optimized: Use json() directly for JSON responses, faster than text() + parse
      const res = await fetch(url, options || {});
      const contentType = res.headers.get('content-type') || '';
      const isJson = contentType.includes('application/json');
      
      let body;
      if (isJson) {
        try {
          body = await res.json(); // Direct JSON parsing, faster
        } catch (jsonError) {
          body = { error: 'Invalid JSON response from server', ok: false };
        }
      } else {
        // Handle HTML error pages
        let errorMsg = `HTTP ${res.status} Error`;
        if (res.status >= 500) {
          errorMsg = 'Internal server error. Please check the backend console for details.';
        } else if (res.status === 401) {
          errorMsg = 'Invalid username or password';
        } else if (res.status === 400) {
          errorMsg = 'Invalid request';
        }
        
        body = { error: errorMsg, ok: false };
      }
      
      return { res, body };
    } catch (fetchError) {
      return { 
        res: { ok: false, status: 0 }, 
        body: { error: 'Network error: ' + fetchError.message, ok: false } 
      };
    }
  }

  function getRedirectTarget(defaultPath) {
    const params = new URLSearchParams(window.location.search);
    const qp = params.get('redirect');
    if (qp) return qp;
    try {
      const stored = sessionStorage.getItem(STORAGE_KEYS.redirect);
      if (stored) return stored;
    } catch (_) {}
    return defaultPath || 'DSR.html';
  }

  function redirectWithReturn(loginPath) {
    const target = window.location.pathname + window.location.search + window.location.hash;
    try { sessionStorage.setItem(STORAGE_KEYS.redirect, target); } catch (_) {}
    const url = (loginPath || 'login.html') + '?redirect=' + encodeURIComponent(target);
    window.location.replace(url);
  }

  async function login(username, password) {
    try {
      // Clear any previous error
      try { window.DSRAuthLastError = undefined; } catch (_) {}
      
      const { res, body } = await httpJson('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      if (!res.ok || !body || !body.ok || !body.token) {
        // Extract error message from response
        let err = 'Login failed';
        if (body && typeof body === 'object') {
          err = body.error || body.detail || body.message || ('HTTP ' + res.status);
        } else if (typeof body === 'string') {
          err = body;
        } else {
          err = 'HTTP ' + res.status;
        }
        
        // Debug: Log error for troubleshooting
        console.error('[AUTH] Login failed:', { status: res.status, error: err, body });
        
        try { window.DSRAuthLastError = err; } catch (_) {}
        return false;
      }
      setToken(body.token);
      return true;
    } catch (e) {
      const errorMsg = e.message || String(e);
      try { window.DSRAuthLastError = errorMsg; } catch (_) {}
      return false;
    }
  }

  async function register(username, password, role) {
    try {
      const payload = { username, password, role: (role || 'client') };
      const headers = Object.assign({ 'Content-Type': 'application/json', 'Accept': 'application/json' }, authHeader());
      const { res, body } = await httpJson('/auth/register', { method: 'POST', headers, body: JSON.stringify(payload) });
      if (!res.ok || !body || !body.ok) {
        return false;
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  async function me() {
    try {
      const headers = Object.assign({ 'Accept': 'application/json' }, authHeader());
      const { res, body } = await httpJson('/auth/me', { method: 'GET', headers });
      if (!res.ok) return { ok: false, authenticated: false };
      return body || { ok: false, authenticated: false };
    } catch (_) {
      return { ok: false, authenticated: false };
    }
  }

  async function logout() {
    try {
      const headers = Object.assign({ 'Accept': 'application/json' }, authHeader());
      // Best-effort logout; don't block if backend is unreachable
      try { await httpJson('/auth/logout', { method: 'POST', headers }); } catch (_) {}
    } catch (_) {}
    // Determine which role to clear based on current token
    const currentToken = getToken();
    const role = currentToken ? getRoleFromToken(currentToken) : null;
    clearToken(role || undefined); // Clear only current user's tokens, or all if unknown
  }

  function isLoggedIn() {
    const t = getToken();
    return !!t && !isExpired(t);
  }

  window.DSRAuth = {
    login,
    register,
    logout,
    me,
    isLoggedIn,
    getRedirectTarget,
    redirectWithReturn,
    getAuthHeader: authHeader,
    getToken,
    setToken,
    getApiBase
  };
  
  console.log('DSR Authentication system loaded');
})();
