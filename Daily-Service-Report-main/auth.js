/* DSR Authentication Helper */
(function () {
  const STORAGE_KEYS = {
    token: 'dsr_jwt_token',
    apiConfig: 'dsr_api_config',
    redirect: 'dsr_redirect_to'
  };

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
    if (cfg && typeof cfg.base === 'string' && cfg.base) return cfg.base;
    try {
      if (location.protocol === 'file:') return 'http://127.0.0.1:5000';
      if (location.hostname === '127.0.0.1' || location.hostname === 'localhost') {
        // If running from any dev server port that's not 5000, point to Flask on 5000
        if (String(location.port) !== '5000') return 'http://127.0.0.1:5000';
      }
    } catch (_) {}
    return '';
  }

  function setToken(token) {
    try { localStorage.setItem(STORAGE_KEYS.token, token || ''); } catch (_) {}
  }

  function getToken() {
    try { return localStorage.getItem(STORAGE_KEYS.token) || ''; } catch (_) { return ''; }
  }

  function clearToken() {
    try { localStorage.removeItem(STORAGE_KEYS.token); } catch (_) {}
  }

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

  function isExpired(token) {
    const payload = decodeJwt(token);
    if (!payload || !payload.exp) return true;
    const nowSec = Math.floor(Date.now() / 1000);
    return payload.exp <= nowSec;
  }

  function authHeader() {
    const token = getToken();
    if (!token || isExpired(token)) return {};
    return { 'Authorization': 'Bearer ' + token };
  }

  async function httpJson(path, options) {
    const base = getApiBase();
    const url = base + path;
    console.log('auth.js: Making request to:', url);
    const res = await fetch(url, options || {});
    console.log('auth.js: Response status:', res.status);
    const isJson = (res.headers.get('content-type') || '').includes('application/json');
    const body = isJson ? await res.json() : await res.text();
    console.log('auth.js: Response body:', body);
    return { res, body };
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
      console.log('auth.js: Attempting login for username:', username);
      const { res, body } = await httpJson('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      console.log('auth.js: Login response:', { status: res.status, body });
      if (!res.ok || !body || !body.ok || !body.token) {
        const err = (body && (body.error || body.detail)) || ('HTTP ' + res.status);
        try { window.DSRAuthLastError = err; } catch (_) {}
        console.log('auth.js: Login failed -', err);
        return false;
      }
      setToken(body.token);
      console.log('auth.js: Token stored successfully');
      return true;
    } catch (e) {
      console.error('auth.js: Login error:', e);
      try { window.DSRAuthLastError = String(e); } catch (_) {}
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
    clearToken();
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
    getApiBase
  };
  
  console.log('DSR Authentication system loaded');
})();
