const CACHE_NAME = 'dsr-cache-v5';
const OFFLINE_ASSETS = [
  './login.html',
  './DSR.html',
  './admin.html',
  './manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(OFFLINE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  
  // Check if URL scheme is cacheable (http/https only)
  // Exclude chrome-extension, data:, blob:, etc.
  const isCacheableScheme = url.protocol === 'http:' || url.protocol === 'https:';
  if (!isCacheableScheme) {
    // Don't intercept non-http/https requests (chrome-extension, data:, etc.)
    return;
  }
  
  const isNavigation = request.mode === 'navigate' || request.destination === 'document';
  const isApi =
    url.pathname.startsWith('/submit_report') ||
    url.pathname.startsWith('/reports') ||
    url.pathname.startsWith('/auth/') ||
    url.pathname.startsWith('/projectdefs') ||  // Exclude project API endpoints
    url.pathname === '/health';

  // Never cache or intercept API requests
  if (isApi) return;

  // Root navigation: always serve login.html (let backend handle the redirect)
  if (isNavigation && (url.pathname === '/' || url.pathname === '')) {
    event.respondWith(
      fetch(request)
        .then((response) => response)
        .catch(() => caches.match('./login.html'))
    );
    return;
  }

  // Other navigations: network-first with same-request cache fallback
  if (isNavigation) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // Only cache if scheme is cacheable and response is ok
          if (response && response.ok && isCacheableScheme) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(request, copy).catch(() => {
                // Silently fail if caching fails (e.g., unsupported scheme)
              });
            }).catch(() => {
              // Cache open failed - ignore
            });
          }
          return response;
        })
        .catch(() => caches.match(request))
    );
    return;
  }

  // For other GET requests, use cache-first with network update
  event.respondWith(
    caches.match(request).then((cached) =>
      cached || fetch(request).then((response) => {
        // Only cache if scheme is cacheable and response is ok
        if (response && response.ok && isCacheableScheme) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(request, copy).catch(() => {
              // Silently fail if caching fails (e.g., unsupported scheme)
            });
          }).catch(() => {
            // Cache open failed - ignore
          });
        }
        return response;
      })
    )
  );
});


