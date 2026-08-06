// Service Worker for static asset caching only.
// Dynamic and authenticated responses must always bypass the Cache API.
const CACHE_NAME = 'submerger-static-v4-6-0';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
];

const STATIC_PATH_PATTERN = /^(?:\/assets\/|\/favicon\.ico$|\/manifest\.json$|\/index\.html$)/;

// Install event - cache static assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
  self.skipWaiting();
});

// Activate event - clean old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames
          .filter(name => name !== CACHE_NAME)
          .map(name => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

// Fetch event - network first, fallback to cache
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Only cache same-origin static assets. In particular, never cache
  // subscriptions, health/metrics responses, or any authenticated endpoint.
  if (url.origin !== self.location.origin || url.pathname.startsWith('/api')) {
    return;
  }
  if (!STATIC_PATH_PATTERN.test(url.pathname) && url.pathname !== '/') {
    return;
  }

  // For static assets, use cache-first strategy
  if (request.method === 'GET') {
    event.respondWith(
      caches.match(request).then(cachedResponse => {
        const fetchPromise = fetch(request).then(networkResponse => {
          // Update cache with new response
          if (networkResponse.ok) {
            const responseClone = networkResponse.clone();
            event.waitUntil(
              caches.open(CACHE_NAME).then(cache => cache.put(request, responseClone))
            );
          }
          return networkResponse;
        }).catch(async () => {
          // Network failed: return cache if available, otherwise a real Response.
          // respondWith() must never resolve to null/undefined.
          if (cachedResponse) return cachedResponse;

          if (request.mode === 'navigate') {
            const fallback = await caches.match('/index.html');
            if (fallback) return fallback;
          }

          return new Response('Offline', {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' }
          });
        });

        // Return cached response immediately, update in background
        return cachedResponse || fetchPromise;
      })
    );
  }
});
