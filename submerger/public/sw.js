// Service Worker for static asset caching only.
// Dynamic and authenticated responses must always bypass the Cache API.
const CACHE_NAME = 'submerger-static-v6.0.1';
const PRECACHE_ASSETS = ['/manifest.json'];

// Vite's hashed assets are safe to cache for the lifetime of this version.
// The HTML shell is deliberately excluded: serving an old index.html can
// reference chunks that no longer exist after a deployment.
const STATIC_PATH_PATTERN = /^(?:\/assets\/|\/favicon\.ico$|\/manifest\.json$)/;

// Install event - cache static assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(PRECACHE_ASSETS);
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
  // Subscription output, health/metrics probes, and all other dynamic
  // endpoints must always use the network and must never enter Cache Storage.
  if (
    url.pathname.startsWith('/sub') ||
    url.pathname === '/health' ||
    url.pathname === '/metrics' ||
    url.pathname.startsWith('/health/') ||
    url.pathname.startsWith('/metrics/')
  ) {
    return;
  }

  if (request.method !== 'GET') {
    return;
  }

  // Always revalidate the application shell.  Fall back to the last known
  // shell only when the browser is genuinely offline.
  if (request.mode === 'navigate' || url.pathname === '/' || url.pathname === '/index.html') {
    event.respondWith(
      fetch(request, { cache: 'no-store' })
        .then(networkResponse => {
          if (networkResponse.ok) {
            const responseClone = networkResponse.clone();
            event.waitUntil(
              caches.open(CACHE_NAME).then(cache => cache.put('/index.html', responseClone))
            );
          }
          return networkResponse;
        })
        .catch(async () => {
          const cachedResponse = await caches.match('/index.html');
          return cachedResponse || new Response('Offline', {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' }
          });
        })
    );
    return;
  }

  // Hashed static resources use cache-first with a network refresh fallback.
  if (STATIC_PATH_PATTERN.test(url.pathname)) {
    event.respondWith(
      caches.match(request).then(cachedResponse => {
        const fetchPromise = fetch(request).then(networkResponse => {
          if (networkResponse.ok) {
            const responseClone = networkResponse.clone();
            event.waitUntil(
              caches.open(CACHE_NAME).then(cache => cache.put(request, responseClone))
            );
          }
          return networkResponse;
        }).catch(() => cachedResponse || new Response('Static asset unavailable', {
          status: 503,
          statusText: 'Service Unavailable',
          headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        }));
        return cachedResponse || fetchPromise;
      })
    );
  }
});
