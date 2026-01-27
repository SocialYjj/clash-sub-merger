// Service Worker for offline support
const CACHE_NAME = 'submerger-v1';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
];

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

  // Skip API requests - always go to network
  if (url.pathname.startsWith('/api')) {
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
            caches.open(CACHE_NAME).then(cache => {
              cache.put(request, responseClone);
            });
          }
          return networkResponse;
        }).catch(() => {
          // Network failed, return cached response
          return cachedResponse;
        });

        // Return cached response immediately, update in background
        return cachedResponse || fetchPromise;
      })
    );
  }
});
