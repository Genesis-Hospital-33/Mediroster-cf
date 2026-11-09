// MediRoster service worker: makes the site installable and shows a friendly page when offline.
// It never stores logins, rosters or any server data: requests to the server always go to the network.
const CACHE = 'mediroster-shell-v1';
const SHELL = ['/offline.html', '/icon-192.png', '/icon-512.png', '/apple-touch-icon.png', '/manifest.webmanifest'];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', (e) => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname === '/api') return;
  if (r.mode === 'navigate') { e.respondWith(fetch(r).catch(() => caches.match('/offline.html'))); return; }
  if (SHELL.includes(u.pathname)) e.respondWith(caches.match(r).then((hit) => hit || fetch(r)));
});
