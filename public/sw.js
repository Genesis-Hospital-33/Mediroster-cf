// MediRoster service worker: makes the site installable and shows a friendly page when offline.
// It never stores logins, rosters or any server data: requests to the server always go to the network.
const CACHE = 'mediroster-shell-v3';
const SHELL = ['/offline.html', '/icon-192.png', '/icon-512.png', '/apple-touch-icon.png', '/manifest.webmanifest'];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', (e) => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname === '/api') return;
  if (r.mode === 'navigate') { e.respondWith(fetch(r).catch(() => caches.match('/offline.html'))); return; }
  if (SHELL.includes(u.pathname)) e.respondWith(caches.match(r).then((hit) => hit || fetch(r)));
});

// Phone notifications: show the title and short text the server sent, and open the right chat when tapped.
self.addEventListener('push', (e) => {
  let d = {}; try { d = e.data ? e.data.json() : {}; } catch (x) { /* empty message */ }
  e.waitUntil(self.registration.showNotification(d.title || 'MediRoster', { body: d.body || '', icon: '/icon-192.png', badge: '/icon-192.png', tag: d.tag || 'mediroster', renotify: true, data: { url: d.url || '/' } }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close(); const url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) { if ('focus' in c) { c.postMessage({ open: url }); return c.focus(); } }
    return self.clients.openWindow(url);
  }));
});
