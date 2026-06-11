// Desinstala cualquier service worker anterior y limpia todos los cachés.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});
