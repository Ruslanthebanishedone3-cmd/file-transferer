// Service worker: turns data arriving in the page into a normal browser download,
// so the file is saved to disk while it arrives and the browser shows its own progress.
const streams = new Map();
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('message', e => {
  const d = e.data;
  if (!d || d.t !== 'new' || !e.ports[0]) return;      // other messages are keep-alive pings
  const port = e.ports[0];
  const stream = new ReadableStream({
    start(ctrl) {
      port.onmessage = m => {
        const x = m.data;
        if (x.t === 'chunk') ctrl.enqueue(new Uint8Array(x.b));
        else if (x.t === 'end') ctrl.close();
        else if (x.t === 'abort') ctrl.error(new Error('aborted'));
      };
    },
    cancel() { port.postMessage({ t: 'cancel' }); }
  });
  streams.set(d.id, { stream, name: d.name, size: d.size });
  setTimeout(() => streams.delete(d.id), 60000);
  port.postMessage({ t: 'ready' });
});
self.addEventListener('fetch', e => {
  const m = /^\/_dl\/([a-z0-9]+)\//.exec(new URL(e.request.url).pathname);
  if (!m) return;
  const s = streams.get(m[1]);
  if (!s) return e.respondWith(new Response('Download expired', { status: 404 }));
  streams.delete(m[1]);
  const h = {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent(s.name),
    'X-Content-Type-Options': 'nosniff'
  };
  if (typeof s.size === 'number') h['Content-Length'] = String(s.size);
  e.respondWith(new Response(s.stream, { headers: h }));
});
