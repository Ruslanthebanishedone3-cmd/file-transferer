// Relay server for the "send files with a 6-digit code" page.
// Serves index.html and pairs a host and a joiner by code, then forwards
// every message between them. Files pass through the server and are not stored.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const MAX_ROOMS = 500;
const WAIT_MS = 10 * 60 * 1000;      // a code expires after 10 minutes unused
const MAX_FAILS = 8;                  // wrong codes allowed per IP per minute
const INDEX = path.join(__dirname, 'index.html');

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  if (url === '/' || url === '/index.html') {
    fs.readFile(INDEX, (err, data) => {
      if (err) { res.writeHead(500); return res.end('index.html not found next to server.js'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(data);
    });
  } else if (url === '/health') {
    res.writeHead(200); res.end('ok');
  } else {
    res.writeHead(404); res.end('Not found');
  }
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 * 1024 });
const rooms = new Map();   // code -> { host, timer }
const fails = new Map();   // ip -> { n, t }

function ipOf(req) {
  const f = req.headers['x-forwarded-for'];
  return (f ? f.split(',')[0].trim() : req.socket.remoteAddress) || '?';
}
function newCode() {
  for (let i = 0; i < 50; i++) {
    const c = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    if (!rooms.has(c)) return c;
  }
  return null;
}
function tooManyFails(ip) {
  const f = fails.get(ip);
  return f && Date.now() - f.t < 60000 && f.n >= MAX_FAILS;
}
function addFail(ip) {
  const f = fails.get(ip);
  if (!f || Date.now() - f.t >= 60000) fails.set(ip, { n: 1, t: Date.now() });
  else f.n++;
}
function say(ws, text, close) {
  try { ws.send(text); if (close) ws.close(); } catch (e) {}
}

server.on('upgrade', (req, socket, head) => {
  if (req.url.split('?')[0] !== '/ws') return socket.destroy();
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

wss.on('connection', (ws, req) => {
  const q = new URL(req.url, 'http://x').searchParams;
  const role = q.get('role');
  const ip = ipOf(req);
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('error', () => {});

  if (role === 'host') {
    if (rooms.size >= MAX_ROOMS) return say(ws, '@full', true);
    const code = newCode();
    if (!code) return say(ws, '@full', true);
    const room = { host: ws, timer: setTimeout(() => ws.close(), WAIT_MS) };
    rooms.set(code, room);
    say(ws, '@code:' + code);
    ws.on('close', () => {
      clearTimeout(room.timer);
      if (rooms.get(code) === room) rooms.delete(code);
      if (ws.peer) try { ws.peer.close(); } catch (e) {}
    });
  } else if (role === 'join') {
    if (tooManyFails(ip)) return say(ws, '@limit', true);
    const code = (q.get('code') || '').replace(/\D/g, '');
    const room = rooms.get(code);
    if (!room) { addFail(ip); return say(ws, '@nocode', true); }
    rooms.delete(code);
    clearTimeout(room.timer);
    const host = room.host;
    host.peer = ws; ws.peer = host;
    say(host, '@paired'); say(ws, '@paired');
    const relay = (from, to) => from.on('message', (data, isBinary) => {
      if (to.readyState === 1) to.send(data, { binary: isBinary });
    });
    relay(host, ws); relay(ws, host);
    ws.on('close', () => { try { host.close(); } catch (e) {} });
  } else {
    ws.close();
  }
});

// keep connections alive through proxies and drop dead ones
setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false; ws.ping();
  });
}, 25000);

server.listen(PORT, '0.0.0.0', () => console.log('Running on port ' + PORT));
