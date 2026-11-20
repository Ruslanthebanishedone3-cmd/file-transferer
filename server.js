// Tiny file drop server. No dependencies. Needs Node 16 or newer.
// Run:  node server.js
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { once } = require('events');

const PORT = +process.env.PORT || 8080;
const DATA = path.resolve(process.env.DATA_DIR || './shares');
const KEEP_DAYS = +process.env.KEEP_DAYS || 7;          // shares are deleted after this many days
const TRUST_PROXY = !!process.env.TRUST_PROXY;           // set if you run behind Caddy/nginx
fs.mkdirSync(DATA, { recursive: true });

const T = new Uint32Array(256);
for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; T[n] = c >>> 0; }
function crc32(c, buf) { c = ~c; for (let i = 0; i < buf.length; i++) c = T[(c ^ buf[i]) & 255] ^ (c >>> 8); return ~c >>> 0; }

const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const safeRel = p => String(p).replace(/[\u0000-\u001f\\]/g, '').split('/').filter(s => s && s !== '.' && s !== '..').join('/').slice(0, 500);
const codeDir = c => /^\d{6}$/.test(c) ? path.join(DATA, c) : null;
const readMeta = d => { try { return JSON.parse(fs.readFileSync(path.join(d, 'meta.json'), 'utf8')); } catch (e) { return null; } };
// each share has its own secret token, so only the page that created a code can add files to it
const tokOK = (req, meta) => { const a = Buffer.from(String(req.headers['x-token'] || '')), b = Buffer.from(String(meta.token || '')); return b.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b); };
const made = new Map();   // limit how many codes one address can create per hour
function makeLimited(ip) { const f = made.get(ip); if (!f || Date.now() - f.t > 3600e3) { made.set(ip, { n: 1, t: Date.now() }); return false; } return ++f.n > 30; }

const fails = new Map();   // simple guess protection for 6-digit codes
function ipOf(req) { return (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress; }
function limited(ip) { const f = fails.get(ip); return f && f.n >= 15 && Date.now() - f.t < 60000; }
function fail(ip) { const f = fails.get(ip); if (!f || Date.now() - f.t > 60000) fails.set(ip, { n: 1, t: Date.now() }); else f.n++; }

function sendFile(req, res, full, name) {
  fs.stat(full, (e, st) => {
    if (e || !st.isFile()) return json(res, 404, { error: 'not found' });
    let start = 0, end = st.size - 1, status = 200;
    const r = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (r && st.size) {
      if (r[1] === '') start = Math.max(0, st.size - +r[2]); else { start = +r[1]; if (r[2] !== '') end = Math.min(end, +r[2]); }
      if (start > end || start >= st.size) { res.writeHead(416, { 'Content-Range': 'bytes */' + st.size }); return res.end(); }
      status = 206;
    }
    const h = { 'Content-Type': 'application/octet-stream', 'Accept-Ranges': 'bytes', 'Content-Length': st.size ? end - start + 1 : 0,
      'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent(name) };
    if (status === 206) h['Content-Range'] = 'bytes ' + start + '-' + end + '/' + st.size;
    res.writeHead(status, h);
    if (!st.size) return res.end();
    fs.createReadStream(full, { start, end }).pipe(res);
  });
}

async function sendZip(res, dir, code, meta) {
  let total = 98; for (const k of Object.keys(meta.files)) total += 124 + 2 * Buffer.byteLength(k) + meta.files[k].size;   // exact size, so the browser shows real progress
  res.writeHead(200, { 'Content-Type': 'application/zip', 'Content-Length': total, 'Content-Disposition': 'attachment; filename="' + code + '.zip"' });
  let off = 0, closed = false; res.on('close', () => closed = true);
  const put = async b => { if (closed) throw new Error('closed'); off += b.length; if (!res.write(b)) await once(res, 'drain'); };
  const d = new Date(), tm = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1), dt = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  const ents = [];
  try {
    for (const rel of Object.keys(meta.files).sort()) {
      const f = meta.files[rel], nm = Buffer.from(rel), h = Buffer.alloc(50 + nm.length);
      h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(45, 4); h.writeUInt16LE(0x0800, 6); h.writeUInt16LE(tm, 10); h.writeUInt16LE(dt, 12);
      h.writeUInt32LE(f.crc, 14); h.writeUInt32LE(0xFFFFFFFF, 18); h.writeUInt32LE(0xFFFFFFFF, 22); h.writeUInt16LE(nm.length, 26); h.writeUInt16LE(20, 28);
      nm.copy(h, 30); h.writeUInt16LE(1, 30 + nm.length); h.writeUInt16LE(16, 32 + nm.length);
      h.writeBigUInt64LE(BigInt(f.size), 34 + nm.length); h.writeBigUInt64LE(BigInt(f.size), 42 + nm.length);
      ents.push({ nm, f, off }); await put(h);
      for await (const c of fs.createReadStream(path.join(dir, 'data', rel))) await put(c);
    }
    const cdOff = off;
    for (const e of ents) {
      const c = Buffer.alloc(74 + e.nm.length), p = 46 + e.nm.length;
      c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(45, 4); c.writeUInt16LE(45, 6); c.writeUInt16LE(0x0800, 8); c.writeUInt16LE(tm, 12); c.writeUInt16LE(dt, 14);
      c.writeUInt32LE(e.f.crc, 16); c.writeUInt32LE(0xFFFFFFFF, 20); c.writeUInt32LE(0xFFFFFFFF, 24); c.writeUInt16LE(e.nm.length, 28); c.writeUInt16LE(28, 30); c.writeUInt32LE(0xFFFFFFFF, 42);
      e.nm.copy(c, 46); c.writeUInt16LE(1, p); c.writeUInt16LE(24, p + 2);
      c.writeBigUInt64LE(BigInt(e.f.size), p + 4); c.writeBigUInt64LE(BigInt(e.f.size), p + 12); c.writeBigUInt64LE(BigInt(e.off), p + 20);
      await put(c);
    }
    const cs = off - cdOff, eo = off, z = Buffer.alloc(98);
    z.writeUInt32LE(0x06064b50, 0); z.writeBigUInt64LE(44n, 4); z.writeUInt16LE(45, 12); z.writeUInt16LE(45, 14);
    z.writeBigUInt64LE(BigInt(ents.length), 24); z.writeBigUInt64LE(BigInt(ents.length), 32); z.writeBigUInt64LE(BigInt(cs), 40); z.writeBigUInt64LE(BigInt(cdOff), 48);
    z.writeUInt32LE(0x07064b50, 56); z.writeBigUInt64LE(BigInt(eo), 64); z.writeUInt32LE(1, 72);
    z.writeUInt32LE(0x06054b50, 76); z.writeUInt16LE(0xFFFF, 84); z.writeUInt16LE(0xFFFF, 86); z.writeUInt32LE(0xFFFFFFFF, 88); z.writeUInt32LE(0xFFFFFFFF, 92);
    await put(z); res.end();
  } catch (e) { res.destroy(); }
}

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'), p = u.pathname, ip = ipOf(req);
  let m;
  if (req.method === 'GET' && p === '/') return fs.createReadStream(path.join(__dirname, 'index.html')).on('error', () => json(res, 500, { error: 'index.html missing' })).pipe(res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }) && res);

  if (req.method === 'POST' && p === '/api/new') {
    if (makeLimited(ip)) return json(res, 429, { error: 'too many codes' });
    for (let i = 0; i < 50; i++) {
      const c = String(crypto.randomInt(0, 1000000)).padStart(6, '0'), d = path.join(DATA, c), token = crypto.randomBytes(16).toString('hex');
      if (fs.existsSync(d)) continue;
      fs.mkdirSync(path.join(d, 'data'), { recursive: true });
      fs.writeFileSync(path.join(d, 'meta.json'), JSON.stringify({ created: Date.now(), files: {}, done: false, token }));
      return json(res, 200, { code: c, token });
    }
    return json(res, 500, { error: 'no free code' });
  }

  if (req.method === 'PUT' && (m = /^\/api\/up\/(\d{6})$/.exec(p))) {
    const dir = codeDir(m[1]), meta = dir && readMeta(dir);
    if (meta && !tokOK(req, meta)) return json(res, 401, { error: 'not your code' });
    let rel; try { rel = safeRel(decodeURIComponent(req.headers['x-path'] || '')); } catch (e) { rel = ''; }
    if (!meta || !rel) return json(res, 400, { error: 'bad request' });
    if (meta.done) return json(res, 409, { error: 'already published' });
    const full = path.join(dir, 'data', rel);
    if (!full.startsWith(path.join(dir, 'data') + path.sep)) return json(res, 400, { error: 'bad path' });
    fs.mkdirSync(path.dirname(full), { recursive: true });
    const ws = fs.createWriteStream(full + '.part'); let crc = 0, size = 0, dead = false;
    const cleanup = () => { if (dead) return; dead = true; ws.destroy(); fs.unlink(full + '.part', () => {}); };
    req.on('data', c => { crc = crc32(crc, c); size += c.length; });
    req.on('aborted', cleanup); req.on('error', cleanup); ws.on('error', () => { cleanup(); if (!res.headersSent) json(res, 500, { error: 'disk error' }); });
    ws.on('finish', () => {
      if (dead) return;
      fs.rename(full + '.part', full, err => {
        if (err) return json(res, 500, { error: 'disk error' });
        const mt = readMeta(dir); mt.files[rel] = { size, crc }; fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify(mt));
        json(res, 200, { ok: true, size });
      });
    });
    return req.pipe(ws);
  }

  if (req.method === 'POST' && (m = /^\/api\/done\/(\d{6})$/.exec(p))) {      // sender finished: publish
    const dir = codeDir(m[1]), meta = dir && readMeta(dir);
    if (!meta) return json(res, 404, { error: 'no such code' });
    if (!tokOK(req, meta)) return json(res, 401, { error: 'not your code' });
    meta.done = true; fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify(meta));
    return json(res, 200, { ok: true });
  }

  if (req.method === 'GET' && (m = /^\/(api\/list|zip|d)\/(\d{6})(?:\/(.*))?$/.exec(p))) {
    if (limited(ip)) return json(res, 429, { error: 'too many tries' });
    const dir = codeDir(m[2]), meta = dir && readMeta(dir);
    if (!meta) { fail(ip); return json(res, 404, { error: 'no such code' }); }
    if (m[1] === 'api/list') return json(res, 200, { done: !!meta.done, files: Object.keys(meta.files).sort().map(k => ({ path: k, size: meta.files[k].size })) });
    if (!meta.done) return json(res, 409, { error: 'still publishing' });
    if (m[1] === 'zip') return sendZip(res, dir, m[2], meta);
    let rel; try { rel = safeRel(decodeURIComponent(m[3] || '')); } catch (e) { rel = ''; }
    if (!meta.files[rel]) return json(res, 404, { error: 'no such file' });
    return sendFile(req, res, path.join(dir, 'data', rel), rel.split('/').pop());
  }
  if (req.method === 'GET' && p === '/health') { res.writeHead(200); return res.end('ok'); }
  json(res, 404, { error: 'not found' });
}).listen(PORT, () => console.log('Running on port ' + PORT + '. Files are kept in ' + DATA + ' for ' + KEEP_DAYS + ' days.')).requestTimeout = 0;

setInterval(() => {
  for (const n of fs.readdirSync(DATA)) {
    const d = path.join(DATA, n), mt = readMeta(d);
    if (!mt || Date.now() - mt.created > KEEP_DAYS * 864e5) fs.rmSync(d, { recursive: true, force: true });
  }
}, 3600e3).unref();
