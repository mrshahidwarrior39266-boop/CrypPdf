'use strict';
/* CrypPDF local gateway. Node 18+, zero dependencies.
   DESIGN RULES (audited by "Agent 5"):
   - The only fs call is a one-time READ of public/index.html at startup. Nothing is ever written.
   - Uploaded bytes are ciphertext (encrypted in the browser). The decryption key lives in the share
     ticket and never reaches this server.
   - Ciphertext is held in RAM only, with a TTL, and is zero-filled when it expires, is deleted or is burned.
   - Binds to 127.0.0.1 unless HOST is set. No request body is ever logged. */
const http = require('http'), https = require('https'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '127.0.0.1';
const MAX = (+process.env.MAX_MB || 25) * 1048576, TTL_MAX = 60;
const GID = process.env.GOOGLE_CLIENT_ID || null;               // OAuth integration point (supplied at deployment)
const DEV = process.env.DEV_LOGIN === '1';                       // local testing only
if (DEV && !['127.0.0.1', 'localhost', '::1'].includes(HOST)) { console.error('DEV_LOGIN requires a loopback HOST.'); process.exit(1); }
const INDEX = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
const sessions = new Map(), transfers = new Map();
const rid = n => crypto.randomBytes(n).toString('base64url');
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://accounts.google.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://accounts.google.com; font-src https://fonts.gstatic.com; connect-src 'self' https://accounts.google.com; frame-src https://accounts.google.com; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'";

function send(res, code, body, type = 'application/json') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': CSP });
  res.end(body);
}
const json = (res, code, o) => send(res, code, JSON.stringify(o));
const fail = (res, code, error) => json(res, code, { error });
function body(req, limit) {
  return new Promise((ok, no) => {
    const chunks = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > limit) { chunks.forEach(x => x.fill(0)); req.destroy(); return no(Object.assign(new Error('too large'), { status: 413 })); } chunks.push(c); });
    req.on('end', () => { const b = Buffer.concat(chunks); chunks.forEach(x => x.fill(0)); ok(b); });
    req.on('error', no);
  });
}
const small = async req => { try { return JSON.parse((await body(req, 8192)).toString() || '{}'); } catch { return {}; } };
const cookie = req => (/(?:^|; )sid=([\w-]+)/.exec(req.headers.cookie || '') || [])[1];
const auth = req => { const s = sessions.get(cookie(req)); return s && s.exp > Date.now() ? s : null; };
function login(res, user) {
  const sid = rid(32); sessions.set(sid, { sid, user, exp: Date.now() + 8 * 3600e3 });
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`);
  json(res, 200, { user });
}
function wipe(t) { if (t.buf) { t.buf.fill(0); t.buf = null; } transfers.delete(t.id); }
const clean = (s, n) => String(s || '').replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, n);
const view = t => ({ id: t.id, name: t.name, size: t.size, createdAt: t.createdAt, expiresAt: t.expiresAt, burn: t.burn, downloads: t.downloads,
  reqs: t.reqs.map(r => ({ id: r.id, who: r.who, at: r.at, state: r.state, decidedAt: r.decidedAt, usedAt: r.usedAt })) });
function tokeninfo(cred) {
  return new Promise(ok => https.get('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(cred), r => {
    let d = ''; r.on('data', c => d += c); r.on('end', () => { try { ok(JSON.parse(d)); } catch { ok(null); } });
  }).on('error', () => ok(null)));
}

async function handle(req, res) {
  const u = new URL(req.url, 'http://x'), p = u.pathname, m = req.method;
  if (m !== 'GET' && req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return fail(res, 403, 'Cross-origin request blocked.');
  if (m === 'GET' && (p === '/' || p === '/index.html')) return send(res, 200, INDEX, 'text/html; charset=utf-8');
  if (!p.startsWith('/api/')) return fail(res, 404, 'Not found');
  const a = p.slice(5).split('/'), s = auth(req);

  if (a[0] === 'config' && m === 'GET') return json(res, 200, { googleClientId: GID, devLogin: DEV });
  if (a[0] === 'me' && !a[1] && m === 'GET') return s ? json(res, 200, { user: s.user }) : fail(res, 401, 'Not signed in');
  if (a[0] === 'auth') {
    if (a[1] === 'dev' && m === 'POST') { if (!DEV) return fail(res, 404, 'Not found'); const n = clean((await small(req)).name, 60); if (!n) return fail(res, 400, 'Enter a name.'); return login(res, { name: n, email: null, provider: 'local' }); }
    if (a[1] === 'google' && m === 'POST') {
      if (!GID) return fail(res, 501, 'Google sign-in is not configured. Set GOOGLE_CLIENT_ID.');
      const i = await tokeninfo((await small(req)).credential);
      if (!i || i.aud !== GID || i.email_verified !== 'true' || +i.exp * 1000 < Date.now()) return fail(res, 401, 'Google sign-in could not be verified.');
      return login(res, { name: clean(i.name || i.email, 60), email: i.email, provider: 'google' });
    }
    if (a[1] === 'logout' && m === 'POST') { sessions.delete(cookie(req)); res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/'); return json(res, 200, { ok: true }); }
  }
  if (a[0] === 'me' && a[1] === 'data' && m === 'DELETE') { if (!s) return fail(res, 401, 'Not signed in'); for (const t of [...transfers.values()]) if (t.owner === s.sid) wipe(t); return json(res, 200, { ok: true }); }
  if (a[0] === 'status' && m === 'GET') { if (!s) return fail(res, 401, 'Not signed in'); return json(res, 200, { storage: 'memory only', maxMB: MAX / 1048576, maxTtlMin: TTL_MAX, held: [...transfers.values()].filter(t => t.owner === s.sid).length, host: HOST }); }

  if (a[0] === 'transfers') {                                    // owner API
    if (!s) return fail(res, 401, 'Not signed in');
    if (!a[1] && m === 'GET') return json(res, 200, [...transfers.values()].filter(t => t.owner === s.sid).map(view).sort((x, y) => y.createdAt - x.createdAt));
    if (!a[1] && m === 'POST') {
      const len = +req.headers['content-length'] || 0;
      if (!len || len > MAX) return fail(res, 413, `File must be under ${MAX / 1048576} MB.`);
      let buf; try { buf = await body(req, MAX); } catch (e) { return fail(res, e.status || 400, 'Upload failed.'); }
      const ttl = Math.min(TTL_MAX, Math.max(5, +req.headers['x-ttl-min'] || 30)), now = Date.now();
      let name = 'file.pdf'; try { name = clean(decodeURIComponent(req.headers['x-file-name'] || ''), 120) || name; } catch {}
      const t = { id: rid(16), owner: s.sid, name, size: buf.length, buf, createdAt: now, expiresAt: now + ttl * 60e3, burn: req.headers['x-burn'] === '1', downloads: 0, reqs: [] };
      transfers.set(t.id, t); return json(res, 200, view(t));
    }
    const t = transfers.get(a[1]); if (!t || t.owner !== s.sid) return fail(res, 404, 'File not found or expired.');
    if (!a[2] && m === 'DELETE') { wipe(t); return json(res, 200, { ok: true }); }
    if (a[2] === 'requests' && a[3] && a[4] && m === 'POST') {
      const r = t.reqs.find(x => x.id === a[3]); if (!r) return fail(res, 404, 'Request not found.');
      const ok = { approve: ['pending', 'approved'], deny: ['pending', 'denied'], revoke: ['approved', 'revoked'] }[a[4]];
      if (!ok || r.state !== ok[0]) return fail(res, 409, 'That request can no longer be changed.');
      r.state = ok[1]; r.decidedAt = Date.now(); return json(res, 200, view(t));
    }
  }

  if (a[0] === 't' && a[1]) {                                    // receiver API (no login)
    const t = transfers.get(a[1]); if (!t) return fail(res, 404, 'This ticket is not valid or has expired.');
    if (!a[2] && m === 'GET') return json(res, 200, { name: t.name, size: t.size });
    if (a[2] === 'request' && !a[3] && m === 'POST') {
      const who = clean((await small(req)).who, 80); if (!who) return fail(res, 400, 'Enter your name.');
      if (t.reqs.filter(r => r.state === 'pending').length >= 20) return fail(res, 429, 'Too many pending requests.');
      const r = { id: rid(8), token: rid(16), who, at: Date.now(), state: 'pending' }; t.reqs.push(r); return json(res, 200, { token: r.token });
    }
    const r = t.reqs.find(x => x.token === a[3]); if (!r) return fail(res, 404, 'Request not found.');
    if (a[2] === 'request' && m === 'GET') return json(res, 200, { state: r.state });
    if (a[2] === 'file' && m === 'GET') {
      if (r.state !== 'approved') return fail(res, 409, r.state === 'used' ? 'This approval was already used.' : 'Access is not approved.');
      r.state = 'used'; r.usedAt = Date.now(); t.downloads++;
      const out = Buffer.from(t.buf); if (t.burn) wipe(t);
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': out.length, 'Cache-Control': 'no-store' });
      return res.end(out, () => out.fill(0));
    }
  }
  return fail(res, 404, 'Not found');
}
http.createServer((q, r) => handle(q, r).catch(() => { if (!r.headersSent) fail(r, 500, 'Server error'); })).listen(PORT, HOST, () => {
  console.log(`CrypPDF gateway on http://${HOST}:${PORT}  | storage: RAM only | google: ${GID ? 'configured' : 'not configured'} | dev login: ${DEV ? 'ON' : 'off'}`);
});
setInterval(() => { const n = Date.now(); for (const t of [...transfers.values()]) if (t.expiresAt < n) wipe(t); for (const [k, s] of sessions) if (s.exp < n) sessions.delete(k); }, 30000).unref();
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { transfers.forEach(wipe); process.exit(0); });
