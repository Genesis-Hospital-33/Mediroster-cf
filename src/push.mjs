// Web Push (phone notifications) for Cloudflare Workers: VAPID signing (RFC 8292) + message encryption (RFC 8291, aes128gcm).
const enc = new TextEncoder();
export const b64uToBytes = (t) => { t = String(t).replace(/-/g, '+').replace(/_/g, '/'); while (t.length % 4) t += '='; return Uint8Array.from(atob(t), (c) => c.charCodeAt(0)); };
export const bytesToB64u = (u) => btoa(String.fromCharCode(...u)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
export async function encryptPush(uaPubB64, authB64, data, opts = {}) {
  const ua = b64uToBytes(uaPubB64), auth = b64uToBytes(authB64);
  const pair = opts.asPair || await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, pair.privateKey, 256));
  const salt = opts.salt || crypto.getRandomValues(new Uint8Array(16));
  const ikm = await hkdf(auth, secret, cat(enc.encode('WebPush: info\0'), ua, asPub), 32);
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16), nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, cat(data, Uint8Array.of(2))));
  return cat(salt, Uint8Array.of(0, 0, 0x10, 0), Uint8Array.of(65), asPub, ct);
}
let VAPID = null; const JWTS = new Map();
export async function vapidKeys(kv) {
  if (VAPID) return VAPID;
  let v = await kv.get('vapid');
  if (!v) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    await kv.set('vapid', { pub: bytesToB64u(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))), jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) });
    v = await kv.get('vapid');
  }
  VAPID = { pub: v.pub, key: await crypto.subtle.importKey('jwk', v.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']) };
  return VAPID;
}
export const resetPushCache = () => { VAPID = null; JWTS.clear(); };
async function vapidHeader(kv, endpoint, subject) {
  const k = await vapidKeys(kv), aud = new URL(endpoint).origin, hit = JWTS.get(aud + subject);
  if (hit && hit.exp > Date.now() + 3600e3) return hit.h;
  const exp = Date.now() + 12 * 3600e3, head = bytesToB64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' }))), claims = bytesToB64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(exp / 1000), sub: subject })));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.key, enc.encode(head + '.' + claims)));
  const h = `vapid t=${head}.${claims}.${bytesToB64u(sig)}, k=${k.pub}`; JWTS.set(aud + subject, { h, exp }); return h;
}
export async function sendOne(kv, sub, obj, subject, opts = {}) {
  const body = await encryptPush(sub.p256dh, sub.auth, enc.encode(JSON.stringify(obj)));
  const r = await fetch(sub.endpoint, { method: 'POST', body, headers: { 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: String(opts.ttl || 3600), Urgency: opts.urgency || 'normal', Authorization: await vapidHeader(kv, sub.endpoint, subject) } });
  return r.status;
}
// Send to every device registered by the given people. Dead subscriptions (expired, uninstalled) are removed automatically.
export async function pushUsers(kv, env, uids, obj, opts = {}) {
  const subject = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(env.GMAIL_USER || '') ? 'mailto:' + env.GMAIL_USER : (opts.site || 'https://example.com');
  await Promise.all([...new Set(uids)].map(async (uid) => {
    for (const key of await kv.list('push/' + uid + '/')) {
      const sub = await kv.get(key); if (!sub) continue;
      try { const st = await sendOne(kv, sub, obj, subject, opts); if ([400, 401, 403, 404, 410].includes(st)) await kv.del(key); } catch (e) { /* network trouble: keep the subscription */ }
    }
  }));
}
