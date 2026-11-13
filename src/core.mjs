// MediRoster server logic: accounts, permissions, roster, attendance, email.
// Storage layout (Netlify Blobs), built so many people can use it at once without overwriting each other:
//   cfg                      departments, shift templates, hospital zone      (Master only writes)
//   staff                    list of all staff (no passcodes)                 (Master only writes)
//   acct/<id>                passcode hash, temp passcode, flags, lockout     (one per person)
//   pend/<id>                one marker per pending passcode-reset request
//   onb/<id>                 one marker per queued welcome email (bulk import)
//   roster/<monday>/<0-f>    shifts for one week, split into 16 parts
//   att/<date>/<id>/<hhmm>/<metres>   one record per clock-in (details live in the key name)
//   attp/<id>/<date>/<hhmm>/<metres>  same, for each person's own history
//   sent/<date>              which reminder emails were already sent
//   logs, maillog            activity logs (newest first, capped)
import { smtpSend } from './smtp.mjs';
import { pushUsers, vapidKeys } from './push.mjs';

export const MASTER_ID = 'EMP-2026-M01';
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new HttpError(status, message); };

/* ---------- passwords and session tokens (Web Crypto, works on Cloudflare Workers) ---------- */
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(String(h).match(/../g) || [], (x) => parseInt(x, 16));
const rhex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const rint = (min, max) => { const range = max - min, limit = Math.floor(4294967296 / range) * range; let x; do { x = crypto.getRandomValues(new Uint32Array(1))[0]; } while (x >= limit); return min + (x % range); };
const ctEq = (a, b) => { a = String(a); b = String(b); if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const b64u = (str) => btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (t) => { t = String(t).replace(/-/g, '+').replace(/_/g, '/'); while (t.length % 4) t += '='; return atob(t); };
const hmacHex = async (keyStr, data) => hex(await crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', enc.encode(keyStr), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), enc.encode(data)));
const sha = async (v) => hex(await crypto.subtle.digest('SHA-256', enc.encode(String(v))));
const safeEq = async (a, b) => ctEq(await sha(a), await sha(b));
let PEPPER = '';
const PBKDF2_ITER = 20000; // moderate on purpose: keeps a login well inside Cloudflare's free CPU limit; a server-side pepper adds protection
async function kdf(p, saltHex) {
  const k = await crypto.subtle.importKey('raw', enc.encode(String(p)), 'PBKDF2', false, ['deriveBits']);
  return hmacHex(PEPPER, hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: PBKDF2_ITER }, k, 256)));
}
const hashPass = async (p) => { const salt = rhex(16); return salt + ':' + (await kdf(p, salt)); };
const verifyPass = async (p, h) => { try { const [salt, x] = String(h).split(':'); return ctEq(await kdf(p, salt), x); } catch (e) { return false; } };
const strong = (x) => typeof x === 'string' && x.length >= 8 && x.length <= 64 && /[A-Za-z]/.test(x) && /\d/.test(x);
function tempPass() {
  const L = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz', D = '23456789', A = L + D;
  const c = [L[rint(0, L.length)], D[rint(0, D.length)]];
  while (c.length < 8) c.push(A[rint(0, A.length)]);
  for (let i = 7; i > 0; i--) { const j = rint(0, i + 1); [c[i], c[j]] = [c[j], c[i]]; }
  return c.join('');
}
const SESSION_DAYS = 30; // stay signed in for 30 days; the session is renewed automatically while the app is used
const goodUrl = (u) => { const t = String(u || '').trim().replace(/\/+$/, ''); return /^https?:\/\/[^\s]+$/.test(t) ? t : ''; };
const zoneOf = (env) => { const z = String(env.TIMEZONE || '').trim(); try { new Intl.DateTimeFormat('en-GB', { timeZone: z }); return z; } catch (e) { return 'Asia/Kolkata'; } };
const sessKey = (env) => 'mediroster|' + (env.SESSION_SECRET || '') + '|' + (env.MASTER_PASSCODE || '');
const sign = async (env, uid) => { const p = uid + '|' + (Date.now() + SESSION_DAYS * 864e5); return b64u(p) + '.' + (await hmacHex(sessKey(env), p)); };
async function unsign(env, tk) {
  try {
    const [b, mac] = String(tk).split('.'), p = unb64u(b);
    if (!ctEq(mac, await hmacHex(sessKey(env), p))) return null;
    const [uid, exp] = p.split('|'); return Number(exp) > Date.now() ? { uid, exp: Number(exp) } : null;
  } catch (e) { return null; }
}

/* ---------- email: Gmail (no domain needed) or Resend (needs a verified domain) ---------- */
export async function sendMail(env, to, subject, text) {
  if (env.GMAIL_USER && env.GMAIL_APP_PASSWORD) {
    try {
      await smtpSend({ host: 'smtp.gmail.com', port: 465, user: env.GMAIL_USER, pass: String(env.GMAIL_APP_PASSWORD).replace(/\s+/g, ''), fromName: env.EMAIL_FROM_NAME || 'MediRoster', to, subject, text });
      return { ok: true, status: 200 };
    } catch (e) { return { ok: false, status: String(e.code || e.message).slice(0, 80) }; }
  }
  if (!env.RESEND_API_KEY) return { ok: false, status: 'no email service configured' };
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: env.EMAIL_FROM || 'MediRoster <onboarding@resend.dev>', to: [to], subject, text }),
    });
    return { ok: r.ok, status: r.status };
  } catch (e) { return { ok: false, status: e.message }; }
}
const onboardText = (site, id, pw) => `Welcome to MediRoster. Your official hospital staff account has been provisioned. Please click this link to set up your profile: ${site}. Use your temporary credentials to log in: Staff ID: ${id}, Temporary Passcode: ${pw}.\n\nTo copy your credentials, press and hold a line below, then choose Copy:\n\nStaff ID:\n${id}\n\nTemporary Passcode:\n${pw}` + (site ? `\n\nQuick sign-in (fills in both for you): ${site}/#u=${id}&p=${pw}` : '');
const SOON_TEXT = 'Reminder: Your shift is about to start in about 30 minutes. Please get ready and make sure you are logged into your dashboard so you can clock in via the designated hospital geofence.';
const START_TEXT = 'Your shift has started. Please ensure you are logged into your dashboard and have clocked in via the designated hospital geofence.';

/* ---------- small helpers ---------- */
const asList = (v) => (Array.isArray(v) ? v : v ? [v] : []);
const clean = (x, max) => String(x == null ? '' : x).trim().slice(0, max);
const ymd = (ms) => new Date(ms).toISOString().slice(0, 10);
const validDate = (d) => /^\d{4}-\d{2}-\d{2}$/.test(d) && !isNaN(Date.parse(d + 'T00:00:00Z'));
const mondayOf = (d) => { const t = Date.parse(d + 'T00:00:00Z'); return ymd(t - ((new Date(t).getUTCDay() + 6) % 7) * 864e5); };
const shardOf = (id) => { let h = 0; for (const c of String(id)) h = (h * 31 + c.charCodeAt(0)) >>> 0; return (h % 16).toString(16); };
const SHARDS = '0123456789abcdef'.split('');
function wall(date, tz) {
  const f = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  const o = {}; f.formatToParts(date).forEach((p) => { o[p.type] = p.value; });
  return { y: +o.year, m: +o.month, d: +o.day, h: +o.hour, mi: +o.minute };
}
const todayIn = (tz, at = new Date()) => { const w = wall(at, tz); return ymd(Date.UTC(w.y, w.m - 1, w.d)); };
const stamp = (tz, at = new Date()) => at.toLocaleString('en-GB', { timeZone: tz });
function dist(a, b, c, d) {
  const R = 6371e3, r = (x) => (x * Math.PI) / 180, p = r(c - a), q = r(d - b);
  const h = Math.sin(p / 2) ** 2 + Math.cos(r(a)) * Math.cos(r(c)) * Math.sin(q / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}
const tsOfKey = (k) => Number(String(k).split('/').pop().split('-')[0]);
const dmRoom = (a, b) => 'dm_' + [a, b].sort().join('_');
const chatKey = (room, ts) => `chat/${room}/${ymd(ts)}/${String(ts).padStart(13, '0')}`;
// Messages of one room in ONE database query. since=0 gives the newest `limit`; otherwise everything from `since` on.
async function chatMsgs(kv, room, since, limit) {
  const base = `chat/${room}/`, end = base + '\uffff';
  if (kv.range) {
    const rows = since ? await kv.range(chatKey(room, since), end, limit, false) : (await kv.range(base, end, limit, true)).reverse();
    return rows.map((r) => ({ ...r.value, k: r.key }));
  }
  let out = []; const now = Date.now();
  for (let d = 0; d < (since ? 2 : 14) && (since || out.length < limit); d++) {
    const ks = (await kv.list(`chat/${room}/${ymd(now - d * 864e5)}/`)).sort();
    out = [...(since ? ks.filter((k) => tsOfKey(k) >= since) : ks), ...out];
  }
  return (await Promise.all(out.slice(-limit).map(async (k) => { const m = await kv.get(k); return m && { ...m, k }; }))).filter(Boolean);
}
async function latestAll(kv) {
  if (kv.range) { const r = await kv.range('chat/all/', 'chat/all/\uffff', 1, true); return r.length ? tsOfKey(r[0].key) : 0; }
  for (let d = 0; d < 2; d++) { const ks = (await kv.list(`chat/all/${ymd(Date.now() - d * 864e5)}/`)).sort(); if (ks.length) return tsOfKey(ks[ks.length - 1]); }
  return 0;
}
const MEDIA_CHUNK = 460800, MEDIA_MAX_CHUNKS = 19, MEDIA_KEEP_DAYS = 30;
const MEDIA_OK = { image: ['image/jpeg'], video: ['video/mp4', 'video/webm', 'video/quicktime'] };
const b64ToBytes = (t) => { const bin = atob(t), u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };
const roomAllows = (room, uid) => room === 'all' || (room.startsWith('dm_') && room.split('_').slice(1).includes(uid));
/* Photos and videos in chat: stored in small pieces; served by the /m/<id> address with the person's session token. */
export async function serveMedia({ kv, env }, id, token, rangeHeader) {
  const deny = (st, msg) => new Response(msg, { status: st, headers: { 'Cache-Control': 'no-store' } });
  if (!env.MASTER_PASSCODE) return deny(500, 'Server not set up');
  const sess = token ? await unsign(env, token) : null; if (!sess) return deny(401, 'Please sign in again');
  const [staff, meta] = await Promise.all([kv.get('staff'), kv.get('media/' + id + '/m')]);
  const me = (staff || []).find((s) => s.id === sess.uid); if (!me) return deny(401, 'Please sign in again');
  if (me.role !== 'master') { const a = await kv.get('acct/' + me.id); if (!a || a.reset || a.setup) return deny(401, 'Please sign in again'); }
  if (!meta || !meta.done) return deny(404, 'This photo or video is no longer available');
  if (!roomAllows(meta.room, me.id)) return deny(403, 'Not allowed');
  const size = meta.size, ch = MEDIA_CHUNK; let start = 0, end = size - 1, partial = false;
  const m = /^bytes=(\d*)-(\d*)$/.exec(String(rangeHeader || '').trim());
  if (m && (m[1] || m[2])) {
    partial = true;
    if (!m[1]) { start = Math.max(0, size - Number(m[2])); } else { start = Number(m[1]); if (m[2]) end = Math.min(end, Number(m[2])); }
    end = Math.min(end, start + ch * 2 - 1, size - 1);
    if (start >= size || start > end) return new Response('', { status: 416, headers: { 'Content-Range': 'bytes */' + size } });
  } else if (meta.n > 3) { partial = true; end = Math.min(size - 1, ch * 2 - 1); } // big video asked without a range: send the first part
  const first = Math.floor(start / ch), last = Math.floor(end / ch), parts = [];
  for (let i = first; i <= last; i++) {
    const c = await kv.get('media/' + id + '/c/' + String(i).padStart(2, '0')); if (typeof c !== 'string') return deny(404, 'This photo or video is no longer available');
    const bytes = b64ToBytes(c), a = i === first ? start - i * ch : 0, b = i === last ? end - i * ch + 1 : bytes.length; parts.push(bytes.subarray(a, b));
  }
  const body = new Uint8Array(end - start + 1); let o = 0; for (const x of parts) { body.set(x, o); o += x.length; }
  const h = { 'Content-Type': meta.mime, 'Content-Length': String(body.length), 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, max-age=604800', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox" };
  if (partial) { h['Content-Range'] = `bytes ${start}-${end}/${size}`; return new Response(body, { status: 206, headers: h }); }
  return new Response(body, { status: 200, headers: h });
}
const readWeek = async (kv, mon) => Object.assign({}, ...(await Promise.all(SHARDS.map((h) => kv.get('roster/' + mon + '/' + h)))).filter(Boolean));
const defaultCfg = () => ({
  depts: ['Management', 'Emergency', 'ICU', 'General Ward', 'Pharmacy'],
  tpl: [
    { id: 't1', name: 'Morning', start: '07:00', end: '15:00', color: '#0369a1' },
    { id: 't2', name: 'Evening', start: '15:00', end: '23:00', color: '#b45309' },
    { id: 't3', name: 'Night', start: '23:00', end: '07:00', color: '#4338ca' },
  ],
  zone: { name: 'City General Hospital', lat: 28.6139, lng: 77.2090, radius: 200 },
});
const masterRec = (old = {}) => ({ id: MASTER_ID, name: 'Sohail Ahmad', role: 'master', designation: old.designation == null ? 'Master Admin' : old.designation, dept: old.dept || 'Management', email: old.email || '' });
async function addLog(kv, name, who, msg, tz, cap = 300) {
  const l = (await kv.get(name)) || []; l.unshift({ ts: Date.now(), t: stamp(tz), who, msg }); await kv.set(name, l.slice(0, cap));
}
const r5 = (x) => Math.round(x * 1e5) / 1e5;
async function scanRows(kv, prefix, limit, desc) {
  if (kv.range) return kv.range(prefix, prefix + '\uffff', limit, desc);
  const ks = (await kv.list(prefix)).sort(); if (desc) ks.reverse();
  return Promise.all(ks.slice(0, limit).map(async (key) => ({ key, value: await kv.get(key) })));
}
const attRow = (key, v, names, type, own) => {
  const q = key.split('/'), id = own ? q[1] : q[2], date = own ? q[2] : q[1], hhmm = q[3];
  return { type, id, name: (names.get(id) || {}).name || id, date, time: hhmm.slice(0, 2) + ':' + hhmm.slice(2), d: Number(q[4]), ...(v && typeof v === 'object' && v.lat != null ? { lat: v.lat, lng: v.lng } : {}) };
};
// everything recorded on one day: clock-ins, clock-outs and blocked attempts (outside the zone)
async function listAtt(kv, prefixDate, names) {
  const date = prefixDate.split('/')[1];
  const parts = await Promise.all([['att', 'in'], ['ato', 'out'], ['atx', 'blocked']].map(async ([pre, type]) => (await scanRows(kv, pre + '/' + date + '/', 2000, false)).map((r) => attRow(r.key, r.value, names, type, false))));
  return parts.flat().sort((x, y) => y.time.localeCompare(x.time));
}
async function listOwnAtt(kv, id, names) {
  const parts = await Promise.all([['attp', 'in'], ['atop', 'out']].map(async ([pre, type]) => (await scanRows(kv, pre + '/' + id + '/', 30, true)).map((r) => attRow(r.key, r.value, names, type, true))));
  return parts.flat().sort((x, y) => (y.date + y.time).localeCompare(x.date + x.time));
}
// Is this person clocked in right now (clock-in with no later clock-out, within the last 16 hours)?
async function openSession(kv, id, w) {
  const t0 = Date.UTC(w.y, w.m - 1, w.d), dates = [ymd(t0), ymd(t0 - 864e5)], now = Date.UTC(w.y, w.m - 1, w.d, w.h, w.mi);
  const keyz = async (pre) => (await Promise.all(dates.map((d) => kv.list(`${pre}/${id}/${d}/`)))).flat().map((k) => { const q = k.split('/'); return q[2] + q[3]; }).sort();
  const [ins, outs] = await Promise.all([keyz('attp'), keyz('atop')]), li = ins[ins.length - 1], lo = outs[outs.length - 1];
  const ms = (x) => Date.UTC(+x.slice(0, 4), +x.slice(5, 7) - 1, +x.slice(8, 10), +x.slice(10, 12), +x.slice(12, 14));
  return { li, lo, open: !!li && (!lo || lo < li) && now - ms(li) < 16 * 3600e3 };
}
// The shift this person is on (or about to start within an hour) right now, if any.
async function onShiftNow(kv, cfg, me, w) {
  const nowWall = Date.UTC(w.y, w.m - 1, w.d, w.h, w.mi), tplBy = new Map(cfg.tpl.map((t) => [t.id, t]));
  for (const o of [-1, 0]) {
    const date = ymd(Date.UTC(w.y, w.m - 1, w.d) + o * 864e5), part = (await kv.get('roster/' + mondayOf(date) + '/' + shardOf(me.id))) || {};
    for (const tid of asList(part[me.id + '|' + date])) {
      const t = tplBy.get(tid); if (!t) continue;
      const [sh, sm] = t.start.split(':').map(Number), [eh, em] = t.end.split(':').map(Number), [y, m, d] = date.split('-').map(Number);
      const st = Date.UTC(y, m - 1, d, sh, sm); let en = Date.UTC(y, m - 1, d, eh, em); if (en <= st) en += 864e5;
      if (nowWall >= st - 60 * 6e4 && nowWall <= en) return t;
    }
  }
  return null;
}

/* ---------- bulk roster changes (used by Import Roster and the AI Assistant) ---------- */
const byStart = (order) => (a, b) => order.get(a).localeCompare(order.get(b));
async function resolveChanges(kv, cfg, byId, list) {
  const tplIds = new Set(cfg.tpl.map((t) => t.id)), order = new Map(cfg.tpl.map((t) => [t.id, t.start])), problems = [], uniq = new Map();
  for (const c of list) {
    const s = byId.get(String(c.sid || '')), dt = String(c.dt || ''), mode = ['set', 'add', 'remove'].includes(c.mode) ? c.mode : 'set';
    const tids = [...new Set((Array.isArray(c.tids) ? c.tids : []).map(String))];
    if (!s) { problems.push('Unknown staff member ' + clean(c.sid, 30)); continue; }
    if (!validDate(dt)) { problems.push('Invalid date for ' + s.name); continue; }
    if (tids.length > 8 || tids.some((t) => !tplIds.has(t))) { problems.push('Unknown shift for ' + s.name + ' on ' + dt); continue; }
    uniq.set(s.id + '|' + dt, { s, dt, mode, tids });
  }
  const valid = [...uniq.values()], maps = {};
  await Promise.all([...new Set(valid.map((v) => mondayOf(v.dt)))].map(async (w) => { maps[w] = await readWeek(kv, w); }));
  const rows = []; let noop = 0; const cmp = byStart(order);
  for (const v of valid) {
    if (asList(maps[mondayOf(v.dt)][v.s.id + '|' + v.dt]).includes('LEAVE')) { problems.push(v.s.name + ' is on approved leave on ' + v.dt + ' (skipped)'); continue; }
    const before = asList(maps[mondayOf(v.dt)][v.s.id + '|' + v.dt]).filter((t) => tplIds.has(t)).sort(cmp);
    const after = (v.mode === 'add' ? [...new Set([...before, ...v.tids])] : v.mode === 'remove' ? before.filter((t) => !v.tids.includes(t)) : v.tids).slice().sort(cmp);
    if (before.length === after.length && before.every((x, i) => x === after[i])) { noop++; continue; }
    rows.push({ sid: v.s.id, dt: v.dt, before, after });
  }
  return { rows, noop, problems };
}
async function applyRows(kv, rows) {
  const groups = new Map();
  for (const r of rows) { const k = 'roster/' + mondayOf(r.dt) + '/' + shardOf(r.sid); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); }
  await Promise.all([...groups].map(async ([k, rs]) => {
    const part = (await kv.get(k)) || {};
    for (const r of rs) { const key = r.sid + '|' + r.dt; if (r.after.length) part[key] = r.after; else delete part[key]; }
    await kv.set(k, part);
  }));
}
function previewOf(rows, noop, problems, cfg, byId) {
  const nm = new Map(cfg.tpl.map((t) => [t.id, t.name])), ids = new Set(rows.map((r) => r.sid)), dates = rows.map((r) => r.dt).sort();
  return {
    total: rows.length, noop, people: ids.size, from: dates[0] || '', to: dates[dates.length - 1] || '', problems: problems.slice(0, 40), moreProblems: Math.max(0, problems.length - 40),
    sample: rows.slice(0, 300).map((r) => ({ id: r.sid, name: (byId.get(r.sid) || {}).name || r.sid, dt: r.dt, before: r.before.map((t) => nm.get(t)), after: r.after.map((t) => nm.get(t)) })),
  };
}

/* ---------- AI assistant plumbing (the AI only PROPOSES; nothing is saved without Confirm) ---------- */
async function callAI(env, system, user, totalMs = 8500) {
  const key = env.AI_API_KEY || env.GEMINI_API_KEY;
  if (!key) fail(400, 'The AI assistant is not switched on yet. The Master Admin needs to add AI_API_KEY in Netlify (see the guide, Part F).');
  const provider = String(env.AI_PROVIDER || 'gemini').toLowerCase();
  // A fast "lite" model first (quick and rarely overloaded), the regular one as backup. AI_MODEL overrides both.
  const models = env.AI_MODEL ? [env.AI_MODEL] : provider === 'gemini' ? ['gemini-flash-lite-latest', 'gemini-flash-latest'] : [provider === 'anthropic' ? 'claude-haiku-5-5' : 'gpt-4o-mini'];
  const t0 = Date.now(); let last = 'no answer';
  const attempt = async (model, ms) => {
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), ms);
    try {
      let r;
      if (provider === 'gemini') {
        r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, { method: 'POST', signal: ctl.signal, headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
          body: JSON.stringify({ systemInstruction: { parts: [{ text: system }] }, contents: [{ role: 'user', parts: [{ text: user }] }], generationConfig: { temperature: 0, responseMimeType: 'application/json' } }) });
      } else if (provider === 'anthropic') {
        r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', signal: ctl.signal, headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
          body: JSON.stringify({ model, max_tokens: 3000, temperature: 0, system, messages: [{ role: 'user', content: user }] }) });
      } else {
        r = await fetch((env.AI_BASE_URL || 'https://api.openai.com/v1').replace(/\/$/, '') + '/chat/completions', { method: 'POST', signal: ctl.signal, headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model, temperature: 0, response_format: { type: 'json_object' }, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] }) });
      }
      const j = await r.json().catch(() => ({}));
      if (!r.ok) {
        if (r.status === 401 || r.status === 403) fail(502, `The AI service refused the key (${r.status}). Check AI_API_KEY in Netlify. ${clean((j.error && (j.error.message || j.error)) || '', 120)}`);
        if ([400, 404, 408, 429, 500, 502, 503, 504].includes(r.status)) return { retry: true, why: String(r.status) };
        fail(502, `The AI service refused the request (${r.status}). ${clean((j.error && (j.error.message || j.error)) || '', 140)}`);
      }
      const text = provider === 'gemini' ? ((j.candidates || [])[0]?.content?.parts || []).map((x) => x.text || '').join('')
        : provider === 'anthropic' ? (j.content || []).map((x) => x.text || '').join('') : j.choices?.[0]?.message?.content || '';
      const t = String(text).replace(/^```(?:json)?/i, '').replace(/```\s*$/, '').trim();
      try { return { ok: true, data: JSON.parse(t) }; } catch (e) { const m = t.match(/\{[\s\S]*\}/); if (m) { try { return { ok: true, data: JSON.parse(m[0]) }; } catch (e2) { /* next */ } } return { retry: true, why: 'unexpected answer' }; }
    } catch (e) {
      if (e instanceof HttpError) throw e;
      return { retry: true, why: e && e.name === 'AbortError' ? 'too slow' : 'no connection' };
    } finally { clearTimeout(timer); }
  };
  for (let i = 0; i < models.length; i++) {
    const left = totalMs - (Date.now() - t0); if (left < 1200) break;
    const r = await attempt(models[i], i < models.length - 1 ? Math.min(left, 5500) : left);
    if (r.ok) return r.data; last = r.why;
  }
  fail(503, `The AI service is busy or slow right now (${last}). Please try again in a minute.`);
}
const PLAN_SYSTEM = `You convert a hospital roster manager's request into JSON. Output ONLY one JSON object: {"reply": string, "ops": [ {"ids": [staff ids], "dept": string|null, "all": boolean, "from": "YYYY-MM-DD", "to": "YYYY-MM-DD", "weekdays": ["mon","tue",...]|null, "shifts": [shift names], "mode": "set"|"add"|"remove"|"clear"} ]}.
Rules:
- "reply" is one or two plain sentences saying exactly what you understood, including the exact dates (for example "Morning shift for Anita Rao from Tue 27 Oct to Mon 2 Nov"), or a short question if something is unclear.
- Use ONLY staff ids listed under CANDIDATES. If a name is not clearly one candidate, return "ops": [] and ask which person is meant. Never invent ids or shift names.
- Use ONLY shift names listed under SHIFTS, written exactly as listed.
- mode "set" = replace that day's shifts with exactly these shifts; "add" = keep existing shifts and add these (use for "also", "in addition", "add"); "remove" = take these shifts away; "clear" = remove every shift (day off, "clear", "cancel all"). When the user simply says "assign", use "set".
- Use dept (exact name from DEPARTMENTS) for "everyone in ICU"; use all=true only when the user clearly says everyone/all staff; otherwise use ids.
- Dates: use the CALENDAR to resolve words. "next N days" starts TOMORROW and covers N days. "this week" = Monday to Sunday of the current week; "next week" = Monday to Sunday of the following week. "today" and "tomorrow" are single days. A weekday name means the next such date from today. Set "from" and "to" (inclusive); use "weekdays" only when the user restricts days (for example "weekdays only" = mon..fri). Never cover more than 62 days.
- If the request is not about the roster, return "ops": [] and a short helpful reply.`;
const PARSE_SYSTEM = `You extract roster entries from messy text copied from a spreadsheet or PDF. Output ONLY one JSON object: {"rows": [[person, date, shifts], ...]} where person is the staff name or id exactly as written, date is YYYY-MM-DD, and shifts is the shift names joined by "+" (for example "Morning+Evening"), or "OFF" for a day off. Use only shift names from SHIFTS (map obvious abbreviations such as M, E, N to them). Dates may be written as columns headers, weekdays (use WEEKSTART to turn Monday..Sunday into dates), or day/month/year (day first). Skip empty cells and anything that is not a roster entry. Never invent entries.`;
const DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
const normName = (x) => String(x || '').toLowerCase().replace(/\b(dr|mr|mrs|ms|prof)\b\.?/g, ' ').replace(/[^a-z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim();
function expandOps(ops, cfg, staff) {
  const changes = [], problems = [], tplBy = new Map();
  cfg.tpl.forEach((t) => { tplBy.set(t.name.toLowerCase(), t.id); tplBy.set(t.start + '-' + t.end, t.id); });
  const byId = new Map(staff.map((s) => [s.id, s]));
  for (const op of ops) {
    const from = clean(op.from, 10), to = clean(op.to || op.from, 10), mode = ['set', 'add', 'remove', 'clear'].includes(op.mode) ? op.mode : 'set';
    if (!validDate(from) || !validDate(to) || to < from) { problems.push('The dates in that request were not clear.'); continue; }
    const span = (Date.parse(to) - Date.parse(from)) / 864e5 + 1;
    if (span > 62) { problems.push('That covers more than 62 days. Please ask for a shorter period.'); continue; }
    const tids = []; let bad = false;
    for (const nme of Array.isArray(op.shifts) ? op.shifts : []) { const id = tplBy.get(String(nme).trim().toLowerCase()); if (id) tids.push(id); else { problems.push('Unknown shift "' + clean(nme, 30) + '".'); bad = true; } }
    if (bad || (mode !== 'clear' && !tids.length)) { if (!bad) problems.push('No shift was named.'); continue; }
    let who = [];
    if (op.all === true) who = staff.filter((s) => s.role !== 'master');
    else if (op.dept) { if (!cfg.depts.includes(op.dept)) { problems.push('Unknown department "' + clean(op.dept, 30) + '".'); continue; } who = staff.filter((s) => s.dept === op.dept && s.role !== 'master'); }
    else who = (Array.isArray(op.ids) ? op.ids : []).map((i) => byId.get(String(i))).filter(Boolean);
    if (!who.length) { problems.push('No matching staff member was found.'); continue; }
    const wd = Array.isArray(op.weekdays) && op.weekdays.length ? new Set(op.weekdays.map((d) => String(d).slice(0, 3).toLowerCase())) : null;
    for (let i = 0; i < span; i++) {
      const dt = ymd(Date.parse(from) + i * 864e5); if (wd && !wd.has(DAYS[new Date(dt + 'T00:00:00Z').getUTCDay()])) continue;
      for (const s of who) changes.push({ sid: s.id, dt, tids: mode === 'clear' ? [] : tids, mode: mode === 'clear' ? 'set' : mode });
    }
  }
  if (changes.length > 3000) return { changes: [], problems: ['That would change more than 3000 days at once. Please narrow it down.'] };
  return { changes, problems };
}

/* ---------- the server entry point used by the app ---------- */
export async function handle({ kv, env, origin, send = sendMail, defer }, body) {
  const tz = zoneOf(env);
  try {
    const { action, payload: p = {}, token } = body || {};
    if (!env.MASTER_PASSCODE) fail(500, 'The server is missing the MASTER_PASSCODE setting.');
    PEPPER = (env.SESSION_SECRET || '') + '|' + env.MASTER_PASSCODE;
    let [staff, cfg] = await Promise.all([kv.get('staff'), kv.get('cfg')]);
    if (!cfg) { cfg = defaultCfg(); await kv.set('cfg', cfg); }
    if (origin && !goodUrl(env.SITE_URL) && cfg.site !== origin) { cfg.site = origin; await kv.set('cfg', cfg); }
    if (!staff) { staff = [masterRec()]; await kv.set('staff', staff); }
    const mi = staff.findIndex((s) => s.id === MASTER_ID);
    if (mi < 0) { staff.unshift(masterRec()); await kv.set('staff', staff); }
    else { const m = staff[mi], fixed = masterRec(m); if (JSON.stringify(m) !== JSON.stringify(fixed)) { staff[mi] = fixed; await kv.set('staff', staff); } }
    staff.forEach((s) => { if (s.id !== MASTER_ID && s.role === 'master') s.role = 'admin'; });
    const byId = new Map(staff.map((s) => [s.id, s]));
    const log = (who, msg) => addLog(kv, 'logs', who, msg, tz);
    const renew = {}; const ok = (b) => ({ status: 200, body: renew.tok ? { ...b, renew: renew.tok } : b });
    const site = () => goodUrl(env.SITE_URL) || goodUrl(origin);

    /* ---- what each person is allowed to see ---- */
    async function state(me, week, dept) {
      const mgr = me.role !== 'worker', today = todayIn(tz);
      const mon = validDate(week) ? mondayOf(week) : mondayOf(today);
      const d = (dept === 'ALL' || (mgr && !dept)) ? '' : mgr ? clean(dept, 60) : (cfg.depts.includes(dept) ? dept : me.dept);
      const ids = d ? new Set(staff.filter((s) => s.dept === d).map((s) => s.id)) : null;
      let roster = await readWeek(kv, mon);
      if (ids) Object.keys(roster).forEach((k) => { if (!ids.has(k.split('|')[0])) delete roster[k]; });
      Object.keys(roster).forEach((k) => { roster[k] = asList(roster[k]); });
      const cur = mondayOf(today);
      const own = await Promise.all([-7, 0, 7, 14].map((o) => kv.get('roster/' + ymd(Date.parse(cur + 'T00:00:00Z') + o * 864e5) + '/' + shardOf(me.id))));
      own.filter(Boolean).forEach((b) => Object.keys(b).forEach((k) => { if (k.startsWith(me.id + '|')) roster[k] = asList(b[k]); }));
      const list = mgr || !ids ? staff : staff.filter((s) => s.id === me.id || ids.has(s.id));
      const out = {
        me: me.id, today, week: mon, dept: d || '', depts: cfg.depts, tpl: cfg.tpl, zone: cfg.zone, roster,
        staff: list.map((s) => ({ id: s.id, name: s.name, role: s.role, designation: s.designation || '', dept: s.dept, ...(mgr ? { email: s.email || '' } : {}), ...(s.buzzer ? { buzzer: true } : {}) })),
      };
      if (mgr) {
        out.ai = !!(env.AI_API_KEY || env.GEMINI_API_KEY);
        out.leavePending = (await kv.list('lvpend/')).filter((k) => { const sid = k.split('/')[1], t = byId.get(sid); return t && t.id !== me.id && (me.role === 'master' || t.role === 'worker'); }).length;
        out.att = (await listAtt(kv, 'att/' + today + '/', byId)).slice(0, 500);
        out.pending = (await kv.list('pend/')).map((k) => k.slice(5)).filter((id) => byId.has(id)).map((id) => ({ id, name: byId.get(id).name }));
        await Promise.all(out.pending.map(async (x) => { const a = await kv.get('acct/' + x.id); x.resetAt = a && a.resetAt; }));
      } else out.att = await listOwnAtt(kv, me.id, byId);
      if (me.role === 'master') {
        const [lg, ml] = await Promise.all([kv.get('logs'), kv.get('maillog')]);
        out.logs = [...(lg || []), ...(ml || [])].sort((a, b) => b.ts - a.ts).slice(0, 300);
        out.mailLog = (ml || []).slice(0, 5);
      }
      return out;
    }

    const newAccount = async (rec, pw) => {
      await kv.set('acct/' + rec.id, { pass: await hashPass(pw), temp: pw, setup: true, reset: false });
    };
    const nextId = (role, taken) => {
      const pre = role === 'admin' ? 'A' : 'W', re = new RegExp('^EMP-2026-' + pre + '(\\d+)$'); let n = 0;
      staff.concat(taken || []).forEach((s) => { const x = re.exec(s.id); if (x) n = Math.max(n, +x[1]); });
      return 'EMP-2026-' + pre + String(n + 1).padStart(2, '0');
    };
    const checkStaffInput = (r) => {
      const name = clean(r.name, 80), email = clean(r.email, 200).toLowerCase(), role = r.role;
      if (!name) return 'Enter the full name.';
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Enter a valid email address.';
      if (!['admin', 'worker'].includes(role)) return 'Choose Admin or Worker.';
      return '';
    };

    /* ---- actions that work before signing in ---- */
    if (action === 'login') {
      const id = clean(p.id, 40).toUpperCase(), pw = String(p.pass || '').slice(0, 100), s = byId.get(id);
      if (!s) fail(401, 'Invalid Staff ID or passcode.');
      const a = (await kv.get('acct/' + id)) || (s.role === 'master' ? {} : null);
      if (!a) fail(401, 'Invalid Staff ID or passcode.');
      if ((a.until || 0) > Date.now()) fail(429, 'Too many failed attempts. Please try again in 15 minutes.');
      if (a.reset) fail(403, 'Your reset request is awaiting approval. You cannot log in until a System Admin or Master Admin approves it.');
      const good = s.role === 'master' ? await safeEq(pw, env.MASTER_PASSCODE) : !!a.pass && (await verifyPass(pw, a.pass));
      if (!good) { a.n = (a.n || 0) + 1; if (a.n >= 5) { a.until = Date.now() + 15 * 60e3; a.n = 0; } await kv.set('acct/' + id, a); fail(401, 'Invalid Staff ID or passcode.'); }
      if (a.n || a.until) { a.n = 0; a.until = 0; await kv.set('acct/' + id, a); }
      if (a.setup) return ok({ needsSetup: true, id: s.id, name: s.name });
      return ok({ token: await sign(env, s.id), state: await state(s, p.week, p.dept) });
    }
    if (action === 'setup') {
      const id = clean(p.id, 40).toUpperCase(), s = byId.get(id), a = s && (await kv.get('acct/' + id));
      if (a && (a.until || 0) > Date.now()) fail(429, 'Too many failed attempts. Please try again in 15 minutes.');
      if (!a || !a.setup || !a.pass || !(await verifyPass(String(p.temp || ''), a.pass))) {
        if (a) { a.n = (a.n || 0) + 1; if (a.n >= 5) { a.until = Date.now() + 15 * 60e3; a.n = 0; } await kv.set('acct/' + id, a); }
        fail(401, 'Your temporary passcode is not valid. Please sign in again.');
      }
      if (!strong(p.newPass)) fail(400, 'Use at least 8 characters including letters and numbers.');
      if (await verifyPass(p.newPass, a.pass)) fail(400, 'Choose a passcode different from the temporary one.');
      a.pass = await hashPass(p.newPass); delete a.temp; a.setup = false; a.n = 0; a.until = 0;
      await kv.set('acct/' + id, a); await log(s.name, 'Completed account setup (new passcode set)');
      return ok({ token: await sign(env, s.id), state: await state(s, p.week, p.dept) });
    }
    if (action === 'forgot') {
      const id = clean(p.id, 40).toUpperCase(), s = byId.get(id);
      if (s && s.role === 'master') return ok({ master: true });
      const a = s && (await kv.get('acct/' + id));
      if (a && !a.reset) { a.reset = true; a.resetAt = stamp(tz); await kv.set('acct/' + id, a); await kv.set('pend/' + id, { at: Date.now() }); await log(s.name, 'Passcode reset requested (' + s.id + ')'); }
      return ok({ ok: true });
    }

    /* ---- everything below needs a valid session ---- */
    const sess = token ? await unsign(env, token) : null, me = sess && byId.get(sess.uid);
    if (!me) fail(401, 'Your session expired. Please sign in again.');
    if (me.role !== 'master') { const a = await kv.get('acct/' + me.id); if (!a || a.reset || a.setup) fail(401, 'Your session expired. Please sign in again.'); }
    if (sess.exp - Date.now() < 15 * 864e5) renew.tok = await sign(env, me.id); // keeps people signed in while they use the app
    const isMaster = me.role === 'master', isMgr = me.role !== 'worker';
    const needBuzz = () => { if (!(isMaster || me.buzzer)) fail(403, 'You do not have buzzer access.'); };
    const needMaster = () => { if (!isMaster) fail(403, 'Only the Master Admin can do that.'); };
    const needMgr = () => { if (!isMgr) fail(403, 'You do not have permission to do that.'); };
    const find = (id) => byId.get(clean(id, 40)) || fail(404, 'Staff member not found.');
    const reply = async (extra = {}) => ok({ ...extra, state: await state(me, p.week, p.dept) });
    const aiGate = async (uid) => {
      const k = 'ai/' + uid + '/' + new Date().toISOString().slice(0, 13), n = ((await kv.get(k)) || 0) + 1;
      if (n > 150) fail(429, 'The AI has been used a lot this hour. Please wait a little.');
      await kv.set(k, n);
    };
    const saveStaff = () => kv.set('staff', staff);
    const saveCfg = () => kv.set('cfg', cfg);
    const notify = (uids, obj, opts) => { const job = pushUsers(kv, env, uids, obj, { site: site(), ...opts }).catch(() => {}); return defer ? defer(job) : job; };
    const putMsg = async (room, from, text, media) => { const ts = Date.now(); await kv.set(`${chatKey(room, ts)}-${rhex(3)}`, { ts, from: from.id, name: from.name, role: from.role, text, ...(media ? { media } : {}) }); return ts; };
    const dmMark = (from, to, ts) => Promise.all([kv.set('dmidx/' + from.id + '/' + to.id, { ts }), kv.set('dmidx/' + to.id + '/' + from.id, { ts }), kv.set('dmnew/' + to.id + '/' + from.id, { ts })]);
    const chatRoom = () => {
      if (p.room !== 'dm') return { room: 'all' };
      const o = find(p.peer);
      if (o.id === me.id) fail(403, 'Choose someone else.');
      return { room: dmRoom(me.id, o.id), other: o };
    };

    switch (action) {
      case 'state': return reply();
      case 'logout': return ok({ ok: true });
      case 'assign': {
        needMgr(); const s = find(p.sid), dt = clean(p.dt, 10);
        if (!validDate(dt)) fail(400, 'Invalid date.');
        const want = [...new Set((Array.isArray(p.tids) ? p.tids : p.tid ? [p.tid] : []).map(String))].slice(0, 8);
        const chosen = cfg.tpl.filter((t) => want.includes(t.id)).sort((x, y) => x.start.localeCompare(y.start));
        if (chosen.length !== want.length) fail(400, 'Unknown shift.');
        const k = 'roster/' + mondayOf(dt) + '/' + shardOf(s.id), part = (await kv.get(k)) || {};
        if (asList(part[s.id + '|' + dt]).includes('LEAVE') && !isMaster) fail(403, 'This day is approved leave. Only the Master Admin can change it.');
        if (chosen.length) part[s.id + '|' + dt] = chosen.map((t) => t.id); else delete part[s.id + '|' + dt];
        await kv.set(k, part);
        return ok({ ok: true });
      }
      case 'setDes': { needMaster(); const s = find(p.id); s.designation = clean(p.v, 60); await saveStaff(); await log(me.name, `Designation for ${s.name} set to "${s.designation || '(none)'}"`); return reply(); }
      case 'leaveApply': {
        if (isMaster) fail(400, 'The Master Admin marks days off directly instead of applying.');
        const from = clean(p.from, 10), to = clean(p.to || p.from, 10), today = todayIn(tz);
        if (!validDate(from) || !validDate(to) || to < from) fail(400, 'Choose valid dates.');
        if (from < today) fail(400, 'Leave must start today or later.');
        const span = (Date.parse(to) - Date.parse(from)) / 864e5 + 1;
        if (span > 31) fail(400, 'Please ask for 31 days or fewer at a time.');
        if ((await kv.list('lvpend/' + me.id + '/')).length >= 5) fail(400, 'You already have 5 requests waiting. Please wait for a decision.');
        const rid = 'r' + Date.now() + rint(100, 999), days = [...Array(span)].map((_, i) => ymd(Date.parse(from) + i * 864e5));
        await kv.set('lvreq/' + me.id + '/' + rid, { rid, sid: me.id, from, to, days, reason: clean(p.reason, 200), status: 'pending', createdAt: Date.now() });
        await kv.set('lvpend/' + me.id + '/' + rid, 1);
        await log(me.name, `Applied for leave ${from} to ${to}`);
        await notify(staff.filter((x) => x.id !== me.id && (x.role === 'master' || (x.role === 'admin' && me.role === 'worker'))).slice(0, 25).map((x) => x.id), { title: 'Leave request', body: me.name + ' applied for leave', url: '/', tag: 'leave-new' }, { ttl: 86400 });
        return ok({ ok: true });
      }
      case 'leaveList': {
        const mine = await Promise.all((await kv.list('lvreq/' + me.id + '/')).sort().reverse().slice(0, 20).map((k) => kv.get(k)));
        const out = { mine: mine.filter(Boolean), queue: [] };
        if (isMgr) {
          const keys = (await kv.list('lvpend/')).filter((k) => { const t = byId.get(k.split('/')[1]); return t && t.id !== me.id && (isMaster || t.role === 'worker'); }).slice(0, 100);
          const reqs = await Promise.all(keys.map((k) => kv.get('lvreq/' + k.slice(7))));
          out.queue = reqs.filter(Boolean).map((r) => ({ ...r, name: (byId.get(r.sid) || {}).name, dept: (byId.get(r.sid) || {}).dept, role: (byId.get(r.sid) || {}).role })).sort((a, b) => a.createdAt - b.createdAt);
        }
        return ok(out);
      }
      case 'leaveCancel': {
        const k = 'lvreq/' + me.id + '/' + clean(p.rid, 40), r = await kv.get(k);
        if (!r || r.status !== 'pending') fail(400, 'That request cannot be cancelled.');
        r.status = 'cancelled'; await kv.set(k, r); await kv.del('lvpend/' + me.id + '/' + r.rid); return ok({ ok: true });
      }
      case 'leaveDecide': {
        needMgr(); const t = find(p.sid), k = 'lvreq/' + t.id + '/' + clean(p.rid, 40), r = await kv.get(k);
        if (!r || r.status !== 'pending') fail(400, 'That request was already decided.');
        if (t.id === me.id || t.role === 'master') fail(403, 'You cannot decide your own leave.');
        if (!isMaster && t.role !== 'worker') fail(403, "Only the Master Admin can decide an Admin's leave.");
        const ok1 = new Set(r.days), days = [...new Set((Array.isArray(p.approve) ? p.approve : []).map(String))].filter((d) => ok1.has(d)).sort();
        if (days.length) await applyRows(kv, days.map((dt) => ({ sid: t.id, dt, after: ['LEAVE'] })));
        r.status = !days.length ? 'rejected' : days.length === r.days.length ? 'approved' : 'partial'; r.approvedDays = days; r.decidedBy = me.name; r.decidedAt = Date.now(); r.note = clean(p.note, 300);
        await kv.set(k, r); await kv.del('lvpend/' + t.id + '/' + r.rid);
        await log(me.name, `Leave for ${t.name} (${r.from} to ${r.to}): ${r.status}, ${days.length} of ${r.days.length} days approved`);
        const said = r.status === 'approved' ? `approved for all ${days.length} days` : r.status === 'partial' ? `partly approved (${days.length} of ${r.days.length} days: ${days.slice(0, 8).join(', ')}${days.length > 8 ? ' ...' : ''})` : 'not approved';
        const ts = await putMsg(dmRoom(me.id, t.id), me, clean(`Your leave request (${r.from} to ${r.to}) was ${said}.${r.note ? ' Message: ' + r.note : ''}`, 500)); await dmMark(me, t, ts);
        await notify([t.id], { title: 'Leave request ' + (r.status === 'approved' ? 'approved' : r.status === 'partial' ? 'partly approved' : 'not approved'), body: 'Open MediRoster for details', url: '/', tag: 'leave-' + r.rid }, { ttl: 86400, urgency: 'high' });
        return reply();
      }
      case 'markLeave': {
        needMaster(); const t = find(p.sid), from = clean(p.from, 10), to = clean(p.to || p.from, 10);
        if (!validDate(from) || !validDate(to) || to < from) fail(400, 'Choose valid dates.');
        const span = (Date.parse(to) - Date.parse(from)) / 864e5 + 1; if (span > 62) fail(400, 'Please use 62 days or fewer at a time.');
        const dates = [...Array(span)].map((_, i) => ymd(Date.parse(from) + i * 864e5));
        if (p.on === false) {
          const maps = {}; await Promise.all([...new Set(dates.map(mondayOf))].map(async (w) => { maps[w] = await readWeek(kv, w); }));
          await applyRows(kv, dates.filter((dt) => asList(maps[mondayOf(dt)][t.id + '|' + dt]).includes('LEAVE')).map((dt) => ({ sid: t.id, dt, after: [] })));
          await log(me.name, `Removed leave for ${t.name} (${from} to ${to})`);
        } else { await applyRows(kv, dates.map((dt) => ({ sid: t.id, dt, after: ['LEAVE'] }))); await log(me.name, `Marked ${t.name} on leave (${from} to ${to})`); }
        return reply();
      }
      case 'chatPing':
      case 'chatInit': {
        const [allLatest, nk, bz] = await Promise.all([latestAll(kv), kv.list('dmnew/' + me.id + '/'), kv.get('buzz/' + me.id)]);
        const unread = nk.map((k) => k.split('/')[2]).filter((i) => byId.has(i)).map((i) => ({ id: i, name: byId.get(i).name }));
        const out = { allLatest, unread, ...(bz && bz.ts > Date.now() - 300000 ? { buzz: bz } : {}) };
        if (action === 'chatInit') {
          out.peers = me.role === 'worker' ? staff.filter((x) => x.id !== me.id).slice(0, 300).map((x) => ({ id: x.id, name: x.name, role: x.role, designation: x.designation || '', dept: x.dept })) : [];
          out.dms = (await kv.list('dmidx/' + me.id + '/')).map((k) => k.split('/')[2]).filter((i) => byId.has(i)).slice(0, 100).map((i) => ({ id: i, name: byId.get(i).name, role: byId.get(i).role }));
        }
        return ok(out);
      }
      case 'chatFetch': {
        const { room, other } = chatRoom(), since = Math.max(0, Number(p.since) || 0);
        const [msgs] = await Promise.all([chatMsgs(kv, room, since, since ? 100 : 50), other ? kv.del('dmnew/' + me.id + '/' + other.id) : null]);
        return ok({ msgs });
      }
      case 'mediaChunk': {
        const { room } = chatRoom(), mid = String(p.mid || ''), i = Number(p.i), n = Number(p.n), data = p.data;
        if (!/^[a-z0-9]{12,24}$/.test(mid) || !Number.isInteger(i) || !Number.isInteger(n) || n < 1 || n > MEDIA_MAX_CHUNKS || i < 0 || i >= n) fail(400, 'That file could not be sent.');
        if (typeof data !== 'string' || !data.length || data.length > 640000) fail(400, 'That file could not be sent.');
        const mk = 'media/' + mid + '/m', old = await kv.get(mk);
        if (i === 0 && !old) {
          const kind = p.kind === 'video' ? 'video' : 'image', mime = String(p.mime || ''), size = Number(p.size);
          if (!MEDIA_OK[kind].includes(mime) || !(size > 0) || size > n * MEDIA_CHUNK || size <= (n - 1) * MEDIA_CHUNK) fail(400, 'That kind of file cannot be sent. Use a photo, or an MP4 / MOV video.');
          await kv.set(mk, { owner: me.id, room, kind, mime, size, n, ts: Date.now(), done: false });
        } else if (!old || old.owner !== me.id || old.room !== room || old.n !== n) fail(400, 'That file could not be sent.');
        await kv.set('media/' + mid + '/c/' + String(i).padStart(2, '0'), data);
        if (i === n - 1) { const m = old || (await kv.get(mk)); if (m) { m.done = true; await kv.set(mk, m); } }
        return ok({ ok: true });
      }
      case 'chatSend': {
        const text = clean(p.text, 500), { room, other } = chatRoom(); let media = null;
        if (p.media) {
          const mid = String(p.media.mid || ''), m = /^[a-z0-9]{12,24}$/.test(mid) ? await kv.get('media/' + mid + '/m') : null;
          if (!m || !m.done || m.owner !== me.id || m.room !== room) fail(400, 'That photo or video was not uploaded properly. Please try again.');
          media = { mid, kind: m.kind, mime: m.mime, size: m.size };
        }
        if (!text && !media) fail(400, 'Type a message first.');
        const lastK = 'chatlast/' + me.id, last = (await kv.get(lastK)) || 0;
        if (Date.now() - last < 500) fail(429, 'Slow down a little.');
        await kv.set(lastK, Date.now());
        const ts = await putMsg(room, me, text, media);
        if (other) {
          await dmMark(me, other, ts);
          const preview = text ? text.slice(0, 120) : media.kind === 'video' ? '🎥 Video' : '📷 Photo';
          await notify([other.id], { title: me.name, body: text && media ? (media.kind === 'video' ? '🎥 ' : '📷 ') + preview : preview, url: '/#dm=' + me.id, tag: 'dm-' + me.id }, { ttl: 86400, urgency: 'high' });
        }
        return ok({ ok: true, ts });
      }
      case 'chatDelete': {
        needMaster(); const k = String(p.k || ''); if (!k.startsWith('chat/all/')) fail(400, 'Only group messages can be deleted.');
        const old = await kv.get(k); if (old && old.media && old.media.mid && kv.delPrefix) await kv.delPrefix('media/' + old.media.mid + '/'); await kv.del(k); await log(me.name, 'Deleted a message from the everyone chat'); return ok({ ok: true });
      }
      case 'pushKey': return ok({ key: (await vapidKeys(kv)).pub });
      case 'pushSubscribe': {
        const sub = p.sub || {}, ep = String(sub.endpoint || ''), k = sub.keys || {};
        if (!/^https:\/\/[^\s]{10,500}$/.test(ep) || !/^[A-Za-z0-9_-]{80,100}$/.test(String(k.p256dh || '')) || !/^[A-Za-z0-9_-]{16,30}$/.test(String(k.auth || ''))) fail(400, 'That device could not be registered for notifications.');
        const h = (await sha(ep)).slice(0, 24), owner = await kv.get('pushep/' + h);
        if (owner && owner !== me.id) await kv.del('push/' + owner + '/' + h);
        await kv.set('push/' + me.id + '/' + h, { endpoint: ep, p256dh: k.p256dh, auth: k.auth, ts: Date.now() }); await kv.set('pushep/' + h, me.id);
        const mine = await kv.list('push/' + me.id + '/');
        if (mine.length > 5) { const subs = await Promise.all(mine.map(async (x) => ({ x, ts: ((await kv.get(x)) || {}).ts || 0 }))); subs.sort((a, b) => a.ts - b.ts); for (const o of subs.slice(0, mine.length - 5)) await kv.del(o.x); }
        return ok({ ok: true });
      }
      case 'pushUnsubscribe': {
        const ep = String(p.endpoint || ''), h = (await sha(ep)).slice(0, 24), owner = await kv.get('pushep/' + h);
        if (owner === me.id) { await kv.del('push/' + me.id + '/' + h); await kv.del('pushep/' + h); }
        return ok({ ok: true });
      }
      case 'pushTest': {
        if (!(await kv.list('push/' + me.id + '/')).length) fail(400, 'Notifications are not turned on for this device yet.');
        await pushUsers(kv, env, [me.id], { title: 'MediRoster notifications are on', body: 'You will get shift reminders and message alerts here.', url: '/', tag: 'test' }, { ttl: 300, site: site() }); return ok({ ok: true });
      }
      case 'setStaffDept': {
        needMaster(); const s = find(p.id), d = clean(p.dept, 60);
        if (!cfg.depts.includes(d)) fail(400, 'Choose one of your departments.');
        const old = s.dept; s.dept = d; await saveStaff(); await log(me.name, `Moved ${s.name} from ${old || '(none)'} to ${d}`); return reply();
      }
      case 'setRole': {
        needMaster(); const s = find(p.id);
        if (s.role === 'master' || !['admin', 'worker'].includes(p.r)) fail(400, 'That change is not allowed.');
        s.role = p.r; await saveStaff(); await log(me.name, `Changed ${s.name} to ${s.role}`); return reply();
      }
      case 'addStaff': {
        needMaster(); const bad = checkStaffInput(p); if (bad) fail(400, bad);
        const rec = { id: nextId(p.role), name: clean(p.name, 80), role: p.role, designation: clean(p.designation, 60), dept: cfg.depts.includes(p.dept) ? p.dept : (cfg.depts[0] || ''), email: clean(p.email, 200).toLowerCase() };
        const pw = tempPass(); staff.push(rec); await newAccount(rec, pw); await saveStaff();
        await log(me.name, `Added staff ${rec.name} (${rec.id}, ${rec.role})`);
        const r = await send(env, rec.email, 'Welcome to MediRoster', onboardText(site(), rec.id, pw));
        await addLog(kv, 'maillog', 'System', r.ok ? `📧 Automated email dispatched to: ${rec.email} for Account Onboarding.` : `⚠ Onboarding email to ${rec.email} failed (${r.status}). Share the temporary passcode manually (see Staff tab).`, tz, 100);
        return reply({ emailed: r.ok });
      }
      case 'bulkAdd': {
        needMaster(); const rows = Array.isArray(p.rows) ? p.rows.slice(0, 200) : [], added = [], skipped = [];
        for (const r of rows) {
          const bad = checkStaffInput(r); if (bad) { skipped.push(`${clean(r.name, 40) || '(blank)'}: ${bad}`); continue; }
          const rec = { id: nextId(r.role, added), name: clean(r.name, 80), role: r.role, designation: clean(r.designation, 60), dept: cfg.depts.includes(r.dept) ? r.dept : (cfg.depts[0] || ''), email: clean(r.email, 200).toLowerCase() };
          added.push(rec);
        }
        await Promise.all(added.map(async (rec) => { const pw = tempPass(); await newAccount(rec, pw); await kv.set('onb/' + rec.id, { at: Date.now() }); }));
        staff.push(...added); await saveStaff();
        await log(me.name, `Bulk-added ${added.length} staff (welcome emails queued)`);
        return reply({ added: added.length, skipped });
      }
      case 'delStaff': {
        needMaster(); const s = find(p.id);
        if (s.role === 'master') fail(400, 'The Master Admin cannot be removed.');
        staff = staff.filter((x) => x.id !== s.id); await saveStaff();
        await Promise.all([kv.del('acct/' + s.id), kv.del('pend/' + s.id), kv.del('onb/' + s.id)]);
        await log(me.name, `Removed staff ${s.name}`); return reply();
      }
      case 'addDept': { needMaster(); const n = clean(p.name, 60); if (!n || cfg.depts.includes(n)) fail(400, 'Enter a unique name.'); cfg.depts.push(n); await saveCfg(); await log(me.name, 'Created department ' + n); return reply(); }
      case 'delDept': { needMaster(); const n = clean(p.name, 60); cfg.depts = cfg.depts.filter((d) => d !== n); await saveCfg(); await log(me.name, 'Deleted department ' + n); return reply(); }
      case 'addTpl': {
        needMaster(); const name = clean(p.name, 40);
        if (!name || !/^\d{2}:\d{2}$/.test(p.start) || !/^\d{2}:\d{2}$/.test(p.end) || !/^#[0-9a-fA-F]{6}$/.test(p.color)) fail(400, 'Enter a name, start time and end time.');
        cfg.tpl.push({ id: 't' + Date.now(), name, start: p.start, end: p.end, color: p.color }); await saveCfg(); await log(me.name, 'Added shift template ' + name); return reply();
      }
      case 'delTpl': {
        needMaster(); const t = cfg.tpl.find((x) => x.id === p.id) || fail(404, 'Shift template not found.');
        cfg.tpl = cfg.tpl.filter((x) => x !== t); await saveCfg(); await log(me.name, 'Deleted shift template ' + t.name); return reply();
      }
      case 'saveZone': {
        needMaster(); const lat = Number(p.lat), lng = Number(p.lng), radius = parseInt(p.radius, 10);
        if (!(lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180) || !(radius >= 10 && radius <= 5000)) fail(400, 'Enter valid coordinates and a radius of 10 to 5000 metres.');
        cfg.zone = { name: clean(p.name, 80) || 'Hospital', lat, lng, radius }; await saveCfg(); await log(me.name, 'Updated hospital zone'); return reply();
      }
      case 'approve': {
        needMgr(); const s = find(p.id), a = await kv.get('acct/' + s.id);
        if (s.role === 'master' || s.id === me.id || !a || !a.reset) fail(400, 'That request cannot be approved.');
        const pw = tempPass(); Object.assign(a, { pass: await hashPass(pw), temp: pw, setup: true, reset: false, n: 0, until: 0 }); delete a.resetAt;
        await kv.set('acct/' + s.id, a); await kv.del('pend/' + s.id);
        await log(me.name, `Approved passcode reset for ${s.name} (${s.id})`); return reply({ temp: pw });
      }
      case 'staffStatus': {
        needMgr(); const ids = (Array.isArray(p.ids) ? p.ids : []).slice(0, 60).map((x) => clean(x, 40)).filter((x) => byId.has(x)), out = {};
        await Promise.all(ids.map(async (id) => { const a = (await kv.get('acct/' + id)) || {}; out[id] = { setup: !!a.setup, reset: !!a.reset, ...(isMaster && a.setup && a.temp ? { temp: a.temp } : {}) }; }));
        return ok({ status: out });
      }
      case 'attDay': {
        needMgr(); const d = clean(p.date, 10); if (!validDate(d)) fail(400, 'Invalid date.');
        return ok({ rows: (await listAtt(kv, 'att/' + d + '/', byId)).slice(0, 2000) });
      }
      case 'clockIn': {
        const lat = Number(p.lat), lng = Number(p.lng);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) fail(400, 'Your location could not be read.');
        const d = Math.round(dist(lat, lng, cfg.zone.lat, cfg.zone.lng)), w = wall(new Date(), tz), date = ymd(Date.UTC(w.y, w.m - 1, w.d)), hhmm = String(w.h).padStart(2, '0') + String(w.mi).padStart(2, '0');
        if (d > cfg.zone.radius) {
          const sh = await onShiftNow(kv, cfg, me, w);
          if (sh) { // on shift but away from the hospital: tell the managers
            const lk = 'awaylast/' + me.id, last = (await kv.get(lk)) || 0;
            if (Date.now() - last > 120000) {
              await kv.set(lk, Date.now()); await kv.set(`atx/${date}/${me.id}/${hhmm}/${d}`, { lat: r5(lat), lng: r5(lng) });
              const far = d >= 1000 ? (d / 1000).toFixed(1) + ' km' : d + ' m';
              await log(me.name, `Tried to clock in ${far} away from the hospital zone during the ${sh.name} shift (${r5(lat)}, ${r5(lng)})`);
              await notify(staff.filter((x) => x.role !== 'worker' && x.id !== me.id).slice(0, 25).map((x) => x.id), { title: '⚠ Clock-in attempt away from hospital', body: `${me.name} tried to clock in ${far} away (${sh.name} shift)`, url: '/#attend', tag: 'away-' + me.id }, { ttl: 3600, urgency: 'high' });
            }
          }
          fail(403, `You are ${d} m from the hospital zone. Move within ${cfg.zone.radius} m to clock in.`);
        }
        if ((await openSession(kv, me.id, w)).open) fail(409, 'You are already clocked in. Clock out first.');
        const v = { lat: r5(lat), lng: r5(lng) };
        await Promise.all([kv.set(`attp/${me.id}/${date}/${hhmm}/${d}`, v), kv.set(`att/${date}/${me.id}/${hhmm}/${d}`, v)]);
        return reply();
      }
      case 'clockOut': {
        const lat = Number(p.lat), lng = Number(p.lng);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) fail(400, 'Your location could not be read.');
        const d = Math.round(dist(lat, lng, cfg.zone.lat, cfg.zone.lng)), w = wall(new Date(), tz), date = ymd(Date.UTC(w.y, w.m - 1, w.d)), hhmm = String(w.h).padStart(2, '0') + String(w.mi).padStart(2, '0');
        if (!(await openSession(kv, me.id, w)).open) fail(409, 'You are not clocked in right now.');
        const v = { lat: r5(lat), lng: r5(lng) };
        await Promise.all([kv.set(`atop/${me.id}/${date}/${hhmm}/${d}`, v), kv.set(`ato/${date}/${me.id}/${hhmm}/${d}`, v)]);
        return reply();
      }
      case 'buzzList': {
        needBuzz();
        return ok({ staff: staff.filter((x) => x.id !== me.id).map((x) => ({ id: x.id, name: x.name, role: x.role, designation: x.designation || '', dept: x.dept })) });
      }
      case 'buzz': {
        needBuzz(); const t = find(p.id); if (t.id === me.id) fail(400, 'Choose someone else.');
        const lk = 'buzzlast/' + me.id, last = (await kv.get(lk)) || 0; if (Date.now() - last < 2500) fail(429, 'Please wait a moment before buzzing again.');
        await kv.set(lk, Date.now());
        const msg = clean(p.msg, 140), ts = Date.now(), label = (me.role === 'master' ? 'Master Admin ' : me.role === 'admin' ? 'Admin ' : '') + me.name;
        const devices = (await kv.list('push/' + t.id + '/')).length;
        await kv.set('buzz/' + t.id, { ts, name: label, msg });
        await notify([t.id], { title: '🔔 ' + label + ' is calling', body: msg || 'Please respond now', url: '/#buzz', tag: 'buzz-' + ts, buzz: { ts, name: label, msg } }, { ttl: 120, urgency: 'high' });
        await log(me.name, `Buzzed ${t.name}${msg ? ': "' + msg + '"' : ''}`);
        return ok({ ok: true, devices });
      }
      case 'setBuzzer': {
        needMaster(); const s = find(p.id); if (s.role === 'master') fail(400, 'The Master Admin always has the buzzer.');
        s.buzzer = !!p.on; await saveStaff(); await log(me.name, `${s.buzzer ? 'Gave' : 'Removed'} buzzer access ${s.buzzer ? 'to' : 'from'} ${s.name}`); return reply();
      }
      case 'previewChanges': {
        needMgr(); const list = Array.isArray(p.changes) ? p.changes.slice(0, 3000) : [];
        const r = await resolveChanges(kv, cfg, byId, list);
        return ok({ preview: previewOf(r.rows, r.noop, r.problems, cfg, byId) });
      }
      case 'applyChanges': {
        needMgr(); const list = Array.isArray(p.changes) ? p.changes.slice(0, 3000) : [];
        const r = await resolveChanges(kv, cfg, byId, list); await applyRows(kv, r.rows);
        const note = clean(p.note, 160);
        if (r.rows.length) await log(me.name, p.source === 'ai' ? `AI assistant: "${note}" - ${r.rows.length} roster changes` : p.source === 'undo' ? `Undid ${r.rows.length} roster changes` : `Roster import (${note || 'pasted text'}): ${r.rows.length} roster changes`);
        return reply({ applied: r.rows.length, noop: r.noop, problems: r.problems.slice(0, 20), undo: r.rows.map((x) => ({ sid: x.sid, dt: x.dt, tids: x.before, mode: 'set' })) });
      }
      case 'aiPlan': {
        needMgr(); const msg = clean(p.message, 600); if (!msg) fail(400, 'Type a request first.');
        await aiGate(me.id);
        const today = todayIn(tz), cal = [...Array(21)].map((_, i) => { const d = ymd(Date.parse(today) + i * 864e5); return DAYS[new Date(d + 'T00:00:00Z').getUTCDay()] + ' ' + d; }).join(', ');
        const hist = (Array.isArray(p.history) ? p.history : []).slice(-6).map((h) => (h.role === 'user' ? 'MANAGER: ' : 'ASSISTANT: ') + clean(h.text, 300)).join('\n');
        const words = new Set((msg + ' ' + hist).toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 2));
        const wl = [...words], pool = staff, cand = (pool.length <= 60 ? pool : pool.filter((s) => normName(s.name).split(' ').some((w) => words.has(w) || (w.length >= 4 && wl.some((x) => x.length >= 4 && x.slice(0, 4) === w.slice(0, 4)))))).slice(0, 40);
        const user = `TODAY: ${DAYS[new Date(today + 'T00:00:00Z').getUTCDay()]} ${today}\nCALENDAR: ${cal}\nSHIFTS: ${cfg.tpl.map((t) => `${t.name} (${t.start}-${t.end})`).join('; ')}\nDEPARTMENTS: ${cfg.depts.join('; ')}\nCANDIDATES (id | name | department):\n${cand.map((s) => `${s.id} | ${s.name} | ${s.dept}`).join('\n') || '(none matched)'}\n${hist ? 'RECENT CONVERSATION:\n' + hist + '\n' : ''}REQUEST: ${msg}`;
        const out = await callAI(env, PLAN_SYSTEM, user), reply0 = clean(out && out.reply, 500);
        const ex = expandOps(Array.isArray(out && out.ops) ? out.ops.slice(0, 10) : [], cfg, staff);
        if (!ex.changes.length) return ok({ reply: reply0 || 'I could not work out a change from that. Please say which person, which shift and which dates.', problems: ex.problems, preview: null, changes: [] });
        const r = await resolveChanges(kv, cfg, byId, ex.changes);
        return ok({ reply: reply0, preview: previewOf(r.rows, r.noop, [...ex.problems, ...r.problems], cfg, byId), changes: r.rows.map((x) => ({ sid: x.sid, dt: x.dt, tids: x.after, mode: 'set' })) });
      }
      case 'aiParse': {
        needMgr(); const text = String(p.text || '').slice(0, 6000); if (!text.trim()) fail(400, 'There is no text to read.');
        await aiGate(me.id);
        const hint = validDate(clean(p.hint, 10)) ? clean(p.hint, 10) : mondayOf(todayIn(tz));
        const out = await callAI(env, PARSE_SYSTEM, `TODAY: ${todayIn(tz)}\nWEEKSTART (Monday): ${hint}\nSHIFTS: ${cfg.tpl.map((t) => `${t.name} (${t.start}-${t.end})`).join('; ')}\nTEXT:\n${text}`);
        const rows = (Array.isArray(out && out.rows) ? out.rows : []).filter((r) => Array.isArray(r) && r.length >= 3).slice(0, 400).map((r) => [clean(r[0], 80), clean(r[1], 10), clean(r[2], 80)]);
        return ok({ rows });
      }
      default: fail(400, 'Unknown request.');
    }
  } catch (e) {
    if (e instanceof HttpError) return { status: e.status, body: { error: e.message } };
    console.error('MediRoster server error:', e && e.message);
    return { status: 500, body: { error: 'Something went wrong on the server. Please try again.' } };
  }
}

/* ---------- automatic emails (called every 5 minutes) ---------- */
export async function runReminders({ kv, env, send = sendMail, at = new Date(), budgetMs = 20000 }) {
  const t0 = Date.now(), tz = zoneOf(env);
  const [staff, cfg] = await Promise.all([kv.get('staff'), kv.get('cfg')]);
  if (!staff || !cfg) return { sent: 0, due: 0, onboard: 0 };
  const w = wall(at, tz), base = Date.UTC(w.y, w.m - 1, w.d), nowWall = Date.UTC(w.y, w.m - 1, w.d, w.h, w.mi);
  const dates = [-1, 0, 1].map((o) => ymd(base + o * 864e5)), weeks = [...new Set(dates.map(mondayOf))];
  const roster = Object.assign({}, ...(await Promise.all(weeks.map((m) => readWeek(kv, m)))));
  const sentMap = {}; await Promise.all(dates.map(async (d) => { sentMap[d] = (await kv.get('sent/' + d)) || {}; }));
  const tplById = new Map(cfg.tpl.map((t) => [t.id, t])), due = [];
  for (const s of staff) for (const date of dates) for (const tid of asList(roster[s.id + '|' + date])) {
    const t = tplById.get(tid); if (!t) continue;
    const [sh, sm] = t.start.split(':').map(Number), [y, m, d] = date.split('-').map(Number), diff = nowWall - Date.UTC(y, m - 1, d, sh, sm);
    const stage = diff >= -30 * 6e4 && diff < -20 * 6e4 ? 'soon' : diff >= 0 && diff < 15 * 6e4 ? 'start' : null;
    if (!stage) continue;
    const k = `${s.id}|${date}|${t.id}|${stage}`; if (sentMap[date][k]) continue;
    due.push({ s, date, stage, k });
  }
  const logs = []; let sent = 0;
  const entry = (msg) => logs.push({ ts: Date.now(), t: stamp(tz, at), who: 'System', msg });
  for (let i = 0; i < due.length && Date.now() - t0 < budgetMs; i += 8) {
    await Promise.all(due.slice(i, i + 8).map(async ({ s, date, stage, k }) => {
      sentMap[date][k] = Date.now();
      const what = stage === 'soon' ? '30-Minute Shift Reminder' : 'Shift Start';
      await pushUsers(kv, env, [s.id], stage === 'soon' ? { title: 'Shift starts in about 30 minutes', body: 'Get ready and clock in at the hospital.', url: '/', tag: 'shift-' + date + '-' + k.split('|')[2] } : { title: 'Your shift has started', body: 'Please clock in at the hospital.', url: '/', tag: 'shift-' + date + '-' + k.split('|')[2] }, { ttl: 1800, urgency: 'high', site: (env.SITE_URL || cfg.site || '') });
      if (!s.email) return entry(`⚠ ${what} email skipped for ${s.name} (no email on file).`);
      const r = await send(env, s.email, stage === 'soon' ? 'Your shift starts in about 30 minutes' : 'Your shift has started', stage === 'soon' ? SOON_TEXT : START_TEXT);
      if (r.ok) sent++;
      entry(r.ok ? `📧 Automated email dispatched to: ${s.email} for ${what}.` : `⚠ ${what} email to ${s.email} failed (${r.status}).`);
    }));
  }
  await Promise.all(dates.map((d) => kv.set('sent/' + d, sentMap[d])));
  kv.del('sent/' + ymd(base - 4 * 864e5)).catch(() => {});
  /* welcome emails queued by bulk import: 20 per run keeps Gmail within its daily limit */
  let onboard = 0; const queue = (await kv.list('onb/')).slice(0, 20), site = goodUrl(env.SITE_URL) || goodUrl(cfg.site);
  for (let i = 0; i < queue.length && Date.now() - t0 < budgetMs + 5000; i += 5) {
    await Promise.all(queue.slice(i, i + 5).map(async (qk) => {
      const id = qk.slice(4), s = staff.find((x) => x.id === id), a = s && (await kv.get('acct/' + id));
      await kv.del(qk);
      if (!s || !a || !a.setup || !a.temp) return;
      const r = await send(env, s.email, 'Welcome to MediRoster', onboardText(site, s.id, a.temp));
      if (r.ok) onboard++;
      entry(r.ok ? `📧 Automated email dispatched to: ${s.email} for Account Onboarding.` : `⚠ Onboarding email to ${s.email} failed (${r.status}). Share the temporary passcode manually (see Staff tab).`);
    }));
  }
  /* once a day (around 03:00 India time): remove photos and videos older than 30 days to keep the database small */
  if (kv.delPrefix && at.getUTCHours() === 21 && at.getUTCMinutes() < 5) {
    try {
      const cut = Date.now() - MEDIA_KEEP_DAYS * 864e5;
      for (const k of (await kv.list('media/')).filter((x) => x.endsWith('/m')).slice(0, 400)) { const m = await kv.get(k); if (m && m.ts < cut) await kv.delPrefix(k.slice(0, -1)); }
    } catch (e) { /* try again tomorrow */ }
  }
  if (logs.length) { const ml = (await kv.get('maillog')) || []; await kv.set('maillog', [...logs.reverse(), ...ml].slice(0, 100)); }
  return { sent, due: due.length, onboard };
}
