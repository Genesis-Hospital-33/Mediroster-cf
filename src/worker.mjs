// MediRoster on Cloudflare: serves the website files, answers /api, and runs the 5-minute reminder job.
import { handle, runReminders } from './core.mjs';
import { d1kv } from './d1kv.mjs';

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname === '/api') {
      if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
      const from = req.headers.get('origin');
      if (from && from !== url.origin) return json({ error: 'Origin not allowed' }, 403);
      let body;
      try { body = await req.json(); } catch (e) { return json({ error: 'Invalid request' }, 400); }
      const res = await handle({ kv: d1kv(env.DB), env, origin: url.origin, defer: (p) => ctx.waitUntil(p) }, body);
      return json(res.body, res.status);
    }
    return env.ASSETS.fetch(req);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runReminders({ kv: d1kv(env.DB), env }).catch((e) => console.error('reminders failed:', e && e.message)));
  },
};
