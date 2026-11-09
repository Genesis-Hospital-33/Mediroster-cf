// Key/value storage on top of Cloudflare D1 (SQLite). Same shape as before: get / set / del / list(prefix).
export function d1kv(db) {
  let ready;
  const init = () => ready || (ready = db.exec('CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)'));
  return {
    async get(key) { await init(); const v = await db.prepare('SELECT value FROM kv WHERE key = ?1').bind(key).first('value'); return v == null ? null : JSON.parse(v); },
    async set(key, val) { await init(); await db.prepare('INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2').bind(key, JSON.stringify(val)).run(); },
    async del(key) { await init(); await db.prepare('DELETE FROM kv WHERE key = ?1').bind(key).run(); },
    async list(prefix) { await init(); const { results } = await db.prepare('SELECT key FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key').bind(prefix, prefix + '\uffff').all(); return results.map((r) => r.key); },
  };
}
