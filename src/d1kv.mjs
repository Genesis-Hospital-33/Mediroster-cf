// Key/value storage on top of Cloudflare D1 (SQLite). get / set / del / list(prefix), plus range (values in one query) and delPrefix.
export function d1kv(db) {
  let ready;
  const init = () => ready || (ready = db.exec('CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)'));
  return {
    async get(key) { await init(); const v = await db.prepare('SELECT value FROM kv WHERE key = ?1').bind(key).first('value'); return v == null ? null : JSON.parse(v); },
    async set(key, val) { await init(); await db.prepare('INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2').bind(key, JSON.stringify(val)).run(); },
    async del(key) { await init(); await db.prepare('DELETE FROM kv WHERE key = ?1').bind(key).run(); },
    async list(prefix) { await init(); const { results } = await db.prepare('SELECT key FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key').bind(prefix, prefix + '\uffff').all(); return results.map((r) => r.key); },
    // Keys AND values between two keys in ONE query (much faster than reading each key separately). desc=true gives the newest first.
    async range(from, to, limit, desc) { await init(); const { results } = await db.prepare('SELECT key, value FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key ' + (desc ? 'DESC' : 'ASC') + ' LIMIT ?3').bind(from, to, limit).all(); return results.map((r) => ({ key: r.key, value: JSON.parse(r.value) })); },
    async delPrefix(prefix) { await init(); await db.prepare('DELETE FROM kv WHERE key >= ?1 AND key < ?2').bind(prefix, prefix + '\uffff').run(); },
  };
}
