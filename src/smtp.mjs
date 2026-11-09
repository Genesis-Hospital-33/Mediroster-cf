// Minimal SMTP client for Cloudflare Workers (uses the built-in TCP sockets). Sends one plain-text email through Gmail.
const te = new TextEncoder(), td = new TextDecoder();
const fail = (msg, code) => { const e = new Error(msg); e.code = code; return e; };
async function defaultConnect(host, port) {
  const { connect } = await import('cloudflare:sockets');
  return connect({ hostname: host, port }, { secureTransport: 'on', allowHalfOpen: false });
}
const clean1 = (x) => String(x == null ? '' : x).replace(/[\r\n<>"]/g, ' ').trim();
const b64 = (str) => btoa(unescape(encodeURIComponent(str)));
export function buildMessage({ user, fromName, to, subject, text, date = new Date(), id }) {
  const ascii = /^[\x20-\x7E\r\n\t]*$/.test(text), subj = /^[\x20-\x7E]*$/.test(subject) ? subject : `=?UTF-8?B?${b64(subject)}?=`;
  const domain = String(user).split('@')[1] || 'localhost';
  const head = [
    `Date: ${date.toUTCString().replace('GMT', '+0000')}`, `From: "${clean1(fromName)}" <${clean1(user)}>`, `To: <${clean1(to)}>`, `Subject: ${subj}`,
    `Message-ID: <${id || Math.random().toString(36).slice(2) + Date.now().toString(36)}@${domain}>`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8',
    `Content-Transfer-Encoding: ${ascii ? '7bit' : 'base64'}`,
  ].join('\r\n');
  const body = ascii ? String(text).replace(/\r?\n/g, '\r\n') : (b64(text).match(/.{1,76}/g) || []).join('\r\n');
  return head + '\r\n\r\n' + body.split('\r\n').map((l) => (l.startsWith('.') ? '.' + l : l)).join('\r\n') + '\r\n.\r\n';
}
export async function smtpSend(o, connectFn) {
  if (/[\r\n<>]/.test(o.to) || /[\r\n<>]/.test(o.user)) throw fail('bad address', 'EENVELOPE');
  const sock = await (connectFn || defaultConnect)(o.host, o.port), reader = sock.readable.getReader(), writer = sock.writable.getWriter();
  let buf = '';
  const timer = setTimeout(() => { try { sock.close(); } catch (e) { /* ignore */ } }, 9000);
  const readReply = async () => {
    for (;;) {
      const lines = buf.split('\r\n');
      for (let i = 0; i < lines.length - 1; i++) if (/^\d{3}( |$)/.test(lines[i])) { const got = lines.slice(0, i + 1); buf = lines.slice(i + 1).join('\r\n'); return { code: +got[0].slice(0, 3), text: got.join('\n') }; }
      const { value, done } = await reader.read();
      if (done) throw fail('connection closed', 'ECLOSED');
      buf += td.decode(value, { stream: true });
    }
  };
  const say = (line) => writer.write(te.encode(line + '\r\n'));
  const expect = async (ok, label) => { const r = await readReply(); if (!ok.includes(r.code)) throw fail(`${label} ${r.code}`, String(r.code)); return r; };
  try {
    await expect([220], 'greeting');
    await say('EHLO mediroster.app'); await expect([250], 'EHLO');
    await say('AUTH LOGIN'); await expect([334], 'AUTH');
    await say(btoa(o.user)); await expect([334], 'AUTH');
    await say(btoa(o.pass)); await expect([235], 'AUTH');
    await say(`MAIL FROM:<${o.user}>`); await expect([250], 'MAIL');
    await say(`RCPT TO:<${o.to}>`); await expect([250, 251], 'RCPT');
    await say('DATA'); await expect([354], 'DATA');
    await writer.write(te.encode(buildMessage({ user: o.user, fromName: o.fromName || 'MediRoster', to: o.to, subject: o.subject, text: o.text })));
    await expect([250], 'SEND');
    await say('QUIT');
  } finally { clearTimeout(timer); try { await sock.close(); } catch (e) { /* ignore */ } }
}
