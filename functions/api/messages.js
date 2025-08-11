export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const body = method === 'POST' ? await request.json().catch(()=>({})) : {};
  // simple jwt verify
  const jwtVerify = async (token) => {
    try {
      const [data, sig] = [token.split('.').slice(0,2).join('.'), token.split('.').pop()];
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET || 'dev_secret'), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
      const expected = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
      const expectedB64 = btoa(String.fromCharCode(...new Uint8Array(expected)));
      return expectedB64 === sig ? JSON.parse(atob(token.split('.')[1])) : null;
    } catch (e) { return null; }
  };

  if (path.endsWith('/publish') && method === 'POST') {
    const auth = request.headers.get('Authorization') || '';
    const token = auth.split(' ')[1];
    const payload = await jwtVerify(token);
    if (!payload) return new Response(JSON.stringify({ error:'未授权' }), { status:401 });
    const { type, title, content, keywords, start_time, end_time } = body;
    if (!type || !title || !keywords) return new Response(JSON.stringify({ error:'缺少字段' }), { status:400 });
    const r = await env.MATCH_DB.prepare('INSERT INTO messages (user_id, type, title, content, keywords, start_time, end_time) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(payload.id, type, title, content||'', keywords, start_time||'', end_time||'').run();
    return new Response(JSON.stringify({ ok:true, id: r.lastInsertRowId }), { status:200 });
  }

  if (path.endsWith('/search') && method === 'GET') {
    const q = url.searchParams.get('q') || '';
    const rows = await env.MATCH_DB.prepare('SELECT m.*, u.username FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.keywords LIKE ? ORDER BY m.created_at DESC LIMIT 100').bind('%'+q+'%').all();
    return new Response(JSON.stringify({ ok:true, results: rows.results || [] }), { status:200 });
  }

  if (path.endsWith('/my') && method === 'GET') {
    const auth = request.headers.get('Authorization') || '';
    const token = auth.split(' ')[1];
    const payload = await jwtVerify(token);
    if (!payload) return new Response(JSON.stringify({ error:'未授权' }), { status:401 });
    const rows = await env.MATCH_DB.prepare('SELECT * FROM messages WHERE user_id = ? ORDER BY created_at DESC').bind(payload.id).all();
    return new Response(JSON.stringify({ ok:true, results: rows.results || [] }), { status:200 });
  }

  return new Response(JSON.stringify({ error:'未知消息接口' }), { status:404 });
}
