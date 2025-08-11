export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const body = request.method === 'POST' ? await request.json().catch(()=>({})) : {};
  // simple helpers
  const toHex = async (str) => {
    const enc = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  };
  const jwtSign = async (payload) => {
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload64 = btoa(JSON.stringify(payload));
    const data = `${header}.${payload64}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET || 'dev_secret'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
    const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
    return `${data}.${sig}`;
  };
  const jwtVerify = async (token) => {
    try {
      const [data, sig] = [token.split('.').slice(0,2).join('.'), token.split('.').pop()];
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET || 'dev_secret'), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
      const expected = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
      const expectedB64 = btoa(String.fromCharCode(...new Uint8Array(expected)));
      return expectedB64 === sig ? JSON.parse(atob(token.split('.')[1])) : null;
    } catch (e) { return null; }
  };

  if (path.endsWith('/register') && request.method === 'POST') {
    const { username, password } = body;
    if (!username || !password) return new Response(JSON.stringify({ error: '缺少用户名或密码' }), { status:400 });
    const password_hash = await toHex(password);
    // insert user if not exists
    const exists = await env.MATCH_DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).all();
    if (exists.results && exists.results.length) return new Response(JSON.stringify({ error: '用户名已存在' }), { status:400 });
    await env.MATCH_DB.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').bind(username, password_hash).run();
    return new Response(JSON.stringify({ ok: true, message: '注册成功' }), { status:200 });
  }

  if (path.endsWith('/login') && request.method === 'POST') {
    const { username, password } = body;
    if (!username || !password) return new Response(JSON.stringify({ error:'缺少用户名或密码' }), { status:400 });
    const password_hash = await toHex(password);
    const r = await env.MATCH_DB.prepare('SELECT id, username FROM users WHERE username = ? AND password_hash = ?').bind(username, password_hash).all();
    if (!r || !r.results || !r.results.length) return new Response(JSON.stringify({ error:'用户名或密码错误' }), { status:401 });
    const user = r.results[0];
    const token = await jwtSign({ id: user.id, username: user.username, iat: Date.now() });
    return new Response(JSON.stringify({ ok:true, token }), { status:200 });
  }

  return new Response(JSON.stringify({ error:'未知 API 路径' }), { status:404 });
}
