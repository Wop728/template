export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  
  // 通用响应头（解决CORS问题）
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*', // 开发环境允许所有域名，生产环境需指定具体域名
    'Access-Control-Allow-Methods': 'POST, OPTIONS', // 允许POST和预检请求
    'Access-Control-Allow-Headers': 'Content-Type' // 允许JSON类型的请求体
  };
  
  // 处理预检请求（浏览器会先发送OPTIONS请求验证跨域）
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers });
  }
  
  const body = request.method === 'POST' ? await request.json().catch(() => ({})) : {};

  const toHex = async (str) => {
    const enc = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const jwtSign = async (payload) => {
    if (!env.JWT_SECRET) {
      throw new Error('JWT_SECRET is not configured');
    }
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload64 = btoa(JSON.stringify(payload));
    const data = `${header}.${payload64}`;
    const key = await crypto.subtle.importKey(
      'raw', 
      new TextEncoder().encode(env.JWT_SECRET), 
      { name: 'HMAC', hash: 'SHA-256' }, 
      false, 
      ['sign']
    );
    const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
    const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
    return `${data}.${sig}`;
  };

  const jwtVerify = async (token) => {
    try {
      if (!env.JWT_SECRET) {
        throw new Error('JWT_SECRET is not configured');
      }
      const [data, sig] = [token.split('.').slice(0, 2).join('.'), token.split('.').pop()];
      const key = await crypto.subtle.importKey(
        'raw', 
        new TextEncoder().encode(env.JWT_SECRET), 
        { name: 'HMAC', hash: 'SHA-256' }, 
        false, 
        ['verify']
      );
      const expected = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
      const expectedB64 = btoa(String.fromCharCode(...new Uint8Array(expected)));
      return expectedB64 === sig ? JSON.parse(atob(token.split('.')[1])) : null;
    } catch (e) {
      console.error('JWT verification failed:', e);
      return null;
    }
  };

  if (path === '/api/auth/register' && request.method === 'POST') {
    try {
      const { username, password } = body;
      if (!username || !password) {
        return new Response(
          JSON.stringify({ error: 'Missing username or password' }), 
          { status: 400, headers }
        );
      }
      const password_hash = await toHex(password);
      const exists = await env.MATCH_DB
        .prepare('SELECT id FROM users WHERE username = ?')
        .bind(username)
        .all();
      if (exists.results && exists.results.length > 0) {
        return new Response(
          JSON.stringify({ error: 'Username already exists' }), 
          { status: 400, headers }
        );
      }
      await env.MATCH_DB
        .prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
        .bind(username, password_hash)
        .run();
      return new Response(
        JSON.stringify({ ok: true, message: 'Registration successful' }), 
        { status: 200, headers }
      );
    } catch (e) {
      console.error('Registration error:', e);
      return new Response(
        JSON.stringify({ error: 'Internal server error', details: e.message }), 
        { status: 500, headers }
      );
    }
  }

  if (path === '/api/auth/login' && request.method === 'POST') {
    try {
      const { username, password } = body;
      if (!username || !password) {
        return new Response(
          JSON.stringify({ error: 'Missing username or password' }), 
          { status: 400, headers }
        );
      }
      const password_hash = await toHex(password);
      const r = await env.MATCH_DB
        .prepare('SELECT id, username FROM users WHERE username = ? AND password_hash = ?')
        .bind(username, password_hash)
        .all();
      if (!r || !r.results || r.results.length === 0) {
        return new Response(
          JSON.stringify({ error: 'Invalid username or password' }), 
          { status: 401, headers }
        );
      }
      const user = r.results[0];
      const token = await jwtSign({ 
        id: user.id, 
        username: user.username, 
        iat: Date.now() 
      });
      return new Response(
        JSON.stringify({ ok: true, token }), 
        { status: 200, headers }
      );
    } catch (e) {
      console.error('Login error:', e);
      return new Response(
        JSON.stringify({ error: 'Internal server error', details: e.message }), 
        { status: 500, headers }
      );
    }
  }

  return new Response(
    JSON.stringify({ error: 'Unknown API path' }), 
    { status: 404, headers }
  );
}
