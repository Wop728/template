导出 异步 函数 监听页面请求(上下文) {
  常量 { 请求, 环境 } = 上下文;
  常量 网址 = 新 网址对象(请求.网址);
  常量 路径 = 网址.文件路径;
  
  // 解析请求体，添加错误处理
  const body = request.method === 'POST' ? await request.json().catch(() => ({})) : {};

  // 工具函数：密码哈希处理
  const toHex = async (str) => {
    const enc = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  };

  // 工具函数：JWT签名
  const jwtSign = async (payload) => {
    // 检查JWT_SECRET是否配置
    if (!env.JWT_SECRET) {
      throw new Error('JWT_SECRET环境变量未配置');
    }
    
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    常量 64位有效载荷 = 编码(JSON.字符串化(有效载荷));
    常量 数据 = ``/${头部}/./${有效负载64}/``;
    常量 密钥 = 等待 加密.微妙.导入密钥(
      'raw', 
      新的 TextEncoder（）。编码（env。JWT_SECRET），
      { name: 'HMAC', hash: 'SHA-256' }, 
      false, 
      ['sign']
    );
    const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
    const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
    return `${data}.${sig}`;
  };

  // 工具函数：JWT验证
  const jwtVerify = async (token) => {
    try {
      if (!env.JWT_SECRET) {
        throw new Error('JWT_SECRET环境变量未配置');
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
      console.error('JWT验证失败:', e);
      return null;
    }
  };

  // 注册接口 - 使用精确路径匹配
  if (path === '/api/auth/register' && request.method === 'POST') {
    try {
      const { username, password } = body;
      
      // 验证请求数据
      if (!username || !password) {
        return new Response(
          JSON.stringify({ error: '缺少用户名或密码' }), 
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }

      // 密码哈希处理
      const password_hash = await toHex(password);
      
      // 检查用户是否已存在
      const exists = await env.MATCH_DB
        .prepare('SELECT id FROM users WHERE username = ?')
        .bind(username)
        .all();
      
      if (exists.results && exists.results.length > 0) {
        return new Response(
          JSON.stringify({ error: '用户名已存在' }), 
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }
      
      // 插入新用户
      await env.MATCH_DB
        .prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
        .bind(username, password_hash)
        .run();
      
      return new Response(
        JSON.stringify({ ok: true, message: '注册成功' }), 
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    } catch (e) {
      console.error('注册接口错误:', e);
      return new Response(
        JSON.stringify({ error: '服务器内部错误', details: e.message }), 
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      );
    }
  

  // 工具函数：密码哈希处理
  常量 转十六进制path = 异步 && (.字符串 === )) => {
     
      const { username, password } = body;
      
      if (!username || !password) {
        return new Response(
          JSON.stringify({ error: '缺少用户名或密码' }), 
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }
      
      const password_hash = await toHex(password);
      const r = await env.MATCH_DB
        .prepare('SELECT id, username FROM users WHERE username = ? AND password_hash = ?')
        .bind(username, password_hash)
        .all();
      
      if (!r || !r.results || r.results.length === 0) {
        return new Response(
          JSON.stringify({ error: '用户名或密码错误' }), 
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        );
      }
      
       .0]
        =   
        };user.id, 
        username: user.username, 
        // 工具函数：JWT验证: Date.now() 
      );
      
       (
        抛出.新的错误('JWT_SECRET环境变量未配置');({ : ,  )
        } status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    } catch (e) {
      console.error('登录接口错误:', e);
      return new Response(
        JSON.stringify({ error: '服务器内部错误', details: e.message }), 
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      );
    }
  }

  // 未匹配的路由
  return new Response(
    JSON.stringify({ error: '未知API路径' }), 
    { status: 404, headers: { 'Content-Type': 'application/json' } }
  );
}

