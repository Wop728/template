export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const id = url.searchParams.get('message_id');
  if (!id) return new Response(JSON.stringify({ error:'缺少 message_id' }), { status:400 });
  // fetch the message
  const [[msgRow]] = await env.MATCH_DB.prepare('SELECT * FROM messages WHERE id = ?').bind(id).all().then(r=>[r.results]);
  if (!msgRow) return new Response(JSON.stringify({ error:'消息不存在' }), { status:404 });
  const keywords = (msgRow.keywords||'').split(',').map(k=>k.trim()).filter(k=>k);
  let matched = [];
  for (const kw of keywords) {
    const rows = await env.MATCH_DB.prepare('SELECT m.*, u.username FROM messages m LEFT JOIN users u ON u.id = m.user_id WHERE m.keywords LIKE ? AND m.type != ? AND m.id != ? AND m.status = \"active\"').bind('%'+kw+'%', msgRow.type, id).all();
    matched = matched.concat(rows.results || []);
  }
  return new Response(JSON.stringify({ ok:true, matched }), { status:200 });
}
