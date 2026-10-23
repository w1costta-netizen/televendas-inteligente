// Recebe o pacote já criptografado no navegador e grava no armazenamento da Vercel.
// O conteúdo chega cifrado (AES-256-GCM) — este servidor nunca vê os dados em claro.
// Autorização: a senha de acesso do app, guardada como variável de ambiente.

const ARQUIVOS = ['data.enc', 'data-equipe.enc', 'cfg.json'];
const LIMITE = 4 * 1024 * 1024; // o envio da Vercel aceita até ~4,5 MB

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ erro: 'Use POST.' });

  const token = process.env.BLOB_READ_WRITE_TOKEN;
  const esperada = process.env.PUBLICAR_SENHA;
  if (!token || !esperada) return res.status(500).json({ erro: 'Publicação ainda não configurada no servidor.' });

  const senha = String(req.headers['x-senha'] || '');
  if (senha.length !== esperada.length || senha !== esperada)
    return res.status(401).json({ erro: 'Senha incorreta — publique com a senha de gerência do app.' });

  const arquivo = String(req.headers['x-arquivo'] || '');
  if (!ARQUIVOS.includes(arquivo)) return res.status(400).json({ erro: 'Arquivo não permitido.' });

  let corpo;
  try { corpo = await leCorpo(req); }
  catch (e) { return res.status(413).json({ erro: e.message }); }
  if (!corpo.length) return res.status(400).json({ erro: 'O pacote chegou vazio.' });

  try {
    const r = await fetch(`https://blob.vercel-storage.com/${arquivo}`, {
      method: 'PUT',
      headers: {
        authorization: 'Bearer ' + token,
        'x-api-version': '7',
        'x-content-type': 'application/octet-stream',
        'x-add-random-suffix': '0',
        'x-allow-overwrite': '1',
        'x-cache-control-max-age': '60',
      },
      body: corpo,
    });
    const txt = await r.text();
    if (!r.ok) return res.status(502).json({ erro: `O armazenamento recusou o envio (${r.status}): ${txt.slice(0, 200)}` });
    const j = JSON.parse(txt);
    return res.status(200).json({ ok: true, arquivo, bytes: corpo.length, url: j.url });
  } catch (e) {
    return res.status(502).json({ erro: 'Falha ao gravar: ' + (e && e.message ? e.message : String(e)) });
  }
};

function leCorpo(req) {
  if (Buffer.isBuffer(req.body)) return Promise.resolve(req.body);
  return new Promise((ok, falha) => {
    const partes = []; let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > LIMITE) { req.destroy(); return falha(new Error('O pacote passou de 4 MB. Avise o responsável técnico.')); }
      partes.push(c);
    });
    req.on('end', () => ok(Buffer.concat(partes)));
    req.on('error', falha);
  });
}
