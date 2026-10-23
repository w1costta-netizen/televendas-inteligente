// Base central de registros de contato.
// Cada vendedor grava o próprio arquivo, já criptografado no navegador.
// Só o administrador lista a base inteira. O servidor nunca vê o conteúdo em claro.

const crypto = require('crypto');

const BLOB = 'https://blob.vercel-storage.com';
const PUBLICO = 'https://x9ugs2bsgfxyllgv.public.blob.vercel-storage.com';
const LIMITE = 4 * 1024 * 1024;

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  if (!token) return res.status(500).json({ erro: 'Armazenamento não configurado.' });

  const senha = String(req.headers['x-senha'] || '');
  if (!senha) return res.status(401).json({ erro: 'Sem senha.' });
  const admin = !!process.env.PUBLICAR_SENHA && senha === process.env.PUBLICAR_SENHA;
  const equipe = admin || (await senhaDaEquipeConfere(senha));
  if (!equipe) return res.status(401).json({ erro: 'Senha incorreta.' });

  // ---- administrador lê a base consolidada
  if (req.method === 'GET') {
    if (!admin) return res.status(403).json({ erro: 'Apenas o administrador acessa a base completa.' });
    try {
      const r = await fetch(`${BLOB}/?prefix=registros/&limit=1000`, {
        headers: { authorization: 'Bearer ' + token, 'x-api-version': '7' },
      });
      if (!r.ok) return res.status(502).json({ erro: 'Não foi possível listar a base (' + r.status + ').' });
      const j = await r.json();
      return res.status(200).json({
        ok: true,
        arquivos: (j.blobs || []).map((b) => ({ pathname: b.pathname, url: b.url, size: b.size, em: b.uploadedAt })),
      });
    } catch (e) {
      return res.status(502).json({ erro: 'Falha ao listar: ' + (e && e.message) });
    }
  }

  if (req.method !== 'POST') return res.status(405).json({ erro: 'Use GET ou POST.' });

  // ---- vendedor (ou administrador) grava os próprios registros
  const quem = String(req.headers['x-vendedor'] || '').trim();
  const slug = quem.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  if (!slug || slug.length > 60) return res.status(400).json({ erro: 'Identificação do vendedor inválida.' });

  let corpo;
  try { corpo = await leCorpo(req); }
  catch (e) { return res.status(413).json({ erro: e.message }); }
  if (!corpo.length) return res.status(400).json({ erro: 'Nada para gravar.' });

  try {
    const r = await fetch(`${BLOB}/registros/${slug}.enc`, {
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
    if (!r.ok) return res.status(502).json({ erro: `O armazenamento recusou (${r.status}): ${txt.slice(0, 200)}` });
    return res.status(200).json({ ok: true, arquivo: `registros/${slug}.enc`, bytes: corpo.length });
  } catch (e) {
    return res.status(502).json({ erro: 'Falha ao gravar: ' + (e && e.message) });
  }
};

/* A senha da equipe não fica no servidor: o administrador publica apenas uma
   derivação dela (PBKDF2, 200 mil iterações) junto com o pacote de dados. */
async function senhaDaEquipeConfere(senha) {
  try {
    const r = await fetch(`${PUBLICO}/cfg.json`, { cache: 'no-store' });
    if (!r.ok) return false;
    const cfg = await r.json();
    if (!cfg || !cfg.equipe || !cfg.equipe.salt || !cfg.equipe.hash) return false;
    const calc = crypto.pbkdf2Sync(senha, Buffer.from(cfg.equipe.salt, 'base64'), cfg.equipe.iter || 200000, 32, 'sha256').toString('base64');
    return calc.length === cfg.equipe.hash.length && crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(cfg.equipe.hash));
  } catch (e) {
    return false;
  }
}

function leCorpo(req) {
  if (Buffer.isBuffer(req.body)) return Promise.resolve(req.body);
  return new Promise((ok, falha) => {
    const partes = []; let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > LIMITE) { req.destroy(); return falha(new Error('Registros acima de 4 MB — avise o responsável técnico.')); }
      partes.push(c);
    });
    req.on('end', () => ok(Buffer.concat(partes)));
    req.on('error', falha);
  });
}
