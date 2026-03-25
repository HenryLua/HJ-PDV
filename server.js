const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'hjpdv2025admin';
const JWT_SECRET = process.env.JWT_SECRET || 'hjpdv_secret_2025';

app.use(cors());
app.use(express.json());

// Banco em JSON persistido no volume do Railway
const DB_PATH = path.join(__dirname, 'data', 'licenses.json');
function loadDB() {
  if (!fs.existsSync(path.dirname(DB_PATH))) fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, JSON.stringify({ keys: {} }));
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function saveDB(db) { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }

// JWT sem dependencia externa
function signToken(payload) {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const s = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest('base64url');
  return `${h}.${b}.${s}`;
}
function verifyToken(token) {
  try {
    const [h, b, s] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest('base64url');
    if (s !== expected) return null;
    const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function gerarChave(plano) {
  const r = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `HJPDV-${plano.slice(0,4).toUpperCase()}-${r.slice(0,4)}-${r.slice(4)}`;
}

// Validar chave (chamado pelo HTML ao logar)
app.post('/api/validate', (req, res) => {
  const { chave, cnpj } = req.body;
  if (!chave) return res.status(400).json({ ok: false, msg: 'Chave nao informada.' });
  const db = loadDB();
  const rec = db.keys[chave.toUpperCase().trim()];
  if (!rec)       return res.status(403).json({ ok: false, msg: 'Chave invalida.' });
  if (!rec.ativa) return res.status(403).json({ ok: false, msg: 'Chave revogada.' });
  if (rec.expira && Date.now() > rec.expira) return res.status(403).json({ ok: false, msg: 'Chave expirada.' });
  if (cnpj && !rec.cnpj) { rec.cnpj = cnpj; }
  if (cnpj && rec.cnpj && rec.cnpj !== cnpj)
    return res.status(403).json({ ok: false, msg: 'Chave vinculada a outro CNPJ.' });
  rec.ultimo_acesso = new Date().toISOString();
  rec.acessos = (rec.acessos || 0) + 1;
  saveDB(db);
  const token = signToken({ chave, plano: rec.plano, user: rec.descricao || 'Cliente', exp: Date.now() + 86400000 });
  res.json({ ok: true, token, plano: rec.plano, user: rec.descricao });
});

// Verificar token (checagem periodica do cliente)
app.post('/api/check', (req, res) => {
  const payload = verifyToken(req.body.token);
  if (!payload) return res.status(401).json({ ok: false, msg: 'Token expirado.' });
  const db = loadDB();
  const rec = db.keys[payload.chave];
  if (!rec || !rec.ativa) return res.status(403).json({ ok: false, msg: 'Chave revogada.' });
  res.json({ ok: true, plano: payload.plano, user: payload.user });
});

// Middleware admin
function adminAuth(req, res, next) {
  if (req.headers['x-admin-pass'] !== ADMIN_PASS) return res.status(401).json({ ok: false, msg: 'Acesso negado.' });
  next();
}

app.get('/api/admin/keys', adminAuth, (req, res) => res.json({ ok: true, keys: loadDB().keys }));

app.post('/api/admin/gerar', adminAuth, (req, res) => {
  const { plano = 'PRO', descricao = '', dias = 365 } = req.body;
  const chave = gerarChave(plano);
  const db = loadDB();
  db.keys[chave] = { plano, descricao, ativa: true, criada: new Date().toISOString(), expira: dias > 0 ? Date.now() + dias * 86400000 : null, cnpj: null, acessos: 0, ultimo_acesso: null };
  saveDB(db);
  res.json({ ok: true, chave });
});

app.post('/api/admin/revogar', adminAuth, (req, res) => {
  const db = loadDB();
  if (!db.keys[req.body.chave]) return res.status(404).json({ ok: false, msg: 'Nao encontrada.' });
  db.keys[req.body.chave].ativa = false;
  saveDB(db);
  res.json({ ok: true });
});

app.post('/api/admin/reativar', adminAuth, (req, res) => {
  const db = loadDB();
  if (!db.keys[req.body.chave]) return res.status(404).json({ ok: false, msg: 'Nao encontrada.' });
  db.keys[req.body.chave].ativa = true;
  saveDB(db);
  res.json({ ok: true });
});

// Servir o HTML
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`HJ PDV rodando na porta ${PORT}`));
