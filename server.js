import express from 'express';
import multer from 'multer';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const DATA = path.resolve(process.env.DATA_DIR || path.join(here, 'data'));
const UP = path.join(DATA, 'uploads'), TMP = path.join(DATA, 'tmp');
fs.mkdirSync(UP, { recursive: true }); fs.mkdirSync(TMP, { recursive: true });
const PROD = process.env.NODE_ENV === 'production';
const MAX_MB = +(process.env.MAX_UPLOAD_MB || 300);

const db = new DatabaseSync(path.join(DATA, 'site.db'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY, email TEXT UNIQUE, salt TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, expires INTEGER);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, caption TEXT DEFAULT '', published INTEGER DEFAULT 0, locked INTEGER DEFAULT 1, created INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS media(id INTEGER PRIMARY KEY, post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, kind TEXT, file TEXT UNIQUE, mime TEXT, size INTEGER, pos INTEGER DEFAULT 0);`);

// ---------- autenticação ----------
const hashPw = (p, s) => crypto.scryptSync(p, s, 64).toString('hex');
if (!db.prepare('SELECT 1 FROM admin').get()) {
  const { ADMIN_EMAIL: e, ADMIN_PASSWORD: p } = process.env;
  if (!e || !p || p.length < 12) { console.error('Defina ADMIN_EMAIL e ADMIN_PASSWORD (mínimo 12 caracteres) no primeiro início.'); process.exit(1); }
  const s = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO admin(email,salt,hash) VALUES(?,?,?)').run(e.toLowerCase(), s, hashPw(p, s));
}
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const getCookie = (req, n) => (req.headers.cookie || '').split(/;\s*/).map(c => c.split('=')).find(c => c[0] === n)?.[1];
const isAdmin = req => {
  const t = getCookie(req, 'sid'); if (!t) return false;
  const r = db.prepare('SELECT expires FROM sessions WHERE token=?').get(sha(t));
  return !!r && r.expires > Date.now();
};
const guard = (req, res, next) => isAdmin(req) ? next() : res.status(401).json({ error: 'Não autenticado.' });

// ---------- perfil ----------
const DEF = { name: 'Seu nome', handle: '@seuperfil', bio: '', price1: 53.48, price3: 136.36, price6: 224.6, avatar: '', cover: '' };
const getProfile = () => ({ ...DEF, ...JSON.parse(db.prepare("SELECT v FROM settings WHERE k='profile'").get()?.v || '{}') });
const saveProfile = p => db.prepare("INSERT INTO settings(k,v) VALUES('profile',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(JSON.stringify(p));

// ---------- arquivos ----------
const rm = f => f && fs.rmSync(path.join(UP, path.basename(f)), { force: true });
function detect(f) {
  const b = Buffer.alloc(16), fd = fs.openSync(f, 'r'); fs.readSync(fd, b, 0, 16, 0); fs.closeSync(fd);
  if (b[0] === 0xFF && b[1] === 0xD8) return ['image', 'jpg', 'image/jpeg'];
  if (b.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))) return ['image', 'png', 'image/png'];
  if (b.subarray(0, 3).toString() === 'GIF') return ['image', 'gif', 'image/gif'];
  if (b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP') return ['image', 'webp', 'image/webp'];
  if (b.subarray(4, 8).toString() === 'ftyp') {
    const brand = b.subarray(8, 12).toString();
    if (/^(heic|heix|hevc|hevx|mif1|msf1)/.test(brand)) return null;
    return brand === 'qt  ' ? ['video', 'mov', 'video/quicktime'] : ['video', 'mp4', 'video/mp4'];
  }
  if (b[0] === 0x1A && b[1] === 0x45 && b[2] === 0xDF && b[3] === 0xA3) return ['video', 'webm', 'video/webm'];
  return null;
}
function store(files = [], only) {
  const out = [];
  try {
    for (const f of files) {
      const d = detect(f.path);
      if (!d || (only && d[0] !== only)) throw new Error(`Formato não suportado: ${f.originalname}. Use JPG, PNG, WEBP, GIF, MP4, MOV ou WEBM.`);
      out.push({ kind: d[0], mime: d[2], size: f.size, file: crypto.randomUUID() + '.' + d[1], tmp: f.path });
    }
  } catch (e) { files.forEach(f => fs.rmSync(f.path, { force: true })); throw e; }
  out.forEach(o => fs.renameSync(o.tmp, path.join(UP, o.file)));
  return out;
}
const upload = multer({ dest: TMP, limits: { fileSize: MAX_MB * 1048576, files: 30 } });

// ---------- posts ----------
const mediaOf = id => db.prepare('SELECT id,kind,file FROM media WHERE post_id=? ORDER BY pos,id').all(id);
function shape(p, full) {
  const m = mediaOf(p.id);
  return {
    id: p.id, caption: p.caption, published: !!p.published, locked: !!p.locked, created: p.created,
    images: m.filter(x => x.kind === 'image').length, videos: m.filter(x => x.kind === 'video').length,
    media: (full || !p.locked) ? m.map(x => ({ id: x.id, kind: x.kind, url: '/media/' + x.file })) : []
  };
}
const addMedia = (postId, files) => {
  let pos = db.prepare('SELECT COALESCE(MAX(pos),0) n FROM media WHERE post_id=?').get(postId).n;
  for (const o of store(files)) db.prepare('INSERT INTO media(post_id,kind,file,mime,size,pos) VALUES(?,?,?,?,?,?)').run(postId, o.kind, o.file, o.mime, o.size, ++pos);
};
const flag = v => (v === '1' || v === 'true' || v === 1 || v === true) ? 1 : 0;

// ---------- app ----------
const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self'; frame-ancestors 'none'"
  });
  next();
});
app.use(express.json({ limit: '100kb' }));
// CSRF: cabeçalho customizado obrigatório em toda escrita (sem CORS, navegadores não o enviam de outros sites) + SameSite=Strict
app.use('/api/admin', (req, res, next) => (req.method === 'GET' || req.headers['x-csrf'] === '1') ? next() : res.status(403).json({ error: 'Requisição inválida.' }));

const tries = new Map();
app.post('/api/admin/login', (req, res) => {
  const now = Date.now(), t = (tries.get(req.ip) || []).filter(x => now - x < 9e5);
  if (t.length >= 5) return res.status(429).json({ error: 'Muitas tentativas. Aguarde 15 minutos.' });
  const { email = '', password = '' } = req.body || {};
  const a = db.prepare('SELECT * FROM admin WHERE email=?').get(String(email).toLowerCase());
  const h = hashPw(String(password), a?.salt || '0');
  if (!a || !crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(a.hash, 'hex'))) {
    t.push(now); tries.set(req.ip, t); return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  }
  tries.delete(req.ip);
  db.prepare('DELETE FROM sessions WHERE expires<?').run(now);
  const tok = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?)').run(sha(tok), now + 7 * 864e5);
  res.set('Set-Cookie', `sid=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${PROD ? '; Secure' : ''}`);
  res.json({ ok: 1 });
});
app.post('/api/admin/logout', (req, res) => {
  const t = getCookie(req, 'sid'); if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(sha(t));
  res.set('Set-Cookie', 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); res.json({ ok: 1 });
});
app.get('/api/admin/me', guard, (req, res) => res.json({ ok: 1 }));

app.get('/api/admin/state', guard, (req, res) =>
  res.json({ profile: getProfile(), posts: db.prepare('SELECT * FROM posts ORDER BY created DESC').all().map(p => shape(p, true)) }));

app.post('/api/admin/posts', guard, upload.array('files'), (req, res) => {
  const b = req.body || {}, pub = flag(b.published);
  if (pub && !req.files?.length) { (req.files || []).forEach(f => fs.rmSync(f.path, { force: true })); throw new Error('Envie ao menos uma imagem ou vídeo para publicar.'); }
  const now = Date.now();
  const id = db.prepare('INSERT INTO posts(caption,published,locked,created,updated) VALUES(?,?,?,?,?)')
    .run(String(b.caption || '').slice(0, 2000), pub, flag(b.locked ?? '1'), now, now).lastInsertRowid;
  try { addMedia(id, req.files); } catch (e) { db.prepare('DELETE FROM posts WHERE id=?').run(id); throw e; }
  res.json(shape(db.prepare('SELECT * FROM posts WHERE id=?').get(id), true));
});

app.put('/api/admin/posts/:id', guard, upload.array('files'), (req, res) => {
  const id = +req.params.id, p = db.prepare('SELECT * FROM posts WHERE id=?').get(id);
  if (!p) { (req.files || []).forEach(f => fs.rmSync(f.path, { force: true })); return res.status(404).json({ error: 'Publicação não encontrada.' }); }
  const b = req.body || {};
  const remove = [].concat(b.remove || []).map(Number).filter(Boolean);
  const gone = remove.length ? db.prepare(`SELECT file FROM media WHERE post_id=? AND id IN (${remove.map(() => '?').join(',')})`).all(id, ...remove) : [];
  if (b.published !== undefined && flag(b.published)) {
    const left = mediaOf(id).length - gone.length + (req.files?.length || 0);
    if (left < 1) { (req.files || []).forEach(f => fs.rmSync(f.path, { force: true })); throw new Error('Envie ao menos uma imagem ou vídeo para publicar.'); }
  }
  addMedia(id, req.files);
  if (gone.length) { db.prepare(`DELETE FROM media WHERE post_id=? AND id IN (${remove.map(() => '?').join(',')})`).run(id, ...remove); gone.forEach(g => rm(g.file)); }
  db.prepare('UPDATE posts SET caption=?,published=?,locked=?,updated=? WHERE id=?').run(
    b.caption !== undefined ? String(b.caption).slice(0, 2000) : p.caption,
    b.published !== undefined ? flag(b.published) : p.published,
    b.locked !== undefined ? flag(b.locked) : p.locked, Date.now(), id);
  res.json(shape(db.prepare('SELECT * FROM posts WHERE id=?').get(id), true));
});

app.delete('/api/admin/posts/:id', guard, (req, res) => {
  const id = +req.params.id, files = mediaOf(id);
  db.prepare('DELETE FROM posts WHERE id=?').run(id); files.forEach(f => rm(f.file)); res.json({ ok: 1 });
});

app.put('/api/admin/profile', guard, upload.fields([{ name: 'avatar', maxCount: 1 }, { name: 'cover', maxCount: 1 }]), (req, res) => {
  const p = getProfile(), b = req.body || {};
  const all = Object.values(req.files || {}).flat();
  try {
    const saved = {};
    for (const k of ['avatar', 'cover']) if (req.files?.[k]?.[0]) saved[k] = store([req.files[k][0]], 'image')[0].file;
    for (const k of ['name', 'handle', 'bio']) if (typeof b[k] === 'string') p[k] = b[k].slice(0, k === 'bio' ? 600 : 80);
    for (const k of ['price1', 'price3', 'price6']) if (b[k] !== undefined && b[k] !== '' && isFinite(+b[k]) && +b[k] >= 0) p[k] = +b[k];
    for (const k in saved) { rm(p[k]); p[k] = saved[k]; }
    saveProfile(p);
  } catch (e) { all.forEach(f => fs.rmSync(f.path, { force: true })); throw e; }
  res.json(p);
});

// ---------- público ----------
app.get('/api/public', (req, res) => {
  const p = getProfile();
  const posts = db.prepare('SELECT * FROM posts WHERE published=1 ORDER BY created DESC').all().map(x => shape(x, false));
  const sum = k => posts.reduce((n, x) => n + x[k], 0);
  res.set('Cache-Control', 'no-cache');
  res.json({
    profile: { ...p, avatar: p.avatar && '/media/' + p.avatar, cover: p.cover && '/media/' + p.cover },
    counts: { posts: posts.length, images: sum('images'), videos: sum('videos') }, posts
  });
});

app.get('/media/:file', (req, res) => {
  const f = path.basename(req.params.file), p = getProfile(), adm = isAdmin(req);
  const ok = adm || f === p.avatar || f === p.cover ||
    !!db.prepare('SELECT 1 FROM media m JOIN posts p ON p.id=m.post_id WHERE m.file=? AND p.published=1 AND p.locked=0').get(f);
  if (!ok) return res.sendStatus(404);
  res.set('Cache-Control', adm ? 'private, no-cache' : 'public, max-age=300');
  res.sendFile(path.join(UP, f), e => { if (e && !res.headersSent) res.sendStatus(404); });
});

app.get('/admin', (req, res) => res.set('X-Robots-Tag', 'noindex').sendFile(path.join(here, 'public', 'admin.html')));
app.use(express.static(path.join(here, 'public'), { index: 'index.html', extensions: [] }));
app.use((e, req, res, next) => {
  const big = e.code === 'LIMIT_FILE_SIZE';
  res.status(big ? 413 : e.status || 400).json({ error: big ? `Arquivo maior que ${MAX_MB} MB.` : e.message });
});
app.listen(process.env.PORT || 3000, () => console.log('Servidor em http://localhost:' + (process.env.PORT || 3000)));
