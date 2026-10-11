import express from 'express';
import multer from 'multer';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import QRCode from 'qrcode';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const DATA = path.resolve(process.env.DATA_DIR || (process.env.NODE_ENV === 'production' ? '/data' : path.join(here, 'data')));
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
CREATE TABLE IF NOT EXISTS media(id INTEGER PRIMARY KEY, post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE, kind TEXT, file TEXT UNIQUE, mime TEXT, size INTEGER, pos INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS pix_transactions(identifier TEXT PRIMARY KEY, transaction_id TEXT, amount REAL NOT NULL, status TEXT NOT NULL, client_email TEXT, pix_code TEXT, pix_image TEXT, webhook_token TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL, plan TEXT NOT NULL DEFAULT '1');
CREATE TABLE IF NOT EXISTS subscriptions(id INTEGER PRIMARY KEY, client_email TEXT NOT NULL, plan TEXT NOT NULL, starts_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'ACTIVE', pix_identifier TEXT NOT NULL UNIQUE, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS subscriptions_email_status ON subscriptions(client_email,status,expires_at);
CREATE TABLE IF NOT EXISTS webhook_events(event_key TEXT PRIMARY KEY, event TEXT NOT NULL, received INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS site_visits(id INTEGER PRIMARY KEY, visited_at INTEGER NOT NULL);`);

// Migração segura para bancos já existentes no Railway.
try { db.exec("ALTER TABLE pix_transactions ADD COLUMN plan TEXT NOT NULL DEFAULT '1'"); } catch (e) { if (!String(e.message).includes('duplicate column name')) throw e; }

// ---------- autenticaÃ§Ã£o ----------
const hashPw = (p, s) => crypto.scryptSync(p, s, 64).toString('hex');
if (!db.prepare('SELECT 1 FROM admin').get()) {
  const { ADMIN_EMAIL: e, ADMIN_PASSWORD: p } = process.env;
  if (!e || !p || p.length < 12) { console.error('Defina ADMIN_EMAIL e ADMIN_PASSWORD (mÃ­nimo 12 caracteres) no primeiro inÃ­cio.'); process.exit(1); }
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
const guard = (req, res, next) => isAdmin(req) ? next() : res.status(401).json({ error: 'NÃ£o autenticado.' });

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
      if (!d || (only && d[0] !== only)) throw new Error(`Formato nÃ£o suportado: ${f.originalname}. Use JPG, PNG, WEBP, GIF, MP4, MOV ou WEBM.`);
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

// ---------- gateways / OmegaPayments ----------
// Credenciais sÃ£o criptografadas em repouso com uma chave derivada do segredo de inicializaÃ§Ã£o.
// Em produÃ§Ã£o, defina ADMIN_PASSWORD estÃ¡vel e mantenha-o fora do cÃ³digo-fonte.
const gatewayCipherKey = crypto.scryptSync(process.env.ADMIN_PASSWORD || 'missing-admin-password', 'site-gateway-config-v1', 32);
function encryptSecret(value) {
  if (!value) return '';
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', gatewayCipherKey, iv);
  const data = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
}
function decryptSecret(value) {
  if (!value) return '';
  try { const b = Buffer.from(value, 'base64'), iv=b.subarray(0,12), tag=b.subarray(12,28), data=b.subarray(28);
    const d=crypto.createDecipheriv('aes-256-gcm', gatewayCipherKey, iv); d.setAuthTag(tag);
    return Buffer.concat([d.update(data),d.final()]).toString('utf8');
  } catch { return ''; }
}
const getGatewayConfig = () => {
  const raw = db.prepare("SELECT v FROM settings WHERE k='gateways' ").get()?.v;
  let cfg={}; try { cfg=JSON.parse(raw||'{}'); } catch {}
  return { omega: { enabled: !!cfg.omega?.enabled, publicKey: decryptSecret(cfg.omega?.publicKeyEnc), secretKey: decryptSecret(cfg.omega?.secretKeyEnc), webhookToken: decryptSecret(cfg.omega?.webhookTokenEnc) } };
};
function saveGatewayConfig(cfg) {
  db.prepare("INSERT INTO settings(k,v) VALUES('gateways',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(JSON.stringify({omega:{enabled:!!cfg.omega.enabled, publicKeyEnc:encryptSecret(cfg.omega.publicKey), secretKeyEnc:encryptSecret(cfg.omega.secretKey), webhookTokenEnc:encryptSecret(cfg.omega.webhookToken)}}));
}
const publicGatewayState = () => { const c=getGatewayConfig().omega; return {omega:{enabled:c.enabled,configured:!!(c.publicKey&&c.secretKey),name:'OmegaPayments'}}; };

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
// CSRF: cabeÃ§alho customizado obrigatÃ³rio em toda escrita (sem CORS, navegadores nÃ£o o enviam de outros sites) + SameSite=Strict
app.use('/api/admin', (req, res, next) => (req.method === 'GET' || req.headers['x-csrf'] === '1') ? next() : res.status(403).json({ error: 'RequisiÃ§Ã£o invÃ¡lida.' }));

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
app.get('/api/admin/gateways', guard, (req,res) => {
  let c=getGatewayConfig().omega;
  if (!c.webhookToken) {
    c={...c,webhookToken:crypto.randomBytes(32).toString('hex')};
    saveGatewayConfig({omega:c});
  }
  res.json({omega:{enabled:c.enabled,publicKey:c.publicKey,secretKeyConfigured:!!c.secretKey,webhookTokenConfigured:!!c.webhookToken,configured:!!(c.publicKey&&c.secretKey)}});
});
app.put('/api/admin/gateways', guard, (req,res) => {
  const body=req.body||{}, old=getGatewayConfig().omega;
  const publicKey=String(body.publicKey??old.publicKey).trim();
  const secretKey=String(body.secretKey||old.secretKey).trim();
  const webhookToken=String(body.webhookToken||old.webhookToken||crypto.randomBytes(32).toString('hex')).trim();
  if (publicKey.length>500 || secretKey.length>1000 || webhookToken.length>500) return res.status(400).json({error:'Credenciais invÃ¡lidas.'});
  if (body.enabled && (!publicKey || !secretKey || !webhookToken)) return res.status(400).json({error:'Para ativar, informe chave pÃºblica e chave secreta.'});
  saveGatewayConfig({omega:{enabled:body.enabled===undefined?old.enabled:!!body.enabled,publicKey,secretKey,webhookToken}});
  res.json({ok:true,...publicGatewayState()});
});
// Checkout Pix: o preço é sempre lido do perfil salvo no servidor.
app.post('/api/pix/create', async (req,res) => {
  const cfg=getGatewayConfig().omega;
  if(!cfg.enabled || !cfg.publicKey || !cfg.secretKey || !cfg.webhookToken) {
    return res.status(503).json({error:'Pagamento Pix temporariamente indisponível. Confira a configuração do gateway.'});
  }
  const {name,email,phone='',document='',plan='1'}=req.body||{};
  const buyerName=typeof name==='string'?name.trim():'';
  const buyerEmail=typeof email==='string'?email.trim():'';
  if(buyerName.length<2||buyerName.length>120||!/^\S+@\S+\.\S+$/.test(buyerEmail)||buyerEmail.length>180) {
    return res.status(400).json({error:'Informe nome e e-mail válidos.'});
  }
  const profile=getProfile(), prices={'1':Number(profile.price1),'3':Number(profile.price3),'6':Number(profile.price6)};
  const amount=prices[String(plan)];
  if(!Number.isFinite(amount)||amount<0.01) return res.status(400).json({error:'Plano ou preço inválido.'});

  const identifier='site_'+crypto.randomUUID().replaceAll('-','');
  const base=`${req.protocol}://${req.get('host')}`;
  const callbackUrl=`${base}/api/webhooks/omegapay/${encodeURIComponent(identifier)}`;
  // O provedor exige vencimento em data futura, telefone e documento do cliente.
  // Use uma data UTC futura com margem para evitar falha quando a data local virar.
  const dueDate=new Date(Date.now()+48*60*60*1000).toISOString().slice(0,10);
  const normalizedPhone=String(phone||'').trim();
  const normalizedDocument=String(document||'').trim();
  if (!normalizedPhone || !normalizedDocument) {
    return res.status(400).json({error:'Para gerar o Pix, informe telefone e CPF/CNPJ.'});
  }
  const payload={
    identifier,amount,callbackUrl,dueDate,
    client:{name:buyerName,email:buyerEmail,phone:normalizedPhone.slice(0,30),document:normalizedDocument.slice(0,30)},
    products:[{id:'subscription_'+plan,name:`Assinatura ${plan} ${plan==='1'?'mês':'meses'}`,quantity:1,price:amount}],
    metadata:{provider:'site',orderId:identifier,plan:String(plan)}
  };
  try {
    const r=await fetch('https://app.omegapayments.com.br/api/v1/gateway/pix/receive',{
      method:'POST',
      headers:{'content-type':'application/json','x-public-key':cfg.publicKey,'x-secret-key':cfg.secretKey},
      body:JSON.stringify(payload),
      signal:AbortSignal.timeout(20000)
    });
    const data=await r.json().catch(()=>({}));
    // Normaliza os formatos de resposta mais comuns sem expor a resposta completa ao comprador.
    const root=data?.data&&typeof data.data==='object'?data.data:data;
    const transaction=root?.transaction||root?.data?.transaction||data?.transaction||{};
    const pix=root?.pix||root?.payment?.pix||root?.payment||transaction?.pixInformation||transaction?.pix_information||root?.pixInformation||root?.pix_information||{};
    const pixCode=pix?.code||pix?.qrCode||pix?.qr_code||pix?.copyPaste||pix?.copy_paste||pix?.brCode||pix?.pixCode||pix?.pixCopyPaste||root?.pixCode||root?.pixCopyPaste||root?.pix_code||root?.qrCode||root?.qr_code||transaction?.pixInformation?.qrCode||transaction?.pix_information?.qrCode;
    const pixImage=pix?.image||pix?.qrImage||pix?.qr_image||pix?.pixImage||pix?.pixQrCode||root?.pixImage||root?.pixQrCode||root?.pix_qr_code||transaction?.pixInformation?.image||transaction?.pix_information?.image||null;
    const transactionId=root?.transactionId||root?.transaction_id||root?.paymentId||root?.payment_id||root?.id||transaction?.id;
    const status=String(root?.transactionStatus||root?.transaction_status||root?.status||root?.transaction?.status||'PENDING').toUpperCase();
    if(!r.ok||!pixCode||!transactionId) {
      const providerError = root?.message || root?.error || root?.detail || root?.description || data?.message || data?.error || data?.detail || null;
      const providerCode = root?.code || root?.errorCode || data?.code || data?.errorCode || null;
      const validationDetails = root?.details ?? data?.details ?? null;
      console.error('OmegaPayments Pix: resposta inválida',JSON.stringify({httpStatus:r.status,providerStatus:root?.status||null,providerCode:providerCode?String(providerCode).slice(0,120):null,providerError:providerError?String(providerError).slice(0,500):null,validationDetails, responseKeys:Object.keys(root||{}).slice(0,30),hasPixCode:!!pixCode,hasTransactionId:!!transactionId}));
      return res.status(502).json({error:r.status===401||r.status===403?'A OmegaPayments recusou as credenciais. Confira as chaves do gateway.':r.status===400?'A OmegaPayments rejeitou os dados da cobrança. Confira a configuração do gateway.':'A OmegaPayments não retornou o código Pix esperado. Confira as chaves e tente novamente.'});
    }
    const now=Date.now();
    db.prepare('INSERT INTO pix_transactions(identifier,transaction_id,amount,status,client_email,pix_code,pix_image,webhook_token,created,updated,plan) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
      .run(identifier,String(transactionId),amount,status,buyerEmail,String(pixCode),String(pixImage||''),String(root?.webhookToken||data?.webhookToken||cfg.webhookToken),now,now,String(plan));
    let qrImage=pixImage?String(pixImage):null;
    if(!qrImage) {
      try { qrImage=await QRCode.toDataURL(String(pixCode),{width:320,margin:2,errorCorrectionLevel:'M'}); }
      catch(qrError) { console.error('Falha ao gerar QR Code Pix no servidor',qrError?.message||'erro'); }
    }
    res.set('Cache-Control','no-store');
    res.json({ok:true,identifier,transactionId:String(transactionId),amount,pix:{code:String(pixCode),image:qrImage,expiresAt:pix?.expiresAt||pix?.expires_at||root?.expiresAt||root?.expires_at||dueDate}});
  } catch (e) {
    console.error('OmegaPayments Pix: falha de conexão',e?.name||'Error',e?.cause?.code||'');
    return res.status(502).json({error:e?.name==='TimeoutError'?'A OmegaPayments demorou para responder. Verifique as cobranças antes de tentar novamente.':'Não foi possível conectar à OmegaPayments. Tente novamente em instantes.'});
  }
});

function handleOmegaWebhook(req,res) {
  const body=req.body||{};
  // A OmegaPayments envia o identificador da aplicação dentro de transaction.identifier.
  // O callback individual também pode fornecer o identificador na própria URL.
  const identifier=String(req.params.identifier||body.transaction?.identifier||body.identifier||body.metadata?.orderId||'').trim();
  if(!identifier) return res.status(400).json({error:'Identificador da transação ausente.'});
  const tx=db.prepare('SELECT * FROM pix_transactions WHERE identifier=?').get(identifier);
  if(!tx) return res.sendStatus(404);

  const supplied=String(body.token||'');
  const configuredToken=String(getGatewayConfig().omega.webhookToken||'');
  const expectedTokens=[tx.webhook_token,configuredToken].filter(Boolean).map(String);
  const validToken=expectedTokens.some(expected=>Buffer.byteLength(supplied)===Buffer.byteLength(expected)&&crypto.timingSafeEqual(Buffer.from(supplied),Buffer.from(expected)));
  const event=String(body.event||'');
  const statusMap={'TRANSACTION_PAID':'COMPLETED','TRANSACTION_CREATED':'PENDING','TRANSACTION_CANCELED':'CANCELED','TRANSACTION_REFUNDED':'REFUNDED','TRANSACTION_CHARGED_BACK':'CHARGED_BACK','TRANSACTION_FAILED':'FAILED'};
  const status=statusMap[event];
  if(!validToken || !status) return res.sendStatus(401);

  const eventKey=String(body.eventId||body.id||`${event}:${body.transaction?.id||body.transactionId||identifier}:${body.occurredAt||body.timestamp||''}`).slice(0,250);
  if(db.prepare('SELECT 1 FROM webhook_events WHERE event_key=?').get(eventKey)) return res.json({ok:true,duplicate:true});
  const now=Date.now();
  const insert=db.prepare('INSERT INTO webhook_events(event_key,event,received) VALUES(?,?,?)');
  const update=db.prepare('UPDATE pix_transactions SET status=?,updated=? WHERE identifier=?');
  const activate = db.prepare("INSERT INTO subscriptions(client_email,plan,starts_at,expires_at,status,pix_identifier,created) VALUES(?,?,?,?, 'ACTIVE',?,?) ON CONFLICT(pix_identifier) DO UPDATE SET client_email=excluded.client_email,plan=excluded.plan,expires_at=excluded.expires_at,status='ACTIVE'");
  // node:sqlite DatabaseSync não possui db.transaction(); use transação SQL explícita.
  try {
    db.exec('BEGIN IMMEDIATE');
    insert.run(eventKey,event,now);
    update.run(status,now,identifier);
    if (status === 'COMPLETED' && tx.client_email) {
      const months = Math.max(1, Math.min(6, Number(tx.plan) || 1));
      const existing = db.prepare("SELECT MAX(expires_at) AS expires_at FROM subscriptions WHERE client_email=? AND status='ACTIVE' AND expires_at>?").get(tx.client_email,now)?.expires_at;
      const startsAt = Math.max(now, Number(existing)||0);
      const expiresAt = new Date(startsAt).setMonth(new Date(startsAt).getMonth()+months);
      activate.run(tx.client_email, String(months), startsAt, expiresAt, identifier, now);
    } else if (['REFUNDED','CHARGED_BACK'].includes(status)) {
      db.prepare("UPDATE subscriptions SET status='REVOKED' WHERE pix_identifier=?").run(identifier);
    }
    db.exec('COMMIT');
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch {}
    throw err;
  }
  return res.status(200).json({ok:true});
}
app.post('/api/webhooks/omegapay', handleOmegaWebhook);
app.post('/api/webhooks/omegapay/:identifier', handleOmegaWebhook);


app.get('/api/admin/state', guard, (req, res) =>
  res.json({ profile: getProfile(), posts: db.prepare('SELECT * FROM posts ORDER BY created DESC').all().map(p => shape(p, true)) }));

app.get('/api/admin/subscriptions', guard, (req, res) => {
  const now = Date.now();
  const rows = db.prepare(`SELECT s.id,s.client_email,s.plan,s.starts_at,s.expires_at,s.status,s.pix_identifier,s.created,t.status AS payment_status,t.amount
    FROM subscriptions s LEFT JOIN pix_transactions t ON t.identifier=s.pix_identifier
    ORDER BY s.created DESC`).all();
  res.set('Cache-Control', 'no-store');
  res.json({subscriptions: rows.map(s => ({
    ...s,
    status: s.status !== 'ACTIVE' ? s.status : (Number(s.expires_at) <= now ? 'EXPIRED' : 'ACTIVE')
  }))});
});

app.get('/api/admin/dashboard', guard, (req, res) => {
  const visits = db.prepare('SELECT COUNT(*) AS n FROM site_visits').get().n;
  const pix = db.prepare('SELECT COUNT(*) AS total, SUM(CASE WHEN status=\'COMPLETED\' THEN 1 ELSE 0 END) AS paid, COALESCE(SUM(CASE WHEN status=\'COMPLETED\' THEN amount ELSE 0 END),0) AS revenue FROM pix_transactions').get();
  res.set('Cache-Control', 'no-store');
  res.json({ visits, pixGenerated: pix.total || 0, pixPaid: pix.paid || 0, revenue: pix.revenue || 0 });
});

app.post('/api/admin/posts', guard, upload.array('files'), (req, res) => {
  const b = req.body || {}, pub = flag(b.published);
  if (pub && !req.files?.length) { (req.files || []).forEach(f => fs.rmSync(f.path, { force: true })); throw new Error('Envie ao menos uma imagem ou vÃ­deo para publicar.'); }
  const now = Date.now();
  const id = db.prepare('INSERT INTO posts(caption,published,locked,created,updated) VALUES(?,?,?,?,?)')
    .run(String(b.caption || '').slice(0, 2000), pub, flag(b.locked ?? '1'), now, now).lastInsertRowid;
  try { addMedia(id, req.files); } catch (e) { db.prepare('DELETE FROM posts WHERE id=?').run(id); throw e; }
  res.json(shape(db.prepare('SELECT * FROM posts WHERE id=?').get(id), true));
});

app.put('/api/admin/posts/:id', guard, upload.array('files'), (req, res) => {
  const id = +req.params.id, p = db.prepare('SELECT * FROM posts WHERE id=?').get(id);
  if (!p) { (req.files || []).forEach(f => fs.rmSync(f.path, { force: true })); return res.status(404).json({ error: 'PublicaÃ§Ã£o nÃ£o encontrada.' }); }
  const b = req.body || {};
  const remove = [].concat(b.remove || []).map(Number).filter(Boolean);
  const gone = remove.length ? db.prepare(`SELECT file FROM media WHERE post_id=? AND id IN (${remove.map(() => '?').join(',')})`).all(id, ...remove) : [];
  if (b.published !== undefined && flag(b.published)) {
    const left = mediaOf(id).length - gone.length + (req.files?.length || 0);
    if (left < 1) { (req.files || []).forEach(f => fs.rmSync(f.path, { force: true })); throw new Error('Envie ao menos uma imagem ou vÃ­deo para publicar.'); }
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

// ---------- pÃºblico ----------
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
app.get('/', (req, res, next) => {
  try { db.prepare('INSERT INTO site_visits(visited_at) VALUES(?)').run(Date.now()); } catch {}
  res.sendFile(path.join(here, 'public', 'index.html'), err => { if (err && !res.headersSent) next(err); });
});
app.use(express.static(path.join(here, 'public'), { index: false, extensions: [] }));
app.use((e, req, res, next) => {
  const big = e.code === 'LIMIT_FILE_SIZE';
  res.status(big ? 413 : e.status || 400).json({ error: big ? `Arquivo maior que ${MAX_MB} MB.` : e.message });
});
app.listen(process.env.PORT || 3000, () => console.log('Servidor em http://localhost:' + (process.env.PORT || 3000)));
