const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.ADMIN_PORT || 3001;
const JWT_SECRET = process.env.ADMIN_JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_USER = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_HASH = process.env.ADMIN_PASSWORD_HASH; // bcrypt hash

// Bot state reference - bu modül bot ana dosyasından import edilecek
let botState = {
  active: true,
  model: process.env.MODEL || 'claude-haiku-4-5-20251001',
  systemPrompt: null,
  stats: { todayMessages: 0, inputTokens: 0, outputTokens: 0, totalTokens: 0 }
};

// ── MIDDLEWARE ──────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
    }
  }
}));

app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// File upload - memory storage, max 10MB
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

// Rate limiting - login endpoint
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Çok fazla deneme. 15 dakika bekleyin.' }
});

// Rate limiting - genel API
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Rate limit aşıldı.' }
});

app.use('/admin/api', apiLimiter);

// ── AUTH MIDDLEWARE ─────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies?.adminToken;
  if (!token) return res.status(401).json({ error: 'Yetkisiz erişim' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    res.clearCookie('adminToken');
    return res.status(401).json({ error: 'Oturum süresi doldu' });
  }
}

function requireAuthPage(req, res, next) {
  const token = req.cookies?.adminToken;
  if (!token) return res.redirect('/admin/login');
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie('adminToken');
    return res.redirect('/admin/login');
  }
}

// ── PAGES ───────────────────────────────────────────────────
app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/admin/dashboard', requireAuthPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/admin', (req, res) => res.redirect('/admin/login'));

// ── AUTH ENDPOINTS ──────────────────────────────────────────
app.post('/admin/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password ||
      typeof username !== 'string' || typeof password !== 'string' ||
      username.length > 50 || password.length > 200) {
    return res.status(400).json({ success: false, error: 'Geçersiz istek' });
  }

  // Timing-safe username comparison
  const userMatch = crypto.timingSafeEqual(
    Buffer.from(username.trim()),
    Buffer.from(ADMIN_USER)
  );

  if (!ADMIN_HASH) {
    return res.status(500).json({ error: 'Şifre hash ayarlanmamış. .env dosyasını kontrol edin.' });
  }

  const passMatch = await bcrypt.compare(password, ADMIN_HASH);

  if (!userMatch || !passMatch) {
    // Sabit gecikme - timing attack önlemi
    await new Promise(r => setTimeout(r, 500 + Math.random() * 500));
    return res.status(401).json({ success: false, error: 'Hatalı giriş' });
  }

  const token = jwt.sign(
    { user: ADMIN_USER, iat: Date.now() },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.cookie('adminToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000
  });

  res.json({ success: true });
});

app.post('/admin/logout', requireAuth, (req, res) => {
  res.clearCookie('adminToken');
  res.json({ success: true });
});

// ── API ENDPOINTS ───────────────────────────────────────────
app.get('/admin/api/status', requireAuth, (req, res) => {
  res.json({ active: botState.active, model: botState.model });
});

app.get('/admin/api/stats', requireAuth, (req, res) => {
  res.json(botState.stats);
});

// Kill switch
app.post('/admin/api/kill', requireAuth, (req, res) => {
  const { active } = req.body;
  if (typeof active !== 'boolean') return res.status(400).json({ error: 'Geçersiz değer' });
  botState.active = active;
  console.log(`[ADMIN] Kill switch: bot ${active ? 'aktif' : 'durduruldu'}`);
  res.json({ success: true, active: botState.active });
});

// Model change
app.post('/admin/api/model', requireAuth, (req, res) => {
  const ALLOWED_MODELS = [
    'claude-haiku-4-5-20251001',
    'claude-sonnet-4-6',
    'claude-opus-4-6'
  ];
  const { model } = req.body;
  if (!ALLOWED_MODELS.includes(model)) {
    return res.status(400).json({ error: 'Geçersiz model' });
  }
  botState.model = model;
  console.log(`[ADMIN] Model değiştirildi: ${model}`);
  res.json({ success: true, model });
});

// Prompt - get
app.get('/admin/api/prompt', requireAuth, (req, res) => {
  res.json({ prompt: botState.systemPrompt || '' });
});

// Prompt - set
app.post('/admin/api/prompt', requireAuth, (req, res) => {
  const { prompt } = req.body;
  if (typeof prompt !== 'string' || prompt.length > 50000) {
    return res.status(400).json({ error: 'Geçersiz prompt' });
  }
  botState.systemPrompt = prompt;
  console.log('[ADMIN] Sistem promptu güncellendi');
  res.json({ success: true });
});

// ── FTP ENDPOINTS ───────────────────────────────────────────
const BOT_ROOT = path.resolve(process.env.BOT_ROOT || path.join(__dirname, '..'));

function safePath(userPath) {
  const resolved = path.resolve(BOT_ROOT, '.' + userPath);
  if (!resolved.startsWith(BOT_ROOT)) return null; // Path traversal önlemi
  return resolved;
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// List directory
app.get('/admin/api/ftp/list', requireAuth, (req, res) => {
  const userPath = req.query.path || '/';
  const absPath = safePath(userPath);
  if (!absPath) return res.status(400).json({ error: 'Geçersiz yol' });

  try {
    const entries = fs.readdirSync(absPath);
    const files = entries
      .filter(name => !name.startsWith('.') && name !== 'node_modules')
      .map(name => {
        const fullPath = path.join(absPath, name);
        const stat = fs.statSync(fullPath);
        const relPath = '/' + path.relative(BOT_ROOT, fullPath).replace(/\\/g, '/');
        return {
          name,
          path: relPath,
          type: stat.isDirectory() ? 'dir' : 'file',
          size: stat.isDirectory() ? null : formatSize(stat.size),
          modified: stat.mtime.toLocaleString('tr-TR')
        };
      })
      .sort((a, b) => {
        if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

    res.json(files);
  } catch (e) {
    res.status(500).json({ error: 'Klasör okunamadı' });
  }
});

// Download file
app.get('/admin/api/ftp/download', requireAuth, (req, res) => {
  const userPath = req.query.path;
  if (!userPath) return res.status(400).json({ error: 'Yol belirtilmedi' });
  const absPath = safePath(userPath);
  if (!absPath) return res.status(400).json({ error: 'Geçersiz yol' });

  try {
    const stat = fs.statSync(absPath);
    if (stat.isDirectory()) return res.status(400).json({ error: 'Klasör indirilemez' });
    res.download(absPath);
  } catch {
    res.status(404).json({ error: 'Dosya bulunamadı' });
  }
});

// Upload file
app.post('/admin/api/ftp/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Dosya bulunamadı' });

  const userPath = req.body.path || '/';
  const absDir = safePath(userPath);
  if (!absDir) return res.status(400).json({ error: 'Geçersiz yol' });

  // Dosya adını sanitize et
  const safeName = path.basename(req.file.originalname).replace(/[^a-zA-Z0-9._\-]/g, '_');
  const destPath = path.join(absDir, safeName);

  try {
    fs.writeFileSync(destPath, req.file.buffer);
    res.json({ success: true, name: safeName });
  } catch {
    res.status(500).json({ error: 'Dosya yazılamadı' });
  }
});

// Delete file
app.post('/admin/api/ftp/delete', requireAuth, (req, res) => {
  const { path: userPath } = req.body;
  if (!userPath) return res.status(400).json({ error: 'Yol belirtilmedi' });
  const absPath = safePath(userPath);
  if (!absPath) return res.status(400).json({ error: 'Geçersiz yol' });

  // .env ve kritik dosyaları koruma
  const protectedFiles = ['.env', 'package.json', 'package-lock.json'];
  if (protectedFiles.includes(path.basename(absPath))) {
    return res.status(403).json({ error: 'Bu dosya silinemez' });
  }

  try {
    const stat = fs.statSync(absPath);
    if (stat.isDirectory()) {
      fs.rmSync(absPath, { recursive: true });
    } else {
      fs.unlinkSync(absPath);
    }
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Silme hatası' });
  }
});

// ── START ───────────────────────────────────────────────────
function startAdminServer() {
  app.listen(PORT, () => {
    console.log(`[ADMIN] Panel başlatıldı: http://localhost:${PORT}/admin/login`);
  });
  return botState;
}

module.exports = { startAdminServer, botState };
