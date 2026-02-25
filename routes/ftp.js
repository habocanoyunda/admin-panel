const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

router.use(requireAuth);

// İzin verilen dizin - sadece bot klasörü
const BASE_DIR = path.resolve(process.env.BOT_DIR || path.join(process.cwd(), '..'));

function safePath(reqPath) {
    if (!reqPath) return BASE_DIR;
    // Normalize slashes
    const clean = reqPath.replace(/\\/g, '/').replace(/\.\./g, '').replace(/^\//, '');
    const resolved = path.resolve(BASE_DIR, clean);
    if (!resolved.startsWith(BASE_DIR)) return BASE_DIR;
    return resolved;
}

// Dosya listesi
router.get('/list', (req, res) => {
    try {
        const dir = safePath(req.query.path || '');
        const items = fs.readdirSync(dir).map(name => {
            const full = path.join(dir, name);
            const stat = fs.statSync(full);
            return {
                name,
                type: stat.isDirectory() ? 'dir' : 'file',
                size: stat.size,
                modified: stat.mtime
            };
        }).filter(i => !i.name.startsWith('.') && i.name !== 'node_modules');
        res.json({ items, currentPath: path.relative(BASE_DIR, dir) || '/' });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// Dosya oku
router.get('/file', (req, res) => {
    try {
        const filePath = safePath(req.query.path);
        const stat = fs.statSync(filePath);
        if (stat.isDirectory()) return res.status(400).json({ error: 'Dizin.' });
        if (stat.size > 1024 * 1024) return res.status(400).json({ error: 'Dosya 1MB\'dan büyük.' });
        const content = fs.readFileSync(filePath, 'utf8');
        res.json({ content, path: req.query.path });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// Dosya kaydet
router.post('/file', (req, res) => {
    try {
        const { filePath, content } = req.body;
        const safe = safePath(filePath);
        // Sadece .js, .json, .env, .txt dosyalarına izin ver
        const ext = path.extname(safe).toLowerCase();
        if (!['.js', '.json', '.env', '.txt', '.md'].includes(ext)) {
            return res.status(400).json({ error: 'Bu dosya türü düzenlenemez.' });
        }
        fs.writeFileSync(safe, content, 'utf8');
        res.json({ success: true });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// Upload
const upload = multer({
    dest: '/tmp/uploads/',
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['.js', '.json', '.txt', '.md', '.env'];
        if (allowed.includes(path.extname(file.originalname).toLowerCase())) cb(null, true);
        else cb(new Error('Geçersiz dosya türü.'));
    }
});

router.post('/upload', upload.single('file'), (req, res) => {
    try {
        const dest = safePath(path.join(req.body.path || '', req.file.originalname));
        fs.renameSync(req.file.path, dest);
        res.json({ success: true });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

module.exports = router;
