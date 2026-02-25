const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { createToken, invalidateToken, requireAuth } = require('../middleware/auth');
const router = express.Router();

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Çok fazla başarısız deneme. 15 dakika bekleyin.' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true
});

router.get('/login', (req, res) => {
    const reason = req.query.reason;
    res.sendFile('login.html', { root: './public' });
});

router.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli.' });
    }
    
    // Timing attack'a karşı - her zaman hash compare yap
    const validUser = username === process.env.ADMIN_USERNAME;
    const hash = process.env.ADMIN_PASSWORD_HASH || '$2a$12$invalidhashtopreventtimingattack000000000000000000000000';
    const validPass = await bcrypt.compare(password, hash);
    
    if (!validUser || !validPass) {
        return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });
    }
    
    const { token, jti } = createToken(username);
    
    res.cookie('adminToken', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 60 * 1000
    });
    
    res.json({ success: true });
});

router.post('/logout', requireAuth, (req, res) => {
    invalidateToken(req.user.jti);
    res.clearCookie('adminToken');
    res.json({ success: true });
});

module.exports = router;
