require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
const http = require('http');
const tracker = require('./token_tracker');
const { WebSocketServer } = require('ws');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            connectSrc: ["'self'", "wss:", "ws:", "ws://localhost:3001"],
            imgSrc: ["'self'", "data:"]
        }
    }
}));

// Global rate limit
app.use(rateLimit({ windowMs: 60000, max: 100 }));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Bot token kaydı - auth middleware olmadan
const apiRouter = require('./routes/api');
app.post('/api/token-record', (req, res, next) => {
    const apiKey = req.headers['x-bot-api-key'];
    if (!apiKey || apiKey !== process.env.BOT_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const tracker = require('./token_tracker');
    const { model, input, output, source } = req.body;
    if (!model || input === undefined || output === undefined) return res.status(400).json({ error: 'Eksik veri' });
    tracker.record(model, parseInt(input), parseInt(output), source || 'bot');
    res.json({ success: true });
});

// Routes
app.use('/', require('./routes/auth'));
app.use('/api', require('./routes/api'));
app.use('/api/ftp', require('./routes/ftp'));

// Dashboard - auth gerekli
const { requireAuth } = require('./middleware/auth');
app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile('dashboard.html', { root: './public' });
});

// Root redirect
app.get('/', (req, res) => res.redirect('/login'));

// WebSocket - chat için
const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
    // Cookie'den token doğrula
    const cookieHeader = req.headers.cookie || '';
    const tokenMatch = cookieHeader.match(/adminToken=([^;]+)/);
    if (!tokenMatch) return ws.close(1008, 'Unauthorized');
    
    try {
        jwt.verify(tokenMatch[1], process.env.JWT_SECRET);
    } catch {
        return ws.close(1008, 'Unauthorized');
    }
    
    ws.on('message', async (data) => {
        try {
            const { message } = JSON.parse(data);
            if (!message || message.length > 4000) return;
            
            // Claude API çağrısı
            const response = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': process.env.ANTHROPIC_API_KEY,
                    'anthropic-version': '2023-06-01'
                },
                body: JSON.stringify({
                    model: process.env.BOT_MODEL || 'claude-haiku-4-5-20251001',
                    max_tokens: 1024,
                    system: 'Sen EMK Bot Admin Panel yardımcısısın. Kısa ve net cevaplar ver.',
                    messages: [{ role: 'user', content: message }]
                })
            });
            
            const result = await response.json();
            const text = result.content?.[0]?.text || 'Hata oluştu.';
            if(result.usage){
                const model = process.env.BOT_MODEL || 'claude-haiku-4-5-20251001';
                tracker.record(model, result.usage.input_tokens||0, result.usage.output_tokens||0, 'admin-chat');
            }
            ws.send(JSON.stringify({ type: 'message', content: text, usage: result.usage }));
        } catch (e) {
            ws.send(JSON.stringify({ type: 'error', content: 'İstek başarısız.' }));
        }
    });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
    console.log(`EMK Admin Panel: http://localhost:${PORT}`);
});
