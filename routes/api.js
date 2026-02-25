const express = require('express');
const tracker = require('../token_tracker');
const fs = require('fs');
const path = require('path');
const { requireAuth } = require('../middleware/auth');
const { invalidateAll } = require('../middleware/auth');
const router = express.Router();

router.use(requireAuth);

const PROMPT_FILE = path.join(__dirname, '..', 'prompt.txt');

function loadPrompt() {
    try {
        if (fs.existsSync(PROMPT_FILE)) return fs.readFileSync(PROMPT_FILE, 'utf8');
    } catch(e) {}
    return process.env.BOT_SYSTEM_PROMPT || '';
}

function savePrompt(text) {
    fs.writeFileSync(PROMPT_FILE, text, 'utf8');
}

let botState = {
    model: process.env.BOT_MODEL || 'claude-haiku-4-5-20251001',
    masterPrompt: loadPrompt(),
    totalTokens: { input: 0, output: 0 },
    isRunning: true
};

const AVAILABLE_MODELS = [
    { id: 'claude-haiku-4-5-20251001', name: 'Claude Haiku 4.5', speed: 'Hızlı', cost: 'Düşük' },
    { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6', speed: 'Orta', cost: 'Orta' },
    { id: 'claude-opus-4-6', name: 'Claude Opus 4.6', speed: 'Yavaş', cost: 'Yüksek' }
];

// State
router.get('/state', (req, res) => {
    res.json({
        model: botState.model,
        masterPrompt: botState.masterPrompt,
        totalTokens: botState.totalTokens,
        isRunning: botState.isRunning,
        availableModels: AVAILABLE_MODELS
    });
});

// Model değiştir
router.post('/model', (req, res) => {
    const { model } = req.body;
    if (!AVAILABLE_MODELS.find(m => m.id === model)) {
        return res.status(400).json({ error: 'Geçersiz model.' });
    }
    botState.model = model;
    // Gerçek projede: bot process'ine sinyal gönder
    updateEnvFile('BOT_MODEL', model);
    res.json({ success: true, model });
});

// Prompt değiştir
router.post('/prompt', (req, res) => {
    const { prompt } = req.body;
    if (typeof prompt !== 'string') {
        return res.status(400).json({ error: 'Geçersiz prompt.' });
    }
    botState.masterPrompt = prompt;
    savePrompt(prompt);
    res.json({ success: true });
});

// Kill switch
router.post('/kill', (req, res) => {
    botState.isRunning = false;
    invalidateAll();
    res.json({ success: true, message: 'Bot durduruldu.' });
    // Gerçek projede process.exit() veya bot process'ine SIGTERM
    setTimeout(() => process.exit(0), 500);
});

// Token stats
router.get('/tokens', (req, res) => {
    res.json(botState.totalTokens);
});

// Token istatistikleri
router.get('/token-stats', (req, res) => {
    res.json(tracker.getStats());
});

// Bot'tan gelen token kaydı (API key ile korunur)
router.post('/token-record', (req, res) => {
    const apiKey = req.headers['x-bot-api-key'];
    if (!apiKey || apiKey !== process.env.BOT_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const { model, input, output, source } = req.body;
    if (!model || !input || !output) return res.status(400).json({ error: 'Eksik veri' });
    tracker.record(model, parseInt(input), parseInt(output), source || 'bot');
    res.json({ success: true });
});

// .env güncelleme helper
function updateEnvFile(key, value) {
    try {
        const envPath = path.join(process.cwd(), '..', '.env');
        if (!fs.existsSync(envPath)) return;
        let content = fs.readFileSync(envPath, 'utf8');
        const regex = new RegExp(`^${key}=.*$`, 'm');
        if (regex.test(content)) {
            content = content.replace(regex, `${key}=${value}`);
        } else {
            content += `\n${key}=${value}`;
        }
        fs.writeFileSync(envPath, content);
    } catch (e) {
        console.error('Env update error:', e.message);
    }
}

function getState(){ return botState; }
module.exports = router;
module.exports.getState = getState;
