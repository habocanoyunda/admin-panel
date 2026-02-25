const fs = require('fs');
const path = require('path');

const USAGE_FILE = path.join(__dirname, 'token_usage.json');

// Model fiyatları ($ per 1M token - Şubat 2026 fiyatları)
const PRICING = {
    'claude-haiku-4-5-20251001': { input: 0.80, output: 4.00 },
    'claude-sonnet-4-6':         { input: 3.00, output: 15.00 },
    'claude-opus-4-6':           { input: 15.00, output: 75.00 },
    'default':                   { input: 0.80, output: 4.00 }
};

function loadUsage() {
    try {
        if (fs.existsSync(USAGE_FILE)) {
            return JSON.parse(fs.readFileSync(USAGE_FILE, 'utf8'));
        }
    } catch(e) {}
    return {
        total: { input: 0, output: 0, cost: 0 },
        daily: {},      // { "2026-02-24": { input, output, cost } }
        entries: []     // Son 200 kayıt: { ts, model, input, output, cost, source }
    };
}

function saveUsage(data) {
    fs.writeFileSync(USAGE_FILE, JSON.stringify(data), 'utf8');
}

function calcCost(model, inputTokens, outputTokens) {
    const price = PRICING[model] || PRICING['default'];
    return (inputTokens / 1e6 * price.input) + (outputTokens / 1e6 * price.output);
}

function record(model, inputTokens, outputTokens, source = 'bot') {
    const data = loadUsage();
    const cost = calcCost(model, inputTokens, outputTokens);
    const now = new Date();
    const day = now.toISOString().slice(0, 10);

    // Toplam
    data.total.input += inputTokens;
    data.total.output += outputTokens;
    data.total.cost = (data.total.cost || 0) + cost;

    // Günlük
    if (!data.daily[day]) data.daily[day] = { input: 0, output: 0, cost: 0 };
    data.daily[day].input += inputTokens;
    data.daily[day].output += outputTokens;
    data.daily[day].cost = (data.daily[day].cost || 0) + cost;

    // Kayıtlar (son 200)
    data.entries.push({ ts: now.toISOString(), model, input: inputTokens, output: outputTokens, cost, source });
    if (data.entries.length > 200) data.entries = data.entries.slice(-200);

    saveUsage(data);
    return cost;
}

function getStats() {
    const data = loadUsage();
    
    // Son 30 günün günlük verisi
    const days = [];
    for (let i = 29; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        const key = d.toISOString().slice(0, 10);
        days.push({
            date: key,
            input: data.daily[key]?.input || 0,
            output: data.daily[key]?.output || 0,
            cost: data.daily[key]?.cost || 0
        });
    }

    return {
        total: data.total,
        days,
        recentEntries: data.entries.slice(-20).reverse()
    };
}

module.exports = { record, getStats, calcCost, PRICING };
