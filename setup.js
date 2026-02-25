const bcrypt = require('bcryptjs');
const fs = require('fs');
const crypto = require('crypto');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const question = (q) => new Promise(resolve => rl.question(q, resolve));

(async () => {
    console.log('\n=== EMK Admin Panel Setup ===\n');
    const username = await question('Admin kullanıcı adı: ');
    const password = await question('Admin şifre (min 12 karakter): ');
    
    if (password.length < 12) {
        console.error('Şifre en az 12 karakter olmalı!');
        process.exit(1);
    }
    
    const hash = await bcrypt.hash(password, 12);
    const jwtSecret = crypto.randomBytes(64).toString('hex');
    const csrfSecret = crypto.randomBytes(32).toString('hex');
    
    const envContent = `ADMIN_USERNAME=${username}
ADMIN_PASSWORD_HASH=${hash}
JWT_SECRET=${jwtSecret}
CSRF_SECRET=${csrfSecret}
PORT=3001
NODE_ENV=development
SESSION_TIMEOUT=1800000
`;
    fs.writeFileSync('.env', envContent);
    console.log('\n✓ .env oluşturuldu, şifre hash\'lendi (bcrypt cost 12)');
    console.log('Başlatmak için: npm start\n');
    rl.close();
})();
