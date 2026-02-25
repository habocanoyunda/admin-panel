#!/usr/bin/env node
// Kullanım: node setup-admin.js
// Bu script ADMIN_PASSWORD_HASH değerini üretir, .env'e ekler

const bcrypt = require('bcrypt');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function ask(question, hidden = false) {
  return new Promise(resolve => {
    if (hidden) {
      process.stdout.write(question);
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.setEncoding('utf8');
      let input = '';
      process.stdin.on('data', function handler(char) {
        if (char === '\n' || char === '\r' || char === '\u0004') {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener('data', handler);
          process.stdout.write('\n');
          resolve(input);
        } else if (char === '\u0003') {
          process.exit();
        } else if (char === '\u007f') {
          if (input.length > 0) {
            input = input.slice(0, -1);
            process.stdout.clearLine(0);
            process.stdout.cursorTo(0);
            process.stdout.write(question + '*'.repeat(input.length));
          }
        } else {
          input += char;
          process.stdout.write('*');
        }
      });
    } else {
      rl.question(question, resolve);
    }
  });
}

async function main() {
  console.log('\n🔐 EMK Bot Admin Panel Kurulum\n');

  const username = await ask('Admin kullanıcı adı [admin]: ');
  const finalUsername = username.trim() || 'admin';

  const password = await ask('Admin şifresi: ', true);
  if (!password || password.length < 8) {
    console.error('\n✗ Şifre en az 8 karakter olmalı.');
    process.exit(1);
  }

  const password2 = await ask('Şifreyi tekrar girin: ', true);
  if (password !== password2) {
    console.error('\n✗ Şifreler eşleşmiyor.');
    process.exit(1);
  }

  console.log('\nHash oluşturuluyor...');
  const hash = await bcrypt.hash(password, 12);
  const jwtSecret = crypto.randomBytes(64).toString('hex');

  // .env dosyasını güncelle
  const envPath = path.join(__dirname, '..', '.env');
  let envContent = '';

  if (fs.existsSync(envPath)) {
    envContent = fs.readFileSync(envPath, 'utf8');
  }

  const updates = {
    ADMIN_USERNAME: finalUsername,
    ADMIN_PASSWORD_HASH: hash,
    ADMIN_JWT_SECRET: jwtSecret,
    ADMIN_PORT: '3001'
  };

  for (const [key, value] of Object.entries(updates)) {
    const regex = new RegExp(`^${key}=.*$`, 'm');
    const line = `${key}=${value}`;
    if (regex.test(envContent)) {
      envContent = envContent.replace(regex, line);
    } else {
      envContent += `\n${line}`;
    }
  }

  fs.writeFileSync(envPath, envContent.trim() + '\n');

  console.log('\n✓ Kurulum tamamlandı!');
  console.log(`  Kullanıcı: ${finalUsername}`);
  console.log(`  .env güncellendi`);
  console.log(`\n  Paneli başlatmak için index.js'e şunu ekle:`);
  console.log(`  const { startAdminServer } = require('./admin-panel/admin-server');`);
  console.log(`  startAdminServer();`);
  console.log(`\n  Sonra: http://localhost:3001/admin/login\n`);

  rl.close();
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
