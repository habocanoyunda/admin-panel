# EMK Admin Panel

## Kurulum

```bash
npm install
node setup.js    # Kullanıcı adı ve şifre belirle
npm start        # http://localhost:3001
```

## .env Değişkenleri
`setup.js` otomatik oluşturur. Eklemen gerekenler:
```
ANTHROPIC_API_KEY=sk-ant-...     # Chat özelliği için
BOT_DIR=../                       # Bot klasörü yolu
```

## Güvenlik Özellikleri
- bcrypt (cost 12) şifre hash
- JWT + httpOnly cookie (XSS koruması)
- Rate limiting: 5 yanlış deneme → 15 dk ban
- Session timeout: 30 dakika
- Tek aktif oturum (token blacklist)
- Helmet.js HTTP header güvenliği
- Path traversal koruması (FTP)
- Input sanitization
