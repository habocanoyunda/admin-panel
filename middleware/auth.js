const jwt = require('jsonwebtoken');

const activeSessions = new Map(); // token -> { createdAt, lastActivity }

function createToken(username) {
    const jti = require('crypto').randomBytes(16).toString('hex');
    const token = jwt.sign(
        { username, jti },
        process.env.JWT_SECRET,
        { expiresIn: '30m' }
    );
    activeSessions.set(jti, { createdAt: Date.now(), lastActivity: Date.now() });
    return { token, jti };
}

function invalidateToken(jti) {
    activeSessions.delete(jti);
}

function invalidateAll() {
    activeSessions.clear();
}

function requireAuth(req, res, next) {
    const token = req.cookies?.adminToken;
    if (!token) return res.redirect('/login');
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const session = activeSessions.get(decoded.jti);
        
        if (!session) return res.redirect('/login');
        
        // Session timeout kontrolü
        const timeout = parseInt(process.env.SESSION_TIMEOUT) || 1800000;
        if (Date.now() - session.lastActivity > timeout) {
            invalidateToken(decoded.jti);
            return res.redirect('/login?reason=timeout');
        }
        
        // lastActivity güncelle
        session.lastActivity = Date.now();
        req.user = decoded;
        next();
    } catch (e) {
        res.clearCookie('adminToken');
        return res.redirect('/login');
    }
}

module.exports = { createToken, invalidateToken, invalidateAll, requireAuth };
