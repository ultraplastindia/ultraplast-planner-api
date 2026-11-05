'use strict';
/* Small crypto helpers (Node built-ins only): password hashing (scrypt), OTP hashing, signed tokens, AES-256-GCM for the stored mail password. */
var crypto = require('crypto');

function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function unb64u(s) { s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Buffer.from(s, 'base64'); }
function safeEq(a, b) { var x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }

function hashPassword(pw) { var salt = crypto.randomBytes(16); var h = crypto.scryptSync(String(pw), salt, 32, { N: 16384, r: 8, p: 1 }); return 's1$' + salt.toString('hex') + '$' + h.toString('hex'); }
function verifyPassword(pw, stored) {
  var p = String(stored || '').split('$'); if (p.length !== 3 || p[0] !== 's1') return false;
  var h = crypto.scryptSync(String(pw), Buffer.from(p[1], 'hex'), 32, { N: 16384, r: 8, p: 1 }); return safeEq(h.toString('hex'), p[2]);
}
function randomOtp() { return String(crypto.randomInt(0, 1000000)).padStart(6, '0'); }
function hashOtp(email, code, secret) { return crypto.createHmac('sha256', String(secret)).update(String(email).toLowerCase() + ':' + String(code)).digest('hex'); }
function newId() { return crypto.randomUUID(); }

function signToken(payload, secret) { var body = b64u(JSON.stringify(payload)), sig = b64u(crypto.createHmac('sha256', String(secret)).update(body).digest()); return body + '.' + sig; }
function verifyToken(token, secret, nowMs) {
  var p = String(token || '').split('.'); if (p.length !== 2) return null;
  var sig = b64u(crypto.createHmac('sha256', String(secret)).update(p[0]).digest()); if (!safeEq(sig, p[1])) return null;
  var d; try { d = JSON.parse(unb64u(p[0]).toString('utf8')); } catch (e) { return null; }
  if (!d || !d.exp || d.exp < (nowMs === undefined ? Date.now() : nowMs)) return null; return d;
}
function keyFrom(secret) { return crypto.createHash('sha256').update('ucp-settings:' + String(secret)).digest(); }
function encrypt(text, secret) { var iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', keyFrom(secret), iv), enc = Buffer.concat([c.update(String(text), 'utf8'), c.final()]); return 'e1.' + b64u(iv) + '.' + b64u(c.getAuthTag()) + '.' + b64u(enc); }
function decrypt(blob, secret) {
  var p = String(blob || '').split('.'); if (p.length !== 4 || p[0] !== 'e1') throw new Error('bad blob');
  var d = crypto.createDecipheriv('aes-256-gcm', keyFrom(secret), unb64u(p[1])); d.setAuthTag(unb64u(p[2])); return Buffer.concat([d.update(unb64u(p[3])), d.final()]).toString('utf8');
}
module.exports = { hashPassword: hashPassword, verifyPassword: verifyPassword, randomOtp: randomOtp, hashOtp: hashOtp, newId: newId, signToken: signToken, verifyToken: verifyToken, encrypt: encrypt, decrypt: decrypt, safeEq: safeEq };
