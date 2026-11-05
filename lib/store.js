'use strict';
/* Data access. Plain portable SQL with $1, $2 ... placeholders; `query(text, params)` must return a Promise of an array of row objects.
   Production passes the Neon driver; tests pass an SQLite adapter, so the same SQL is exercised. */
var fs = require('fs'), path = require('path'), C = require('./crypto');

function createStore(query) {
  var S = {};
  var SCHEMA = null;
  function schemaStatements() {
    if (!SCHEMA) SCHEMA = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8').split(/;\s*(?:\r?\n|$)/).map(function (s) { return s.replace(/^\s*--.*$/gm, '').trim(); }).filter(Boolean);
    return SCHEMA;
  }
  S.ensureSchema = async function () { var st = schemaStatements(); for (var i = 0; i < st.length; i++) await query(st[i], []); return st.length; };
  S.ping = async function () { var r = await query('SELECT 1 AS ok', []); return !!(r && r.length); };
  S.counts = async function () {
    var out = {}, t = ['users', 'otps', 'settings', 'audit'];
    for (var i = 0; i < t.length; i++) { var r = await query('SELECT COUNT(*) AS n FROM ' + t[i], []); out[t[i]] = Number(r[0].n); }
    var s = await query('SELECT status, COUNT(*) AS n FROM users GROUP BY status', []); out.byStatus = {}; s.forEach(function (x) { out.byStatus[x.status] = Number(x.n); });
    return out;
  };
  S.getUserByEmail = async function (email) { var r = await query('SELECT * FROM users WHERE email = $1', [String(email).toLowerCase()]); return r[0] || null; };
  S.getUserById = async function (id) { var r = await query('SELECT * FROM users WHERE id = $1', [id]); return r[0] || null; };
  S.insertUser = async function (u) {
    await query('INSERT INTO users (id, email, name, company, phone, purpose, pass_hash, role, status, created_at, verified_at, decided_at, decided_by, last_login_at, note) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)',
      [u.id, u.email, u.name, u.company, u.phone, u.purpose, u.pass_hash, u.role || 'user', u.status || 'unverified', u.created_at, u.verified_at || null, u.decided_at || null, u.decided_by || null, u.last_login_at || null, u.note || null]);
  };
  S.updateUser = async function (id, f) {
    var keys = Object.keys(f); if (!keys.length) return;
    var sets = keys.map(function (k, i) { if (!/^[a-z_]+$/.test(k)) throw new Error('bad column'); return k + ' = $' + (i + 2); });
    await query('UPDATE users SET ' + sets.join(', ') + ' WHERE id = $1', [id].concat(keys.map(function (k) { return f[k]; })));
  };
  S.deleteUser = async function (id) { await query('DELETE FROM users WHERE id = $1', [id]); };
  S.listUsers = async function (status) {
    if (status && status !== 'all') return query('SELECT id, email, name, company, phone, purpose, role, status, created_at, verified_at, decided_at, decided_by, last_login_at, note FROM users WHERE status = $1 ORDER BY created_at DESC', [status]);
    return query('SELECT id, email, name, company, phone, purpose, role, status, created_at, verified_at, decided_at, decided_by, last_login_at, note FROM users ORDER BY created_at DESC', []);
  };
  S.listAdmins = async function () { return query("SELECT email, name FROM users WHERE role = 'admin' AND status = 'approved'", []); };
  S.getOtp = async function (email) { var r = await query('SELECT * FROM otps WHERE email = $1', [email]); return r[0] || null; };
  S.putOtp = async function (o) {
    await query('INSERT INTO otps (email, code_hash, expires_at, attempts, sent_count, window_start) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (email) DO UPDATE SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, attempts = EXCLUDED.attempts, sent_count = EXCLUDED.sent_count, window_start = EXCLUDED.window_start',
      [o.email, o.code_hash, o.expires_at, o.attempts, o.sent_count, o.window_start]);
  };
  S.bumpOtpAttempts = async function (email) { await query('UPDATE otps SET attempts = attempts + 1 WHERE email = $1', [email]); };
  S.deleteOtp = async function (email) { await query('DELETE FROM otps WHERE email = $1', [email]); };
  S.getSetting = async function (key) { var r = await query('SELECT value FROM settings WHERE key = $1', [key]); if (!r[0]) return null; try { return JSON.parse(r[0].value); } catch (e) { return null; } };
  S.setSetting = async function (key, val, nowIso) {
    await query('INSERT INTO settings (key, value, updated_at) VALUES ($1,$2,$3) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at', [key, JSON.stringify(val), nowIso]);
  };
  S.audit = async function (actor, action, target, detail, nowIso) {
    try { await query('INSERT INTO audit (id, at, actor, action, target, detail) VALUES ($1,$2,$3,$4,$5,$6)', [C.newId(), nowIso, actor || null, action, target || null, detail ? String(detail).slice(0, 300) : null]); } catch (e) { /* auditing must never break a request */ }
  };
  S.listAudit = async function (limit) { return query('SELECT at, actor, action, target, detail FROM audit ORDER BY at DESC LIMIT ' + (parseInt(limit, 10) || 100), []); };
  /** fixed-window throttle: returns true when the call is allowed */
  S.throttle = async function (key, max, windowMs, nowMs) {
    var r = await query('SELECT * FROM throttle WHERE key = $1', [key]), now = new Date(nowMs).toISOString();
    if (!r[0] || nowMs - Date.parse(r[0].window_start) > windowMs) { await query('INSERT INTO throttle (key, count, window_start) VALUES ($1,1,$2) ON CONFLICT (key) DO UPDATE SET count = 1, window_start = EXCLUDED.window_start', [key, now]); return true; }
    if (Number(r[0].count) >= max) return false;
    await query('UPDATE throttle SET count = count + 1 WHERE key = $1', [key]); return true;
  };
  return S;
}
module.exports = { createStore: createStore };
