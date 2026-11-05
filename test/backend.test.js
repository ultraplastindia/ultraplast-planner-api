'use strict';
process.removeAllListeners('warning');
var assert = require('assert'), C = require('../lib/crypto.js'), M = require('../lib/mailer.js'), createStore = require('../lib/store.js').createStore, createApp = require('../lib/app.js').createApp, sqlite = require('./sqlite-adapter.js');
var pass = 0, fail = 0, queue = [];
function test(n, f) { queue.push([n, f]); }
function eq(a, b, m) { assert.deepStrictEqual(a, b, m); } function ok(v, m) { assert.ok(v, m); }

var clock = Date.UTC(2026, 10, 4, 10, 0, 0), sent = [], verifyOk = true, mxMap = {};
function fresh(envExtra) {
  sent = []; var store = createStore(sqlite());
  var env = Object.assign({ AUTH_SECRET: 'test-secret-0123456789abcdef', SETTINGS_KEY: 'settings-key-xyz', SUPERADMIN_EMAIL: 'Admin@ultraplast.test', SUPERADMIN_PASSWORD: 'Admin12345', ALLOWED_ORIGIN: 'https://ultraplast.github.io' }, envExtra || {});
  var app = createApp({ store: store, env: env, now: function () { return clock; }, resolveMx: async function (d) { if (mxMap[d]) return mxMap[d]; throw new Error('no mx'); },
    transportFactory: function (cfg) { return { verify: async function () { if (!verifyOk) { var e = new Error('Invalid login 535'); e.code = 'EAUTH'; throw e; } return true; }, sendMail: async function (m) { sent.push(Object.assign({ via: cfg.user + '@' + cfg.host + ':' + cfg.port }, m)); } }; } });
  return { app: app, store: store, env: env };
}
async function call(F, method, path, body, token, query) { var r = await F.app.handle({ method: method, path: '/api' + path, headers: Object.assign({ origin: 'https://ultraplast.github.io' }, token ? { authorization: 'Bearer ' + token } : {}), body: body || {}, query: query || {}, ip: '1.2.3.4' }); return r; }
async function loginAdmin(F) { var r = await call(F, 'POST', '/auth/login', { email: 'admin@ultraplast.test', password: 'Admin12345' }); return r.body.token; }
async function setupMail(F, tok) { return call(F, 'POST', '/admin/mail', { email: 'planner@gmail.com', appPassword: 'abcd efgh ijkl mnop' }, tok); }
var REG = { name: 'Ravi Kumar', company: 'Acme Foods', email: 'Ravi@Acme.com', phone: '+91 98765 43210', purpose: 'Plan a bottle line', password: 'Secret123' };
function lastCode() { var m = /code: (\d{6})/.exec(sent[sent.length - 1].subject); return m && m[1]; }

test('crypto: password hash, token, AES round trip, tampering fails', function () {
  var h = C.hashPassword('Abc12345'); ok(C.verifyPassword('Abc12345', h)); ok(!C.verifyPassword('abc12345', h)); ok(h.indexOf('Abc12345') < 0);
  var t = C.signToken({ uid: 'u1', exp: Date.now() + 1000 }, 's'); eq(C.verifyToken(t, 's').uid, 'u1'); eq(C.verifyToken(t, 'other'), null); eq(C.verifyToken(t.slice(0, -2) + 'xx', 's'), null); eq(C.verifyToken(C.signToken({ uid: 'u1', exp: 5 }, 's'), 's'), null);
  var e = C.encrypt('my app password', 'k'); ok(e.indexOf('my app') < 0); eq(C.decrypt(e, 'k'), 'my app password'); assert.throws(function () { C.decrypt(e, 'wrong'); });
});
test('server refuses to run without a proper AUTH_SECRET; health works with no setup', async function () {
  var F = fresh({ AUTH_SECRET: 'short' }); eq((await call(F, 'GET', '/health')).status, 500);
  var G = fresh(); var h = await call(G, 'GET', '/health'); eq(h.status, 200); eq(h.body.db, true); eq(h.body.mailConfigured, false);
});
test('CORS: allowed origin echoed, other origins not; OPTIONS answered', async function () {
  var F = fresh(), r = await call(F, 'GET', '/health'); eq(r.headers['Access-Control-Allow-Origin'], 'https://ultraplast.github.io');
  var o = await F.app.handle({ method: 'OPTIONS', path: '/api/auth/login', headers: { origin: 'https://evil.example' } }); eq(o.status, 204); ok(!o.headers['Access-Control-Allow-Origin']);
});
test('super admin is created from environment variables and can log in; wrong password fails', async function () {
  var F = fresh(); eq((await call(F, 'POST', '/auth/login', { email: 'admin@ultraplast.test', password: 'nope' })).status, 401);
  var r = await call(F, 'POST', '/auth/login', { email: 'ADMIN@ultraplast.test', password: 'Admin12345' }); eq(r.status, 200); eq(r.body.user.role, 'admin'); ok(r.body.token);
  var me = await call(F, 'GET', '/auth/me', null, r.body.token); eq(me.body.user.email, 'admin@ultraplast.test'); eq((await call(F, 'GET', '/auth/me')).status, 401);
});
test('register validates every field', async function () {
  var F = fresh(), r = await call(F, 'POST', '/auth/register', { name: 'x', company: '', email: 'bad', phone: '12', purpose: '', password: 'short' });
  eq(r.status, 400); ['name', 'company', 'email', 'phone', 'purpose', 'password'].forEach(function (k) { ok(r.body.fields[k], k); });
});
test('register without mail configured says so honestly and never claims a code was sent', async function () {
  var F = fresh(), r = await call(F, 'POST', '/auth/register', REG); eq(r.status, 503); ok(/Mail is not set up/.test(r.body.error)); eq(sent.length, 0);
});
test('full journey: register -> OTP mail -> verify -> pending -> admin approves -> login', async function () {
  var F = fresh(), at = await loginAdmin(F); var m = await setupMail(F, at); eq(m.status, 200); ok(m.body.verified);
  var r = await call(F, 'POST', '/auth/register', REG); eq(r.status, 200); eq(r.body.next, 'verify'); eq(sent.length, 1); eq(sent[0].to, 'ravi@acme.com'); ok(/^\d{6}$/.test(lastCode())); ok(sent[0].via.indexOf('planner@gmail.com@smtp.gmail.com:465') === 0);
  var l0 = await call(F, 'POST', '/auth/login', { email: 'ravi@acme.com', password: 'Secret123' }); eq(l0.status, 403); eq(l0.body.status, 'unverified');
  eq((await call(F, 'POST', '/auth/verify', { email: 'ravi@acme.com', otp: '000000' })).status, 400);
  var v = await call(F, 'POST', '/auth/verify', { email: 'ravi@acme.com', otp: lastCode() }); eq(v.status, 200); eq(v.body.status, 'pending');
  ok(sent.some(function (s) { return /New Planner access request/.test(s.subject) && s.to === 'admin@ultraplast.test'; }), 'admin notified');
  var l1 = await call(F, 'POST', '/auth/login', { email: 'ravi@acme.com', password: 'Secret123' }); eq(l1.status, 403); eq(l1.body.status, 'pending');
  var list = await call(F, 'GET', '/admin/users', null, at, { status: 'pending' }); eq(list.body.users.length, 1); var u = list.body.users[0]; eq(u.company, 'Acme Foods'); ok(!('pass_hash' in u) && !JSON.stringify(u).includes('Secret123'));
  eq((await call(F, 'POST', '/admin/user-action', { id: u.id, action: 'approve' }, at)).status, 200); ok(sent.some(function (s) { return /approved/.test(s.subject) && s.to === 'ravi@acme.com'; }));
  var l2 = await call(F, 'POST', '/auth/login', { email: 'ravi@acme.com', password: 'Secret123' }); eq(l2.status, 200); eq(l2.body.user.role, 'user'); ok(l2.body.token);
  eq((await call(F, 'GET', '/admin/users', null, l2.body.token)).status, 403, 'normal user cannot use admin routes');
  await call(F, 'POST', '/admin/user-action', { id: u.id, action: 'revoke' }, at); eq((await call(F, 'GET', '/auth/me', null, l2.body.token)).status, 401, 'revoke takes effect immediately'); eq((await call(F, 'POST', '/auth/login', { email: 'ravi@acme.com', password: 'Secret123' })).body.status, 'revoked');
});
test('OTP: expiry, wrong attempts lock, resend gives a new code, resend limit', async function () {
  var F = fresh(), at = await loginAdmin(F); await setupMail(F, at); await call(F, 'POST', '/auth/register', REG); var c1 = lastCode();
  for (var i = 0; i < 5; i++) await call(F, 'POST', '/auth/verify', { email: 'ravi@acme.com', otp: '111111' });
  var lk = await call(F, 'POST', '/auth/verify', { email: 'ravi@acme.com', otp: c1 }); eq(lk.status, 429, 'locked after 5 wrong tries even with the right code');
  await call(F, 'POST', '/auth/resend', { email: 'ravi@acme.com' }); var c2 = lastCode(); eq((await call(F, 'POST', '/auth/verify', { email: 'ravi@acme.com', otp: c2 })).status, 200);
  var G = fresh(), gt = await loginAdmin(G); await setupMail(G, gt); await call(G, 'POST', '/auth/register', REG); var c = lastCode(); clock += 11 * 60000; var ex = await call(G, 'POST', '/auth/verify', { email: 'ravi@acme.com', otp: c }); eq(ex.status, 400); ok(ex.body.expired); clock -= 11 * 60000;
  var H = fresh(), ht = await loginAdmin(H); await setupMail(H, ht); await call(H, 'POST', '/auth/register', REG); var last; for (var k = 0; k < 6; k++) last = await call(H, 'POST', '/auth/resend', { email: 'ravi@acme.com' }); eq(last.status, 429);
});
test('register again: pending / approved / rejected are handled; unverified can retry with new details', async function () {
  var F = fresh(), at = await loginAdmin(F); await setupMail(F, at); await call(F, 'POST', '/auth/register', REG);
  var again = await call(F, 'POST', '/auth/register', Object.assign({}, REG, { name: 'Ravi K' })); eq(again.status, 200);
  await call(F, 'POST', '/auth/verify', { email: 'ravi@acme.com', otp: lastCode() }); eq((await call(F, 'POST', '/auth/register', REG)).body.status, 'pending');
  var u = (await call(F, 'GET', '/admin/users', null, at)).body.users.filter(function (x) { return x.email === 'ravi@acme.com'; })[0]; eq(u.name, 'Ravi K');
  await call(F, 'POST', '/admin/user-action', { id: u.id, action: 'reject', note: 'not a customer' }, at); eq((await call(F, 'POST', '/auth/register', REG)).status, 403); eq((await call(F, 'POST', '/auth/login', { email: 'ravi@acme.com', password: 'Secret123' })).body.status, 'rejected');
});
test('mail settings: detects provider, verifies login, stores password encrypted, never returns it, reports a rejected login', async function () {
  var F = fresh(), at = await loginAdmin(F); verifyOk = false; var bad = await call(F, 'POST', '/admin/mail', { email: 'planner@gmail.com', appPassword: 'wrong' }, at); eq(bad.status, 400); ok(/App Password/.test(bad.body.error)); eq((await call(F, 'GET', '/admin/settings', null, at)).body.mail, null);
  verifyOk = true; var good = await setupMail(F, at); eq(good.body.verified, true);
  var s = await call(F, 'GET', '/admin/settings', null, at); eq(s.body.mail.user, 'planner@gmail.com'); eq(s.body.mail.hasPassword, true); ok(!JSON.stringify(s.body).includes('abcdefgh')); eq(s.body.mailSource, 'settings');
  var raw = await F.store.getSetting('mail'); ok(raw.passEnc.indexOf('abcd') < 0 && /^e1\./.test(raw.passEnc)); eq(C.decrypt(raw.passEnc, F.env.SETTINGS_KEY), 'abcdefghijklmnop');
  var t = await call(F, 'POST', '/admin/mail-test', { to: 'me@x.com' }, at); eq(t.status, 200); eq(sent[sent.length - 1].to, 'me@x.com');
  eq((await call(F, 'POST', '/admin/mail', { email: 'planner@gmail.com' }, at)).status, 200, 'saving again without retyping the password keeps the stored one');
  eq((await call(F, 'POST', '/admin/mail', { email: 'other@gmail.com' }, at)).status, 400, 'a different mail id needs its own password');
  eq((await call(F, 'POST', '/admin/mail-remove', {}, at)).status, 200); eq((await call(F, 'GET', '/admin/settings', null, at)).body.mail, null);
});
test('any mail id: Outlook, Zoho, Yahoo by name; Google Workspace / Zoho / Microsoft 365 company domains by MX; unknown domain guessed', async function () {
  var d = function (e) { return M.detectSmtp(e, async function (dom) { if (mxMap[dom]) return mxMap[dom]; throw new Error('x'); }); };
  eq((await d('a@outlook.com')).host, 'smtp.office365.com'); eq((await d('a@zoho.in')).host, 'smtp.zoho.in'); eq((await d('a@yahoo.co.in')).host, 'smtp.mail.yahoo.com'); eq((await d('a@gmail.com')).host, 'smtp.gmail.com');
  mxMap['ultraplast.in'] = [{ exchange: 'aspmx.l.google.com', priority: 1 }]; eq((await d('sales@ultraplast.in')).provider, 'gmail');
  mxMap['firm.com'] = [{ exchange: 'firm-com.mail.protection.outlook.com', priority: 0 }]; eq((await d('a@firm.com')).provider, 'outlook');
  mxMap['zz.in'] = [{ exchange: 'mx.zoho.in', priority: 10 }]; eq((await d('a@zz.in')).provider, 'zohoin');
  var u = await d('a@own-host.org'); eq(u.provider, 'custom'); eq(u.host, 'smtp.own-host.org'); eq(u.detected, false);
  var F = fresh(), at = await loginAdmin(F); var r = await call(F, 'POST', '/admin/mail', { email: 'a@own-host.org', appPassword: 'pw', host: 'mail.own-host.org', port: 587, secure: false }, at); eq(r.status, 200); var raw = await F.store.getSetting('mail'); eq(raw.host, 'mail.own-host.org'); eq(raw.port, 587); eq(raw.secure, false);
});
test('registration rules: domain allow-list, no approval needed, OTP minutes; saved only by admin', async function () {
  var F = fresh(), at = await loginAdmin(F); await setupMail(F, at);
  eq((await call(F, 'POST', '/admin/rules', { allowedDomains: '@acme.com, other.org', otpMinutes: 5 }, 'bad-token')).status, 401);
  var r = await call(F, 'POST', '/admin/rules', { allowedDomains: '@acme.com, other.org', otpMinutes: 5 }, at); eq(r.body.rules.allowedDomains, ['acme.com', 'other.org']); eq(r.body.rules.otpMinutes, 5);
  var blocked = await call(F, 'POST', '/auth/register', Object.assign({}, REG, { email: 'x@gmail.com' })); eq(blocked.status, 400); ok(blocked.body.fields.email);
  await call(F, 'POST', '/auth/register', REG); clock += 6 * 60000; eq((await call(F, 'POST', '/auth/verify', { email: 'ravi@acme.com', otp: lastCode() })).status, 400); clock -= 6 * 60000;
  await call(F, 'POST', '/admin/rules', { requireApproval: false }, at); await call(F, 'POST', '/auth/resend', { email: 'ravi@acme.com' }); var v = await call(F, 'POST', '/auth/verify', { email: 'ravi@acme.com', otp: lastCode() }); eq(v.body.status, 'approved');
});
test('database panel: connected, counts, setup is repeatable; audit log records admin actions', async function () {
  var F = fresh(), at = await loginAdmin(F); var d = await call(F, 'GET', '/admin/db', null, at); eq(d.body.connected, true); eq(d.body.counts.users, 1);
  eq((await call(F, 'POST', '/admin/db-setup', {}, at)).status, 200); eq((await call(F, 'POST', '/admin/db-setup', {}, at)).status, 200);
  var a = await call(F, 'GET', '/admin/audit', null, at); ok(a.body.rows.some(function (r) { return r.action === 'db-setup'; }));
});
test('admin safety: cannot change own access; password change; reset password; login throttle', async function () {
  var F = fresh(), at = await loginAdmin(F), me = (await call(F, 'GET', '/admin/users', null, at)).body.users[0];
  eq((await call(F, 'POST', '/admin/user-action', { id: me.id, action: 'revoke' }, at)).status, 400);
  eq((await call(F, 'POST', '/auth/change-password', { oldPassword: 'wrong', newPassword: 'NewPass123' }, at)).status, 400); eq((await call(F, 'POST', '/auth/change-password', { oldPassword: 'Admin12345', newPassword: 'NewPass123' }, at)).status, 200);
  eq((await call(F, 'POST', '/auth/login', { email: 'admin@ultraplast.test', password: 'Admin12345' })).status, 401); eq((await call(F, 'POST', '/auth/login', { email: 'admin@ultraplast.test', password: 'NewPass123' })).status, 200);
  var T = fresh(), r; for (var i = 0; i < 11; i++) r = await call(T, 'POST', '/auth/login', { email: 'admin@ultraplast.test', password: 'bad' }); eq(r.status, 429);
});
test('env-only mail (SMTP_USER / SMTP_PASS) works before Settings is used', async function () {
  var F = fresh({ SMTP_USER: 'boot@gmail.com', SMTP_PASS: 'aaaa bbbb cccc dddd' }); var r = await call(F, 'POST', '/auth/register', REG); eq(r.status, 200); ok(sent[0].via.indexOf('boot@gmail.com@smtp.gmail.com') === 0);
});

(async function () {
  for (var i = 0; i < queue.length; i++) { try { await queue[i][1](); pass++; console.log('  PASS  ' + queue[i][0]); } catch (e) { fail++; console.log('  FAIL  ' + queue[i][0] + '\n        ' + (e && e.stack ? e.stack.split('\n').slice(0, 4).join('\n        ') : e)); } }
  console.log('\n' + pass + ' passed, ' + fail + ' failed'); process.exit(fail ? 1 : 0);
})();
