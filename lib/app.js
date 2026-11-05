'use strict';
/* Request handler for the Ultraplast Planner API. Framework-free: handle({method, path, headers, query, body, ip}) -> {status, body, headers}.
   Flow: register -> email OTP -> pending -> Ultraplast super admin approves -> login. Admin-only routes live under /admin. */
var C = require('./crypto'), M = require('./mailer');

var STATUS = ['unverified', 'pending', 'approved', 'rejected', 'revoked'];
var DEFAULT_RULES = { otpMinutes: 10, notifyAdmin: true, allowedDomains: [], blockedDomains: [], requireApproval: true };
var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function createApp(deps) {
  var store = deps.store, env = deps.env || {}, now = deps.now || function () { return Date.now(); }, mailer = deps.mailer || M.createMailer({ store: store, env: env, resolveMx: deps.resolveMx, transportFactory: deps.transportFactory });
  var iso = function () { return new Date(now()).toISOString(); };
  var ready = null, SECRET = env.AUTH_SECRET || '';
  function J(status, body, headers) { return { status: status, body: body, headers: headers || {} }; }
  function bad(msg, code, extra) { return J(code || 400, Object.assign({ ok: false, error: msg }, extra || {})); }
  function t(v) { return String(v === undefined || v === null ? '' : v).trim(); }
  function pub(u) { return { id: u.id, email: u.email, name: u.name, company: u.company, phone: u.phone, purpose: u.purpose, role: u.role, status: u.status, createdAt: u.created_at, verifiedAt: u.verified_at, decidedAt: u.decided_at, decidedBy: u.decided_by, lastLoginAt: u.last_login_at, note: u.note }; }

  async function setup() {
    await store.ensureSchema();
    if (env.SUPERADMIN_EMAIL && env.SUPERADMIN_PASSWORD) {   // the first super admin comes from environment variables
      var em = t(env.SUPERADMIN_EMAIL).toLowerCase(), u = await store.getUserByEmail(em);
      if (!u) await store.insertUser({ id: C.newId(), email: em, name: env.SUPERADMIN_NAME || 'Ultraplast Super Admin', company: 'UCPL', phone: '-', purpose: 'Administration', pass_hash: C.hashPassword(env.SUPERADMIN_PASSWORD), role: 'admin', status: 'approved', created_at: iso(), verified_at: iso(), decided_at: iso(), decided_by: 'setup' });
      else if (u.role === 'admin' && u.decided_by === 'setup' && u.company === 'Ultraplast Chainbelts Pvt. Ltd.') await store.updateUser(u.id, { company: 'UCPL' });   // short name shown in the header; only the untouched setup default is changed
    }
  }
  function ensureReady() { if (!ready) ready = setup().catch(function (e) { ready = null; throw e; }); return ready; }

  async function rules() { var r = await store.getSetting('rules'); return Object.assign({}, DEFAULT_RULES, r || {}); }
  function validateReg(b, R) {
    var e = {}, em = t(b.email).toLowerCase(), ph = t(b.phone).replace(/[\s\-()]/g, '');
    if (t(b.name).length < 2) e.name = 'Enter your name.';
    if (t(b.company).length < 2) e.company = 'Enter your company name.';
    if (!EMAIL_RE.test(em)) e.email = 'Enter a valid email address.';
    else { var dom = em.split('@')[1]; if ((R.allowedDomains || []).length && R.allowedDomains.indexOf(dom) < 0) e.email = 'This email domain is not allowed. Use your company email.'; if ((R.blockedDomains || []).indexOf(dom) >= 0) e.email = 'This email domain is not allowed. Use your company email.'; }
    if (!/^\+?\d{8,15}$/.test(ph)) e.phone = 'Enter the contact number with country code, e.g. +91 98XXXXXXXX.';
    if (t(b.purpose).length < 3) e.purpose = 'Tell us the purpose of using the planner.';
    var pw = String(b.password || ''); if (pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)) e.password = 'Password must be at least 8 characters with letters and numbers.';
    return e;
  }
  async function sendOtp(email, R) {
    var code = C.randomOtp(), n = now(), old = await store.getOtp(email), sent = 1, ws = new Date(n).toISOString();
    if (old && n - Date.parse(old.window_start) < 3600000) { if (Number(old.sent_count) >= 5) return { ok: false, error: 'Too many codes requested. Please wait an hour and try again.' }; sent = Number(old.sent_count) + 1; ws = old.window_start; }
    await store.putOtp({ email: email, code_hash: C.hashOtp(email, code, SECRET), expires_at: new Date(n + R.otpMinutes * 60000).toISOString(), attempts: 0, sent_count: sent, window_start: ws });
    try {
      await mailer.send({ to: email, subject: 'Your Ultraplast Planner verification code: ' + code, text: 'Your verification code is ' + code + '. It is valid for ' + R.otpMinutes + ' minutes.\n\nIf you did not register on the Ultraplast Conveyor Planner, ignore this email.\n\nUltraplast Chainbelts Pvt. Ltd.',
        html: '<p>Your verification code is</p><p style="font-size:26px;letter-spacing:4px"><b>' + code + '</b></p><p>It is valid for ' + R.otpMinutes + ' minutes.</p><p>If you did not register on the Ultraplast Conveyor Planner, ignore this email.</p><p>Ultraplast Chainbelts Pvt. Ltd.</p>' });
    } catch (e) { return { ok: false, error: e.message, mail: true }; }
    return { ok: true };
  }
  async function notifyAdmins(u, R) {
    if (!R.notifyAdmin) return; var admins = await store.listAdmins(); if (!admins.length) return;
    try { await mailer.send({ to: admins.map(function (a) { return a.email; }).join(','), subject: 'New Planner access request: ' + u.name + ' (' + u.company + ')', text: 'A new person verified their email and is waiting for your approval.\n\nName: ' + u.name + '\nCompany: ' + u.company + '\nEmail: ' + u.email + '\nContact: ' + u.phone + '\nPurpose: ' + u.purpose + '\n\nOpen the planner, then Settings > Users to approve or reject.' }); } catch (e) { /* the request is still saved; admin sees it in Settings */ }
  }
  async function notifyUser(u, approved) {
    try { await mailer.send({ to: u.email, subject: approved ? 'Your Ultraplast Planner access is approved' : 'Your Ultraplast Planner access request', text: approved ? 'Hello ' + u.name + ',\n\nYour access to the Ultraplast Conveyor Planner has been approved. You can now log in with your email and password.\n\nUltraplast Chainbelts Pvt. Ltd.' : 'Hello ' + u.name + ',\n\nWe could not approve your access request at this time. Please contact Ultraplast if you think this is a mistake.\n\nUltraplast Chainbelts Pvt. Ltd.' }); } catch (e) { /* ignore */ }
  }
  function issue(u) { return C.signToken({ uid: u.id, exp: now() + 12 * 3600000 }, SECRET); }
  async function authed(req) {
    var h = req.headers || {}, a = h.authorization || h.Authorization || '', tok = /^Bearer (.+)$/.exec(a); if (!tok) return null;
    var d = C.verifyToken(tok[1], SECRET, now()); if (!d) return null;
    var u = await store.getUserById(d.uid); if (!u || u.status !== 'approved') return null; return u;
  }

  var routes = {};
  routes['GET /health'] = async function () {
    var db = false, mail = false, dbError; try { db = await store.ping(); } catch (e) { db = false; dbError = String(e && e.message || e).replace(/postgres(ql)?:\/\/\S+/gi, '[url hidden]').slice(0, 200); } try { mail = await mailer.configured(); } catch (e) { mail = false; }
    return J(200, { ok: true, service: 'ultraplast-planner-api', db: db, dbError: dbError, mailConfigured: mail, allowedOrigins: String(env.ALLOWED_ORIGIN || '').split(',').map(function (x) { return x.trim(); }).filter(Boolean), authSecretSet: !!SECRET, settingsKeySet: !!env.SETTINGS_KEY });
  };
  routes['POST /auth/register'] = async function (req) {
    var b = req.body || {}, R = await rules(), er = validateReg(b, R); if (Object.keys(er).length) return bad('Please fix the highlighted fields.', 400, { fields: er });
    var em = t(b.email).toLowerCase();
    if (!(await store.throttle('reg:' + (req.ip || '-'), 20, 3600000, now()))) return bad('Too many attempts from this network. Try again later.', 429);
    var u = await store.getUserByEmail(em);
    if (u && u.status === 'approved') return bad('This email is already registered. Please log in.', 409, { status: 'approved' });
    if (u && u.status === 'pending') return bad('Your request is already submitted and waiting for Ultraplast approval.', 409, { status: 'pending' });
    if (u && (u.status === 'rejected' || u.status === 'revoked')) return bad('This email cannot register again. Please contact Ultraplast.', 403, { status: u.status });
    var fields = { name: t(b.name), company: t(b.company), phone: t(b.phone).replace(/[\s\-()]/g, ''), purpose: t(b.purpose), pass_hash: C.hashPassword(b.password) };
    if (u) await store.updateUser(u.id, fields);
    else await store.insertUser(Object.assign({ id: C.newId(), email: em, role: 'user', status: 'unverified', created_at: iso() }, fields));
    var o = await sendOtp(em, R); if (!o.ok) return bad(o.error, o.mail ? 503 : 429, { mail: !!o.mail });
    await store.audit(em, 'register', em, null, iso());
    return J(200, { ok: true, next: 'verify', message: 'We sent a 6-digit code to ' + em + '.' });
  };
  routes['POST /auth/resend'] = async function (req) {
    var em = t((req.body || {}).email).toLowerCase(), u = await store.getUserByEmail(em);
    if (!u || u.status !== 'unverified') return bad('Nothing to verify for this email.', 404);
    var o = await sendOtp(em, await rules()); if (!o.ok) return bad(o.error, o.mail ? 503 : 429, { mail: !!o.mail });
    return J(200, { ok: true, message: 'A new code was sent.' });
  };
  routes['POST /auth/verify'] = async function (req) {
    var b = req.body || {}, em = t(b.email).toLowerCase(), code = t(b.otp), u = await store.getUserByEmail(em);
    if (!u) return bad('Register first.', 404);
    if (u.status !== 'unverified') return J(200, { ok: true, status: u.status, message: u.status === 'pending' ? 'Already verified. Waiting for approval.' : 'Already verified.' });
    var o = await store.getOtp(em); if (!o) return bad('No code found. Press Resend code.', 400);
    if (Date.parse(o.expires_at) < now()) return bad('The code has expired. Press Resend code.', 400, { expired: true });
    if (Number(o.attempts) >= 5) return bad('Too many wrong attempts. Press Resend code.', 429, { locked: true });
    if (!/^\d{6}$/.test(code) || !C.safeEq(C.hashOtp(em, code, SECRET), o.code_hash)) { await store.bumpOtpAttempts(em); return bad('That code is not correct.', 400); }
    var R = await rules(); await store.deleteOtp(em);
    await store.updateUser(u.id, { status: R.requireApproval === false ? 'approved' : 'pending', verified_at: iso() });
    await store.audit(em, 'verify', em, null, iso());
    if (R.requireApproval !== false) { await notifyAdmins(u, R); return J(200, { ok: true, status: 'pending', message: 'Email verified. Your request was submitted to Ultraplast. You can log in after the super admin approves it.' }); }
    return J(200, { ok: true, status: 'approved', message: 'Email verified. You can log in now.' });
  };
  routes['POST /auth/login'] = async function (req) {
    var b = req.body || {}, em = t(b.email).toLowerCase();
    if (!(await store.throttle('login:' + em + ':' + (req.ip || '-'), 10, 900000, now()))) return bad('Too many login attempts. Try again in 15 minutes.', 429);
    var u = await store.getUserByEmail(em);
    if (!u || !C.verifyPassword(b.password, u.pass_hash)) return bad('Email or password is not correct.', 401);
    if (u.status === 'unverified') return bad('Your email is not verified yet.', 403, { status: 'unverified' });
    if (u.status === 'pending') return bad('Your request is waiting for Ultraplast approval.', 403, { status: 'pending' });
    if (u.status === 'rejected') return bad('Your access request was not approved. Please contact Ultraplast.', 403, { status: 'rejected' });
    if (u.status === 'revoked') return bad('Your access has been stopped. Please contact Ultraplast.', 403, { status: 'revoked' });
    await store.updateUser(u.id, { last_login_at: iso() });
    return J(200, { ok: true, token: issue(u), user: { name: u.name, company: u.company, email: u.email, role: u.role } });
  };
  routes['GET /auth/me'] = async function (req) { var u = await authed(req); if (!u) return bad('Please log in.', 401); return J(200, { ok: true, user: { name: u.name, company: u.company, email: u.email, role: u.role } }); };
  routes['POST /auth/change-password'] = async function (req) {
    var u = await authed(req); if (!u) return bad('Please log in.', 401); var b = req.body || {};
    if (!C.verifyPassword(b.oldPassword, u.pass_hash)) return bad('The current password is not correct.', 400);
    var pw = String(b.newPassword || ''); if (pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return bad('New password must be at least 8 characters with letters and numbers.', 400);
    await store.updateUser(u.id, { pass_hash: C.hashPassword(pw) }); await store.audit(u.email, 'change-password', u.email, null, iso()); return J(200, { ok: true });
  };

  /* ---------- admin ---------- */
  async function admin(req) { var u = await authed(req); if (!u) return { err: bad('Please log in.', 401) }; if (u.role !== 'admin') return { err: bad('Admin access only.', 403) }; return { u: u }; }
  routes['GET /admin/users'] = async function (req) { var a = await admin(req); if (a.err) return a.err; var q = (req.query || {}).status; var rows = await store.listUsers(STATUS.indexOf(q) >= 0 ? q : 'all'); return J(200, { ok: true, users: rows.map(pub) }); };
  routes['POST /admin/user-action'] = async function (req) {
    var a = await admin(req); if (a.err) return a.err; var b = req.body || {}, u = await store.getUserById(t(b.id)); if (!u) return bad('User not found.', 404);
    if (u.id === a.u.id) return bad('You cannot change your own access.', 400);
    var act = t(b.action), n = iso();
    if (act === 'approve') { await store.updateUser(u.id, { status: 'approved', decided_at: n, decided_by: a.u.email, note: t(b.note) || null }); await notifyUser(u, true); }
    else if (act === 'reject') { await store.updateUser(u.id, { status: 'rejected', decided_at: n, decided_by: a.u.email, note: t(b.note) || null }); await notifyUser(u, false); }
    else if (act === 'revoke') await store.updateUser(u.id, { status: 'revoked', decided_at: n, decided_by: a.u.email });
    else if (act === 'restore') await store.updateUser(u.id, { status: 'approved', decided_at: n, decided_by: a.u.email });
    else if (act === 'make-admin') await store.updateUser(u.id, { role: 'admin' });
    else if (act === 'make-user') await store.updateUser(u.id, { role: 'user' });
    else if (act === 'delete') await store.deleteUser(u.id);
    else if (act === 'reset-password') { var pw = String(b.password || ''); if (pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return bad('New password must be at least 8 characters with letters and numbers.', 400); await store.updateUser(u.id, { pass_hash: C.hashPassword(pw) }); }
    else return bad('Unknown action.', 400);
    await store.audit(a.u.email, act, u.email, null, n); return J(200, { ok: true });
  };
  routes['GET /admin/settings'] = async function (req) {
    var a = await admin(req); if (a.err) return a.err; var m = await store.getSetting('mail'), R = await rules(), live = await mailer.load().catch(function () { return null; });
    return J(200, { ok: true, mail: m ? { user: m.user, host: m.host, port: m.port, secure: !!m.secure, fromName: m.fromName, provider: m.provider, hasPassword: !!m.passEnc, verifiedAt: m.verifiedAt || null } : null, mailSource: live ? live.source : null, rules: R, settingsKeySet: !!env.SETTINGS_KEY, presets: Object.keys(M.PRESETS).map(function (k) { return { id: k, label: M.PRESETS[k].label, host: M.PRESETS[k].host, port: M.PRESETS[k].port, secure: M.PRESETS[k].secure }; }) });
  };
  routes['POST /admin/mail-detect'] = async function (req) { var a = await admin(req); if (a.err) return a.err; var em = t((req.body || {}).email).toLowerCase(); if (!EMAIL_RE.test(em)) return bad('Enter a valid mail id.', 400); return J(200, { ok: true, smtp: await mailer.detect(em) }); };
  routes['POST /admin/mail'] = async function (req) {
    var a = await admin(req); if (a.err) return a.err; var b = req.body || {}, em = t(b.email).toLowerCase(), pass = M.cleanPass(b.appPassword);
    if (!env.SETTINGS_KEY) return bad('SETTINGS_KEY is not set on the server, so the password cannot be stored safely. See the setup guide.', 400);
    if (!EMAIL_RE.test(em)) return bad('Enter a valid mail id.', 400);
    var old = await store.getSetting('mail'), passEnc = null;
    if (pass) passEnc = C.encrypt(pass, env.SETTINGS_KEY); else if (old && old.user === em && old.passEnc) { passEnc = old.passEnc; pass = C.decrypt(old.passEnc, env.SETTINGS_KEY); } else return bad('Paste the App Password for this mail id.', 400);
    var d = await mailer.detect(em), host = t(b.host) || d.host, port = Number(b.port) || d.port, secure = b.secure === undefined || b.secure === '' ? d.secure : (b.secure === true || b.secure === 'true');
    var cfg = { user: em, pass: pass, host: host, port: port, secure: secure }, v = await mailer.verify(cfg);
    if (!v.ok && !b.saveAnyway) return bad(v.error, 400, { verify: false, smtp: { host: host, port: port, secure: secure } });
    await store.setSetting('mail', { user: em, passEnc: passEnc, host: host, port: port, secure: secure, fromName: t(b.fromName) || 'Ultraplast Planner', provider: d.provider, verifiedAt: v.ok ? iso() : null }, iso());
    await store.audit(a.u.email, 'mail-settings', em, v.ok ? 'verified' : 'saved without verification', iso());
    return J(200, { ok: true, verified: v.ok, message: v.ok ? 'Connected. The mail id ' + em + ' is now used to send OTP and approval emails.' : 'Saved, but the login could not be verified: ' + v.error });
  };
  routes['POST /admin/mail-test'] = async function (req) {
    var a = await admin(req); if (a.err) return a.err; var to = t((req.body || {}).to).toLowerCase() || a.u.email; if (!EMAIL_RE.test(to)) return bad('Enter a valid email address.', 400);
    try { await mailer.send({ to: to, subject: 'Ultraplast Planner test mail', text: 'This is a test mail from the Ultraplast Conveyor Planner. Mail is connected.' }); } catch (e) { return bad(e.message, 502); }
    return J(200, { ok: true, message: 'Test mail sent to ' + to + '.' });
  };
  routes['POST /admin/mail-remove'] = async function (req) { var a = await admin(req); if (a.err) return a.err; await store.setSetting('mail', null, iso()); await store.audit(a.u.email, 'mail-removed', null, null, iso()); return J(200, { ok: true }); };
  routes['POST /admin/rules'] = async function (req) {
    var a = await admin(req); if (a.err) return a.err; var b = req.body || {}, cur = await rules();
    var dm = function (s) { return String(s || '').split(/[\s,;]+/).map(function (x) { return x.toLowerCase().replace(/^@/, ''); }).filter(function (x) { return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(x); }); };
    var next = { otpMinutes: Math.max(3, Math.min(30, parseInt(b.otpMinutes, 10) || cur.otpMinutes)), notifyAdmin: b.notifyAdmin === undefined ? cur.notifyAdmin : !!b.notifyAdmin, requireApproval: b.requireApproval === undefined ? cur.requireApproval : !!b.requireApproval, allowedDomains: b.allowedDomains === undefined ? cur.allowedDomains : dm(b.allowedDomains), blockedDomains: b.blockedDomains === undefined ? cur.blockedDomains : dm(b.blockedDomains) };
    await store.setSetting('rules', next, iso()); await store.audit(a.u.email, 'rules', null, JSON.stringify(next), iso()); return J(200, { ok: true, rules: next });
  };
  routes['GET /admin/db'] = async function (req) { var a = await admin(req); if (a.err) return a.err; try { var c = await store.counts(); return J(200, { ok: true, connected: true, counts: c }); } catch (e) { return J(200, { ok: true, connected: false, error: 'Tables are missing or the database is not reachable. Press Run database setup.' }); } };
  routes['POST /admin/db-setup'] = async function (req) { var a = await admin(req); if (a.err) return a.err; try { var n = await store.ensureSchema(); await store.audit(a.u.email, 'db-setup', null, null, iso()); return J(200, { ok: true, message: 'Database tables are ready (' + n + ' statements checked).' }); } catch (e) { return bad('Database setup failed: ' + e.message, 500); } };
  routes['GET /admin/audit'] = async function (req) { var a = await admin(req); if (a.err) return a.err; return J(200, { ok: true, rows: await store.listAudit(100) }); };

  var ORIGINS = String(env.ALLOWED_ORIGIN || '').split(',').map(function (s) { return s.trim().replace(/\/$/, ''); }).filter(Boolean);
  function cors(req, res) {
    var o = (req.headers || {}).origin || (req.headers || {}).Origin, h = { 'Vary': 'Origin', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Max-Age': '600', 'Cache-Control': 'no-store' };
    if (o && (ORIGINS.indexOf('*') >= 0 || ORIGINS.indexOf(o.replace(/\/$/, '')) >= 0)) h['Access-Control-Allow-Origin'] = o;
    res.headers = Object.assign(h, res.headers); return res;
  }
  return {
    handle: async function (req) {
      var path = String(req.path || '/').replace(/^\/api(?=\/)/, '').replace(/\/+$/, '') || '/';
      if (req.method === 'OPTIONS') return cors(req, J(204, null));
      if (!SECRET || SECRET.length < 16) return cors(req, bad('The server is not configured: set AUTH_SECRET (at least 16 characters).', 500));
      var fn = routes[req.method + ' ' + path]; if (!fn) return cors(req, bad('Not found.', 404));
      try { if (path !== '/health') await ensureReady(); return cors(req, await fn(req)); }
      catch (e) { return cors(req, bad('Server error: ' + (e && e.message ? e.message : e), 500)); }
    },
    setup: ensureReady
  };
}
module.exports = { createApp: createApp, DEFAULT_RULES: DEFAULT_RULES };
