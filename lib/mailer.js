'use strict';
/* Outgoing mail over SMTP with an App Password. The admin pastes a mail id + app password in Settings; the password is stored
   AES-256-GCM encrypted (key = SETTINGS_KEY env var) and is never sent back to the browser.
   Works with any mailbox: the SMTP host is detected from the address (Gmail, Outlook / Microsoft 365, Zoho, Yahoo) or from the
   domain's MX records (Google Workspace, Zoho, Microsoft 365 on your own domain); anything else can be typed in by hand. */
var C = require('./crypto');

var PRESETS = {
  gmail: { host: 'smtp.gmail.com', port: 465, secure: true, label: 'Gmail / Google Workspace' },
  outlook: { host: 'smtp.office365.com', port: 587, secure: false, label: 'Outlook / Microsoft 365' },
  zohoin: { host: 'smtp.zoho.in', port: 465, secure: true, label: 'Zoho Mail (India)' },
  zohocom: { host: 'smtp.zoho.com', port: 465, secure: true, label: 'Zoho Mail (.com)' },
  yahoo: { host: 'smtp.mail.yahoo.com', port: 465, secure: true, label: 'Yahoo Mail' }
};
function byDomain(domain) {
  domain = String(domain || '').toLowerCase();
  if (/^(gmail|googlemail)\.com$/.test(domain)) return 'gmail';
  if (/^(outlook|hotmail|live|msn)\.[a-z.]+$/.test(domain) || domain === 'office365.com') return 'outlook';
  if (/(^|\.)zoho\.in$/.test(domain)) return 'zohoin';
  if (/(^|\.)zoho(mail)?\.com$/.test(domain)) return 'zohocom';
  if (/^yahoo\.[a-z.]+$/.test(domain) || /^ymail\.com$/.test(domain)) return 'yahoo';
  return null;
}
function byMx(host) {
  host = String(host || '').toLowerCase();
  if (/google\.com\.?$|googlemail\.com\.?$/.test(host)) return 'gmail';
  if (/protection\.outlook\.com\.?$|outlook\.com\.?$/.test(host)) return 'outlook';
  if (/zoho\.in\.?$/.test(host)) return 'zohoin';
  if (/zoho\.com\.?$/.test(host)) return 'zohocom';
  if (/yahoodns\.net\.?$/.test(host)) return 'yahoo';
  return null;
}
/** Work out the SMTP settings for a mail id. resolveMx(domain) -> Promise<[{exchange,priority}]> (injectable for tests). */
async function detectSmtp(email, resolveMx) {
  var domain = String(email || '').split('@')[1] || '', key = byDomain(domain);
  if (!key && resolveMx) { try { var mx = await resolveMx(domain); mx = (mx || []).slice().sort(function (a, b) { return a.priority - b.priority; }); for (var i = 0; i < mx.length && !key; i++) key = byMx(mx[i].exchange); } catch (e) { /* no MX info */ } }
  if (key) return Object.assign({ provider: key, detected: true }, PRESETS[key]);
  return { provider: 'custom', detected: false, host: 'smtp.' + domain, port: 465, secure: true, label: 'Other (check the host)' };
}
function friendlyError(e) {
  var code = e && e.code, m = String((e && e.message) || e);
  if (code === 'EAUTH' || /535|534|auth/i.test(m)) return 'The mail server rejected the login. Use an App Password (not your normal mailbox password). For Gmail, turn on 2-Step Verification first, then create the App Password.';
  if (code === 'ESOCKET' || code === 'ECONNECTION' || code === 'ETIMEDOUT' || code === 'ENOTFOUND' || code === 'ECONNREFUSED') return 'Could not reach the mail server. Check the host and port (' + m + ').';
  return 'Mail could not be sent: ' + m;
}
function cleanPass(p) { return String(p || '').replace(/\s+/g, ''); }

function createMailer(opts) {
  var store = opts.store, env = opts.env || {}, resolveMx = opts.resolveMx, factory = opts.transportFactory;
  function make(cfg) {
    if (factory) return factory(cfg);
    var nm = require('nodemailer');   // installed on the server by `npm install`
    return nm.createTransport({ host: cfg.host, port: cfg.port, secure: !!cfg.secure, auth: { user: cfg.user, pass: cfg.pass }, connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000 });
  }
  async function load() {
    var m = await store.getSetting('mail');
    if (m && m.user && m.passEnc && env.SETTINGS_KEY) { try { return { user: m.user, pass: C.decrypt(m.passEnc, env.SETTINGS_KEY), host: m.host, port: m.port, secure: !!m.secure, fromName: m.fromName || 'Ultraplast Planner', source: 'settings' }; } catch (e) { return null; } }
    if (env.SMTP_USER && env.SMTP_PASS) { var d = await detectSmtp(env.SMTP_USER, resolveMx); return { user: env.SMTP_USER, pass: cleanPass(env.SMTP_PASS), host: env.SMTP_HOST || d.host, port: Number(env.SMTP_PORT) || d.port, secure: env.SMTP_SECURE ? env.SMTP_SECURE === 'true' : d.secure, fromName: env.SMTP_FROM_NAME || 'Ultraplast Planner', source: 'environment' }; }
    return null;
  }
  return {
    detect: function (email) { return detectSmtp(email, resolveMx); },
    load: load,
    configured: async function () { return !!(await load()); },
    /** try a login without sending anything */
    verify: async function (cfg) { var t = make(cfg); try { await t.verify(); return { ok: true }; } catch (e) { return { ok: false, error: friendlyError(e) }; } },
    send: async function (msg) {
      var cfg = await load(); if (!cfg) { var er = new Error('Mail is not set up yet. An admin must add the mail id and App Password in Settings.'); er.code = 'MAIL_NOT_CONFIGURED'; throw er; }
      var t = make(cfg);
      try { await t.sendMail({ from: '"' + String(cfg.fromName).replace(/"/g, '') + '" <' + cfg.user + '>', to: msg.to, subject: msg.subject, text: msg.text, html: msg.html }); }
      catch (e) { var er2 = new Error(friendlyError(e)); er2.code = 'MAIL_FAILED'; throw er2; }
    }
  };
}
module.exports = { createMailer: createMailer, detectSmtp: detectSmtp, cleanPass: cleanPass, PRESETS: PRESETS, friendlyError: friendlyError };
