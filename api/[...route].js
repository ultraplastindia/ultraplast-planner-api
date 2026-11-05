'use strict';
/* Vercel serverless entry: every /api/* request lands here. The database is Neon Postgres (DATABASE_URL). */
var createApp = require('../lib/app.js').createApp, createStore = require('../lib/store.js').createStore, dns = require('dns').promises;
var app = null;
function getApp() {
  if (app) return app;
  if (!process.env.DATABASE_URL) return null;
  var neon = require('@neondatabase/serverless').neon, sql = neon(process.env.DATABASE_URL);
  var store = createStore(function (text, params) { return typeof sql.query === 'function' ? sql.query(text, params || []) : sql(text, params || []); });
  app = createApp({ store: store, env: process.env, resolveMx: function (d) { return dns.resolveMx(d); } });
  return app;
}
module.exports = async function (req, res) {
  var a = getApp();
  if (!a) { res.statusCode = 500; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ ok: false, error: 'DATABASE_URL is not set. Add the Neon connection string in the Vercel project settings.' })); return; }
  var body = req.body; if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
  var url = new URL(req.url, 'http://x'), query = {}; url.searchParams.forEach(function (v, k) { query[k] = v; });
  var r = await a.handle({ method: req.method, path: url.pathname, headers: req.headers || {}, query: query, body: body || {}, ip: String((req.headers['x-forwarded-for'] || '')).split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || '' });
  res.statusCode = r.status; Object.keys(r.headers || {}).forEach(function (k) { res.setHeader(k, r.headers[k]); });
  if (r.body === null || r.body === undefined) { res.end(); return; }
  res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(r.body));
};
