'use strict';
/* Test-only: lets the Postgres-style SQL ($1, $2 ...) run on Node's built-in SQLite, so the real store SQL is exercised without a server. */
var DatabaseSync = require('node:sqlite').DatabaseSync;
module.exports = function () {
  var db = new DatabaseSync(':memory:');
  return function query(text, params) {
    var sql = String(text).replace(/\$(\d+)/g, '?$1'), st = db.prepare(sql), p = params || [];
    if (/^\s*(SELECT|WITH)/i.test(sql) || /\bRETURNING\b/i.test(sql)) return Promise.resolve(st.all.apply(st, p).map(function (r) { return Object.assign({}, r); }));
    st.run.apply(st, p); return Promise.resolve([]);
  };
};
