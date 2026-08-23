// Intentionally vulnerable head-to-head corpus. Never use in an application.
//
// Admin routes are registered without any authorization middleware and the
// file carries no global auth signal, so the missing-authorization check
// (SP108) and the Express hardening checks apply.
const express = require("express");

const app = express();

app.delete("/admin/users/:id", (req, res) => {
  db.removeUser(req.params.id);
  res.json({ removed: true });
});

app.post("/admin/grant", (req, res) => {
  db.query(`INSERT INTO roles (user_id, role) VALUES ('${req.body.userId}', 'admin')`);
  res.json({ granted: true });
});

module.exports = app;
