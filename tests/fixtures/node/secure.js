// Secure counterpart of insecure.js: must produce no findings.
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE name = $1", [req.query.name]);
  res.json({ name: String(req.query.name) });
});

app.get("/token", (req, res) => {
  res.json({ token: jwt.sign({ user: req.query.user }, process.env.JWT_SECRET) });
});
