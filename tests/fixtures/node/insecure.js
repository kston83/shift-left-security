// Intentionally vulnerable test data for slsec-sast. Do not use.
const express = require("express");
const jwt = require("jsonwebtoken");
const path = require("path");
const vm = require("vm");
const app = express();

app.get("/user", (req, res) => {
  const sql = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  db.query(sql);
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.get("/calc", (req, res) => {
  const code = req.query.expr;
  res.send(String(vm.runInThisContext(code)));
});

app.get("/file", (req, res) => {
  res.sendFile(path.join(__dirname, req.query.file));
});

app.get("/go", (req, res) => {
  res.redirect(req.query.next);
});

app.get("/token", (req, res) => {
  res.json({ token: jwt.sign({ user: req.query.user }, "secret") });
});
