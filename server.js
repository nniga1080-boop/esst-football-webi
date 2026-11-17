"use strict";
/* ESST site: serves the website AND its built-in backend (accounts + data on Railway PostgreSQL). */
const http = require("node:http"), fs = require("node:fs"), path = require("node:path"), zlib = require("node:zlib");
const db = require("./db"), api = require("./auth");
const ROOT = __dirname, PORT = parseInt(process.env.PORT, 10) || 3000;
const TYPES = { ".html": "text/html; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".ico": "image/x-icon", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8" };

function originOf(req) {                         // the site talks to its own address: no external keys needed
  const proto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim() === "https" ? "https" : "http";
  let host = String(req.headers["x-forwarded-host"] || req.headers.host || "localhost").split(",")[0].trim();
  if (!/^[A-Za-z0-9.\-:]+$/.test(host)) host = "localhost";
  return proto + "://" + host;
}
const cache = new Map();
function pageBuffer(file, st, origin) {
  const key = file + "|" + origin, etag = '"' + st.size.toString(36) + "-" + Math.floor(st.mtimeMs).toString(36) + '"';
  let c = cache.get(key);
  if (!c || c.etag !== etag) {
    const cfg = "<script>window.__ESST_CONFIG__=" + JSON.stringify({ VITE_SUPABASE_URL: origin, VITE_SUPABASE_PUBLISHABLE_KEY: "esst-builtin-key" }).replace(/</g, "\\u003c") + ";</script>";
    const raw = Buffer.from(fs.readFileSync(file, "utf8").replace("<!--ESST_CONFIG-->", cfg), "utf8");
    c = { etag, raw, gz: zlib.gzipSync(raw) }; cache.set(key, c);
  }
  return c;
}

http.createServer((req, res) => {
  let p, url;
  try { url = new URL(req.url, "http://x"); p = decodeURIComponent(url.pathname); } catch (_) { res.writeHead(400); return res.end(); }
  res.setHeader("X-Content-Type-Options", "nosniff"); res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin"); res.setHeader("X-Frame-Options", "SAMEORIGIN");
  if (p === "/health") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify({ ok: true, db: db.state.ready })); }
  if (p.startsWith("/auth/v1/") || p.startsWith("/rest/v1/") || p.startsWith("/api/")) return api.handle(req, res, p, url);
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405); return res.end(); }
  const rel = p === "/" ? "index.html" : p.replace(/^\/+/, "");
  const allowed = rel === "index.html" || rel === "favicon.svg";
  const file = path.join(ROOT, allowed ? rel : "index.html");           // unknown path: give the app (it routes by itself)
  if (!allowed && path.extname(rel)) { res.writeHead(404); return res.end("Not found"); }
  fs.stat(file, (e, st) => {
    if (e || !st.isFile()) { res.writeHead(404); return res.end("Not found"); }
    const ext = path.extname(file), type = TYPES[ext] || "application/octet-stream", head = req.method === "HEAD";
    const wantsGzip = /\bgzip\b/.test(req.headers["accept-encoding"] || "");
    if (file.endsWith("index.html")) {
      const origin = originOf(req), c = pageBuffer(file, st, origin), h = { "Content-Type": type, ETag: c.etag.slice(0, -1) + "-" + Buffer.from(origin).toString("base64url").slice(0, 12) + '"', "Cache-Control": "no-cache", Vary: "Accept-Encoding" };
      if (req.headers["if-none-match"] === h.ETag) { res.writeHead(304, h); return res.end(); }
      const body = wantsGzip ? c.gz : c.raw; if (wantsGzip) h["Content-Encoding"] = "gzip";
      h["Content-Length"] = body.length; res.writeHead(200, h); return res.end(head ? undefined : body);
    }
    const etag = '"' + st.size.toString(36) + "-" + Math.floor(st.mtimeMs).toString(36) + '"', h = { "Content-Type": type, ETag: etag, "Cache-Control": "public, max-age=86400" };
    if (req.headers["if-none-match"] === etag) { res.writeHead(304, h); return res.end(); }
    res.writeHead(200, Object.assign(h, { "Content-Length": st.size })); if (head) res.end(); else fs.createReadStream(file).pipe(res);
  });
}).listen(PORT, "0.0.0.0", () => { console.log("ESST site listening on " + PORT); db.start(); });
process.on("unhandledRejection", (e) => console.error("[unhandledRejection]", e));
