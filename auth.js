"use strict";
/* Accounts (email + password), sessions, and the HTTP entry point for /auth/v1, /rest/v1 and /api. */
const crypto = require("node:crypto"), db = require("./db"), rest = require("./rest");
const { HttpErr } = rest;

/* Super-admin activation password: stored ONLY as a salted scrypt hash (never in plain text).
   Override on Railway with SUPER_ADMIN_PASSWORD_HASH (or SUPER_ADMIN_PASSWORD) to change it. */
const DEFAULT_SUPER_HASH = "scrypt$66xRRRINazoTZMqS+lFStA==$pyMunfZS5wts/Mt7/qsl1IpHghJXO3Ovd/MKEnojRNspTH7WZNtyezc5/XQiGmzCEZbKakpmU5QtZwzTuq92wA==";

const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (e, k) => (e ? no(e) : ok(k))));
async function hashPassword(pw) { const salt = crypto.randomBytes(16); return "scrypt$" + salt.toString("base64") + "$" + (await scrypt(pw, salt)).toString("base64"); }
async function verifyPassword(pw, stored) {
  const [t, s, h] = String(stored || "").split("$"); if (t !== "scrypt" || !s || !h) return false;
  const k = await scrypt(pw, Buffer.from(s, "base64")), e = Buffer.from(h, "base64");
  return e.length === k.length && crypto.timingSafeEqual(e, k);
}
let superHashPromise = null;
function superHash() {
  if (!superHashPromise) superHashPromise = Promise.resolve(process.env.SUPER_ADMIN_PASSWORD_HASH || (process.env.SUPER_ADMIN_PASSWORD ? hashPassword(process.env.SUPER_ADMIN_PASSWORD) : DEFAULT_SUPER_HASH));
  return superHashPromise;
}
const DUMMY_HASH = "scrypt$" + Buffer.alloc(16).toString("base64") + "$" + Buffer.alloc(64).toString("base64");

/* ---- tiny JWT (HS256) ---- */
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const mac = (s) => crypto.createHmac("sha256", db.state.jwt).update(s).digest();
function sign(claims) { const h = b64({ alg: "HS256", typ: "JWT" }), p = b64(claims); return h + "." + p + "." + mac(h + "." + p).toString("base64url"); }
function verify(tok) {
  const parts = tok.split("."); if (parts.length !== 3) return null;
  try {
    if (JSON.parse(Buffer.from(parts[0], "base64url").toString()).alg !== "HS256") return null;
    const given = Buffer.from(parts[2], "base64url"), want = mac(parts[0] + "." + parts[1]);
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) return null;
    const c = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    return c && c.sub && c.exp > Date.now() / 1000 ? c : "expired";
  } catch (_) { return null; }
}
function claimsOf(req) {                       // null = visitor (anon); throws 401 for a bad/expired token
  const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization || ""); if (!m || m[1].split(".").length !== 3) return null;
  const c = verify(m[1]);
  if (c === "expired") throw new HttpErr(401, { code: "PGRST301", message: "JWT expired", details: null, hint: null });
  if (!c) throw new HttpErr(401, { code: "PGRST301", message: "Invalid token", details: null, hint: null });
  return c;
}

/* ---- rate limiting (in memory) ---- */
const hits = new Map();
const recent = (k, w) => { const n = Date.now(), a = (hits.get(k) || []).filter((t) => n - t < w); hits.set(k, a); return a; };
const tooMany = (k, max, w) => recent(k, w).length >= max;
const fail = (k, w) => recent(k, w).push(Date.now());
setInterval(() => { for (const k of hits.keys()) if (!recent(k, 3600e3).length) hits.delete(k); }, 600e3).unref();
const ipOf = (req) => (String(req.headers["x-forwarded-for"] || "").split(",").pop().trim() || req.socket.remoteAddress || "?");

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const authErr = (status, error_code, msg) => new HttpErr(status, { code: status, error_code, msg });
const userObj = (u) => ({ id: u.id, aud: "authenticated", role: "authenticated", email: u.email, email_confirmed_at: u.created_at, phone: "", confirmed_at: u.created_at, last_sign_in_at: u.last_sign_in_at || u.created_at,
  app_metadata: { provider: "email", providers: ["email"] }, user_metadata: u.raw_user_meta_data || {}, identities: [], created_at: u.created_at, updated_at: u.created_at });
async function session(u) {
  const now = Math.floor(Date.now() / 1000), refresh = crypto.randomBytes(32).toString("base64url");
  await db.pool.query("insert into auth.refresh_tokens (token_hash, user_id) values ($1, $2)", [sha(refresh), u.id]);
  db.pool.query("delete from auth.refresh_tokens where created_at < now() - interval '60 days'").catch(() => {});
  return { access_token: sign({ aud: "authenticated", sub: u.id, role: "authenticated", email: u.email, iat: now, exp: now + 3600, session_id: crypto.randomUUID() }),
    token_type: "bearer", expires_in: 3600, expires_at: now + 3600, refresh_token: refresh, user: userObj(u) };
}

async function readBody(req) {
  const chunks = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > 1e6) throw new HttpErr(413, { message: "Body too large" }); chunks.push(c); }
  if (!n) return null;
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch (_) { throw new HttpErr(400, { code: "PGRST102", message: "Invalid JSON body" }); }
}

async function authRoute(req, res, p, url) {
  const m = req.method, ip = ipOf(req), body = m === "POST" || m === "PUT" ? await readBody(req) : null;
  if (p === "/auth/v1/signup" && m === "POST") {
    const email = String(body && body.email || "").trim().toLowerCase(), pw = String(body && body.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw authErr(422, "validation_failed", "Unable to validate email address: invalid format");
    if (pw.length < 6 || pw.length > 200) throw authErr(422, "weak_password", "Password should be at least 6 characters.");
    if (tooMany("signup|" + ip, 10, 3600e3)) throw authErr(429, "over_request_rate_limit", "Too many sign-ups, try again later");
    fail("signup|" + ip, 3600e3);
    try {
      const meta = body.data && typeof body.data === "object" ? body.data : {};
      const r = await db.pool.query("insert into auth.users (email, encrypted_password, raw_user_meta_data) values ($1, $2, $3::jsonb) returning *", [email, await hashPassword(pw), JSON.stringify(meta)]);
      return { status: 200, body: await session(r.rows[0]) };
    } catch (e) { if (e.code === "23505") throw authErr(422, "user_already_exists", "User already registered"); throw e; }
  }
  if (p === "/auth/v1/token" && m === "POST") {
    const gt = url.searchParams.get("grant_type");
    if (gt === "password") {
      const email = String(body && body.email || "").trim().toLowerCase(), pw = String(body && body.password || "").slice(0, 200), k1 = "login|" + ip + "|" + email, k2 = "loginip|" + ip;
      if (tooMany(k1, 8, 600e3) || tooMany(k2, 40, 600e3)) throw authErr(429, "over_request_rate_limit", "Too many attempts, try again in a few minutes");
      const r = await db.pool.query("select * from auth.users where lower(email) = $1", [email]), u = r.rows[0];
      const ok = await verifyPassword(pw, u ? u.encrypted_password : DUMMY_HASH);
      if (!u || !ok) { fail(k1, 600e3); fail(k2, 600e3); throw authErr(400, "invalid_credentials", "Invalid login credentials"); }
      await db.pool.query("update auth.users set last_sign_in_at = now() where id = $1", [u.id]);
      return { status: 200, body: await session(u) };
    }
    if (gt === "refresh_token") {
      const h = sha(String(body && body.refresh_token || ""));
      const r = await db.pool.query("update auth.refresh_tokens set revoked = true where token_hash = $1 and not revoked and created_at > now() - interval '60 days' returning user_id", [h]);
      if (!r.rowCount) throw authErr(400, "refresh_token_not_found", "Invalid Refresh Token: Refresh Token Not Found");
      const u = (await db.pool.query("select * from auth.users where id = $1", [r.rows[0].user_id])).rows[0];
      if (!u) throw authErr(400, "refresh_token_not_found", "Invalid Refresh Token: Refresh Token Not Found");
      return { status: 200, body: await session(u) };
    }
    throw authErr(400, "validation_failed", "Unsupported grant_type");
  }
  if (p === "/auth/v1/user" && m === "GET") {
    const c = claimsOf(req); if (!c) throw authErr(401, "no_authorization", "This endpoint requires a Bearer token");
    const u = (await db.pool.query("select * from auth.users where id = $1", [c.sub])).rows[0];
    if (!u) throw authErr(401, "user_not_found", "User from sub claim in JWT does not exist");
    return { status: 200, body: userObj(u) };
  }
  if (p === "/auth/v1/logout" && m === "POST") {
    let c = null; try { c = claimsOf(req); } catch (_) {}
    if (c) await db.pool.query("update auth.refresh_tokens set revoked = true where user_id = $1", [c.sub]);
    return { status: 204, body: null };
  }
  throw authErr(404, "not_found", "Not found");
}

async function activateAdmin(req) {
  const c = claimsOf(req); if (!c) throw new HttpErr(401, { error: "NOT_AUTHENTICATED", message: "Log in first" });
  const ip = ipOf(req), body = await readBody(req), pw = String(body && body.password || "").slice(0, 300), k1 = "su|" + c.sub, k2 = "suip|" + ip;
  if (tooMany(k1, 5, 900e3) || tooMany(k2, 15, 900e3)) throw new HttpErr(429, { error: "TOO_MANY_ATTEMPTS", message: "Too many attempts. Try again in 15 minutes." });
  if (!(await verifyPassword(pw, await superHash()))) { fail(k1, 900e3); fail(k2, 900e3); throw new HttpErr(403, { error: "WRONG_PASSWORD", message: "Wrong password" }); }
  const r = await db.pool.query("update public.profiles set role = 'super_admin' where id = $1 returning email", [c.sub]);
  if (!r.rowCount) throw new HttpErr(404, { error: "NO_PROFILE", message: "Profile not found" });
  console.log("[admin] super admin activated for " + r.rows[0].email);
  return { status: 200, body: { ok: true } };
}

async function handle(req, res, p, url) {
  const send = (status, body) => { const s = body == null ? "" : JSON.stringify(body); res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Length": Buffer.byteLength(s) }); res.end(req.method === "HEAD" ? undefined : s); };
  try {
    if (req.method === "OPTIONS") return send(204, null);
    if (p === "/api/status") return send(200, { db: db.state.ready, error: db.state.ready ? null : db.state.error });
    if (!db.state.ready) return send(503, { message: "Database not ready: " + (db.state.error || "starting") });
    let out;
    if (p.startsWith("/auth/v1/")) out = await authRoute(req, res, p, url);
    else if (p === "/api/activate-admin" && req.method === "POST") out = await activateAdmin(req);
    else if (p.startsWith("/rest/v1/rpc/") && req.method === "POST") out = await rest.rpc(p.slice(13), await readBody(req), claimsOf(req));
    else if (p.startsWith("/rest/v1/") && /^[A-Za-z_][A-Za-z0-9_]*$/.test(p.slice(9))) {
      const body = req.method === "POST" || req.method === "PATCH" ? await readBody(req) : null;
      out = await rest.table(p.slice(9), req, url, body, claimsOf(req));
    } else throw new HttpErr(404, { message: "Not found" });
    return send(out.status, out.body);
  } catch (e) {
    if (e instanceof HttpErr) return send(e.status, e.body);
    console.error("[api] unexpected error:", e); return send(500, { message: "Internal error" });
  }
}
module.exports = { handle, hashPassword, verifyPassword, sign, verify };
