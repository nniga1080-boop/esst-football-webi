"use strict";
/* Minimal PostgREST-compatible layer (the subset this site uses): select with embeds, filters, order, limit,
   insert / update / delete, and RPC. Every statement runs as role anon/authenticated, so the database's
   row-level-security rules decide what each person may see or change. */
const db = require("./db");
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const q = (s) => '"' + String(s).replace(/"/g, '""') + '"';
const lit = (s) => "'" + String(s).replace(/'/g, "''") + "'";
class HttpErr extends Error { constructor(status, body) { super(body.message); this.status = status; this.body = body; } }
const bad = (m, code = "PGRST100") => new HttpErr(400, { code, message: m, details: null, hint: null });

function splitTop(s) {
  const out = []; let d = 0, cur = "";
  for (const ch of s) { if (ch === "(") d++; else if (ch === ")") d--; if (ch === "," && d === 0) { out.push(cur); cur = ""; } else cur += ch; }
  if (cur.trim()) out.push(cur);
  return out.map((x) => x.trim()).filter(Boolean);
}
function parseSelect(s) {
  return splitTop(s || "*").map((tok) => {
    const p = tok.indexOf("(");
    if (p > 0 && tok.endsWith(")")) {
      let head = tok.slice(0, p).trim(), alias = null, hint = null;
      const ci = head.indexOf(":"); if (ci > 0) { alias = head.slice(0, ci); head = head.slice(ci + 1); }
      const bi = head.indexOf("!"); if (bi > 0) { hint = head.slice(bi + 1).split("!")[0]; head = head.slice(0, bi); }
      return { embed: true, alias: alias || head, table: head, hint, items: parseSelect(tok.slice(p + 1, -1)) };
    }
    if (tok === "*") return { star: true };
    let alias = null, name = tok; const ci = tok.indexOf(":");
    if (ci > 0 && tok[ci + 1] !== ":") { alias = tok.slice(0, ci); name = tok.slice(ci + 1); }
    return { col: true, name: name.trim(), alias: (alias || name).trim() };
  });
}

function selectExpr(cat, table, items, ta, ctx) {
  const T = cat.tables.get(table); if (!T) throw bad("Unknown table " + table, "42P01");
  let base = null; const cols = [], parts = [];
  for (const it of items) {
    if (it.star) base = "to_jsonb(" + ta + ")";
    else if (it.col) {
      if (!T.has(it.name) || !IDENT.test(it.alias)) throw bad("Unknown column " + table + "." + it.name, "42703");
      cols.push(lit(it.alias) + ", " + ta + "." + q(it.name));
    } else {
      if (!IDENT.test(it.alias)) throw bad("Bad alias");
      parts.push("jsonb_build_object(" + lit(it.alias) + ", " + embedExpr(cat, table, it, ta, ctx) + ")");
    }
  }
  const out = []; if (base) out.push(base); if (cols.length) out.push("jsonb_build_object(" + cols.join(", ") + ")");
  return out.concat(parts).join(" || ") || "'{}'::jsonb";
}
function embedExpr(cat, table, it, ta, ctx) {
  const tgt = it.table; if (!cat.tables.has(tgt)) throw bad("Unknown table " + tgt, "PGRST200");
  let cands = cat.fks.filter((f) => (f.src === table && f.dst === tgt) || (f.src === tgt && f.dst === table));
  if (it.hint) cands = cands.filter((f) => f.name === it.hint || (f.src === table && f.scols.includes(it.hint)) || (f.src === tgt && f.scols.includes(it.hint)));
  if (!cands.length) throw new HttpErr(400, { code: "PGRST200", message: "No relationship between " + table + " and " + tgt, details: null, hint: null });
  if (cands.length > 1) throw new HttpErr(300, { code: "PGRST201", message: "Ambiguous relationship between " + table + " and " + tgt, details: null, hint: null });
  const f = cands[0], e = "e" + (++ctx.n), toOne = f.src === table;
  const join = toOne ? f.scols.map((c, i) => e + "." + q(f.dcols[i]) + " = " + ta + "." + q(c))
                     : f.scols.map((c, i) => e + "." + q(c) + " = " + ta + "." + q(f.dcols[i]));
  const expr = selectExpr(cat, tgt, it.items, e, ctx), from = " from public." + q(tgt) + " " + e + " where " + join.join(" and ");
  return toOne ? "(select " + expr + from + " limit 1)" : "coalesce((select jsonb_agg(" + expr + ")" + from + "), '[]'::jsonb)";
}

const RESERVED = new Set(["select", "order", "limit", "offset", "columns", "on_conflict"]);
function parseList(s) {
  s = s.trim(); if (s[0] === "(" && s.endsWith(")")) s = s.slice(1, -1);
  if (s === "") return [];
  const out = []; let cur = "", inq = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inq) { if (ch === "\\" && i + 1 < s.length) cur += s[++i]; else if (ch === '"') inq = false; else cur += ch; }
    else if (ch === '"') inq = true; else if (ch === ",") { out.push(cur); cur = ""; } else cur += ch;
  }
  out.push(cur); return out;
}
const OPS = { eq: "=", neq: "<>", gt: ">", gte: ">=", lt: "<", lte: "<=", like: "like", ilike: "ilike" };
function filtersSQL(cat, table, sp, ta, params) {
  const T = cat.tables.get(table), conds = [];
  for (const [k, v] of sp) {
    if (RESERVED.has(k)) continue;
    if (!T.has(k)) throw bad("Unknown column " + table + "." + k, "42703");
    const m = /^(not\.)?([a-z]+)\.([\s\S]*)$/.exec(v); if (!m) throw bad("Invalid filter on " + k);
    const neg = !!m[1], op = m[2], val = m[3], ref = ta + "." + q(k), ty = T.get(k); let c;
    if (op === "is") {
      const w = val.toLowerCase(); if (!["null", "true", "false", "unknown"].includes(w)) throw bad("Invalid is. value");
      c = ref + " is " + (w === "null" ? "null" : w);
    } else if (op === "in") {
      if (ty.endsWith("[]")) throw bad("in. not supported on array columns");
      params.push(parseList(val)); c = ref + " = any($" + params.length + "::" + ty + "[])";
    } else if (OPS[op]) {
      if (op === "like" || op === "ilike") { params.push(val.replace(/\*/g, "%")); c = ref + "::text " + OPS[op] + " $" + params.length; }
      else { params.push(val); c = ref + " " + OPS[op] + " $" + params.length + "::" + ty; }
    } else throw bad("Unsupported operator " + op);
    conds.push(neg ? "not (" + c + ")" : c);
  }
  return conds;
}
function orderSQL(T, o, ta) {
  if (!o) return "";
  return " order by " + splitTop(o).map((p) => {
    const [col, ...mods] = p.split("."); if (!T.has(col)) throw bad("Unknown column " + col, "42703");
    return ta + "." + q(col) + (mods.includes("desc") ? " desc" : " asc") + (mods.includes("nullsfirst") ? " nulls first" : mods.includes("nullslast") ? " nulls last" : "");
  }).join(", ");
}
const intParam = (v) => (v == null || v === "" ? null : (/^\d+$/.test(v) ? parseInt(v, 10) : (() => { throw bad("Invalid number"); })()));

function pgError(e) {
  const c = e.code || "";
  const status = c === "23505" || c === "23503" ? 409 : c === "42501" ? 403 : c === "42P01" ? 404 : /^(22|23|42|P0|PT)/.test(c) ? 400 : 500;
  if (status === 500) { console.error("[rest] database error:", e.message); return new HttpErr(500, { code: c || "500", message: "Internal error", details: null, hint: null }); }
  return new HttpErr(status, { code: c, message: e.message, details: e.detail || null, hint: e.hint || null });
}

async function table(name, req, url, body, claims) {
  const cat = db.state.cat, T = cat.tables.get(name);
  if (!T) throw new HttpErr(404, { code: "42P01", message: "Unknown table " + name, details: null, hint: null });
  const sp = [...url.searchParams.entries()], get = (k) => url.searchParams.get(k);
  const prefer = req.headers.prefer || "", rep = /return=representation/.test(prefer);
  const wantsObject = /vnd\.pgrst\.object\+json/.test(req.headers.accept || "");
  const items = parseSelect(get("select") || "*"), ctx = { n: 0 }, m = req.method;
  const run = (sql, params) => db.withRole(claims, (c) => c.query(sql, params));
  try {
    if (m === "GET" || m === "HEAD") {
      const params = [], conds = filtersSQL(cat, name, sp, "t", params), lim = intParam(get("limit")), off = intParam(get("offset"));
      const sql = "select coalesce(jsonb_agg(x.j), '[]'::jsonb) as r from (select " + selectExpr(cat, name, items, "t", ctx) + " as j from public." + q(name) + " t" +
        (conds.length ? " where " + conds.join(" and ") : "") + orderSQL(T, get("order"), "t") + (lim != null ? " limit " + lim : "") + (off != null ? " offset " + off : "") + ") x";
      const rows = (await run(sql, params)).rows[0].r;
      if (wantsObject) return rows.length === 1 ? { status: 200, body: rows[0] } : { status: 406, body: { code: "PGRST116", message: "JSON object requested, multiple (or no) rows returned", details: "The result contains " + rows.length + " rows", hint: null } };
      return { status: 200, body: rows };
    }
    const wrap = (verb) => (rep ? "with m as (" + verb + " returning t.*) select coalesce(jsonb_agg(" + selectExpr(cat, name, items, "t", ctx) + "), '[]'::jsonb) as r from m t" : verb);
    const done = (status, res) => {
      if (!rep) return { status: status === 201 ? 201 : 204, body: null };
      const rows = res.rows[0].r; return { status, body: wantsObject ? (rows.length === 1 ? rows[0] : null) : rows };
    };
    if (m === "POST") {
      const arr = Array.isArray(body) ? body : [body]; if (!arr.length || arr.some((o) => !o || typeof o !== "object")) throw bad("Invalid body");
      const cols = [...new Set(arr.flatMap((o) => Object.keys(o)))]; for (const c of cols) if (!T.has(c)) throw bad("Unknown column " + name + "." + c, "PGRST204");
      const rs = "jsonb_populate_recordset(null::public." + q(name) + ", $1::jsonb)";
      const ins = cols.length ? "insert into public." + q(name) + " as t (" + cols.map(q).join(", ") + ") select " + cols.map(q).join(", ") + " from " + rs : "insert into public." + q(name) + " as t default values";
      const res = await run(wrap(ins), cols.length ? [JSON.stringify(arr)] : []);
      return done(201, res);
    }
    if (m === "PATCH" || m === "DELETE") {
      const params = []; if (m === "PATCH") params.push(null);
      const conds = filtersSQL(cat, name, sp, "t", params); if (!conds.length) throw bad("Filter required for " + m);
      let verb;
      if (m === "PATCH") {
        if (!body || typeof body !== "object" || Array.isArray(body)) throw bad("Invalid body");
        const cols = Object.keys(body); if (!cols.length) throw bad("Empty body"); for (const c of cols) if (!T.has(c)) throw bad("Unknown column " + name + "." + c, "PGRST204");
        params[0] = JSON.stringify(body);
        verb = "update public." + q(name) + " as t set " + cols.map((c) => q(c) + " = _p." + q(c)).join(", ") + " from (select * from jsonb_populate_record(null::public." + q(name) + ", $1::jsonb)) _p where " + conds.join(" and ");
      } else verb = "delete from public." + q(name) + " as t where " + conds.join(" and ");
      return done(200, await run(wrap(verb), params));
    }
    throw new HttpErr(405, { code: "405", message: "Method not allowed", details: null, hint: null });
  } catch (e) { throw e instanceof HttpErr ? e : pgError(e); }
}

async function rpc(name, body, claims) {
  const f = db.state.cat.fns.get(name);
  if (!f) throw new HttpErr(404, { code: "PGRST202", message: "Unknown function " + name, details: null, hint: null });
  const args = body && typeof body === "object" && !Array.isArray(body) ? body : {}, parts = [], params = [];
  for (const k of Object.keys(args)) {
    const i = f.names.indexOf(k); if (i < 0 || !IDENT.test(k)) throw new HttpErr(404, { code: "PGRST202", message: "Unknown argument " + k + " for " + name, details: null, hint: null });
    const ty = f.types[i]; params.push(/^jsonb?$/.test(ty) && typeof args[k] !== "string" ? JSON.stringify(args[k]) : args[k]);
    parts.push(q(k) + " => $" + params.length + "::" + ty);
  }
  const call = "public." + q(name) + "(" + parts.join(", ") + ")";
  const sql = f.ret === "void" ? "select " + call : f.isset ? "select coalesce(jsonb_agg(to_jsonb(f)), '[]'::jsonb) as r from " + call + " f" : "select to_jsonb(" + call + ") as r";
  try { const res = await db.withRole(claims, (c) => c.query(sql, params)); return { status: 200, body: f.ret === "void" ? null : res.rows[0].r }; }
  catch (e) { throw pgError(e); }
}

module.exports = { table, rpc, HttpErr, parseSelect, selectExpr, filtersSQL };
