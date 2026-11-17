"use strict";
/* Railway PostgreSQL: connection, first-start setup, and the catalog the REST layer needs. */
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), { Pool } = require("pg");

const configured = !!(process.env.DATABASE_URL || process.env.PGHOST);
const pool = configured ? new Pool(process.env.DATABASE_URL ? { connectionString: process.env.DATABASE_URL, max: 10 } : { max: 10 }) : null;
if (pool) pool.on("error", (e) => console.error("[db] idle client error:", e.message));
const state = { configured, ready: false, error: null, jwt: null, cat: null };

const BOOT = `
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin; end if;
end $$;
create schema if not exists auth;
create table if not exists auth.users (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  encrypted_password text not null,
  raw_user_meta_data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  last_sign_in_at timestamptz
);
create unique index if not exists auth_users_email_idx on auth.users (lower(email));
create table if not exists auth.refresh_tokens (
  token_hash text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  revoked boolean not null default false
);
create index if not exists auth_refresh_user_idx on auth.refresh_tokens (user_id);
create table if not exists auth.secrets (key text primary key, value text not null);
create or replace function auth.uid() returns uuid language sql stable as $f$
  select coalesce(nullif(current_setting('request.jwt.claim.sub', true), ''),
                  nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')::uuid
$f$;
grant usage on schema auth to anon, authenticated, service_role;
grant execute on function auth.uid() to anon, authenticated, service_role;
`;

async function loadCatalog(c) {
  const tables = new Map(), fks = [], fns = new Map();
  for (const r of (await c.query(`select c.relname as t, a.attname::text as col, a.atttypid::regtype::text as ty
    from pg_attribute a join pg_class c on c.oid = a.attrelid join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r','p') and a.attnum > 0 and not a.attisdropped`)).rows) {
    if (!tables.has(r.t)) tables.set(r.t, new Map());
    tables.get(r.t).set(r.col, r.ty);
  }
  for (const r of (await c.query(`select con.conname::text as name, sc.relname::text as src, dc.relname::text as dst,
      (select array_agg(a.attname::text order by k.o) from unnest(con.conkey) with ordinality k(n, o) join pg_attribute a on a.attrelid = con.conrelid and a.attnum = k.n) as scols,
      (select array_agg(a.attname::text order by k.o) from unnest(con.confkey) with ordinality k(n, o) join pg_attribute a on a.attrelid = con.confrelid and a.attnum = k.n) as dcols
    from pg_constraint con
      join pg_class sc on sc.oid = con.conrelid join pg_namespace sn on sn.oid = sc.relnamespace
      join pg_class dc on dc.oid = con.confrelid join pg_namespace dn on dn.oid = dc.relnamespace
    where con.contype = 'f' and sn.nspname = 'public' and dn.nspname = 'public'`)).rows) fks.push(r);
  for (const r of (await c.query(`select p.proname::text as name, p.proretset as isset, p.prorettype::regtype::text as ret,
      coalesce(p.proargnames, '{}') as names,
      coalesce((select array_agg(t::regtype::text order by o) from unnest(p.proargtypes::oid[]) with ordinality u(t, o)), '{}') as types
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prokind = 'f' and p.prorettype <> 'trigger'::regtype`)).rows) fns.set(r.name, r);
  return { tables, fks, fns };
}

async function bootstrap() {
  const c = await pool.connect();
  try {
    await c.query("select pg_advisory_lock(7272727)");
    await c.query(BOOT);
    try { await c.query("grant anon, authenticated to current_user"); } catch (e) { console.warn("[db] could not grant roles to current user:", e.message); }
    if (!(await c.query("select to_regclass('public.profiles') as r")).rows[0].r) {
      console.log("[db] empty database: creating tables (one time)...");
      await c.query("begin");
      try { await c.query(fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8")); await c.query("commit"); }
      catch (e) { await c.query("rollback"); throw e; }
      console.log("[db] tables created.");
    }
    await c.query(fs.readFileSync(path.join(__dirname, "indexes.sql"), "utf8"));
    let r = await c.query("select value from auth.secrets where key = 'jwt'");
    if (!r.rowCount) {
      await c.query("insert into auth.secrets (key, value) values ('jwt', $1) on conflict do nothing", [crypto.randomBytes(48).toString("base64url")]);
      r = await c.query("select value from auth.secrets where key = 'jwt'");
    }
    state.jwt = (process.env.JWT_SECRET || "").length >= 32 ? process.env.JWT_SECRET : r.rows[0].value;
    state.cat = await loadCatalog(c);
    state.ready = true; state.error = null;
    console.log("[db] ready: " + state.cat.tables.size + " tables, " + state.cat.fns.size + " functions.");
  } finally { try { await c.query("select pg_advisory_unlock(7272727)"); } catch (_) {} c.release(); }
}

async function start() {
  if (!configured) { state.error = "DATABASE_URL is not set"; console.error("[db] DATABASE_URL is not set: add a PostgreSQL database in Railway and set DATABASE_URL (see README)."); return; }
  for (;;) {
    try { await bootstrap(); return; }
    catch (e) { state.error = e.message; console.error("[db] setup failed, retrying in 5s:", e.message); await new Promise((r) => setTimeout(r, 5000)); }
  }
}

/* Run fn inside one transaction with the row-level-security identity of the caller. */
async function withRole(claims, fn) {
  const c = await pool.connect();
  try {
    await c.query("begin");
    await c.query(claims && claims.sub ? "set local role authenticated" : "set local role anon");
    await c.query("select set_config('request.jwt.claim.sub', $1, true), set_config('request.jwt.claims', $2, true)", [(claims && claims.sub) || "", JSON.stringify(claims || {})]);
    const out = await fn(c);
    await c.query("commit");
    return out;
  } catch (e) { try { await c.query("rollback"); } catch (_) {} throw e; }
  finally { c.release(); }
}

module.exports = { pool, state, start, withRole };
