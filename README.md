# ESST Football Tournament — website + database on Railway

One repo = the website, its built-in server (accounts + data) and the database setup.
The database is a Railway PostgreSQL. Nothing else to install, no Supabase.

## Put it online (about 5 minutes)

1. **GitHub**: create a new repository and upload everything from this folder
   (all files are at the top level: there are no folders).
2. **Railway** → *New Project* → *Deploy from GitHub repo* → pick your repo.
3. In the same Railway project click **+ New → Database → Add PostgreSQL**.
4. Open your **web service → Variables → New Variable**
   - Name: `DATABASE_URL`
   - Value: `${{Postgres.DATABASE_URL}}`   (use the exact name of your database service if it is not "Postgres")
5. Web service → **Settings → Networking → Generate Domain**. Open that address.

On the first start the server creates all the tables by itself (check *Deploy Logs*: you should see
`[db] ready`). No fake data is created.

## Accounts

- **Player**: opens the site → *Créer un compte* → done. Nothing else is needed.
- **Normal admin** (score manager…): registers like a player, opens `/admin`, fills
  *Request admin access*. The super admin accepts it in the dashboard → **Demandes**.
- **Super admin** (owner): registers like a player, opens `/admin`, types the secret password in
  *Activate super admin*, and gets the full dashboard. Wrong passwords are refused, and after 5 wrong
  tries the account is locked for 15 minutes.

The secret password is stored only as a salted hash (`auth.js`), never in clear text.
To change it later: in Railway add the variable `SUPER_ADMIN_PASSWORD` with the new password and redeploy
(it replaces the built-in one).

## Notes
- Accounts are email + password. No confirmation e-mail and no "forgot password" e-mail exist (no mail service).
- Match scores refresh on their own every 15 seconds.
- Optional variables: `JWT_SECRET` (32+ characters; otherwise a random one is created and kept in the database).
- Run locally: `DATABASE_URL=postgres://... npm install && npm start`.
