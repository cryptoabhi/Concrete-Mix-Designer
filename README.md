# Concrete Mix Designer — with Accounts & Saved Trial Sheets

Your original single-page calculator (`concreteDesign.html`), now backed by a
small server that adds user accounts and per-user storage of trial sheets.

## What changed

- **Accounts**: sign up / sign in with name, email, password.
- **Save Trial**: saves everything on the page (Section 1–7, including any
  manually edited "Qty" and "Extra Addition" cells) to your account.
- **Save As New**: saves the current sheet as a brand-new trial instead of
  overwriting the one you loaded.
- **My Trials**: lists your saved trials (ref no., customer, project, grade,
  last updated) with **Load** and **Delete**.
- **New Trial**: clears the form to start a fresh sheet.
- **Logout**.
- All of your original calculation logic (`calculate()`, moisture/absorption
  correction, etc.) is untouched — the new code only adds saving/loading on
  top of it.

## Stack (and why)

- **Backend**: plain Node.js (`http`, `fs`, `crypto`) — **zero npm packages**
  to install. This is a prototype, so I optimized for "clone and run" with no
  install step that can break. Passwords are hashed with `scrypt` (built into
  Node); sessions are a signed-nothing random cookie mapped to an in-memory
  session store.
- **Storage**: two flat JSON files (`data/users.json`, `data/trials.json`)
  acting as a tiny database. Good enough for a prototype / small team; see
  "What to harden before real use" below for the upgrade path.
- **Frontend**: your original HTML/CSS/JS, plus a login page and a thin layer
  of `fetch()` calls for auth + save/load.

## Project structure

```
concrete-mix-app/
├── server.js          # HTTP server: auth + trial CRUD + static file serving
├── package.json
├── data/               # auto-created on first run (git-ignored)
│   ├── users.json       # {id, name, email, passwordHash, createdAt}[]
│   └── trials.json      # {id, userId, trialRef, data, createdAt, updatedAt}[]
└── public/
    ├── login.html      # sign in / create account
    └── app.html         # your calculator + top bar + "My Trials" modal
```

## How to run it

Requires [Node.js](https://nodejs.org) 18 or newer. No `npm install` needed.

```bash
cd concrete-mix-app
node server.js
```

Then open **http://localhost:3000** — it redirects to the login page.
Create an account, and you're in the tool.

To run on a different port: `PORT=4000 node server.js`.

## How saving works (so nothing feels like a black box)

- **Save Trial** collects the value of every input/select/textarea on the
  page (by its `id`) into a plain JSON object, plus the per-material rows of
  the generated trial-mix table (so manual "Qty" / "Extra Addition" edits
  aren't lost), and POSTs/PUTs it to `/api/trials`.
- **Load** fetches that JSON back, fills in every field, re-runs your
  existing `calculate()` to rebuild the derived trial sheet, then re-applies
  any manual table edits and reruns the moisture correction — so a loaded
  trial looks exactly like it did when you saved it.
- Trials are scoped to `userId` server-side, so one account can never see or
  load another account's trials via the API.

## What I'd extend first

1. **Move storage to a real database.** Flat JSON files aren't safe under
   concurrent writes from multiple users at once. Swap `data/*.json` for
   SQLite (`better-sqlite3` or `node:sqlite` in newer Node) or Postgres — the
   `lib`-style read/write functions in `server.js` are isolated enough to
   replace without touching the frontend.
2. **Persist sessions.** Sessions currently live in memory, so a server
   restart logs everyone out. Move to a signed cookie (e.g. JWT) or a
   session table in the database.
3. **Add PDF/report export per saved trial**, not just browser print — e.g.
   a "Download PDF" button on each row in "My Trials" using a library like
   Puppeteer or PDFKit server-side.
4. **Add basic roles** (e.g. lab technician vs. approver) if multiple people
   in one company should share/approve the same trials rather than each
   person only seeing their own.
5. **Autosave / draft recovery** — periodically POST the current form state
   as a draft so an accidental tab close doesn't lose unsaved work.
6. **Rate-limit and validate auth endpoints** (currently only checks
   password length ≥ 6) before exposing this outside your local machine.
7. **HTTPS + secure cookies** if this is ever deployed beyond localhost —
   currently the session cookie is `HttpOnly` but not `Secure`.
