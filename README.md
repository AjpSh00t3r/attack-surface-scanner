# Attack Surface Scanner

> ⚠️ **Run this on your own machine only — do not deploy it to a public server.**
> The scanning happens *server-side*: the Node process fetches whatever domain is
> submitted. On localhost that's just you auditing your own sites. Exposed on a public
> host it becomes an open scanning/SSRF proxy — anyone could drive it at internal hosts,
> cloud metadata endpoints (`169.254.169.254`) or third-party sites, and the traffic would
> come from **your** server's IP. It binds to `127.0.0.1` by default for exactly this reason.
> Keep it there.

Scan **your own** domain for three kinds of exposure, all in parallel, server-side:

| Module | What it checks | Marked as |
|---|---|---|
| Exposed panels | ~70 sensitive paths (`/admin`, `/wp-admin`, `/phpmyadmin`, `/.git/HEAD`, `/.env`, `/actuator/env`, `/server-status`, `/swagger`, `/manager/html` …) | `OPEN` if the page is real (differs from the site's own 404, or matches the file's known format); `PROTECTED` for 401/403 |
| Leaking logs | common log paths (`/logs/app.log`, `/log/error.log`, `/storage/logs/laravel.log` …) | `LEAKING` with each token / API key / email found, or `READABLE` |
| Exposed keys | key paths (`/.ssh/id_rsa`, `/server.key`, `/privkey.pem` …) | `CAPTURED` when the body holds a PEM private key |

Real data only: results come straight from the HTTP responses. Secrets and keys are
**masked on the server**. The full value never reaches the browser.

## Run

```bash
npm start            # → http://127.0.0.1:4777
```

No dependencies (Node ≥ 20). The server listens on localhost only.

## Try it safely

```bash
npm run test-target  # deliberately vulnerable local site → http://127.0.0.1:4778
```

Scan `http://127.0.0.1:4778`. It acts like a single-page app (returns 200 for every
path), which shows the soft-404 filtering working: only the planted exposures light up.
Its private key is generated in memory on each start, and its tokens are documented
example values.

## How false positives are avoided

- Two random paths are fetched first to learn the site's own "not found" page (status,
  title, normalised body hash, redirect target). Hits that look the same are dropped.
- Files with a known format (`.git/HEAD`, `.env`, actuator JSON, `server-status` …) only
  count when the body actually matches that format.
- Keys need a full `-----BEGIN … PRIVATE KEY----- … -----END … PRIVATE KEY-----` block.

## Scope

Only scan domains you own or have written permission to test. The UI requires you to
confirm this before every scan. Requests identify themselves with the User-Agent
`AttackSurfaceScanner/1.0 (self-audit of own domain)`, run 6 at a time, and time out
after 8 s.
