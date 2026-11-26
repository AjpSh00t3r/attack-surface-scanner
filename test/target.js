// Deliberately vulnerable LOCAL test site for trying the scanner end to end.
// Run: npm run test-target   then scan  http://127.0.0.1:4778
// Everything here is fake: the key pair is generated in memory on each start,
// the tokens are documented example values. It behaves like a single-page app
// (returns 200 + the same index for unknown paths) to exercise soft-404 checks.
import { createServer } from "node:http";
import { generateKeyPairSync } from "node:crypto";

const PORT = Number(process.env.PORT || 4778);
const { privateKey } = generateKeyPairSync("ed25519");
const pem = privateKey.export({ type: "pkcs8", format: "pem" });

const index = `<!doctype html><title>Acme Shop</title><div id="root">Loading…</div>`;
const pages = {
  "/admin": [200, "text/html", `<!doctype html><title>Acme Admin · Sign in</title><form><input name=user><input type=password name=pass><button>Sign in</button></form>`],
  "/.git/HEAD": [200, "text/plain", "ref: refs/heads/main\n"],
  "/.env": [200, "text/plain", "APP_ENV=production\nDB_HOST=db.internal\n"],
  "/actuator/env": [200, "application/json", `{"activeProfiles":["prod"],"propertySources":[]}`],
  "/phpmyadmin": [401, "text/plain", "auth required"],
  "/logs/app.log": [200, "text/plain", [
    "2026-11-25T10:01:12Z INFO login ok user=alice@example.com",
    "2026-11-25T10:01:12Z DEBUG set-cookie sessionid=f3a9c1e07b2d4e6f8a1c3e5d7b9f0a2c",
    "2026-11-25T10:02:40Z WARN upstream call with api_key=EXAMPLEKEY1234567890abcdef",
    "2026-11-25T10:03:05Z DEBUG aws creds AKIAIOSFODNN7EXAMPLE",
    "2026-11-25T10:04:44Z INFO auth header Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlLXRlc3Q",
  ].join("\n")],
  "/server.key": [200, "application/octet-stream", pem],
};

createServer((req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  const [status, type, body] = pages[path] || [200, "text/html", index]; // SPA catch-all
  res.writeHead(status, { "content-type": type });
  res.end(body);
}).listen(PORT, "127.0.0.1", () => console.log(`vulnerable test target → http://127.0.0.1:${PORT}`));
