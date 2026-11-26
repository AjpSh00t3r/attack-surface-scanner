// Scan engine: three modules that GET paths on the owner's own site and
// report only what the real responses contain. Nothing here is simulated.
import { createHash, randomBytes } from "node:crypto";

const UA = "AttackSurfaceScanner/1.0 (self-audit of own domain)";
const TIMEOUT_MS = 8000;
const MAX_BODY = 512 * 1024;
const CONCURRENCY = 6;

export const PANEL_PATHS = [
  "/admin", "/admin/", "/administrator", "/admin/login", "/admin.php", "/adminpanel",
  "/wp-admin", "/wp-login.php", "/user/login", "/login", "/signin", "/dashboard",
  "/cpanel", "/webmail", "/panel", "/controlpanel", "/manage", "/management",
  "/phpmyadmin", "/phpMyAdmin", "/pma", "/adminer.php", "/adminer", "/myadmin",
  "/.git/HEAD", "/.git/config", "/.svn/entries", "/.hg/hgrc", "/.env", "/.env.local",
  "/.env.production", "/.DS_Store", "/.htaccess", "/.htpasswd", "/config", "/config.php",
  "/config.json", "/wp-config.php.bak", "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
  "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump", "/actuator/mappings",
  "/debug", "/_debug", "/debug/vars", "/debug/pprof", "/trace", "/server-status", "/server-info",
  "/phpinfo.php", "/info.php", "/swagger", "/swagger-ui.html", "/swagger.json", "/api-docs",
  "/v2/api-docs", "/openapi.json", "/graphql", "/graphiql", "/manager/html", "/jenkins",
  "/console", "/elmah.axd", "/telescope", "/horizon", "/.well-known/security.txt", "/.well-known",
];

export const LOG_PATHS = [
  "/logs/app.log", "/log/error.log", "/logs/error.log", "/logs/access.log", "/log/app.log",
  "/error.log", "/error_log", "/access.log", "/debug.log", "/app.log", "/logs/debug.log",
  "/storage/logs/laravel.log", "/wp-content/debug.log", "/var/log/app.log", "/npm-debug.log",
  "/logs/server.log", "/log/development.log", "/log/production.log",
];

export const KEY_PATHS = [
  "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/id_ecdsa", "/.ssh/id_dsa", "/id_rsa", "/id_ed25519",
  "/server.key", "/private.key", "/privkey.pem", "/key.pem", "/ssl/private.key", "/ssl/server.key",
  "/certs/private.key", "/cert/key.pem", "/tls.key", "/.well-known/private.key", "/jwt.key",
];

// Content fingerprints for paths whose real contents are recognisable. If a path
// has one, a 200 only counts when the body matches it (kills SPA catch-alls).
const FINGERPRINTS = {
  "/.git/HEAD": /^ref: refs\/|^[0-9a-f]{40}\s*$/,
  "/.git/config": /\[core\]/,
  "/.svn/entries": /^\d+\s*$|svn:/m,
  "/.hg/hgrc": /\[paths\]|\[ui\]/,
  "/.env": /^[A-Z_][A-Z0-9_]*=/m,
  "/.env.local": /^[A-Z_][A-Z0-9_]*=/m,
  "/.env.production": /^[A-Z_][A-Z0-9_]*=/m,
  "/.htpasswd": /^[^:\s]+:\S+/m,
  "/actuator": /"_links"/,
  "/actuator/env": /"propertySources"|"activeProfiles"/,
  "/actuator/health": /"status"\s*:/,
  "/actuator/mappings": /"contexts"|"dispatcherServlets"/,
  "/server-status": /Apache Server Status|Server uptime|Total Accesses/i,
  "/server-info": /Apache Server Information/i,
  "/phpinfo.php": /phpinfo\(\)|PHP Version/,
  "/info.php": /phpinfo\(\)|PHP Version/,
  "/swagger.json": /"swagger"\s*:|"openapi"\s*:/,
  "/openapi.json": /"openapi"\s*:/,
  "/v2/api-docs": /"swagger"\s*:/,
  "/debug/vars": /"cmdline"|"memstats"/,
};

// ------------------------------------------------------------------ http
export function normalizeTarget(input) {
  let s = String(input || "").trim();
  if (!s) throw new Error("Enter your domain, e.g. example.com");
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  const u = new URL(s);
  if (!/^https?:$/.test(u.protocol)) throw new Error("Only http and https targets are supported");
  return u.origin;
}

async function get(origin, path, { redirect = "follow" } = {}) {
  const url = origin + path;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      redirect, signal: ctrl.signal,
      headers: { "user-agent": UA, accept: "*/*" },
    });
    // read at most MAX_BODY bytes
    let body = "";
    if (res.body) {
      const reader = res.body.getReader();
      const dec = new TextDecoder("utf-8", { fatal: false });
      let n = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        n += value.byteLength;
        body += dec.decode(value, { stream: true });
        if (n >= MAX_BODY) { await reader.cancel(); break; }
      }
    }
    return {
      ok: true, path, status: res.status, finalUrl: res.url,
      redirected: res.redirected, type: res.headers.get("content-type") || "",
      body,
    };
  } catch (e) {
    return { ok: false, path, error: e.name === "AbortError" ? "timeout" : (e.cause?.code || e.cause?.errors?.[0]?.code || e.cause?.message || e.message) };
  } finally {
    clearTimeout(t);
  }
}

// ------------------------------------------------------------------ soft-404 baseline
const titleOf = (b) => (b.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] || "").trim();
const norm = (b, path) => b.split(path).join("").replace(/\s+/g, " ").trim();
const hash = (s) => createHash("sha1").update(s).digest("hex");

export async function baseline(origin) {
  const probes = [];
  for (let i = 0; i < 2; i++) {
    const p = "/" + randomBytes(8).toString("hex") + (i ? ".php" : "");
    probes.push(await get(origin, p));
  }
  if (probes.every((p) => !p.ok)) {
    throw new Error(`Could not reach ${origin} (${probes[0].error})`);
  }
  return probes.filter((p) => p.ok).map((p) => ({
    status: p.status, finalUrl: p.finalUrl, title: titleOf(p.body),
    len: norm(p.body, p.path).length, hash: hash(norm(p.body, p.path)),
    path: p.path,
  }));
}

function looksLikeSoft404(r, base) {
  const n = norm(r.body, r.path);
  for (const b of base) {
    if (hash(n) === b.hash) return true;
    // same redirect destination as a random path -> catch-all redirect
    if (r.redirected && r.finalUrl.replace(r.path, "") === b.finalUrl.replace(b.path, "")) return true;
    const close = b.len > 0 && Math.abs(n.length - b.len) / b.len < 0.04;
    if (close && titleOf(r.body) === b.title) return true;
  }
  return false;
}

async function pool(items, worker, onEach) {
  let i = 0;
  const run = async () => {
    while (i < items.length) {
      const item = items[i++];
      const out = await worker(item);
      onEach(out);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, run));
}

// ------------------------------------------------------------------ masking
export function mask(v, keep = 4) {
  if (v.length <= keep * 2 + 2) return v[0] + "•".repeat(Math.max(v.length - 1, 1));
  return v.slice(0, keep) + "•".repeat(Math.min(v.length - keep * 2, 16)) + v.slice(-keep);
}
function maskEmail(e) {
  const [u, d] = e.split("@");
  return (u[0] || "") + "•••@" + d;
}

// ------------------------------------------------------------------ module 1
export async function scanPanels(origin, base, emit) {
  let done = 0;
  await pool(PANEL_PATHS, (p) => get(origin, p), (r) => {
    done++;
    emit("progress", { done, total: PANEL_PATHS.length });
    if (!r.ok) return;
    const fp = FINGERPRINTS[r.path];
    if (r.status === 200) {
      if (fp ? !fp.test(r.body) : looksLikeSoft404(r, base)) return;
      if (!fp && r.body.trim().length === 0) return;
      emit("hit", {
        state: "OPEN", path: r.path, status: r.status,
        finalUrl: r.finalUrl, title: titleOf(r.body).slice(0, 80) || null,
        evidence: fp ? "content matches " + r.path.split("/").pop() + " format" : "differs from site 404",
        bytes: r.body.length,
      });
    } else if ((r.status === 401 || r.status === 403) && !base.some((b) => b.status === r.status)) {
      emit("hit", { state: "PROTECTED", path: r.path, status: r.status, finalUrl: r.finalUrl });
    }
  });
}

// ------------------------------------------------------------------ module 2
const SECRET_RULES = [
  ["AWS access key", /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ["Stripe key", /\b[sr]k_(live|test)_[0-9a-zA-Z]{16,}\b/g],
  ["GitHub token", /\bgh[pousr]_[0-9A-Za-z]{30,}\b/g],
  ["Google API key", /\bAIza[0-9A-Za-z_\-]{35}\b/g],
  ["Slack token", /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/g],
  ["OpenAI-style key", /\bsk-(proj-)?[A-Za-z0-9_\-]{20,}\b/g],
  ["JWT", /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
  ["Bearer token", /\bBearer\s+([A-Za-z0-9._~+/=-]{16,})/g],
  ["Session token", /\b(?:PHPSESSID|JSESSIONID|sessionid|session_id|sid|connect\.sid|laravel_session)=([A-Za-z0-9%._\-]{12,})/gi],
  ["API key", /\b(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})/gi],
  ["Email", /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
];

function findSecrets(body) {
  const out = [];
  const seen = new Set();
  const lines = body.split(/\r?\n/);
  lines.forEach((line, i) => {
    for (const [kind, re] of SECRET_RULES) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(line))) {
        const raw = m[1] && kind !== "Stripe key" && kind !== "AWS access key" && kind !== "GitHub token" ? m[1] : m[0];
        const key = raw;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ kind, line: i + 1, value: kind === "Email" ? maskEmail(raw) : mask(raw) });
        if (out.length >= 50) return;
      }
    }
  });
  return out;
}

export async function scanLogs(origin, base, emit) {
  let done = 0;
  await pool(LOG_PATHS, (p) => get(origin, p), (r) => {
    done++;
    emit("progress", { done, total: LOG_PATHS.length });
    if (!r.ok || r.status !== 200 || !r.body.trim()) return;
    if (/text\/html/i.test(r.type) && looksLikeSoft404(r, base)) return;
    if (looksLikeSoft404(r, base)) return;
    const secrets = findSecrets(r.body);
    emit("hit", {
      state: secrets.length ? "LEAKING" : "READABLE",
      path: r.path, status: r.status, bytes: r.body.length,
      lines: r.body.split(/\r?\n/).length, secrets,
    });
  });
}

// ------------------------------------------------------------------ module 3
const PEM_RE = /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----([\s\S]*?)-----END \1-----/;

function keyType(label, b64) {
  if (label === "PRIVATE KEY") {           // PKCS#8: read the algorithm OID
    const hex = Buffer.from(b64, "base64").toString("hex");
    if (hex.includes("06032b6570")) return "PKCS#8 Ed25519";
    if (hex.includes("06032b6571")) return "PKCS#8 Ed448";
    if (hex.includes("2a864886f70d010101")) return "PKCS#8 RSA";
    if (hex.includes("2a8648ce3d0201")) return "PKCS#8 EC";
    return "PKCS#8";
  }
  if (label !== "OPENSSH PRIVATE KEY") return label.replace(/\s*PRIVATE KEY$/, "");
  try {
    const bin = Buffer.from(b64.replace(/\s+/g, ""), "base64").toString("latin1");
    const t = bin.match(/ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp\d+/);
    return t ? "OpenSSH " + t[0] : "OpenSSH";
  } catch { return "OpenSSH"; }
}

export async function scanKeys(origin, base, emit) {
  let done = 0;
  await pool(KEY_PATHS, (p) => get(origin, p), (r) => {
    done++;
    emit("progress", { done, total: KEY_PATHS.length });
    if (!r.ok || r.status !== 200) return;
    const m = r.body.match(PEM_RE);
    if (!m) return;
    const b64 = m[2].replace(/^[A-Za-z-]+:.*$/gm, "").replace(/\s+/g, "");
    const encrypted = /ENCRYPTED|Proc-Type: 4,ENCRYPTED/.test(m[0]);
    // the full key never leaves the server: only a masked preview is sent
    emit("hit", {
      state: "CAPTURED", path: r.path, status: r.status,
      keyType: keyType(m[1], b64), encrypted,
      fingerprint: "sha256:" + createHash("sha256").update(b64).digest("base64").slice(0, 16),
      masked: [
        `-----BEGIN ${m[1]}-----`,
        b64.slice(0, 12) + "•".repeat(24) + b64.slice(-6),
        `(${b64.length} base64 chars hidden)`,
        `-----END ${m[1]}-----`,
      ].join("\n"),
    });
  });
}

export const MODULES = { panels: scanPanels, logs: scanLogs, keys: scanKeys };
