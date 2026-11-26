// Attack Surface Scanner — local server. Serves the dashboard and streams each
// module's real results over Server-Sent Events. Binds to localhost only.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { MODULES, baseline, normalizeTarget } from "./lib/scan.js";

const PORT = Number(process.env.PORT || 4777);
const HOST = process.env.HOST || "127.0.0.1";
const PUBLIC = join(fileURLToPath(new URL(".", import.meta.url)), "public");
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };

// One baseline per target, shared by the three parallel module requests.
const baselines = new Map();
function getBaseline(origin) {
  const hit = baselines.get(origin);
  if (hit && Date.now() - hit.at < 60_000) return hit.p;
  const p = baseline(origin);
  baselines.set(origin, { at: Date.now(), p });
  p.catch(() => baselines.delete(origin));
  return p;
}

async function stream(req, res, mod, url) {
  res.writeHead(200, {
    "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive",
  });
  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  let closed = false;
  req.on("close", () => { closed = true; });
  const emit = (e, d) => { if (!closed) send(e, d); };

  try {
    if (url.searchParams.get("authorized") !== "1") {
      throw new Error("Confirm you own or are authorised to test this domain");
    }
    const origin = normalizeTarget(url.searchParams.get("target"));
    emit("start", { origin });
    const base = await getBaseline(origin);
    const t0 = Date.now();
    await MODULES[mod](origin, base, emit);
    emit("done", { ms: Date.now() - t0 });
  } catch (e) {
    emit("fail", { message: e.message || String(e) });
  } finally {
    res.end();
  }
}

createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const m = url.pathname.match(/^\/api\/scan\/(panels|logs|keys)$/);
  if (m && req.method === "GET") return stream(req, res, m[1], url);

  const rel = url.pathname === "/" ? "/index.html" : url.pathname;
  const file = normalize(join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC)) { res.writeHead(403).end(); return; }
  try {
    const data = await readFile(file);
    res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream" });
    res.end(data);
  } catch {
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
  }
}).listen(PORT, HOST, () => {
  console.log(`Attack Surface Scanner → http://${HOST}:${PORT}`);
});
