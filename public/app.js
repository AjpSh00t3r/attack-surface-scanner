// Dashboard: opens one event stream per module and renders only what the
// server reports from real responses.
const $ = (s, el = document) => el.querySelector(s);
const MODULES = ["panels", "logs", "keys"];
const LABEL = { panels: "panel paths", logs: "log paths", keys: "key paths" };

const form = $("#form");
const go = $("#go");
const sevEl = $("#sev");
const lootEl = $("#loot");
const statusEl = $("#status");
const meter = $("#meter-fill");
const banner = $("#banner");

let state, streams = [];

function reset() {
  streams.forEach((s) => s.close());
  streams = [];
  state = {};
  for (const m of MODULES) {
    state[m] = { loot: 0, done: 0, total: 0, finished: false, error: null, rows: 0 };
    const card = $("#card-" + m);
    card.dataset.state = "scanning";
    card.classList.remove("flip");
    $(".findings", card).innerHTML = "";
    $(".progress span", card).style.width = "0";
    setBadge(m, 0);
    setCardText(m, "Connecting…");
  }
  banner.hidden = true;
  updateSummary();
}

function setBadge(m, n) {
  const b = $("#card-" + m + " .badge");
  b.textContent = n;
  b.dataset.count = n;
}
function setCardText(m, t) { $("#card-" + m + " .state-text").textContent = t; }

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

// ------------------------------------------------------------------ rendering hits
function renderHit(m, h) {
  const li = el("li", "finding");
  const top = el("div", "f-top");
  top.append(el("span", "tag " + h.state.toLowerCase(), h.state), el("span", "f-path", h.path));
  top.lastChild.title = h.path;
  li.append(top);

  if (m === "panels") {
    const bits = [`HTTP ${h.status}`];
    if (h.title) bits.push(`“${h.title}”`);
    if (h.evidence) bits.push(h.evidence);
    if (h.finalUrl && !h.finalUrl.endsWith(h.path)) bits.push("→ " + new URL(h.finalUrl).pathname);
    li.append(el("div", "f-meta", bits.join(" · ")));
  }

  if (m === "logs") {
    li.append(el("div", "f-meta", `HTTP ${h.status} · ${h.lines} lines · ${fmtBytes(h.bytes)} · ${h.secrets.length} secret${h.secrets.length === 1 ? "" : "s"}`));
    if (h.secrets.length) {
      const ul = el("ul", "f-secrets");
      h.secrets.slice(0, 12).forEach((s) => {
        const row = el("li");
        row.append(el("b", null, s.kind), el("code", null, s.value), el("span", "f-meta", "L" + s.line));
        ul.append(row);
      });
      if (h.secrets.length > 12) ul.append(el("li", "f-meta", `+ ${h.secrets.length - 12} more`));
      li.append(ul);
    } else {
      li.append(el("div", "f-meta", "Publicly readable, but no tokens, keys or emails matched."));
    }
  }

  if (m === "keys") {
    li.append(el("div", "f-meta", `${h.keyType}${h.encrypted ? " · passphrase-encrypted" : " · unencrypted"} · ${h.fingerprint}`));
    li.append(el("pre", "key", h.masked));
  }

  $("#card-" + m + " .findings").append(li);
}

function lootValue(m, h) {
  if (m === "panels") return h.state === "OPEN" ? 1 : 0;
  if (m === "logs") return h.secrets.length;
  if (m === "keys") return 1;
  return 0;
}

// ------------------------------------------------------------------ summary
function updateSummary() {
  const total = MODULES.reduce((a, m) => a + state[m].loot, 0);
  const hitMods = MODULES.filter((m) => state[m].loot > 0).length;
  const running = MODULES.some((m) => !state[m].finished);
  const done = MODULES.reduce((a, m) => a + state[m].done, 0);
  const all = MODULES.reduce((a, m) => a + state[m].total, 0);

  lootEl.textContent = total;
  meter.style.width = all ? Math.round((done / all) * 100) + "%" : "0";

  let sev = "idle", label = "Idle";
  if (total === 0) { sev = running ? "scanning" : "clean"; label = running ? "Scanning" : "Clean"; }
  else if (hitMods === 3 || state.keys.loot > 0) { sev = "critical"; label = "Critical"; }
  else { sev = "exposed"; label = "Exposed"; }
  if (!running && MODULES.every((m) => state[m].error)) { sev = "idle"; label = "Error"; }

  sevEl.dataset.sev = sev;
  sevEl.textContent = label;
  document.body.dataset.sev = sev;

  if (hitMods === 3 && banner.hidden) banner.hidden = false;

  if (running) statusEl.textContent = `Probing ${done} of ${all || "…"} paths`;
  else if (sev !== "idle") statusEl.textContent = `Scan complete · ${done} paths checked · ${hitMods} of 3 modules found exposure`;
}

function finish(m, kind, msg) {
  const s = state[m];
  if (s.finished) return;
  s.finished = true;
  const card = $("#card-" + m);
  const list = $(".findings", card);

  if (kind === "error") {
    s.error = msg;
    card.dataset.state = "error";
    setCardText(m, "Scan failed");
    list.append(el("li", "err", msg));
  } else if (s.loot > 0) {
    card.dataset.state = "hit";
    setCardText(m, `Exposed · ${s.loot} found`);
  } else {
    card.dataset.state = "clean";
    setCardText(m, `Clean · ${s.total} ${LABEL[m]} checked`);
    const e = el("li", "empty");
    if (s.rows) e.textContent = "Nothing exploitable here, only the items listed above.";
    else {
      e.append(el("b", null, "Nothing exposed. "),
        `None of the ${s.total} ${LABEL[m]} returned ${m === "keys" ? "a PEM private key" : m === "logs" ? "a readable log" : "a real panel"}.`);
    }
    list.append(e);
  }
  card.classList.remove("flip"); void card.offsetWidth; card.classList.add("flip");
  updateSummary();
  if (MODULES.every((x) => state[x].finished)) go.disabled = false;
}

// ------------------------------------------------------------------ run
function run(target) {
  reset();
  go.disabled = true;
  statusEl.textContent = "Measuring the site's own 404 page…";
  for (const m of MODULES) {
    const qs = new URLSearchParams({ target, authorized: "1" });
    const es = new EventSource(`/api/scan/${m}?${qs}`);
    streams.push(es);
    es.addEventListener("start", () => setCardText(m, "Scanning"));
    es.addEventListener("progress", (e) => {
      const d = JSON.parse(e.data);
      state[m].done = d.done; state[m].total = d.total;
      $("#card-" + m + " .progress span").style.width = (d.done / d.total) * 100 + "%";
      setCardText(m, `Scanning ${d.done}/${d.total}`);
      updateSummary();
    });
    es.addEventListener("hit", (e) => {
      const h = JSON.parse(e.data);
      state[m].rows++;
      state[m].loot += lootValue(m, h);
      setBadge(m, state[m].loot);
      renderHit(m, h);
      updateSummary();
    });
    es.addEventListener("done", () => { es.close(); finish(m, "done"); });
    es.addEventListener("fail", (e) => { es.close(); finish(m, "error", JSON.parse(e.data).message); });
    es.onerror = () => { es.close(); finish(m, "error", "Lost connection to the local scanner server."); };
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const t = $("#target").value.trim();
  if (!t || !$("#authorized").checked) return;
  run(t);
});

function fmtBytes(n) { return n < 1024 ? n + " B" : (n / 1024).toFixed(1) + " KB"; }
