// Snitchy dashboard logic. Plain JavaScript, no libraries.
//
// SECURITY NOTE for future editors: hostnames, app names and paths come from
// network traffic and running programs, so treat them as untrusted. This file
// only ever puts them on the page with textContent (via the el() helper),
// never innerHTML, so a malicious hostname can't inject code.

"use strict";

const state = {
  range: "24h",
  view: "dashboard",
  filters: { q: "", app: "", domain: "", direction: "", flagged: false },
  paused: false,
  oldestId: null,
  rowsShown: 0,
};

// ---------- Small helpers ----------

/** Create an element: el("td", {class: "num"}, "text", childNode, ...) */
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const SVG_NS = "http://www.w3.org/2000/svg";
function svg(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, value);
  return node;
}

const fmtInt = new Intl.NumberFormat();
function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return (n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)) + " " + units[i];
}
function fmtTime(ts, withDate) {
  const d = new Date(ts * 1000);
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  if (!withDate) return time;
  return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + time;
}
function fmtAgo(ts) {
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 86400) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " d ago";
}

async function api(path, params) {
  const url = new URL(path, location.origin);
  for (const [k, v] of Object.entries(params || {})) if (v !== "" && v !== false && v !== null) url.searchParams.set(k, v === true ? "1" : v);
  const res = await fetch(url);
  if (res.status === 401) { showLocked(); throw new Error("locked"); }
  if (!res.ok) throw new Error(path + " -> " + res.status);
  return res.json();
}

// Signature verdict -> badge (icon + label + color, so color is never alone)
const SIGNATURES = {
  apple:     { level: "good",     icon: "✓", label: "Apple",            help: "Part of macOS or made by Apple" },
  appstore:  { level: "good",     icon: "✓", label: "App Store",        help: "Distributed through the Mac App Store" },
  developer: { level: "good",     icon: "✓", label: "Developer ID",     help: "Signed by an identified developer" },
  adhoc:     { level: "warning",  icon: "!", label: "Ad-hoc",           help: "Signed with no identity: nobody vouches for it" },
  unsigned:  { level: "serious",  icon: "!", label: "Unsigned",         help: "No signature at all" },
  untrusted: { level: "critical", icon: "✕", label: "Untrusted cert",   help: "Signed with a certificate Apple didn't issue (e.g. homemade, with a borrowed name)" },
  invalid:   { level: "critical", icon: "✕", label: "Broken signature", help: "Files no longer match the signature (modified after signing)" },
  unknown:   { level: "unknown",  icon: "?", label: "Unknown",          help: "Couldn't check (program gone or unreadable)" },
};
// Verdicts the dashboard highlights (keep in sync with FLAGGED in store.py).
const FLAGGED = ["unsigned", "adhoc", "untrusted", "invalid"];

function badge(signing, signer) {
  const info = SIGNATURES[signing] || { level: "unknown", icon: "…", label: "Checking", help: "Signature check pending" };
  const title = info.help + (signer ? " — " + signer : "");
  return el("span", { class: "badge " + info.level, title }, el("span", { "aria-hidden": "true" }, info.icon), info.label);
}

// ---------- Tooltip ----------
const tooltip = document.getElementById("tooltip");
function showTip(evt, ...content) {
  tooltip.replaceChildren(...content);
  tooltip.hidden = false;
  const pad = 14, rect = tooltip.getBoundingClientRect();
  let x = evt.clientX + pad, y = evt.clientY + pad;
  if (x + rect.width > innerWidth - 8) x = evt.clientX - rect.width - pad;
  if (y + rect.height > innerHeight - 8) y = evt.clientY - rect.height - pad;
  tooltip.style.left = x + "px";
  tooltip.style.top = y + "px";
}
function hideTip() { tooltip.hidden = true; }

// ---------- Locked (not signed in) ----------
function showLocked() {
  document.getElementById("locked").hidden = false;
  for (const v of ["dashboard", "log"]) document.getElementById("view-" + v).hidden = true;
}

// ---------- Status ----------
async function refreshStatus() {
  const box = document.getElementById("capture-status");
  try {
    const s = await api("/api/status");
    box.className = "capture-status " + (s.capturing ? "on" : "off");
    box.querySelector(".label").textContent = s.demo ? "Demo data" : (s.capturing ? "Capturing" : "Capture stopped");
    box.title = s.stats && s.stats.packets !== undefined ? fmtInt.format(s.stats.packets) + " packets seen since start" : "";
    document.getElementById("version").textContent = "v" + s.version;
  } catch (e) {
    box.className = "capture-status off";
    box.querySelector(".label").textContent = e.message === "locked" ? "Locked" : "Service unreachable";
  }
}

// ---------- Dashboard ----------
async function refreshDashboard() {
  const data = await api("/api/summary", { range: state.range });
  const t = data.totals;
  document.getElementById("t-connections").textContent = fmtInt.format(t.connections);
  document.getElementById("t-data").textContent = fmtBytes(t.bytes_out) + " sent · " + fmtBytes(t.bytes_in) + " received";
  document.getElementById("t-apps").textContent = fmtInt.format(t.apps);
  document.getElementById("t-destinations").textContent = fmtInt.format(t.destinations);
  document.getElementById("t-unnamed").textContent = fmtInt.format(t.unnamed) + " connections with no hostname";
  document.getElementById("t-flagged").textContent = fmtInt.format(t.flagged);
  drawTimeline(data);
  drawTopApps(data.top_apps);
  drawTopDomains(data.top_domains);
  drawFlagged(data.flagged_apps);
}

function niceMax(v) {
  if (v <= 5) return 5;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function bucketLabel(ts, bucketSeconds) {
  const d = new Date(ts * 1000);
  if (bucketSeconds >= 86400) return d.toLocaleDateString([], { month: "short", day: "numeric" });
  if (bucketSeconds >= 3600 * 6) return d.toLocaleDateString([], { weekday: "short" }) + " " + d.toLocaleTimeString([], { hour: "2-digit" });
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function drawTimeline(data) {
  const box = document.getElementById("timeline");
  const counts = data.timeline;
  const W = box.clientWidth || 800, H = box.clientHeight || 200;
  const m = { top: 8, right: 4, bottom: 22, left: 40 };
  const iw = W - m.left - m.right, ih = H - m.top - m.bottom;
  const max = niceMax(Math.max(1, ...counts));
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" });

  // Gridlines + y labels (recessive)
  const grid = svg("g", { class: "grid" });
  for (let i = 0; i <= 4; i++) {
    const y = m.top + ih - (ih * i) / 4;
    grid.append(svg("line", { x1: m.left, x2: W - m.right, y1: y, y2: y }));
    const label = svg("text", { x: m.left - 6, y: y + 4, "text-anchor": "end" });
    label.textContent = fmtInt.format((max * i) / 4);
    grid.append(label);
  }
  root.append(grid);

  const step = iw / counts.length;
  const gap = counts.length > 1 ? Math.min(2, step * 0.2) : 0;        // 2px surface gap between bars
  const bw = Math.max(1, step - gap);
  const labelEvery = Math.ceil(counts.length / Math.max(2, Math.floor(iw / 90)));
  counts.forEach((n, i) => {
    const x = m.left + i * step + gap / 2;
    const h = (n / max) * ih;
    const y = m.top + ih - h;
    const start = data.since + i * data.bucket_seconds;
    const g = svg("g", {});
    // Rounded top (data end), square bottom anchored to the baseline.
    const r = Math.min(4, bw / 2, h);
    const bar = svg("path", {
      class: "bar",
      d: h <= 0 ? "" : `M${x},${y + h} V${y + r} Q${x},${y} ${x + r},${y} H${x + bw - r} Q${x + bw},${y} ${x + bw},${y + r} V${y + h} Z`,
    });
    const hit = svg("rect", { class: "hit", x: m.left + i * step, y: m.top, width: step, height: ih });
    hit.addEventListener("mousemove", (e) => {
      bar.classList.add("hover");
      showTip(e, el("div", {}, bucketLabel(start, data.bucket_seconds)), el("strong", {}, fmtInt.format(n)), " connections");
    });
    hit.addEventListener("mouseleave", () => { bar.classList.remove("hover"); hideTip(); });
    g.append(bar, hit);
    root.append(g);
    if (i % labelEvery === 0) {
      const label = svg("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle" });
      label.textContent = bucketLabel(start, data.bucket_seconds);
      root.append(label);
    }
  });
  const axis = svg("g", { class: "axis" });
  axis.append(svg("line", { x1: m.left, x2: W - m.right, y1: m.top + ih, y2: m.top + ih }));
  root.append(axis);
  box.replaceChildren(root);

  const width = data.bucket_seconds >= 86400 ? "1 day" : data.bucket_seconds >= 3600 ? (data.bucket_seconds / 3600) + " hours" : (data.bucket_seconds / 60) + " min";
  document.getElementById("chart-caption").textContent = "each bar = " + width;
}

function meter(n, max) {
  const fill = el("div", { class: "fill" });
  // Set via .style (not a style="" attribute) so the page's strict
  // Content-Security-Policy allows it.
  fill.style.width = (max ? Math.max(2, (n / max) * 100) : 0) + "%";
  return el("div", { class: "meter" },
    el("div", { class: "track" }, fill),
    el("span", { class: "val" }, fmtInt.format(n)));
}

function filterButton(kind, value, label) {
  return el("button", { type: "button", class: "linkish", title: "Show these in the connection log",
    onclick: () => { state.filters[kind] = value; showView("log"); } }, label);
}

function drawTopApps(rows) {
  const max = rows.length ? rows[0].n : 0;
  document.getElementById("apps-body").replaceChildren(...(rows.length ? rows.map((r) =>
    el("tr", {},
      el("td", { class: "name", title: r.path || "" }, filterButton("app", r.name, r.name || "unknown")),
      el("td", {}, badge(r.signing, r.signer)),
      el("td", { class: "num" }, fmtInt.format(r.destinations)),
      el("td", {}, meter(r.n, max)))) : [emptyRow(4)]));
}

function drawTopDomains(rows) {
  const max = rows.length ? rows[0].n : 0;
  document.getElementById("domains-body").replaceChildren(...(rows.length ? rows.map((r) =>
    el("tr", {},
      el("td", { class: "name" + (r.is_ip ? " mono" : ""), title: r.name },
        r.is_ip ? filterButton("q", r.name, r.name) : filterButton("domain", r.name, r.name)),
      el("td", { class: "num" }, fmtInt.format(r.apps)),
      el("td", {}, meter(r.n, max)))) : [emptyRow(3)]));
}

function drawFlagged(rows) {
  document.getElementById("flagged-panel").hidden = !rows.length;
  document.getElementById("flagged-body").replaceChildren(...rows.map((r) =>
    el("tr", {},
      el("td", { class: "name" }, filterButton("app", r.name, r.name)),
      el("td", {}, badge(r.signing)),
      el("td", { class: "name mono", title: r.path }, r.path),
      el("td", { class: "num" }, fmtInt.format(r.n)),
      el("td", { class: "muted" }, fmtAgo(r.last_seen)))));
}

function emptyRow(cols) {
  return el("tr", {}, el("td", { colspan: cols, class: "muted" }, "Nothing yet in this time range."));
}

// ---------- Connection log ----------
const logBody = document.getElementById("log-body");

function logParams(extra) {
  return { range: state.range, ...state.filters, limit: 200, ...extra };
}

function rowFor(r, isNew) {
  const dest = r.domain
    ? el("span", {}, r.domain, el("span", { class: "src", title: "hostname source: " + sourceHelp(r.domain_source) }, r.domain_source))
    : el("span", { class: "ip mono" }, r.remote_ip);
  const tr = el("tr", { class: isNew ? "new" : null, "data-id": r.id, onclick: () => openDrawer(r) },
    el("td", { class: "muted", title: fmtTime(r.ts_start, true) }, fmtTime(r.ts_start)),
    el("td", { class: "app", title: r.path || "" },
      r.app || "unknown", " ", badge(r.signing, r.signer),
      r.via ? el("span", { class: "via" }, " via " + r.via) : null),
    el("td", { class: "dest", title: (r.domain ? r.domain + " — " : "") + r.remote_ip }, dest),
    el("td", { class: "mono" }, r.proto + "/" + r.remote_port),
    el("td", { class: r.direction === "in" ? "dir-in" : "muted", title: r.direction === "in" ? "Incoming: something connected to your Mac" : "Outgoing" }, r.direction === "in" ? "← in" : "→ out"),
    el("td", { class: "num" }, fmtBytes(r.bytes_out)),
    el("td", { class: "num" }, fmtBytes(r.bytes_in)),
    el("td", { class: "muted" }, r.iface || ""));
  return tr;
}

function sourceHelp(src) {
  return { sni: "the name the app sent when starting HTTPS (most reliable)",
           dns: "the name the app looked up to get this IP",
           rdns: "who owns this IP (reverse lookup; may be a hosting company)" }[src] || "unknown";
}

function matchesFilters(r) {
  const f = state.filters;
  if (f.app && r.app !== f.app) return false;
  if (f.domain && r.domain !== f.domain) return false;
  if (f.direction && r.direction !== f.direction) return false;
  if (f.flagged && !FLAGGED.includes(r.signing)) return false;
  if (f.q) {
    const q = f.q.toLowerCase();
    if (![r.app, r.domain, r.remote_ip, r.path, r.via].some((v) => v && v.toLowerCase().includes(q))) return false;
  }
  return true;
}

async function loadLog(older) {
  const params = logParams(older && state.oldestId ? { before: state.oldestId } : {});
  const { rows } = await api("/api/connections", params);
  if (!older) { logBody.replaceChildren(); state.rowsShown = 0; }
  for (const r of rows) logBody.append(rowFor(r, false));
  state.rowsShown += rows.length;
  if (rows.length) state.oldestId = rows[rows.length - 1].id;
  document.getElementById("load-more").hidden = rows.length < params.limit;
  if (!state.rowsShown) logBody.append(emptyRow(8));
  updateLogCount();
  drawChips();
}

function updateLogCount() {
  document.getElementById("log-count").textContent = "Showing " + fmtInt.format(state.rowsShown) + " connections, newest first";
}

function drawChips() {
  const chips = [];
  for (const kind of ["app", "domain"]) {
    if (!state.filters[kind]) continue;
    chips.push(el("span", { class: "chip" }, kind + ": " + state.filters[kind],
      el("button", { type: "button", "aria-label": "Remove filter", onclick: () => { state.filters[kind] = ""; loadLog(false); } }, "✕")));
  }
  document.getElementById("f-chips").replaceChildren(...chips);
  document.getElementById("f-search").value = state.filters.q;
}

function openDrawer(r) {
  const rows = [
    ["App", r.app], ["Signature", badge(r.signing, r.signer)], ["Signed by", r.signer || "—"],
    ["Program", r.path || "—"], ["Process ID", r.pid ?? "—"], ["Sent via helper", r.via || "—"],
    ["Hostname", r.domain || "—"], ["Hostname source", r.domain ? sourceHelp(r.domain_source) : "—"],
    ["Remote address", r.remote_ip + " port " + r.remote_port], ["Protocol", r.proto.toUpperCase()],
    ["Direction", r.direction === "in" ? "Incoming (something connected to your Mac)" : "Outgoing (your Mac connected out)"],
    ["Local address", r.local_ip + " port " + r.local_port], ["Interface", r.iface || "—"],
    ["Started", fmtTime(r.ts_start, true)], ["Last packet", fmtTime(r.ts_last, true)],
    ["Sent", fmtBytes(r.bytes_out) + " in " + fmtInt.format(r.packets_out) + " packets"],
    ["Received", fmtBytes(r.bytes_in) + " in " + fmtInt.format(r.packets_in) + " packets"],
  ];
  document.getElementById("drawer-title").textContent = (r.app || "unknown") + " → " + (r.domain || r.remote_ip);
  document.getElementById("drawer-body").replaceChildren(...rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
  document.getElementById("drawer").hidden = false;
  document.getElementById("drawer-close").focus();
}
function closeDrawer() { document.getElementById("drawer").hidden = true; }

// ---------- Live feed (Server-Sent Events) ----------
let dashTimer = null;
function connectStream() {
  const source = new EventSource("/api/stream");
  source.onmessage = (msg) => {
    const event = JSON.parse(msg.data);
    if (event.type === "new" && state.view === "log" && !state.paused && matchesFilters(event.row)) {
      const empty = logBody.querySelector("td[colspan]");
      if (empty) empty.parentElement.remove();
      logBody.prepend(rowFor(event.row, true));
      state.rowsShown++;
      // Keep the page light: trim very long live sessions.
      while (logBody.children.length > 2000) { logBody.lastElementChild.remove(); state.rowsShown--; }
      updateLogCount();
    } else if (event.type === "update" && state.view === "log") {
      const old = logBody.querySelector(`tr[data-id="${Number(event.row.id)}"]`);
      if (old) old.replaceWith(rowFor(event.row, false));
    }
    if (state.view === "dashboard" && !dashTimer) {
      // Batch dashboard refreshes: at most every 5 seconds while traffic flows.
      dashTimer = setTimeout(() => { dashTimer = null; refreshDashboard().catch(console.error); }, 5000);
    }
  };
  source.onerror = () => refreshStatus();
}

// ---------- Navigation & controls ----------
function showView(view) {
  state.view = view;
  for (const v of ["dashboard", "log"]) document.getElementById("view-" + v).hidden = v !== view;
  document.querySelectorAll(".sidebar nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === view));
  document.getElementById("view-title").textContent = view === "log" ? "Connection log" : "Dashboard";
  if (location.hash !== "#" + view) history.replaceState(null, "", "#" + view);
  if (view === "log") {
    document.getElementById("f-direction").value = state.filters.direction;
    document.getElementById("f-flagged").checked = state.filters.flagged;
    loadLog(false).catch(console.error);
  } else {
    refreshDashboard().catch(console.error);
  }
}

function setup() {
  document.querySelectorAll(".sidebar nav a").forEach((a) => a.addEventListener("click", (e) => {
    e.preventDefault(); showView(a.dataset.view);
  }));
  document.querySelectorAll(".range button").forEach((b) => b.addEventListener("click", () => {
    state.range = b.dataset.range;
    document.querySelectorAll(".range button").forEach((x) => x.classList.toggle("active", x === b));
    showView(state.view);
  }));
  let searchTimer;
  document.getElementById("f-search").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.filters.q = e.target.value.trim(); loadLog(false); }, 250);
  });
  document.getElementById("f-direction").addEventListener("change", (e) => { state.filters.direction = e.target.value; loadLog(false); });
  document.getElementById("f-flagged").addEventListener("change", (e) => { state.filters.flagged = e.target.checked; loadLog(false); });
  document.getElementById("load-more").addEventListener("click", () => loadLog(true));
  document.getElementById("pause").addEventListener("click", (e) => {
    state.paused = !state.paused;
    e.target.setAttribute("aria-pressed", state.paused);
    e.target.textContent = state.paused ? "Paused — resume" : "Pause live";
    if (!state.paused) loadLog(false);
  });
  document.getElementById("drawer-close").addEventListener("click", closeDrawer);
  document.getElementById("drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") closeDrawer(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  // Theme toggle: remembered in this browser only (try/catch: storage can be blocked).
  const themeBtn = document.getElementById("theme-toggle");
  try { const saved = localStorage.getItem("snitchy-theme"); if (saved) document.documentElement.dataset.theme = saved; } catch (e) {}
  themeBtn.addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("snitchy-theme", document.documentElement.dataset.theme); } catch (e) {}
  });

  let resizeTimer;
  addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => state.view === "dashboard" && refreshDashboard(), 200); });

  refreshStatus();
  setInterval(refreshStatus, 10000);
  setInterval(() => state.view === "dashboard" && refreshDashboard().catch(console.error), 60000);
  connectStream();
  showView(location.hash === "#log" ? "log" : "dashboard");
}

setup();
