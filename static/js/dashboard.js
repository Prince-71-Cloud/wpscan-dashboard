/* WPScan Console — client-side aggregation, filtering and sorting.
 * The server returns all normalized findings; filtering/sorting is done here
 * so the UI stays responsive and the API stays trivial. */

const SEVS = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = Object.fromEntries(SEVS.map((s, i) => [s, i]));

const state = {
  findings: [],
  sites: [],
  activeSeverities: new Set(SEVS),   // legend chips act as filters
  pollTimer: null,
  lastEventId: 0,       // cursor so each progress toast is shown exactly once
  primed: false,        // suppress replaying old events on first page load
  scanning: false,
  paused: false,
  pausedSite: null,
  currentSite: null,
  consoleOpen: false,   // verbose console panel visible
  logTimer: null,
  lastLogId: 0,
  autoScroll: true,     // stick to bottom unless the user scrolls up
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, txt) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (txt != null) n.textContent = txt;
  return n;
};
const host = (url) => { try { return new URL(url).host; } catch { return url; } };

/* ------------------------------- Data ------------------------------- */
async function load() {
  const res = await fetch(`/api/findings?since=${state.lastEventId}`);
  const data = await res.json();
  state.findings = data.findings || [];
  state.sites = data.sites || [];
  const wasScanning = state.scanning;
  state.scanning    = !!data.scanning;
  state.paused      = !!data.paused;
  state.pausedSite  = data.paused_site  || null;
  state.currentSite = data.current_site || null;
  // Pop the console open on the rising edge of a scan so output is visible
  // without a manual click (only after the first load, to avoid surprising
  // the user on a page refresh while a scan happens to be running).
  if (state.primed && state.scanning && !wasScanning && !state.consoleOpen) {
    openConsole();
  }

  // On first load, jump the cursor to the end so a page refresh mid-session
  // doesn't replay every event as a burst of toasts.
  if (!state.primed) {
    state.lastEventId = data.last_event_id || 0;
    state.primed = true;
  } else if (data.events && data.events.length) {
    for (const ev of data.events) showToast(ev.message, ev.level, ev.kind);
    state.lastEventId = data.events[data.events.length - 1].id;
  }

  renderPosture(data.summary || {});
  renderTargets(state.sites);
  renderSiteFilter(state.sites);
  renderScanState(data.scanning, data.progress);
  render();

  // Always keep polling, but adapt the rate: fast while a batch runs so
  // progress toasts land near real time, slow when idle so a scan started
  // elsewhere (another tab, or a POST to /api/scan) is still picked up.
  schedulePoll(data.scanning ? 2000 : 6000);
}

function schedulePoll(delay) {
  if (state.pollTimer) clearTimeout(state.pollTimer);
  state.pollTimer = setTimeout(() => {
    load().catch(() => schedulePoll(6000));   // keep trying after a blip
  }, delay);
}

/* ------------------------------ Toasts ------------------------------ */
/* Scans run server-side on background threads, so progress is pushed to the
 * UI as events (target changes, API key rotation, batch completion) and shown
 * here as stacked, auto-dismissing toasts. */
const TOAST_ICONS = {
  scan_start: "▶",
  target_start: "◆",
  target_done: "✓",
  key_rotated: "⟳",
  scan_complete: "■",
};

function showToast(message, level = "info", kind = "") {
  const wrap = $("#toasts");
  if (!wrap) return;

  const t = el("div", `toast toast--${level}`);
  t.setAttribute("role", level === "error" ? "alert" : "status");
  // Failures take an icon from the level, not the kind — a failed target is
  // still a "target_done" event but must never show a checkmark.
  const icon = TOAST_ICONS[kind] && kind === "key_rotated" ? TOAST_ICONS[kind]
             : level === "error" ? "✕"
             : level === "warn" ? "⚠"
             : TOAST_ICONS[kind] || "•";
  t.appendChild(el("span", "toast__icon", icon));
  t.appendChild(el("span", "toast__msg", message));

  const close = el("button", "toast__close", "×");
  close.setAttribute("aria-label", "Dismiss");
  close.addEventListener("click", () => dismissToast(t));
  t.appendChild(close);

  wrap.appendChild(t);

  // Completion messages matter most — keep them up longer.
  const life = kind === "scan_complete" ? 9000
             : level === "error" || level === "warn" ? 8000
             : 4500;
  t.dataset.timer = String(setTimeout(() => dismissToast(t), life));

  // Cap the stack so a big batch can't fill the screen.
  const toasts = wrap.querySelectorAll(".toast");
  if (toasts.length > 5) dismissToast(toasts[0]);
}

function dismissToast(t) {
  if (!t || t.classList.contains("toast--out")) return;
  clearTimeout(Number(t.dataset.timer));
  t.classList.add("toast--out");
  setTimeout(() => t.remove(), 220);
}

/* --------------------------- Verbose console ------------------------ */
/* A small side panel streaming WPScan's live output. It polls a dedicated
 * endpoint while open so it stays light, and is purely a UI element — these
 * lines are never part of an exported or printed report. */
function openConsole() {
  state.consoleOpen = true;
  $("#console").hidden = false;
  $("#btn-console").setAttribute("aria-pressed", "true");
  document.body.classList.add("has-console");
  pollLog();
  if (!state.logTimer) state.logTimer = setInterval(pollLog, 1500);
}

function closeConsole() {
  state.consoleOpen = false;
  $("#console").hidden = true;
  $("#btn-console").setAttribute("aria-pressed", "false");
  document.body.classList.remove("has-console");
  if (state.logTimer) { clearInterval(state.logTimer); state.logTimer = null; }
}

function toggleConsole() {
  state.consoleOpen ? closeConsole() : openConsole();
}

async function pollLog() {
  try {
    const res = await fetch(`/api/scan-log?since=${state.lastLogId}`);
    const data = await res.json();
    const status = $("#console-status");
    status.textContent = data.scanning ? "● running" : "idle";
    status.className = "console__status" + (data.scanning ? " live" : "");
    const lines = data.lines || [];
    if (lines.length) {
      const body = $("#console-body");
      const frag = document.createDocumentFragment();
      for (const ln of lines) {
        const row = el("div", "cline");
        // Dim our own synthetic markers ($ command, !! killed) vs scan output.
        if (ln.text.startsWith("$ ")) row.classList.add("cline--cmd");
        else if (ln.text.startsWith("!!")) row.classList.add("cline--err");
        row.textContent = ln.text;
        frag.appendChild(row);
      }
      body.appendChild(frag);
      state.lastLogId = lines[lines.length - 1].id;
      // Trim very long consoles in the DOM to stay responsive.
      while (body.childNodes.length > 2500) body.removeChild(body.firstChild);
      if (state.autoScroll) body.scrollTop = body.scrollHeight;
    }
  } catch { /* transient; try again next tick */ }
}

/* ----------------------------- Posture ------------------------------ */
function renderPosture(summary) {
  const scanned = state.sites.filter((s) => s.status === "success").length;
  $("#stat-sites").textContent = `${scanned}/${state.sites.length || 0}`;
  $("#stat-total").textContent = summary.total || 0;

  const total = summary.total || 0;
  const bar = $("#posture-bar");
  bar.innerHTML = "";
  SEVS.forEach((s) => {
    const n = summary[s] || 0;
    if (!n) return;
    const seg = el("div", `seg ${s}`);
    seg.style.flexGrow = String(n);
    seg.title = `${n} ${s}`;
    bar.appendChild(seg);
  });
  if (!total) bar.appendChild(Object.assign(el("div", "seg info"),
    { style: "flex-grow:1;opacity:.25" }));

  const legend = $("#severity-legend");
  legend.innerHTML = "";
  SEVS.forEach((s) => {
    const chip = el("button", `legend-chip ${s}`);
    chip.setAttribute("aria-pressed", state.activeSeverities.has(s));
    chip.appendChild(el("span", "dot"));
    chip.appendChild(el("span", "name", s));
    chip.appendChild(el("span", "n", ` ${summary[s] || 0}`));
    chip.addEventListener("click", () => {
      state.activeSeverities.has(s)
        ? state.activeSeverities.delete(s)
        : state.activeSeverities.add(s);
      chip.setAttribute("aria-pressed", state.activeSeverities.has(s));
      render();
    });
    legend.appendChild(chip);
  });
}

/* ----------------------------- Targets ------------------------------ */
function renderTargets(sites) {
  const wrap = $("#targets");
  wrap.innerHTML = "";
  const scanning    = state.scanning;
  const paused      = state.paused;
  const pausedSite  = state.pausedSite;
  const currentSite = state.currentSite;

  sites.forEach((s) => {
    const rawStatus = s.status || "not scanned";
    const isActive    = scanning && currentSite === s.site;
    const isQueued    = scanning && rawStatus === "queued";
    const isSitePaused = scanning && pausedSite === s.site && !isActive;

    // Display class
    const cls = rawStatus === "success" ? "success"
      : rawStatus === "error"   ? "error"
      : isActive                ? "running"
      : isSitePaused            ? "site-paused"
      : isQueued                ? "queued"
      : rawStatus === "running" ? "running"
      : "not";

    const node = el("div", `target ${cls}`);
    node.appendChild(el("span", "dot"));
    node.appendChild(el("span", "host", host(s.site)));

    // Status label
    if (rawStatus === "error" && s.error) {
      const e = el("span", "err err-link", "scan failed");
      e.title = "Click to see error";
      e.addEventListener("click", (ev) => {
        ev.stopPropagation();
        showToast(`${host(s.site)} — ${s.error}`, "error");
      });
      node.appendChild(e);

    } else if (rawStatus === "success" && s.wp_version) {
      const v = el("span", "badge-wp", `WP ${s.wp_version}`);
      node.appendChild(v);

    } else if (isActive) {
      node.appendChild(el("span", "badge-scan", "scanning…"));

    } else if (isSitePaused) {
      const p = el("span", "badge-paused", "⏸ paused");
      node.appendChild(p);

    } else if (isQueued) {
      node.appendChild(el("span", "badge-queued", "queued"));
    }

    // Per-site controls
    const controls = el("span", "target-controls");

    if (rawStatus === "error") {
      // Retry button
      const retry = el("button", "t-btn t-retry", "↻");
      retry.title = scanning ? "Wait for current scan to finish" : `Retry ${host(s.site)}`;
      retry.disabled = scanning;
      retry.setAttribute("aria-label", `Retry ${host(s.site)}`);
      retry.addEventListener("click", (ev) => { ev.stopPropagation(); retryTarget(s.site); });
      controls.appendChild(retry);

    } else if (scanning && isQueued) {
      // Pause-before button — hold this site before WPScan starts on it
      const isPending = pausedSite === s.site;
      const pbtn = el("button", `t-btn ${isPending ? "t-paused" : "t-pause"}`,
                      isPending ? "▶" : "⏸");
      pbtn.title = isPending ? "Click to let this site run" : `Hold before ${host(s.site)}`;
      pbtn.setAttribute("aria-label", isPending ? "Resume site" : "Pause before site");
      pbtn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        isPending ? resumeSite(s.site) : pauseSite(s.site);
      });
      controls.appendChild(pbtn);

    } else if (scanning && isActive) {
      // Currently scanning — show a "pause batch after this" button
      const pbatch = el("button", `t-btn ${paused ? "t-paused" : "t-pause"}`,
                        paused ? "▶" : "⏸");
      pbatch.title = paused ? "Resume batch" : "Pause after this site";
      pbatch.addEventListener("click", (ev) => {
        ev.stopPropagation();
        paused ? resumeBatch() : pauseBatch();
      });
      controls.appendChild(pbatch);
    }

    if (controls.children.length) node.appendChild(controls);
    wrap.appendChild(node);
  });
}

async function retryTarget(site) {
  if (state.scanning) {
    showToast("A scan is already running — wait for it to finish.", "warn");
    return;
  }
  showToast(`Retrying ${host(site)}…`, "info");
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ site }),
    });
    const data = await res.json();
    if (!res.ok) { showToast(data.error || "Retry failed.", "error"); return; }
    await load();   // picks up the running state and starts fast polling
  } catch (e) {
    showToast("Retry failed: " + e.message, "error");
  }
}

function renderSiteFilter(sites) {
  const sel = $("#filter-site");
  const current = sel.value;
  sel.innerHTML = '<option value="">All sites</option>';
  sites.forEach((s) => {
    const o = el("option", null, host(s.site));
    o.value = s.site;
    sel.appendChild(o);
  });
  sel.value = current;
}

function renderScanState(scanning, progress) {
  const badge  = $("#scan-state");
  const btn    = $("#btn-scan");
  const pbtn   = $("#btn-pause");
  const canbtn = $("#btn-cancel");
  if (scanning) {
    badge.hidden = false;
    const p = progress || {};
    const prog = p.total ? `${p.done || 0}/${p.total}` : "";
    badge.textContent = state.paused
      ? `⏸ Paused ${prog}`
      : `Scanning… ${prog}`;
    badge.className = "scan-state" + (state.paused ? " scan-state--paused" : "");
    btn.disabled = true;
    if (pbtn) {
      pbtn.hidden = false;
      pbtn.textContent = state.paused ? "▶ Resume" : "⏸ Pause";
      pbtn.title = state.paused ? "Resume batch" : "Pause after current site";
    }
    if (canbtn) canbtn.hidden = false;
  } else {
    badge.hidden = true;
    badge.className = "scan-state";
    btn.disabled = false;
    if (pbtn)  pbtn.hidden = true;
    if (canbtn) canbtn.hidden = true;
  }
}

/* ------------- Batch-level pause / resume / cancel ------------------- */
async function pauseBatch() {
  await fetch("/api/pause", { method: "POST" });
  showToast("Batch will pause after the current site finishes.", "info");
  await load();
}
async function resumeBatch() {
  await fetch("/api/resume", { method: "POST" });
  showToast("Batch resumed.", "info");
  await load();
}
async function cancelBatch() {
  if (!confirm("Cancel the scan batch? Sites not yet scanned will be skipped.")) return;
  await fetch("/api/cancel", { method: "POST" });
  showToast("Batch cancelled.", "warn");
  await load();
}
/* ------------- Per-site pause / resume ------------------------------- */
async function pauseSite(site) {
  await fetch("/api/pause-site", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ site }),
  });
  showToast(`Scan will hold before ${host(site)}.`, "info");
  await load();
}
async function resumeSite(site) {
  await fetch("/api/resume-site", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ site }),
  });
  showToast(`Releasing hold on ${host(site)}.`, "info");
  await load();
}

/* ------------------------ Filter + sort + render -------------------- */
function currentView() {
  const q = $("#search").value.trim().toLowerCase();
  const site = $("#filter-site").value;
  const type = $("#filter-type").value;
  const sortKey = $("#sort").value;

  let rows = state.findings.filter((f) => {
    if (!state.activeSeverities.has(f.severity)) return false;
    if (site && f.site !== site) return false;
    if (type && f.component_type !== type) return false;
    if (q) {
      const hay = [f.title, f.component_name, f.component_type,
                   (f.cves || []).join(" ")].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  rows.sort((a, b) => {
    if (sortKey === "severity") {
      const d = SEV_RANK[a.severity] - SEV_RANK[b.severity];
      return d !== 0 ? d : (a.site || "").localeCompare(b.site || "");
    }
    return String(a[sortKey] || "").localeCompare(String(b[sortKey] || ""));
  });
  return rows;
}

function render() {
  const rows = currentView();
  const body = $("#findings-body");
  const empty = $("#empty");
  body.innerHTML = "";

  $("#result-count").textContent =
    `${rows.length} of ${state.findings.length} findings`;

  if (state.findings.length === 0) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  const frag = document.createDocumentFragment();
  rows.forEach((f) => frag.appendChild(rowFor(f)));
  body.appendChild(frag);
}

function rowFor(f) {
  const tr = el("tr");

  // Severity
  const sev = el("td");
  const pill = el("span", `sev-pill ${f.severity}`, f.severity);
  sev.appendChild(pill);
  tr.appendChild(sev);

  // Title + kind + cvss
  const title = el("td");
  const t = el("span", "finding-title", f.title || "—");
  title.appendChild(t);
  if (f.cvss != null) title.appendChild(el("span", "cvss", `CVSS ${f.cvss}`));
  if (f.finding_kind && f.finding_kind !== "vulnerability")
    title.appendChild(document.createElement("br")),
      title.appendChild(el("span", "kind", f.finding_kind));
  tr.appendChild(title);

  // Site
  const site = el("td");
  site.appendChild(el("span", "host-cell", host(f.site)));
  tr.appendChild(site);

  // Component
  const comp = el("td");
  comp.appendChild(el("div", "comp-type", f.component_type || ""));
  comp.appendChild(el("div", "comp-name", f.component_name || "—"));
  tr.appendChild(comp);

  // Version
  const ver = el("td");
  ver.appendChild(el("span", "ver", f.component_version || "—"));
  tr.appendChild(ver);

  // Fixed in
  const fix = el("td");
  fix.appendChild(el("span", f.fixed_in ? "fix" : "fix none",
    f.fixed_in || "no fix"));
  tr.appendChild(fix);

  // References
  const ref = el("td");
  const box = el("div", "refs");
  (f.cves || []).slice(0, 3).forEach((cve) => {
    const a = el("a", "cve", cve);
    a.href = `https://nvd.nist.gov/vuln/detail/${cve}`;
    a.target = "_blank"; a.rel = "noopener noreferrer";
    box.appendChild(a);
  });
  const firstUrl = (f.references || []).find((r) => /^https?:\/\//.test(r || ""));
  if (firstUrl) {
    const a = el("a", "reflink", "advisory ↗");
    a.href = firstUrl; a.target = "_blank"; a.rel = "noopener noreferrer";
    box.appendChild(a);
  }
  if (!box.children.length) box.appendChild(el("span", "no-ref", "—"));
  ref.appendChild(box);
  tr.appendChild(ref);

  return tr;
}

/* ------------------------------ Actions ----------------------------- */
async function post(url, okMsg) {
  try {
    const res = await fetch(url, { method: "POST" });
    const data = await res.json();
    if (!res.ok) { alert(data.error || "Request failed."); return; }
    await load();
  } catch (e) {
    alert("Network error: " + e.message);
  }
}

$("#btn-scan").addEventListener("click", () => {
  if (!confirm("Start a WPScan batch against every site in sites.txt?\n" +
               "Only scan sites you are authorized to test.")) return;
  post("/api/scan");
});
$("#btn-samples").addEventListener("click", () => post("/api/ingest-samples"));
$("#btn-clear").addEventListener("click", () => {
  if (confirm("Clear all stored scans and findings?")) post("/api/clear");
});

/* ----------------------------- Settings ----------------------------- */
function fmtTimeout(s) {
  const v = Number(s);
  if (v < 60)  return `${v}s`;
  if (v < 3600) return `${Math.round(v/60)}m`;
  return `${(v/3600).toFixed(1)}h`;
}

async function openSettings() {
  try {
    const r = await fetch("/api/settings");
    const cfg = await r.json();
    $("#s-preflight").checked      = cfg.PREFLIGHT_CHECK !== "false";
    $("#s-preflight-timeout").value = cfg.PREFLIGHT_TIMEOUT ?? 10;
    $("#s-timeout").value           = cfg.SCAN_TIMEOUT ?? 1800;
    $("#s-timeout-val").textContent = fmtTimeout(cfg.SCAN_TIMEOUT ?? 1800);
    $("#s-detection").value         = cfg.WPSCAN_PLUGINS_DETECTION ?? "aggressive";
    $("#s-enumerate").value         = cfg.WPSCAN_ENUMERATE ?? "vp,vt,u,cb,dbe";
    $("#s-concurrent").value        = cfg.MAX_CONCURRENT ?? 3;
  } catch { /* use whatever values are already in the inputs */ }
  $("#settings-panel").hidden = false;
  $("#btn-settings").setAttribute("aria-pressed", "true");
}

function closeSettings() {
  $("#settings-panel").hidden = true;
  $("#btn-settings").setAttribute("aria-pressed", "false");
  $("#settings-status").textContent = "";
}

$("#btn-settings").addEventListener("click", openSettings);
$("#settings-close").addEventListener("click", closeSettings);
$("#settings-panel .settings-backdrop").addEventListener("click", closeSettings);

$("#s-timeout").addEventListener("input", (e) => {
  $("#s-timeout-val").textContent = fmtTimeout(e.target.value);
});

$("#settings-save").addEventListener("click", async () => {
  const body = {
    SCAN_TIMEOUT:          Number($("#s-timeout").value),
    PREFLIGHT_CHECK:       $("#s-preflight").checked ? "true" : "false",
    PREFLIGHT_TIMEOUT:     Number($("#s-preflight-timeout").value),
    WPSCAN_PLUGINS_DETECTION: $("#s-detection").value,
    WPSCAN_ENUMERATE:      $("#s-enumerate").value.trim(),
    MAX_CONCURRENT:        Number($("#s-concurrent").value),
  };
  try {
    const r = await fetch("/api/settings", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (d.saved) {
      $("#settings-status").textContent = "✓ Saved";
      setTimeout(() => { $("#settings-status").textContent = ""; }, 2500);
    }
  } catch { $("#settings-status").textContent = "Save failed"; }
});

/* ------------------------------ Export ------------------------------ */
/* Downloads go through fetch rather than a plain link so a server-side
 * failure (e.g. reportlab not installed) surfaces as a readable message
 * instead of a browser error page. */
async function download(url, kind) {
  if (!state.findings.length && !state.sites.length) {
    showToast("Nothing to export yet — run a scan or load sample data first.",
              "warn");
    return;
  }
  showToast(`Building ${kind} report…`, "info");
  try {
    const res = await fetch(url);
    if (!res.ok) {
      let msg = `${kind} export failed.`;
      try { msg = (await res.json()).error || msg; } catch { /* non-JSON */ }
      showToast(msg, "error");
      return;
    }
    const blob = await res.blob();
    // Prefer the filename the server chose (it carries the timestamp).
    const disp = res.headers.get("Content-Disposition") || "";
    const match = disp.match(/filename="?([^"]+)"?/);
    const name = match ? match[1] : `wpscan-audit.${kind.toLowerCase()}`;

    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(href), 2000);
    showToast(`${kind} report downloaded — ${name}`, "success");
  } catch (e) {
    showToast("Export failed: " + e.message, "error");
  }
}

$("#btn-export-pdf").addEventListener("click",
  () => download("/api/export.pdf", "PDF"));
$("#btn-export-json").addEventListener("click",
  () => download("/api/export.json", "JSON"));

/* Batch controls */
$("#btn-pause").addEventListener("click",  () => state.paused ? resumeBatch() : pauseBatch());
$("#btn-cancel").addEventListener("click", cancelBatch);

/* Console controls */
$("#btn-console").addEventListener("click", toggleConsole);
$("#console-close").addEventListener("click", closeConsole);
$("#console-clear").addEventListener("click", () => {
  $("#console-body").innerHTML = "";
});
$("#console-wrap").addEventListener("click", (e) => {
  const body = $("#console-body");
  body.classList.toggle("wrap");
  e.currentTarget.classList.toggle("on", body.classList.contains("wrap"));
});
// Pause auto-scroll when the user scrolls up to read; resume at the bottom.
$("#console-body").addEventListener("scroll", (e) => {
  const b = e.currentTarget;
  state.autoScroll = (b.scrollHeight - b.scrollTop - b.clientHeight) < 24;
});

["#search", "#filter-site", "#filter-type", "#sort"].forEach((sel) => {
  const node = $(sel);
  node.addEventListener(node.tagName === "SELECT" ? "change" : "input", render);
});

load();
