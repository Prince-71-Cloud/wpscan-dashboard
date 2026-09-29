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
  const res = await fetch("/api/findings");
  const data = await res.json();
  state.findings = data.findings || [];
  state.sites = data.sites || [];

  renderPosture(data.summary || {});
  renderTargets(state.sites);
  renderSiteFilter(state.sites);
  renderScanState(data.scanning);
  render();

  // Poll while a scan batch is running, then stop.
  if (data.scanning && !state.pollTimer) {
    state.pollTimer = setInterval(load, 3000);
  } else if (!data.scanning && state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
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
  sites.forEach((s) => {
    const status = s.status || "not scanned";
    const cls = status === "success" ? "success"
      : status === "error" ? "error"
      : status === "running" ? "running" : "not";
    const node = el("div", `target ${cls}`);
    node.appendChild(el("span", "dot"));
    node.appendChild(el("span", "host", host(s.site)));
    if (status === "error" && s.error) {
      const e = el("span", "err", "scan failed");
      e.title = s.error;
      node.appendChild(e);
    } else if (status === "success" && s.wp_version) {
      node.appendChild(el("span", "err", `WP ${s.wp_version}`));
      node.lastChild.style.color = "var(--muted)";
    }
    wrap.appendChild(node);
  });
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

function renderScanState(scanning) {
  const badge = $("#scan-state");
  const btn = $("#btn-scan");
  if (scanning) {
    badge.hidden = false;
    badge.textContent = "Scanning…";
    btn.disabled = true;
  } else {
    badge.hidden = true;
    btn.disabled = false;
  }
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

["#search", "#filter-site", "#filter-type", "#sort"].forEach((sel) => {
  const node = $(sel);
  node.addEventListener(node.tagName === "SELECT" ? "change" : "input", render);
});

load();
