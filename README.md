# WPScan Console

A single-user security dashboard that runs [WPScan](https://wpscan.com/)
against your WordPress sites (or ingests existing WPScan JSON reports),
aggregates every finding into one filterable, severity-ranked view, and exports
a client-ready PDF or JSON audit report.

> ⚠️ **Only scan sites you own or are explicitly authorized to test.** Running a
> vulnerability scanner against systems without permission may be illegal.

## 🎬 Video user manual

[![Watch the WPScan Console video user manual](docs/media/user-manual-thumbnail.png)](docs/media/user-manual.mp4)

*A 2:40 walkthrough of setup, the dashboard, running and controlling scans, and
the PDF/JSON reports. Click the image to play
([download the MP4](docs/media/user-manual.mp4)).*

## 📸 Screenshot tour

| | | |
|:---:|:---:|:---:|
| [<img src="docs/media/dashboard.png" width="260" alt="Dashboard">](#32-reading-the-dashboard)<br>**Dashboard** | [<img src="docs/media/scan-running.png" width="260" alt="Scan running">](#42-start-a-scan)<br>**Live scan** | [<img src="docs/media/scan-paused.png" width="260" alt="Batch paused">](#43-pause-resume-and-cancel)<br>**Pause / cancel** |
| [<img src="docs/media/settings.png" width="260" alt="Settings">](#41-tune-the-settings-optional)<br>**Settings** | [<img src="docs/media/scan-failed.png" width="260" alt="Failed target">](#8-troubleshooting)<br>**Failed target** | [<img src="docs/media/pdf-report.png" width="150" alt="PDF report">](#5-exporting-the-audit-report)<br>**PDF report** |

*All screenshots use the bundled `example.*` sample sites.*

---

## Contents

1. [Quick start](#1-quick-start)
2. [Installation and configuration](#2-installation-and-configuration)
3. [Using the dashboard](#3-using-the-dashboard)
4. [Running scans](#4-running-scans)
5. [Exporting the audit report](#5-exporting-the-audit-report)
6. [What it checks](#6-what-it-checks)
7. [How severity is decided](#7-how-severity-is-decided)
8. [Troubleshooting](#8-troubleshooting)
9. [Configuration reference](#9-configuration-reference)
10. [API reference](#10-api-reference)
11. [Architecture](#11-architecture)
12. [Deployment and security](#12-deployment-and-security)

---

## 1. Quick start

```bash
cd wpscan-dashboard
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000> and click **Load sample data** to explore the
console immediately — no WPScan install, API key, or live targets needed. The
sample data comes from the bundled reports in `sample_scans/`; nothing is
contacted.

---

## 2. Installation and configuration

### 2.1 Install WPScan

Live scanning needs the WPScan CLI (Ruby gem or the official Docker image):

```bash
gem install wpscan
```

### 2.2 Add WPScan API keys

Vulnerability data comes from the WPScan API. Get free keys at
<https://wpscan.com/profile>, then:

```bash
cp api_keys.txt.example api_keys.txt   # then put one key per line
python scanner.py                      # shows which keys were loaded (masked)
```

- The free plan allows **25 requests per key per day**.
- The current key is reused across sites. When WPScan rejects it or reports its
  limit, it is retired for the session and the scan retries with the next key.
- Keys are re-read at the start of every batch — no restart needed after edits.
- A single `WPSCAN_API_TOKEN` environment variable is also supported and is
  tried first.
- `api_keys.txt` is gitignored. **Never commit real keys.**

Without keys WPScan still enumerates the site, but returns little or no
vulnerability data.

### 2.3 Add your targets

Put the sites you are authorized to scan in `sites.txt`, one URL per line.
Lines starting with `#` are ignored, a missing scheme defaults to `https://`,
and duplicate entries are scanned only once.

---

## 3. Using the dashboard

### 3.1 First run

![Empty dashboard on first run](docs/media/first-run.png)

On first launch the dashboard is empty:

1. **Header buttons** (top right): **Run scan** · **Load sample data** ·
   **⚙ Settings** · **Scan output** (live console) · **Export PDF** ·
   **Export JSON** · **Clear**.
2. **Summary band** shows `0/N sites scanned` — N is the number of targets in
   `sites.txt`.
3. **Site chips** list every configured target as *not scanned*.
4. The **empty-state message** points you to `sites.txt` or the sample data.

Click **Load sample data** for an instant demo, or **Run scan** once your
targets and API keys are set up.

### 3.2 Reading the dashboard

![Dashboard with findings](docs/media/dashboard.png)

1. **Sites scanned / open findings** — how many targets have a successful scan,
   and how many findings are currently open across all of them.
2. **Severity bar and legend** — the share of findings per severity
   (critical · high · medium · low · info). Click a legend chip to hide or show
   that severity in the table.
3. **Site chips** — one per target. The dot shows its status (green success,
   amber partial, red failed, grey not scanned) next to the detected WordPress
   version.
4. **Findings table** — every finding ranked worst first:

   | Column | Meaning |
   |---|---|
   | **Severity** | Critical → info ([how it's decided](#7-how-severity-is-decided)). Tags like `exposure` or `outdated` mark non-CVE findings; a `CVSS` score is shown when WPScan provides one. |
   | **Finding** | The vulnerability or exposure title. |
   | **Site** | Which target it was found on. |
   | **Component** | Type (core · plugin · theme · config · user) and name, e.g. `plugin` / `contact-form-7`. |
   | **Version** | The installed version WPScan detected. |
   | **Fixed in** | The first version that fixes it (green), or `no fix`. Upgrading to at least this version resolves the finding. |
   | **References** | CVE IDs and advisory links. |

### 3.3 Search, filter and sort

![Searching for "upload"](docs/media/filter.png)

- **Search box** — matches finding titles, component names and CVE IDs as you
  type. Above, searching `upload` narrows 12 findings to the 2 file-upload
  issues.
- **All sites** — show findings for one target only.
- **All components** — show only core, plugin, theme, config, server or user
  findings.
- **Sort** — by severity (default), site, component type, or component name.
- The counter on the right (`2 of 12 findings`) shows how much is filtered out.

### Load or clear data

- **Load sample data** imports the bundled JSON reports (no scan is run).
- To ingest your own reports, drop WPScan JSON files (made with
  `wpscan --url … --format json -o report.json`) into `sample_scans/` (or set
  `SAMPLE_DIR`) and click **Load sample data**.
- **Clear** deletes stored scans and findings. It does not touch `sites.txt` or
  `api_keys.txt`.

---

## 4. Running scans

### 4.1 Tune the settings (optional)

![Scan settings](docs/media/settings.png)

Open **⚙ Settings** before a batch:

| Setting | Effect |
|---|---|
| **Pre-flight site check** | Checks reachability and a WordPress fingerprint first, so unreachable or non-WordPress targets don't spend API quota. |
| **Pre-flight timeout** | How long the pre-flight check waits. |
| **Scan timeout** | When WPScan is stopped. Findings gathered so far are kept and the site is marked **partial**. |
| **Plugin detection** | `aggressive` (thorough, slow) · `mixed` (balanced) · `passive` (fast). |
| **Enumeration flags** | WPScan `--enumerate` value; default `vp,vt,u,cb,dbe`. |

Settings live in memory and reset when the server restarts. For permanent
defaults use the [environment variables](#9-configuration-reference).

### 4.2 Start a scan

![Scan in progress with the live console](docs/media/scan-running.png)

1. Click **Run scan** and confirm that you are authorized to scan the targets.
2. Sites are scanned **one at a time**, in the order of `sites.txt`. Sequential
   scanning keeps pauses predictable and spends API quota one site at a time.
3. The **Scan output** console opens and streams WPScan's live progress (API
   token masked). Findings appear in the table as soon as they are found.
4. Toast notifications report scan start, each target, key rotation, and the
   batch summary.

What you see in the screenshot above:

- **Header** — `Scanning… 1/3` progress, plus **⏸ Pause** and **✕ Cancel**.
- **Site chips** — the active site says *scanning…*; the others say *queued*,
  each with a ⏸ button to hold it before it starts.
- **Findings table** — already shows the new Elementor Pro findings for the
  first site while the second is still being scanned.
- **Scan output** panel (right) — WPScan's live progress for the current site.

Each successful scan is followed by the passive
[web-hygiene checks](#6-what-it-checks).

### 4.3 Pause, resume and cancel

![Batch paused](docs/media/scan-paused.png)

**Batch controls** (in the header while scanning):

- **⏸ Pause** — holds after the current site finishes. A running scan is never
  interrupted mid-flight.
- **▶ Resume** — continues with the next queued site.
- **✕ Cancel** — skips all remaining sites. Skipped sites keep their previous
  results and are reported as *skipped*, not failed.

In the screenshot, **⏸ Pause** was clicked while `docs.example.org` was being
scanned: the header shows `Paused 1/3`, the button changes to **▶ Resume**, a
toast confirms *Batch will pause after the current site finishes*, and
`shop.example.net` waits as *queued*.

**Per-site controls** (on each chip):

- **⏸** on a queued site — hold before that site starts; **▶** releases it.
- **↻** on a failed or partial site — retry just that site.

**Chip states:** scanning… (blue) → queued (grey) → ⏸ held (amber) →
success (green) / partial (amber, timed out) / scan failed (red, with reason).

### 4.4 The live console

<img src="docs/media/console.png" alt="Live scan output console" width="300" align="right">

**Scan output** shows WPScan's human-readable progress: the command (token
masked), each enumeration phase, plugins and themes as they are found, and
warnings. It auto-scrolls unless you scroll up, and has `wrap` / `clear`
controls.

How to read the lines:

| Prefix | Meaning |
|---|---|
| `$` | The WPScan command being run (API token masked). |
| `[+]` | Something found: the target URL, a plugin or theme, a user, or a summary. |
| `[i]` | Information, e.g. *2 plugin(s) Identified* or *version could not be detected*. |
| `[!]` | A vulnerability (`Title: …`) or a warning. |
| `│` | Details of the item above: location, how it was found, version, *Fixed in*, references. |
| `!! FAILED:` / `!! PARTIAL:` | The dashboard's own note when a site fails or times out. |

<br clear="right">

The console is **display-only**: it is held in memory, never stored in the
database, never included in exports, and hidden when printing. It relies on
WPScan's `--verbose` flag and a pseudo-terminal so output isn't buffered;
disable it with `WPSCAN_VERBOSE=false`.

### 4.5 Reviewing the results

![Results after a scan](docs/media/results.png)

When the batch ends, a toast summarizes it (succeeded / partial / failed /
skipped) and the dashboard shows the final state:

- **Summary band** — `3/3 sites scanned`, 13 open findings, and the severity
  split (2 critical, 1 high, 5 medium, 2 low, 3 info).
- **Site chips** — all green. `shop.example.net` was skipped by a **Cancel** in
  this batch, so it keeps the result of its previous scan (WordPress 6.4.2)
  rather than showing as failed.
- **Findings table** — the critical *Elementor Pro < 4.2.2 Unauthenticated
  Arbitrary File Upload* on two sites tops the list, with **Fixed in 4.2.2**
  telling you exactly which update resolves it. Below it, an exposed
  `wp-config` backup is tagged `exposure` with `no fix` (remove the file).

Each site always shows the findings from its **latest** successful (or
partial) scan. Re-scanning replaces them, so fixed issues disappear and nothing
goes stale.

---

## 5. Exporting the audit report

Click **Export PDF** or **Export JSON** in the header (or call
`GET /api/export.pdf` / `GET /api/export.json`). Files are named
`wpscan-audit-YYYYMMDD-HHMM.{pdf,json}`.

### 5.1 PDF report

| Page 1 | Page 2 |
|:---:|:---:|
| <img src="docs/media/pdf-report.png" alt="PDF audit report, page 1" width="400"> | <img src="docs/media/pdf-report-page2.png" alt="PDF audit report, page 2" width="400"> |

A paginated audit deliverable you can hand to a client or attach to a ticket:

1. **Header** — report title, generation time, how many targets were assessed,
   and the total finding count.
2. **Summary** — finding counts per severity, with a plain-language meaning
   for each level (e.g. *critical: remote code execution or equivalent full
   compromise; patch immediately*).
3. **Scope and coverage** — every target with its status, WordPress version,
   last scan time and number of findings. Failed targets are flagged as *not
   assessed* and partial (timed-out) targets as *incomplete*, so a coverage gap
   is never mistaken for a clean result.
4. **Findings** — the full table ordered by severity, with critical rows tinted
   red and high rows tinted orange. Each row has the finding, target, component
   (with type), installed version, *fixed in* version and the CVE or reference.
5. **Method and caveats** (page 2) — how severity was decided, and what the
   report does and doesn't prove.

Every page carries a footer with the report name and page number.

### 5.2 JSON report

The same data as structured fields, for diffing two runs or feeding a ticket
tracker. An abridged example:

```json
{
  "report_type": "WordPress security audit",
  "generated_at": "2026-11-19T18:38:46+06:00",
  "scope":   { "targets_total": 3, "targets_scanned": 3, "targets_partial": 0, "targets_failed": 0 },
  "summary": { "critical": 2, "high": 1, "medium": 5, "low": 2, "info": 3, "total": 13 },
  "targets": [ { "site": "https://blog.example.com", "status": "success", "findings": 5, "...": "..." } ],
  "findings": [
    {
      "site": "https://blog.example.com",
      "severity": "critical",
      "title": "Elementor Pro < 4.2.2 - Unauthenticated Arbitrary File Upload via Upload Field Array Validation Bypass",
      "component_type": "plugin",
      "component_name": "elementor-pro",
      "component_version": "3.20.0",
      "fixed_in": "4.2.2",
      "cves": [],
      "references": []
    }
  ],
  "severity_definitions": { "critical": "Remote code execution or equivalent full compromise. Patch immediately.", "...": "..." },
  "notes": [ "Findings reflect the most recent successful scan of each target.", "..." ]
}
```

PDF export needs `reportlab` (in `requirements.txt`). Without it the dashboard
and JSON export still work, and the PDF button says reportlab is missing.

---

## 6. What it checks

**WPScan (with API keys):** vulnerable WordPress core, plugins and themes (with
versions), enumerated users, config backups and database exports. The default
enumeration is thorough — `--enumerate vp,vt,u,cb,dbe --plugins-detection
aggressive` — which is slower and noisier than a passive scan. Tune it with
`WPSCAN_ENUMERATE` / `WPSCAN_PLUGINS_DETECTION`, or pass extra flags (throttling,
threads) with `WPSCAN_EXTRA_ARGS`.

**Passive web-hygiene checks** (after each successful or partial scan; toggle
with `EXTRA_CHECKS`):

- missing security headers (CSP, X-Frame-Options, HSTS, …), HSTS `max-age` /
  `includeSubDomains` quality, and `Server` / `X-Powered-By` version disclosure
- permissive CORS (`*` on the homepage) and REST-API Origin reflection
  (`/wp-json/` is probed with a foreign `Origin`)
- HTTP vs HTTPS, plain HTTP served without a redirect, certificate validity and
  expiry, and whether legacy TLS 1.0 / 1.1 are still accepted (each version is
  probed explicitly)
- cookies set by `/wp-login.php` without `Secure` / `HttpOnly` / `SameSite`
- directory listing
- REST-API user enumeration (`/wp-json/wp/v2/users`)
- a reachable admin login page
- a small curated set of commonly exposed files (`/wp-content/debug.log`,
  `/_wpeprivate/config.json`, `wp-config` backups, `.env`, `/.git/HEAD`,
  `readme.html`, `xmlrpc.php`)

These are unauthenticated GET requests and header inspection only — bounded,
rate-limited and gentle on the target. File probes never follow redirects, and
an "exposed file" is only reported when the body actually looks like that file
(a `wp-config` backup must contain `DB_PASSWORD`, a `.env` must contain
`KEY=value` lines, and so on), so a site that answers 200 to every URL does not
produce false criticals in the report.

**Deliberately not included:** credential brute-forcing / password spraying and
active exploitation. They cause lockouts and outages, and automating them into a
point-and-shoot dashboard is out of scope by design. For an authorized
engagement that needs a throttled password audit, run WPScan's own
`--passwords` option directly, with agreed rules of engagement.

---

## 6b. From finding to fix

Click any row in the findings table to open its detail panel:

- **Why this severity** — the exact reason (CVSS score and its source, title
  keyword, Admin+ cap, CISA KEV listing) plus the EPSS exploitation probability.
- **How to fix** — one concrete action (*Update contact-form-7 to 5.3.2 or
  later*, *Remove exposed backup files and rotate the secrets they contain*),
  ordered steps, and copy-paste snippets for WP-CLI, wp-config.php, Nginx,
  Apache and PHP mu-plugins. Guidance is derived from a rule set in
  `remediation.py`, so improving a rule improves every existing report.
- **Evidence** — how the finding was produced: the request and status code,
  the header or body sample observed, or WPScan's *Found By* / version
  confidence. A developer can reproduce each one with a single `curl`.
- **History** — first seen, last seen and whether it is new, recurring or
  regressed.

The PDF and JSON exports end with a **remediation plan**: findings grouped by
action, worst severity first, so "update these three plugins" and "add these
headers" read as a to-do list instead of forty separate rows.

### CVE enrichment (NVD, EPSS, KEV)

WPScan's CLI output carries no CVSS at all. After every scan or ingest the
console looks up each CVE id (in the background, on one thread, never
touching the scanned sites):

| Source | What it adds |
|---|---|
| NVD | CVSS v3.1/3.0/2 base score and vector; a finding without its own score is re-graded with the standard bands |
| FIRST EPSS | probability of exploitation in the next 30 days, shown as a percentage |
| CISA KEV | "known exploited" flag; a KEV finding is always **critical** |

Results are cached per CVE for `ENRICH_TTL_DAYS`, so a re-scan is graded
instantly from the cache. Without `NVD_API_KEY` the public rate limit is about
5 requests per 30 seconds, so a first run over many CVEs takes a few minutes;
the header shows *CVE data: n pending* until it finishes. Set
`ENRICHMENT=false` to turn it off, or `POST /api/enrich` to trigger a refresh.

### History and diffs

Every finding is tracked per site across scans. A re-scan reports what
changed — **new**, **recurring**, **regressed** (previously fixed, now back)
and **fixed** — on the target card, in the batch-complete toast, as badges in
the table, and in the report's coverage and *Resolved since the previous scan*
sections. The **Fixed** button lists everything that has been resolved.

---

## 7. How severity is decided

WPScan's free feed rarely includes a CVSS score, so severity is layered:

1. An explicit **CVSS score** is used when present (standard bands).
2. Otherwise **keywords in the title** decide (e.g. *remote code execution* /
   *unauthenticated arbitrary file upload* / *unauthenticated SQL injection* /
   *arbitrary plugin installation* → critical, *SQL injection* / *privilege
   escalation* → high, *XSS* → medium).
3. A vulnerability that needs an **Admin+** (or Super Admin+) account is capped
   at **medium**: that role can already install arbitrary code.
4. Any other known vulnerability defaults to **medium**.

Exposures outside the vulnerability model (exposed `wp-config` backups, database
dumps, debug logs, user enumeration) have their own fixed severities. When
WPScan's advisory lists a public exploit (Exploit-DB, Metasploit, Packet Storm)
the link is kept and the table shows an **exploit available** badge — use it to
order remediation. Treat severity as a prioritization aid, not a substitute for
reading the advisory.

A scan whose API key runs out of daily requests part-way through is recorded as
**partial**, not success: WPScan silently returns no vulnerability data for the
components it checks after the quota is gone, so the result is incomplete.

---

## 8. Troubleshooting

![A failed target with its error](docs/media/scan-failed.png)

When a target fails:

1. Its **chip turns red** and says **scan failed**.
2. **Click "scan failed"** to see the reason. Here WPScan aborted because the
   site answered with HTTP 403, which usually means a WAF blocked the scan.
3. Click **↻** on the chip to retry just that site once the cause is fixed.
4. Findings from the site's last successful scan stay in the table. A failed
   re-scan never erases them.

| Symptom | What to do |
|---|---|
| **A target shows "scan failed"** | Click the red chip text, read the `!! FAILED:` line in **Scan output**, or run `python show_errors.py`. WPScan's own error lines (connection refused, Scan Aborted, WAF block) are included. |
| **A target shows "partial"** | The scan hit the timeout; findings so far were saved. Retry with **↻** after raising the timeout or using faster plugin detection. |
| **Scans time out on large sites** | Use `WPSCAN_PLUGINS_DETECTION=mixed` (much faster) or `passive` (fastest), or raise `SCAN_TIMEOUT`. |
| **The site is blocking you** | Add throttling: `WPSCAN_EXTRA_ARGS="--throttle 500 --max-threads 5"`. |
| **Every scan fails instantly** | WPScan is probably not installed or not on `PATH` (`gem install wpscan`); a WAF may also block the scan. Check the stored error. |
| **No vulnerability data** | No API key loaded, or all keys are spent for the day. Run `python scanner.py`. |

---

## 9. Configuration reference

All settings are environment variables (see `config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `WPSCAN_PATH` | `wpscan` | Path to the WPScan binary |
| `WPSCAN_ENUMERATE` | `vp,vt,u,cb,dbe` | What WPScan enumerates |
| `WPSCAN_PLUGINS_DETECTION` | `aggressive` | `passive` / `mixed` / `aggressive` |
| `WPSCAN_VERBOSE` | `true` | Stream live progress to the console |
| `WPSCAN_FORMAT` | `cli-no-colour` | WPScan output format; CLI output enables live findings |
| `WPSCAN_THROTTLE` | `0` | Milliseconds between WPScan requests (forces one thread); be gentle on production sites |
| `WPSCAN_MAX_THREADS` | *(wpscan default)* | WPScan `--max-threads`, ignored when a throttle is set |
| `WPSCAN_EXTRA_ARGS` | *(none)* | Extra raw WPScan args (advanced) |
| `PREFLIGHT_CHECK` | `true` | Check reachability and WordPress fingerprint first |
| `PREFLIGHT_TIMEOUT` | `10` | Pre-flight timeout (seconds) |
| `EXTRA_CHECKS` | `true` | Run passive web-hygiene checks after each scan |
| `CHECK_TIMEOUT` | `10` | Per-request timeout for hygiene checks (seconds) |
| `WPSCAN_API_TOKEN` | *(none)* | Optional single key, tried before the key file |
| `API_KEYS_FILE` | `api_keys.txt` | File of API keys, rotated when one is spent |
| `SITES_FILE` | `sites.txt` | Target list |
| `DATABASE` | `dashboard.db` | SQLite file |
| `SCAN_TIMEOUT` | `1800` | Per-site scan timeout (seconds) |
| `SAMPLE_DIR` | `sample_scans` | Directory of JSON reports to ingest |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Bind address |
| `ALLOW_REMOTE_BIND` | `false` | `python app.py` refuses a non-loopback `HOST` unless this is `true` (there is no login) |
| `TRUSTED_HOSTS` | *(loopback + HOST)* | Extra `Host` header values to accept, comma separated; anything else gets HTTP 400 (DNS-rebinding guard) |
| `AUDIT_LOG` | `audit.log` | Append-only log of scan / clear / settings / export actions with the caller's address |
| `ENRICHMENT` | `true` | Look up CVSS / EPSS / KEV for every CVE (NVD, FIRST, CISA); never touches the targets |
| `NVD_API_KEY` | *(none)* | Free key from nvd.nist.gov raises the NVD rate limit tenfold |
| `ENRICH_TTL_DAYS` | `7` | Re-fetch cached CVE data after this many days |

`SCAN_TIMEOUT`, `PREFLIGHT_*`, `EXTRA_CHECKS`, `WPSCAN_ENUMERATE`,
`WPSCAN_PLUGINS_DETECTION`, `WPSCAN_FORMAT`, `WPSCAN_THROTTLE` and
`WPSCAN_MAX_THREADS` can also be changed at runtime through the settings panel
or `POST /api/settings`; values are range- and choice-checked and an invalid
request changes nothing.

---

## 10. API reference

| Method | Route | Description |
|---|---|---|
| GET | `/` | Dashboard page |
| GET | `/api/findings` | All findings, severity summary and per-site status |
| POST | `/api/scan` | Start a batch from `sites.txt`; body `{ "site": "https://example.com" }` retries one site (must already be in `sites.txt` or scan history) |
| POST | `/api/ingest-samples` | Load JSON reports from `SAMPLE_DIR` |
| GET/POST | `/api/settings` | Read or update runtime scan settings |
| POST | `/api/pause`, `/api/resume`, `/api/cancel` | Pause between sites, resume, or cancel the batch |
| POST | `/api/pause-site`, `/api/resume-site` | Hold or release a queued site; body includes `site` |
| GET | `/api/scan-log` | Incremental live console output (`?since=<id>`) |
| GET | `/api/history` | Findings resolved by a later scan (`?site=` to narrow) |
| POST | `/api/enrich` | Fetch CVSS / EPSS / KEV for uncached CVEs in the background |
| GET | `/api/export.json` | Full audit report as JSON (download) |
| GET | `/api/export.pdf` | Full audit report as PDF (download) |
| POST | `/api/clear` | Wipe stored scans and findings |

Every `POST` must carry the header `X-Requested-With: XMLHttpRequest` (the
dashboard adds it) and, when the browser sends one, a same-origin `Origin`.
Requests without it are answered `403`. This is what stops a malicious web page
from driving the API through your browser (clearing data, launching scans of
your real targets). From `curl`:

```bash
curl -X POST -H 'X-Requested-With: XMLHttpRequest' http://127.0.0.1:5000/api/scan
```

---

## 11. Architecture

Deliberately small — a single Flask process, SQLite, no ORM, no build step.

```
app.py         Flask routes: dashboard page + JSON API
scanner.py     WPScan runner, API-key rotation, pre-flight, ingest, batch manager
cli_parser.py  Streams WPScan CLI output into structured findings during a scan
parser.py      WPScan JSON -> unified findings + severity engine
checks.py      Passive web-hygiene checks
report.py      JSON and PDF audit reports
db.py          SQLite persistence (scans + findings)
config.py      Environment-variable configuration
show_errors.py Print the stored error for every failed target
templates/     dashboard.html
static/        css/style.css, js/dashboard.js (client-side filter/sort)
sample_scans/  Example WPScan JSON reports for a zero-setup demo
docs/media/    Video user manual and screenshots
```

Findings always reflect the **latest** successful (or partial) scan per site;
re-scanning a site replaces its findings so nothing goes stale.

---

## 12. Deployment and security

`app.py` uses Flask's development server, which is fine for local single-user
use. On a shared host, put it behind a production WSGI server:

```bash
pip install gunicorn
gunicorn -w 1 -b 127.0.0.1:5000 app:app
```

- Use a **single worker** (`-w 1`) so the in-process scan manager and SQLite stay
  consistent.
- The dashboard has **no built-in authentication**. Keep it bound to localhost,
  or behind a VPN / reverse proxy with access control. `python app.py` refuses
  to bind to anything but loopback unless `ALLOW_REMOTE_BIND=true`; when you do
  put it behind a proxy, add the proxy's hostname to `TRUSTED_HOSTS`.
- Browser-side protection is built in: state-changing requests need the
  `X-Requested-With` header and a same-origin `Origin`, the `Host` header is
  validated, and the page ships a strict Content-Security-Policy, `X-Frame-Options:
  DENY` and friends.
- Keep `api_keys.txt` and `dashboard.db` at mode `0600` (the database is created
  that way; the key file is yours to lock down — the scan start toast warns if
  it is readable by other users). Never commit either (both are gitignored),
  and treat `audit.log` the same way: it names your targets.
- Dependencies are pinned in `requirements.txt`; run `pip-audit -r
  requirements.txt` before deploying.
- Run the test suite after changes (no network, no API quota — WPScan is
  replaced by a replay script):

```bash
python -m unittest discover -s tests -t .
```
