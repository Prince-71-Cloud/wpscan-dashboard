# WPScan Console

A single-user security dashboard that ingests [WPScan](https://wpscan.com/)
output, aggregates vulnerability findings across many WordPress sites, and
surfaces them in one filterable, severity-ranked view.

It works two ways:

- **Live scanning** — reads a list of target URLs and runs `wpscan` against each.
- **Ingest** — loads existing WPScan JSON reports from disk (no `wpscan`
  binary required), which is also how the bundled sample data works.

> ⚠️ **Only scan sites you own or are explicitly authorized to test.** Running a
> vulnerability scanner against systems without permission may be illegal.

---

## Quick start

```bash
cd wpscan-dashboard
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000> and click **Load sample data** to explore the
console immediately — no WPScan install or live targets needed.

## Running real scans

### Install WPScan

Install the Ruby gem or use the official Docker image:

```bash
gem install wpscan
```

### Configure API keys

For full vulnerability data, add one or more free API keys from
<https://wpscan.com/profile>. Copy the template, then replace its dummy values
with your own keys, one per line:

```bash
cp api_keys.txt.example api_keys.txt
```

The free plan allows **25 requests per key per day**. The current key is reused
across sites; when WPScan rejects it or reports a rate limit, the key is retired
for the running session and the scan retries with the next available key. Keys
are re-read at the start of each batch, so edits take effect without restarting
the app. `api_keys.txt` is gitignored; never commit real keys. A single
`WPSCAN_API_TOKEN` environment variable is also supported and is tried before
keys from the file.

To check which keys were loaded, run `python scanner.py`. It prints the resolved
key-file path, the number of parsed keys (masked), and the available key order.
This is a configuration diagnostic; during scans, the current key is reused
until WPScan rejects it or reports a rate limit.

### Configure targets

Replace the reserved example URLs in `sites.txt` with targets you are authorized
to scan. Use one URL per line; lines beginning with `#` are ignored.

### Run a scan

Start the app using the Quick start instructions, then click **Run scan**. A
pre-flight check tests reachability and looks for a WordPress fingerprint;
targets that fail are skipped before WPScan runs. Scans run in the background
and findings appear as they are parsed. A failed target shows a retry button to
rescan just that site. Progress notifications report scan start, target progress,
key rotation, and batch completion.

### Dashboard workflow

* **Try a demo:** click **Load sample data**. This ingests the bundled JSON
  reports; it does not run WPScan or contact the listed sites.
* **Review findings:** use the search box and site/component filters to narrow
  the table. Click severity chips to toggle those findings, and use the sort
  menu to group results by severity, site, component type, or component name.
* **Watch a scan:** click **Scan output** to open the live console. It shows
  WPScan progress and masks API tokens. The console is temporary and is not
  included in saved data or exports.
* **Export or clear:** use **Export PDF** or **Export JSON** to download a report.
  **Clear** deletes stored scans and findings from the database; it does not
  change `sites.txt` or `api_keys.txt`.

Scans run a thorough enumeration by default —
`--enumerate vp,vt,u,cb,dbe --plugins-detection aggressive` — so vulnerable
plugins, vulnerable themes, users, config backups and DB exports are all
surfaced, not just the version WordPress advertises on its homepage. This is
slower and noisier than a passive scan; that is the trade-off for completeness.
Tune it with `WPSCAN_ENUMERATE` / `WPSCAN_PLUGINS_DETECTION`, or pass raw flags
(throttling, threads) via `WPSCAN_EXTRA_ARGS`.

Each successful WPScan is also followed by a set of **passive web-hygiene
checks** (see below). Without any API keys, WPScan still enumerates the site but
returns limited vulnerability data — the dashboard shows whatever it gets.

## Ingesting existing reports

Drop WPScan JSON reports (produced with `wpscan --url ... --format json -o
report.json`) into `sample_scans/` (or set `SAMPLE_DIR`) and click **Load sample
data**, or POST to `/api/ingest-samples`.

---

## What it checks

**WPScan (with API keys):** vulnerable WordPress core/version, vulnerable
plugins and their versions, vulnerable themes, enumerated users, config backups
and database exports.

**Passive web-hygiene checks** (run after each successful WPScan; toggle with
`EXTRA_CHECKS`): missing security headers (CSP, X-Frame-Options, HSTS, etc.),
permissive CORS, HTTP-vs-HTTPS and weak TLS protocol, directory listing,
REST-API user enumeration (`/wp-json/wp/v2/users`), a reachable admin login
page, and a small curated set of commonly-exposed sensitive files
(`/wp-content/debug.log`, `/_wpeprivate/config.json`, `wp-config` backups,
`.env`, `readme.html`, `xmlrpc.php`). These are unauthenticated GET requests and
header inspection only — bounded, rate-limited, and gentle on the target.

**Deliberately not included:** credential brute-forcing / password spraying
(Hydra, Burp Intruder, "common admin password"), and active exploitation of
findings (SSRF, HLI, etc.). Those are intrusive attacks that cause account
lockouts and outages; this tool is for *assessment*, and automating them into a
point-and-shoot dashboard is out of scope by design. If you run an authorised
engagement that calls for a throttled WordPress password audit, WPScan's own
`--passwords` option exists for that — run it directly, against sites you are
authorised to test, with agreed rules of engagement.

---

## Scan settings and controls

Scans run **one site at a time** in the order they appear in `sites.txt`. Open
**Settings** before a batch to change the pre-flight check, pre-flight timeout,
scan timeout, plugin-detection mode, and enumeration flags. These settings are
held in memory and reset when the server restarts. The **Max concurrent scans**
field is currently not applied; batches remain sequential.

**Batch controls (header while scanning):**
* **⏸ Pause** — holds after the current site finishes. The current scan is never
  interrupted mid-flight.
* **▶ Resume** — continues from the next queued site.
* **✕ Cancel** — skips all remaining queued sites.

**Per-site controls (on each chip):**
* **⏸** on a queued site — hold before that specific site starts. The batch
  continues with the sites before it, then waits. Click **▶** on the chip to
  release.
* **↻** on a failed site — retry just that one site without re-running the batch.

**Chip states:** scanning… (active, blue dot) → queued (grey, dimmed) →
⏸ paused (amber dot, hold set) → success (green) → scan failed (red, with ↻).

---

## Live scan console

Click **Scan output** in the header (it also opens automatically when a scan
starts) to show a side panel that streams WPScan's live progress — the command
being run (with the API token masked), each enumeration phase, plugins/themes as
they're found, and any warnings. It polls while open, auto-scrolls unless you
scroll up to read, and has `wrap` / `clear` controls.

The console relies on WPScan's `--verbose` flag (added automatically) to emit
live progress, and runs WPScan attached to a pseudo-terminal so its output
isn't buffered (Ruby buffers when writing to a pipe, which otherwise delays all
output until the scan ends). The raw JSON report is filtered out of the view so
you see human-readable progress (`[i] Enumerating…`, `[+] plugin`, `[!] vuln`)
rather than a wall of JSON. Disable with `WPSCAN_VERBOSE=false`.

This console is **display-only**: the verbose output is held in memory for the
current session, is never written to the database, and is deliberately excluded
from exported reports. It is also hidden when you print the page, so a printed
or PDF report never contains the raw scan log.

---

## Exporting an audit report

Two buttons in the header export whatever is currently stored:

* **Export PDF** — a paginated audit report: severity summary with definitions,
  a scope-and-coverage table (including targets that *failed* to scan, flagged
  explicitly so a coverage gap is never mistaken for a clean result), and the
  findings table ordered by severity with critical/high rows tinted. Suitable
  for handing to a client or attaching to a ticket.
* **Export JSON** — the same report as structured data (`report_type`,
  `generated_at`, `scope`, `summary`, `targets`, `findings`,
  `severity_definitions`, `notes`), for diffing between runs or feeding into
  another tool.

Files are named `wpscan-audit-YYYYMMDD-HHMM.{pdf,json}`. The equivalent
endpoints are `GET /api/export.pdf` and `GET /api/export.json`.

PDF export needs `reportlab` (included in `requirements.txt`). If it isn't
installed the dashboard still runs and JSON export still works — the PDF button
reports that reportlab is missing instead of failing silently.

---

## Configuration

All settings are environment variables (see `config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `WPSCAN_PATH` | `wpscan` | Path to the WPScan binary |
| `WPSCAN_ENUMERATE` | `vp,vt,u,cb,dbe` | What WPScan enumerates |
| `WPSCAN_PLUGINS_DETECTION` | `aggressive` | Plugin detection mode (`passive`/`mixed`/`aggressive`) |
| `WPSCAN_VERBOSE` | `true` | Stream live scan progress to the console |
| `WPSCAN_FORMAT` | `cli-no-colour` | WPScan output format; CLI output enables live findings |
| `WPSCAN_EXTRA_ARGS` | *(none)* | Extra raw wpscan args, e.g. `--throttle 500` |
| `PREFLIGHT_CHECK` | `true` | Check reachability and WordPress fingerprint before scanning |
| `PREFLIGHT_TIMEOUT` | `10` | Pre-flight timeout in seconds |
| `EXTRA_CHECKS` | `true` | Run passive web-hygiene checks after each scan |
| `CHECK_TIMEOUT` | `10` | Per-request timeout for hygiene checks (seconds) |
| `WPSCAN_API_TOKEN` | *(none)* | Optional single key, added to the front of the rotation |
| `API_KEYS_FILE` | `api_keys.txt` | File of API keys, rotated when one hits its daily limit |
| `SITES_FILE` | `sites.txt` | Target list |
| `DATABASE` | `dashboard.db` | SQLite file |
| `SCAN_TIMEOUT` | `1800` | Per-site scan timeout (seconds) |
| `MAX_CONCURRENT` | `3` | Settings value only; scans currently run sequentially |
| `SAMPLE_DIR` | `sample_scans` | Directory of JSON reports to ingest |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Bind address |

---

## How severity is decided

WPScan's free feed rarely includes a CVSS score, so `parser.py` uses a layered
approach: it trusts an explicit CVSS score when present (mapped
critical/high/medium/low by the standard bands), otherwise classifies by
keywords in the vulnerability title (e.g. *remote code execution* → critical,
*SQL injection* → high, *XSS* → medium), and falls back to **medium** for any
known vulnerability with no other signal. Exposures found outside the vuln model
— exposed `wp-config` backups, database dumps, debug logs, user enumeration —
are mapped to their own severities. Treat the derived severity as a
prioritization aid, not a substitute for reading the advisory.

## Architecture

Deliberately small — a single Flask process, SQLite, no ORM, no build step.

```
app.py        Flask routes: dashboard page + JSON API
scanner.py    WPScan subprocess runner, JSON ingest, background batch manager
parser.py     Normalizes WPScan JSON -> unified findings + severity engine
db.py         SQLite persistence (scans + findings)
config.py     Environment-variable configuration
templates/    dashboard.html
static/       css/style.css, js/dashboard.js  (client-side filter/sort)
sample_scans/ example WPScan JSON reports for a zero-setup demo
sites.txt     target list
```

Findings always reflect the **latest** successful scan per site; re-scanning a
site replaces its findings so nothing goes stale.

### API

| Method | Route | Description |
|---|---|---|
| GET | `/` | Dashboard page |
| GET | `/api/findings` | All findings + severity summary + per-site status |
| POST | `/api/scan` | Start a background batch from `sites.txt`; JSON `{ "site": "https://example.com" }` retries one site |
| POST | `/api/ingest-samples` | Load JSON reports from `SAMPLE_DIR` |
| GET/POST | `/api/settings` | Read or update runtime scan settings |
| POST | `/api/pause`, `/api/resume`, `/api/cancel` | Pause between sites, resume, or cancel the batch |
| POST | `/api/pause-site`, `/api/resume-site` | Hold or release a queued site; JSON body includes `site` |
| GET | `/api/scan-log` | Incremental live console output (`?since=<id>`) |
| GET | `/api/export.json` | Full audit report as JSON (download) |
| GET | `/api/export.pdf` | Full audit report as PDF (download) |
| POST | `/api/clear` | Wipe stored scans and findings |

## Troubleshooting

**A target shows "scan failed".** The reason is shown three ways: click the
"scan failed" text on the chip for a popup, read the red `!! FAILED:` line in the
Scan output console, or run `python show_errors.py` to print the stored error for
every failed target. WPScan's own error lines (connection refused, Scan Aborted,
WAF block, etc.) are extracted into the message.

**Scan fails after a long wait (timeout).** Aggressive plugin detection
(`--plugins-detection aggressive`, the default) probes thousands of plugin paths
and, on a large or distant site (e.g. a big WooCommerce store behind a CDN), can
exceed the scan timeout. Options, fastest first:
* `WPSCAN_PLUGINS_DETECTION=mixed` — much faster, still finds most plugins.
* `WPSCAN_PLUGINS_DETECTION=passive` — fastest, only plugins advertised on the page.
* Raise `SCAN_TIMEOUT` (default 1800s) to give aggressive detection more time.
* Add throttling if the site is rate-limiting/blocking you, e.g.
  `WPSCAN_EXTRA_ARGS="--throttle 500 --max-threads 5"`.

**Every scan fails instantly.** Usually WPScan isn't installed
(`gem install wpscan`) or isn't on `PATH`; the error text will say so. A WAF or
Cloudflare may also block the scan outright — check the stored error.

---

## Deployment note

`app.py` uses Flask's development server, which is fine for local single-user
use. To run it on a shared host, put it behind a production WSGI server, e.g.:

```bash
pip install gunicorn
gunicorn -w 1 -b 127.0.0.1:5000 app:app
```

Use a single worker (`-w 1`) so the in-process scan manager and SQLite stay
consistent, and keep the dashboard bound to localhost or behind a
VPN/reverse-proxy with access control — it has no built-in authentication by
design.
