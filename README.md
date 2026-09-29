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

1. Install WPScan (Ruby):
   ```bash
   gem install wpscan          # or use the official Docker image
   ```
2. (Recommended) Add one or more free API keys from <https://wpscan.com/profile>
   for full vulnerability data. Copy the template and add your keys, one per line:
   ```bash
   cp api_keys.txt.example api_keys.txt
   # then edit api_keys.txt:
   #   0123456789abcdef0123456789abcdef0123456789abcdef01
   #   fedcba9876543210fedcba9876543210fedcba9876543210fe
   ```
   The free plan allows **25 requests per key per day**, so list as many keys as
   you have. The dashboard uses them **round-robin** — each site in a batch takes
   the next key in the list, so the daily quota is spread across every key rather
   than draining the first one. If a key comes back rate-limited or rejected, it
   is retired for the session and the scan is **retried immediately on the next
   key**; a site only errors once every key is spent. Keys are re-read at the
   start of each scan batch, so you can add keys without restarting, and
   `api_keys.txt` is `.gitignore`d so your keys are never committed. (A single
   `WPSCAN_API_TOKEN` env var still works and joins the rotation.)

   To confirm your keys are being read, run:
   ```bash
   python scanner.py
   ```
   It prints the resolved key-file path, how many keys were parsed (masked), and
   the round-robin order — useful if you suspect only one key is in play.
3. List your targets in `sites.txt` (one URL per line; `#` comments allowed).
4. Start the app and click **Run scan**. Scans run in the background; the target
   chips turn green (success) or red (failed), and the table fills in as results
   arrive. Progress appears as toast notifications in the bottom-right corner:
   when a scan starts, as it moves to each target, whenever an API key is
   rotated, and a summary when the whole batch finishes. The header badge shows
   live progress (`Scanning… 2/3`).

Without any keys, WPScan still enumerates the site but returns limited
vulnerability data — the dashboard shows whatever it gets.

## Ingesting existing reports

Drop WPScan JSON reports (produced with `wpscan --url ... --format json -o
report.json`) into `sample_scans/` (or set `SAMPLE_DIR`) and click **Load sample
data**, or POST to `/api/ingest-samples`.

---

## Configuration

All settings are environment variables (see `config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `WPSCAN_PATH` | `wpscan` | Path to the WPScan binary |
| `WPSCAN_API_TOKEN` | *(none)* | Optional single key, added to the front of the rotation |
| `API_KEYS_FILE` | `api_keys.txt` | File of API keys, rotated when one hits its daily limit |
| `SITES_FILE` | `sites.txt` | Target list |
| `DATABASE` | `dashboard.db` | SQLite file |
| `SCAN_TIMEOUT` | `600` | Per-site scan timeout (seconds) |
| `MAX_CONCURRENT` | `3` | Parallel scans per batch |
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
| POST | `/api/scan` | Start a WPScan batch over `sites.txt` (background) |
| POST | `/api/ingest-samples` | Load JSON reports from `SAMPLE_DIR` |
| POST | `/api/clear` | Wipe stored scans and findings |

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
