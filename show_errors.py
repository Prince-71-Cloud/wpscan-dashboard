#!/usr/bin/env python3
"""Print the stored error for every failed target.

Usage: python show_errors.py
Reads the same database the dashboard uses (DATABASE env var or the default)
so you can see exactly why a scan failed without digging through the UI.
"""
from config import CONFIG
from db import Database

db = Database(CONFIG["DATABASE"])
rows = db.latest_scan_status()
any_err = False
for site, st in sorted(rows.items()):
    if st.get("status") == "error":
        any_err = True
        print(f"\n{site}")
        print(f"  status : {st['status']}")
        print(f"  error  : {st.get('error')}")
if not any_err:
    print("No failed targets in the database.")
