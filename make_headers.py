#!/usr/bin/env python3
"""Write site/_headers with security headers for Netlify.

The Content-Security-Policy only lets the page run its own inline script,
identified by a SHA-256 hash of that script. Run this after every change to
site/index.html, before deploying:

    python3 make_headers.py
"""
import base64
import hashlib
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent
html = (ROOT / "site" / "index.html").read_text(encoding="utf-8")

scripts = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
if len(scripts) != 1 or re.search(r"<script\s+src=", html):
    raise SystemExit("Expected exactly one inline <script> and no external scripts.")
digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode()

m = re.search(r'supabaseUrl:"(https://[a-z0-9]+\.supabase\.co)"', html)
supabase = m.group(1) if m else ""

csp = "; ".join([
    "default-src 'none'",
    f"script-src 'sha256-{digest}'",
    "style-src 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src data:",
    f"connect-src {supabase}".strip(),
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
])

headers = f"""/*
  Content-Security-Policy: {csp}
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
"""
(ROOT / "site" / "_headers").write_text(headers, encoding="utf-8")
print(f"Wrote site/_headers (script hash sha256-{digest[:12]}…)")
