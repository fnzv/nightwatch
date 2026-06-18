#!/usr/bin/env python3
"""
Dev server — fast local build using cached historical data, no network fetches.

Usage:  python3 dev.py
        python3 dev.py 9000   # custom port
"""
import http.server
import json
import os
import sys
from datetime import datetime

from build import (
    BASE_URL, _HTML, _xe,
    HISTORICAL_DIR,
    build_historical_index,
    load_historical,
    merge,
    write_cve_pages,
    write_cwe_pages,
    write_digest_pages,
    write_sitemap,
    write_robots,
    write_stats_page,
    write_vendor_pages,
)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
date_str = datetime.now().strftime("%Y-%m-%d")

print(f"[dev] Loading historical snapshots from historical/...")
historical = load_historical(days=30)
if not historical:
    print("[dev] No historical data found — run 'python3 build.py' once to populate it.")
    sys.exit(1)

vulns = merge(historical)
print(f"[dev] {len(vulns)} vulns after dedup")

hist_dates = build_historical_index()

# Skip news fetch — empty list for dev
news = []

# Generate all static pages (fast, no network)
print("[dev] Writing CVE pages...")
cve_pages = write_cve_pages(vulns, date_str)
write_stats_page(vulns, date_str)
vendor_pages = write_vendor_pages(vulns, date_str)
cwe_pages = write_cwe_pages(vulns, date_str)
digest_dates = write_digest_pages(vulns, date_str, hist_dates)
write_sitemap(cve_pages, date_str, vendor_pages=vendor_pages,
              cwe_pages=cwe_pages, digest_dates=digest_dates)
write_robots()

# Static SEO section
critical_ids = {v["id"] for v in cve_pages}
top_static = sorted(
    [v for v in vulns if v["id"].startswith("CVE-")],
    key=lambda v: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}.get(
            v.get("severity", "UNKNOWN"), 4
        ),
        -(v.get("score") or 0),
    ),
)[:50]

def _seo_li(v):
    href = (f'/cve/{v["id"]}.html' if v["id"] in critical_ids
            else f'https://nvd.nist.gov/vuln/detail/{v["id"]}')
    sev  = v.get("severity", "")
    sc   = f' {v["score"]:.1f}' if v.get("score") is not None else ""
    ttl  = _xe((v.get("title") or "")[:100])
    return f'<li><a href="{href}">{_xe(v["id"])}</a>: {ttl}<small>[{_xe(sev)}{sc}]</small></li>'

static_html = (
    '<section id="seo-index">'
    '<h2>Recent Critical &amp; High-Severity CVEs</h2>'
    "<ul>" + "".join(_seo_li(v) for v in top_static) + "</ul>"
    "</section>"
)

vendor_index_html = (
    '<section id="vendor-browse">'
    '<h2>Browse by product</h2>'
    '<div class="vb-grid">'
    + "".join(
        f'<a class="vb-link" href="/vendor/{p["slug"]}.html">'
        f'{p["display_name"]} <span>{p["count"]}</span></a>'
        for p in vendor_pages
    )
    + '</div></section>'
)

cwe_index_html = (
    '<section id="cwe-browse">'
    '<h2>Browse by weakness</h2>'
    '<div class="vb-grid">'
    + "".join(
        f'<a class="cwe-link" href="/cwe/{p["id"]}.html">'
        f'{p["display_name"]} <span>{p["count"]}</span></a>'
        for p in cwe_pages
    )
    + '</div></section>'
)

json_blob    = json.dumps(vulns,      ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
news_blob    = json.dumps(news,       ensure_ascii=False, separators=(",", ":"))
dates_blob   = json.dumps(hist_dates)
source_counts = {}
for v in vulns:
    src = v.get("source", "unknown")
    source_counts[src] = source_counts.get(src, 0) + 1
health_blob  = json.dumps(source_counts)

html = _HTML
html = html.replace("__DATE__",              date_str)
html = html.replace("__COUNT__",             str(len(vulns)))
html = html.replace("__JSON__",              json_blob)
html = html.replace("__DATES_JSON__",        dates_blob)
html = html.replace("__NEWS_JSON__",         news_blob)
html = html.replace("__HEALTH__",            health_blob)
html = html.replace("__VENDOR_INDEX_HTML__", vendor_index_html)
html = html.replace("__CWE_INDEX_HTML__",    cwe_index_html)
html = html.replace("__STATIC_CVE_HTML__",   static_html)

with open("index.html", "w", encoding="utf-8") as f:
    f.write(html)

size_kb = len(html.encode()) // 1024
print(f"[dev] Written: index.html ({size_kb} KB)")
print(f"[dev] Serving at http://localhost:{PORT}  —  Ctrl+C to stop\n")

os.chdir(os.path.dirname(os.path.abspath(__file__)))
httpd = http.server.HTTPServer(
    ("", PORT),
    http.server.SimpleHTTPRequestHandler,
)
httpd.serve_forever()
