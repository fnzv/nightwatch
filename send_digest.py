#!/usr/bin/env python3
"""
Weekly digest emailer — reads last 7 days of historical snapshots,
picks top CVEs by severity/EPSS, and sends via Buttondown API.

Usage:
    BUTTONDOWN_API_KEY=<key> python3 send_digest.py
    BUTTONDOWN_API_KEY=<key> python3 send_digest.py --dry-run   # print HTML, don't send
"""
import json
import os
import sys
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.error import HTTPError

HISTORICAL_DIR = "historical"
BUTTONDOWN_API  = "https://api.buttondown.email/v1/emails"
BASE_URL        = "https://vulnfeed.it"
TOP_N           = 20

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#16a34a",
    "UNKNOWN":  "#6b7280",
}


def load_week():
    """Merge last 7 days of snapshots, newest first, dedup by CVE id."""
    if not os.path.isdir(HISTORICAL_DIR):
        return [], None
    today = datetime.now()
    dates = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
    seen, vulns, latest_date = set(), [], None
    for d in dates:
        path = os.path.join(HISTORICAL_DIR, f"{d}.json")
        if not os.path.exists(path):
            continue
        if latest_date is None:
            latest_date = d
        with open(path, encoding="utf-8") as f:
            for v in json.load(f):
                if v["id"] not in seen:
                    seen.add(v["id"])
                    vulns.append(v)
    return vulns, latest_date


def top_cves(vulns):
    return sorted(
        [v for v in vulns if v["id"].startswith("CVE-")],
        key=lambda v: (
            SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4),
            -(v.get("epss") or 0),
            -(v.get("score") or 0),
        ),
    )[:TOP_N]


def xe(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def build_email_html(vulns, week_end):
    top     = top_cves(vulns)
    n_crit  = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    n_high  = sum(1 for v in vulns if v.get("severity") == "HIGH")
    n_expl  = sum(1 for v in vulns if v.get("kev"))

    rows = ""
    for v in top:
        sev    = v.get("severity", "UNKNOWN")
        color  = SEV_COLOR.get(sev, "#6b7280")
        score  = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
        epss   = f'{v["epss"] * 100:.1f}%' if v.get("epss") else "—"
        kev    = ' <span style="color:#7c3aed;font-weight:700;font-size:.7rem">KEV</span>' if v.get("kev") else ""
        cve_url = f"{BASE_URL}/cve/{v['id']}.html"
        title  = xe((v.get("title") or "")[:120])
        rows += (
            f'<tr>'
            f'<td style="padding:.5rem .75rem;border-bottom:1px solid #e2e8f0;white-space:nowrap">'
            f'<a href="{cve_url}" style="color:#2563eb;font-family:monospace;font-weight:700;'
            f'font-size:.8rem;text-decoration:none">{xe(v["id"])}</a>'
            f'</td>'
            f'<td style="padding:.5rem .75rem;border-bottom:1px solid #e2e8f0">'
            f'<span style="background:{color};color:#fff;padding:.08rem .4rem;border-radius:3px;'
            f'font-size:.65rem;font-weight:700;text-transform:uppercase">{xe(sev)}</span>'
            f'</td>'
            f'<td style="padding:.5rem .75rem;border-bottom:1px solid #e2e8f0;font-size:.78rem;color:#1e293b">'
            f'{title}{kev}'
            f'</td>'
            f'<td style="padding:.5rem .75rem;border-bottom:1px solid #e2e8f0;font-size:.78rem;'
            f'color:#475569;white-space:nowrap;text-align:right">{xe(score)}</td>'
            f'<td style="padding:.5rem .75rem;border-bottom:1px solid #e2e8f0;font-size:.78rem;'
            f'color:#7c3aed;white-space:nowrap;text-align:right">{xe(epss)}</td>'
            f'</tr>'
        )

    digest_url = f"{BASE_URL}/digest/{week_end}.html"

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;margin:0;padding:0">
<div style="max-width:700px;margin:0 auto;padding:2rem 1rem">

  <!-- header -->
  <div style="background:#0f172a;padding:1.2rem 1.8rem;border-radius:10px 10px 0 0">
    <span style="font-size:1.3rem;font-weight:800;color:#f1f5f9">vuln<span style="color:#60a5fa">feed</span></span>
    <span style="font-size:.75rem;color:#94a3b8;margin-left:1rem">Weekly Security Digest &mdash; {xe(week_end)}</span>
  </div>

  <!-- body -->
  <div style="background:#fff;border:1px solid #e2e8f0;border-top:none;padding:1.5rem 1.8rem">

    <!-- summary stats -->
    <div style="display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem">
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:.75rem 1.2rem;min-width:120px">
        <div style="font-size:1.6rem;font-weight:800;color:#0f172a">{len(vulns)}</div>
        <div style="font-size:.72rem;color:#64748b">Total CVEs</div>
      </div>
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:.75rem 1.2rem;min-width:120px">
        <div style="font-size:1.6rem;font-weight:800;color:#dc2626">{n_crit}</div>
        <div style="font-size:.72rem;color:#64748b">Critical</div>
      </div>
      <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:.75rem 1.2rem;min-width:120px">
        <div style="font-size:1.6rem;font-weight:800;color:#ea580c">{n_high}</div>
        <div style="font-size:.72rem;color:#64748b">High</div>
      </div>
      <div style="background:#f5f3ff;border:1px solid #ddd6fe;border-radius:8px;padding:.75rem 1.2rem;min-width:120px">
        <div style="font-size:1.6rem;font-weight:800;color:#7c3aed">{n_expl}</div>
        <div style="font-size:.72rem;color:#64748b">Actively Exploited</div>
      </div>
    </div>

    <!-- top CVEs table -->
    <div style="font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;
                letter-spacing:.08em;margin-bottom:.75rem">Top {TOP_N} vulnerabilities</div>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden">
      <thead>
        <tr style="background:#f8fafc">
          <th style="text-align:left;padding:.5rem .75rem;border-bottom:2px solid #e2e8f0;
                     font-size:.68rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">CVE</th>
          <th style="text-align:left;padding:.5rem .75rem;border-bottom:2px solid #e2e8f0;
                     font-size:.68rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">Sev</th>
          <th style="text-align:left;padding:.5rem .75rem;border-bottom:2px solid #e2e8f0;
                     font-size:.68rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">Description</th>
          <th style="text-align:right;padding:.5rem .75rem;border-bottom:2px solid #e2e8f0;
                     font-size:.68rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">CVSS</th>
          <th style="text-align:right;padding:.5rem .75rem;border-bottom:2px solid #e2e8f0;
                     font-size:.68rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">EPSS</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>

    <!-- footer links -->
    <p style="margin:1.5rem 0 0;font-size:.82rem;color:#64748b;text-align:center">
      <a href="{digest_url}" style="color:#2563eb;font-weight:600;text-decoration:none">View full digest &rarr;</a>
      &nbsp;&middot;&nbsp;
      <a href="{BASE_URL}/" style="color:#2563eb;font-weight:600;text-decoration:none">Live feed</a>
      &nbsp;&middot;&nbsp;
      <a href="{BASE_URL}/feed.xml" style="color:#2563eb;font-weight:600;text-decoration:none">RSS</a>
    </p>
  </div>

  <!-- unsubscribe footer -->
  <div style="background:#f1f5f9;border:1px solid #e2e8f0;border-top:none;padding:.75rem 1.8rem;
              border-radius:0 0 10px 10px;text-align:center">
    <span style="font-size:.7rem;color:#94a3b8">
      You subscribed to the vulnfeed weekly digest.
      <a href="{{ unsubscribe_url }}" style="color:#94a3b8">Unsubscribe</a>
    </span>
  </div>

</div>
</body>
</html>"""


def send(api_key, subject, html_body):
    payload = json.dumps({
        "subject": subject,
        "body": html_body,
        "status": "about_to_send",
    }).encode()
    req = Request(
        BUTTONDOWN_API,
        data=payload,
        headers={
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
            print(f"[ok] Email queued — id={resp.get('id')} status={resp.get('status')}")
            return True
    except HTTPError as e:
        body = e.read().decode()
        print(f"[error] HTTP {e.code}: {body}", file=sys.stderr)
        return False


def main():
    dry_run = "--dry-run" in sys.argv

    api_key = os.environ.get("BUTTONDOWN_API_KEY")
    if not api_key and not dry_run:
        print("[error] BUTTONDOWN_API_KEY env var not set", file=sys.stderr)
        sys.exit(1)

    vulns, week_end = load_week()
    if not vulns:
        print("[error] No historical data found — run build.py at least once", file=sys.stderr)
        sys.exit(1)

    n_crit = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    subject = f"vulnfeed weekly: {len(vulns)} CVEs · {n_crit} critical — {week_end}"
    html_body = build_email_html(vulns, week_end)

    print(f"[digest] {len(vulns)} vulns from last 7 days, week ending {week_end}")
    print(f"[digest] Subject: {subject}")

    if dry_run:
        with open("/tmp/digest_preview.html", "w", encoding="utf-8") as f:
            f.write(html_body)
        print("[dry-run] HTML written to /tmp/digest_preview.html")
        return

    ok = send(api_key, subject, html_body)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
