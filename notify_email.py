#!/usr/bin/env python3
"""Send real-time email alerts for critical/KEV CVEs via Buttondown.

Runs every 4 hours alongside notify_ntfy.py.  Only sends when there are
new critical or actively-exploited CVEs in the last WINDOW_HOURS.
Subject line encodes the 4-hour slot so Buttondown's duplicate-detection
prevents double-sends if the workflow re-runs.

Usage:
  BUTTONDOWN_API_KEY=<key> python3 notify_email.py
  python3 notify_email.py --dry-run   # writes HTML to /tmp/, no send
"""
import datetime
import json
import os
import sys
import urllib.request
from urllib.error import HTTPError

VULNS_URL      = "https://vulnfeed.it/vulns.json"
BUTTONDOWN_API = "https://api.buttondown.email/v1/emails"
BASE_URL       = "https://vulnfeed.it"
WINDOW_HOURS   = 5   # slightly > 4h build interval to tolerate drift

SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#16a34a",
    "UNKNOWN":  "#6b7280",
}


def load_vulns():
    print(f"[email] Fetching {VULNS_URL}", flush=True)
    with urllib.request.urlopen(VULNS_URL, timeout=30) as r:
        return json.loads(r.read())


def is_new(v, now):
    pub = (v.get("published") or "").strip().rstrip("Z") + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(pub)
        return 0 < (now - dt).total_seconds() < WINDOW_HOURS * 3600
    except Exception:
        return False


def xe(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def cve_card(v):
    sev    = v.get("severity", "UNKNOWN")
    color  = SEV_COLOR.get(sev, "#6b7280")
    score  = f'CVSS {v["score"]:.1f}' if v.get("score") is not None else ""
    is_kev = v.get("badge") == "ACTIVELY EXPLOITED" or v.get("kev")
    has_poc = v.get("poc")
    url    = f"{BASE_URL}/cve/{v['id']}.html"
    title  = xe((v.get("title") or v["id"])[:110])
    desc   = xe((v.get("description") or "")[:200])

    badges = (
        f'<span style="background:{color};color:#fff;font-size:.6rem;font-weight:700;'
        f'padding:.05rem .3rem;border-radius:3px;text-transform:uppercase">{xe(sev)}</span>'
    )
    if is_kev:
        badges += (
            ' <span style="background:#7c3aed;color:#fff;font-size:.6rem;font-weight:700;'
            'padding:.05rem .3rem;border-radius:3px">KEV</span>'
        )
    if has_poc:
        badges += (
            ' <span style="background:#ea580c;color:#fff;font-size:.6rem;font-weight:700;'
            'padding:.05rem .3rem;border-radius:3px">PoC</span>'
        )

    return (
        f'<div style="border-left:3px solid {color};padding:.7rem 1rem;margin-bottom:.75rem;'
        f'background:#f8fafc;border-radius:0 6px 6px 0">'
        f'<div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.25rem">'
        f'<a href="{url}" style="font-family:monospace;font-weight:700;font-size:.85rem;'
        f'color:#2563eb;text-decoration:none">{xe(v["id"])}</a>'
        f'{badges}'
        f'</div>'
        f'<div style="font-size:.8rem;color:#1e293b;line-height:1.4;margin-bottom:.2rem">{title}</div>'
        + (f'<div style="font-size:.73rem;color:#64748b;line-height:1.4">{desc}</div>' if desc else '')
        + (f'<div style="font-size:.72rem;color:#475569;margin-top:.2rem">{score}</div>' if score else '')
        + f'</div>'
    )


def build_alert_html(vulns, now):
    date_str = now.strftime("%Y-%m-%d %H:%M UTC")
    n_kev  = sum(1 for v in vulns if v.get("badge") == "ACTIVELY EXPLOITED" or v.get("kev"))
    n_crit = sum(1 for v in vulns if (v.get("score") or 0) >= 9.0)
    cards  = "".join(cve_card(v) for v in vulns[:15])

    summary_parts = []
    if n_kev:
        summary_parts.append(
            f'<strong style="color:#7c3aed">{n_kev} actively exploited (CISA KEV)</strong>'
        )
    if n_crit:
        summary_parts.append(
            f'<strong style="color:#dc2626">{n_crit} CVSS&nbsp;&ge;&nbsp;9.0</strong>'
        )
    summary = " &middot; ".join(summary_parts) or f"<strong>{len(vulns)} critical</strong>"

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;margin:0;padding:0">
<div style="max-width:640px;margin:0 auto;padding:2rem 1rem">

  <div style="background:#0f172a;padding:1.2rem 1.8rem;border-radius:10px 10px 0 0;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem">
    <span style="font-size:1.3rem;font-weight:800;color:#f1f5f9">vuln<span style="color:#60a5fa">feed</span></span>
    <span style="font-size:.75rem;color:#94a3b8">Critical alert &mdash; {xe(date_str)}</span>
  </div>

  <div style="background:#fff;border:1px solid #e2e8f0;border-top:none;padding:1.5rem 1.8rem">

    <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:.85rem 1.1rem;
                margin-bottom:1.4rem;font-size:.85rem;color:#991b1b;line-height:1.6">
      <strong>{len(vulns)} new critical CVE{"s" if len(vulns) != 1 else ""}</strong>
      in the last {WINDOW_HOURS}&nbsp;hours &mdash; {summary}
    </div>

    <div style="font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;
                letter-spacing:.08em;margin-bottom:.6rem">New vulnerabilities</div>

    {cards}

    <p style="margin:1.4rem 0 0;font-size:.82rem;color:#64748b;text-align:center;
              border-top:1px solid #e2e8f0;padding-top:1rem">
      <a href="{BASE_URL}/" style="color:#2563eb;font-weight:600;text-decoration:none">Live feed &rarr;</a>
      &nbsp;&middot;&nbsp;
      <a href="{BASE_URL}/subscribe.html" style="color:#2563eb;font-weight:600;text-decoration:none">Notification settings</a>
    </p>
  </div>

  <div style="background:#f1f5f9;border:1px solid #e2e8f0;border-top:none;padding:.75rem 1.8rem;
              border-radius:0 0 10px 10px;text-align:center">
    <span style="font-size:.7rem;color:#94a3b8">
      vulnfeed critical alerts &mdash; <a href="{BASE_URL}" style="color:#94a3b8">vulnfeed.it</a>.
      <a href="{{{{ unsubscribe_url }}}}" style="color:#94a3b8">Unsubscribe</a>
    </span>
  </div>

</div>
</body>
</html>"""


def send_alert(api_key, subject, html_body):
    data = {
        "subject": subject,
        "body": html_body,
        "status": "about_to_send",
    }
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        BUTTONDOWN_API,
        data=payload,
        headers={
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json",
            "X-Buttondown-Live-Dangerously": "true",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
            print(f"[email] Alert sent — id={resp.get('id')} status={resp.get('status')}")
            return True
    except HTTPError as e:
        body = e.read().decode()
        try:
            err = json.loads(body)
        except Exception:
            err = {}
        if err.get("code") == "email_duplicate":
            print("[email] Duplicate detected by Buttondown — already sent this window, skipping.")
            return True
        print(f"[error] HTTP {e.code}: {body}", file=sys.stderr)
        return False


def run(dry_run=False):
    api_key = os.environ.get("BUTTONDOWN_API_KEY")
    if not api_key and not dry_run:
        print("[email] BUTTONDOWN_API_KEY not set — skipping email alerts")
        return

    now   = datetime.datetime.now(datetime.timezone.utc)
    vulns = load_vulns()

    new_all = [v for v in vulns if is_new(v, now)]
    print(f"[email] {len(new_all)} CVEs in last {WINDOW_HOURS}h  (feed total: {len(vulns)})")

    critical = sorted(
        [
            v for v in new_all
            if v.get("badge") == "ACTIVELY EXPLOITED"
            or v.get("kev")
            or (v.get("score") or 0) >= 9.0
        ],
        key=lambda v: (
            0 if (v.get("badge") == "ACTIVELY EXPLOITED" or v.get("kev")) else 1,
            -(v.get("score") or 0),
        ),
    )

    if not critical:
        print("[email] No critical/KEV CVEs in window — skipping")
        return

    print(f"[email] {len(critical)} critical/KEV CVEs → sending alert")

    # 4-hour slot in subject → Buttondown dedup prevents double-sends per window
    slot = (now.hour // 4) * 4
    subject = (
        f"[vulnfeed] {len(critical)} critical CVE{'s' if len(critical) != 1 else ''}"
        f" — {now.strftime('%Y-%m-%d')} {slot:02d}:00 UTC"
    )
    html = build_alert_html(critical, now)

    if dry_run:
        out = "/tmp/alert_email_preview.html"
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[dry-run] Subject: {subject}")
        print(f"[dry-run] HTML written to {out}")
        return

    ok = send_alert(api_key, subject, html)
    print("[email] Done", flush=True)
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    run(dry_run="--dry-run" in sys.argv)
