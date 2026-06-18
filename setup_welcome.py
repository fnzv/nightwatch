#!/usr/bin/env python3
"""
Sets the Buttondown introduction (welcome) email for new subscribers.

Usage:
    BUTTONDOWN_API_KEY=<key> python3 setup_welcome.py             # send to Buttondown
    BUTTONDOWN_API_KEY=<key> python3 setup_welcome.py --dry-run  # write HTML to /tmp/
"""
import json
import os
import sys
from urllib.request import urlopen, Request
from urllib.error import HTTPError

BASE_URL       = "https://vulnfeed.it"
BUTTONDOWN_API = "https://api.buttondown.email/v1"


def xe(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_welcome_html():
    return f"""\
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;margin:0;padding:0">
<div style="max-width:640px;margin:0 auto;padding:2rem 1rem">

  <!-- header -->
  <div style="background:#0f172a;padding:1.4rem 2rem;border-radius:10px 10px 0 0">
    <span style="font-size:1.5rem;font-weight:800;color:#f1f5f9">vuln<span style="color:#60a5fa">feed</span></span>
  </div>

  <!-- body -->
  <div style="background:#fff;border:1px solid #e2e8f0;border-top:none;padding:2rem">

    <h1 style="font-size:1.2rem;font-weight:800;color:#0f172a;margin:0 0 .75rem">
      Welcome — you're subscribed to the weekly security digest.
    </h1>

    <p style="font-size:.88rem;color:#334155;line-height:1.65;margin:0 0 1.25rem">
      Every Monday morning you'll receive the most important CVEs of the week:
      critical and high-severity vulnerabilities, actively exploited bugs (CISA KEV),
      and an infrastructure-focused edition covering Kubernetes, OpenStack,
      Linux Kernel, nginx and Traefik.
    </p>

    <!-- what's inside box -->
    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:1.1rem 1.4rem;margin-bottom:1.5rem">
      <div style="font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.75rem">
        What's in each digest
      </div>
      <table style="width:100%;border-collapse:collapse">
        <tr>
          <td style="padding:.3rem 0;vertical-align:top;width:28px">
            <span style="background:#dc2626;color:#fff;font-size:.63rem;font-weight:700;padding:.06rem .35rem;border-radius:3px">CRIT</span>
          </td>
          <td style="padding:.3rem 0 .3rem .5rem;font-size:.82rem;color:#334155">Critical &amp; high-severity CVEs ranked by CVSS and EPSS exploit probability</td>
        </tr>
        <tr>
          <td style="padding:.3rem 0;vertical-align:top">
            <span style="background:#7c3aed;color:#fff;font-size:.63rem;font-weight:700;padding:.06rem .35rem;border-radius:3px">KEV</span>
          </td>
          <td style="padding:.3rem 0 .3rem .5rem;font-size:.82rem;color:#334155">CISA Known Exploited Vulnerabilities — bugs actively used in attacks right now</td>
        </tr>
        <tr>
          <td style="padding:.3rem 0;vertical-align:top">
            <span style="background:#0f172a;color:#60a5fa;font-size:.63rem;font-weight:700;padding:.06rem .35rem;border-radius:3px">INFRA</span>
          </td>
          <td style="padding:.3rem 0 .3rem .5rem;font-size:.82rem;color:#334155">Separate infrastructure edition for Kubernetes, OpenStack, Kernel, nginx &amp; Traefik</td>
        </tr>
      </table>
    </div>

    <!-- sources -->
    <p style="font-size:.82rem;color:#64748b;line-height:1.6;margin:0 0 1.5rem">
      Data is aggregated from <strong style="color:#334155">NVD, CISA KEV, GitHub Security Advisories,
      Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, OSS-Security, Microsoft MSRC,
      Fortinet, Juniper, Cisco</strong> and more — updated every 4 hours.
    </p>

    <!-- CTA buttons -->
    <div style="display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1.5rem">
      <a href="{BASE_URL}/"
         style="display:inline-block;background:#2563eb;color:#fff;padding:.55rem 1.1rem;
                border-radius:7px;font-size:.84rem;font-weight:600;text-decoration:none">
        Live feed &rarr;
      </a>
      <a href="{BASE_URL}/digest/"
         style="display:inline-block;background:#f1f5f9;color:#1e293b;padding:.55rem 1.1rem;
                border-radius:7px;font-size:.84rem;font-weight:600;text-decoration:none;
                border:1px solid #e2e8f0">
        Past digests
      </a>
      <a href="{BASE_URL}/feed.xml"
         style="display:inline-block;background:#f1f5f9;color:#1e293b;padding:.55rem 1.1rem;
                border-radius:7px;font-size:.84rem;font-weight:600;text-decoration:none;
                border:1px solid #e2e8f0">
        RSS feed
      </a>
    </div>

    <p style="font-size:.78rem;color:#94a3b8;margin:0">
      You can also browse by product:
      <a href="{BASE_URL}/vendor/kubernetes.html" style="color:#2563eb;text-decoration:none">Kubernetes</a>,
      <a href="{BASE_URL}/vendor/linux-kernel.html" style="color:#2563eb;text-decoration:none">Linux Kernel</a>,
      <a href="{BASE_URL}/vendor/nginx.html" style="color:#2563eb;text-decoration:none">nginx</a>,
      <a href="{BASE_URL}/vendor/openstack.html" style="color:#2563eb;text-decoration:none">OpenStack</a>
      and <a href="{BASE_URL}/" style="color:#2563eb;text-decoration:none">30+ more</a>.
    </p>
  </div>

  <!-- footer -->
  <div style="background:#f1f5f9;border:1px solid #e2e8f0;border-top:none;padding:.75rem 2rem;
              border-radius:0 0 10px 10px;text-align:center">
    <span style="font-size:.7rem;color:#94a3b8">
      You subscribed at <a href="{BASE_URL}" style="color:#94a3b8">vulnfeed.it</a>.
      <a href="{{{{ unsubscribe_url }}}}" style="color:#94a3b8">Unsubscribe</a>
    </span>
  </div>

</div>
</body>
</html>"""


def api_get(path, api_key):
    req = Request(
        f"{BUTTONDOWN_API}{path}",
        headers={"Authorization": f"Token {api_key}"},
    )
    with urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def api_patch(path, api_key, payload):
    data = json.dumps(payload).encode()
    req = Request(
        f"{BUTTONDOWN_API}{path}",
        data=data,
        headers={
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json",
        },
        method="PATCH",
    )
    with urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def main():
    dry_run = "--dry-run" in sys.argv
    api_key = os.environ.get("BUTTONDOWN_API_KEY")

    html = build_welcome_html()

    if dry_run:
        out = "/tmp/welcome_email_preview.html"
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[dry-run] Welcome email HTML written to {out}")
        print("[dry-run] Open it in a browser to preview, then run without --dry-run to apply.")
        return

    if not api_key:
        print("[error] BUTTONDOWN_API_KEY env var not set", file=sys.stderr)
        sys.exit(1)

    # Discover newsletter ID
    try:
        newsletters = api_get("/newsletters", api_key)
    except HTTPError as e:
        print(f"[error] Could not fetch newsletters: HTTP {e.code}", file=sys.stderr)
        sys.exit(1)

    items = newsletters.get("results") or newsletters if isinstance(newsletters, list) else []
    if not items:
        print("[error] No newsletters found for this API key", file=sys.stderr)
        sys.exit(1)

    newsletter = items[0]
    nl_id   = newsletter.get("id") or newsletter.get("username")
    nl_name = newsletter.get("name") or nl_id
    print(f"[ok] Found newsletter: {nl_name} (id={nl_id})")

    # Patch introduction email
    try:
        result = api_patch(f"/newsletters/{nl_id}", api_key, {"introduction_email": html})
        print(f"[ok] Welcome email set on newsletter '{result.get('name', nl_name)}'")
        print(f"[ok] New subscribers will now receive it automatically.")
    except HTTPError as e:
        body = e.read().decode()
        print(f"[error] PATCH failed HTTP {e.code}: {body}", file=sys.stderr)
        print("\nManual fallback: copy the HTML from /tmp/welcome_email_preview.html")
        print("and paste it in Buttondown dashboard → Settings → Introduction email")
        with open("/tmp/welcome_email_preview.html", "w", encoding="utf-8") as f:
            f.write(html)
        sys.exit(1)


if __name__ == "__main__":
    main()
