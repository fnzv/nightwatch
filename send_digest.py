#!/usr/bin/env python3
"""
Weekly digest emailer — reads last 7 days of historical snapshots,
picks top CVEs by severity/EPSS, and sends via Buttondown API.

Usage:
    BUTTONDOWN_API_KEY=<key> python3 send_digest.py              # general top-20 digest
    BUTTONDOWN_API_KEY=<key> python3 send_digest.py --vendors    # infra vendor digest
    BUTTONDOWN_API_KEY=<key> python3 send_digest.py --dry-run    # print HTML, don't send
    BUTTONDOWN_API_KEY=<key> python3 send_digest.py --vendors --dry-run
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
TOP_N           = 5   # critical/KEV highlights in the weekly email

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#16a34a",
    "UNKNOWN":  "#6b7280",
}

# Vendor groups for the infrastructure digest.
# Each entry: (display_name, slug, [keywords])  — any keyword match → included.
VENDOR_GROUPS = [
    ("Kubernetes",      "kubernetes",    ["kubernetes", "k8s", "etcd", "kubectl", "kubelet", "kube"]),
    ("OpenStack",       "openstack",     ["openstack", "nova", "neutron", "keystone", "cinder", "glance"]),
    ("Linux Kernel",    "linux-kernel",  ["linux kernel", "kernel", "kvm", "bpf", "ebpf", "netfilter", "nftables"]),
    ("nginx / Traefik", "nginx-traefik", ["nginx", "traefik"]),
]

# Sources that are authoritative for a given vendor (used to restrict noisy keyword matches)
VENDOR_AUTHORITATIVE_SOURCES = {
    "kubernetes":    {"kubernetes"},              # only official k8s advisory feed
    "linux-kernel":  {"ubuntu", "debian"},        # only distro security advisories, not random NVD noise
    "openstack":     {"openstack", "oss-security"},# official OSSAs only, not Ubuntu USNs about Ironic
}

# Vendors where the keyword must appear in the title (not just description/affected)
# — prevents broad keyword matches on unrelated CVEs
VENDOR_TITLE_ONLY = {"nginx-traefik"}

# Filtered digest topics — each corresponds to a Buttondown subscriber tag.
# "sources": only vulns from these sources are considered (empty = all sources)
# "keywords": must appear in title/description/affected (empty = all from source)
# "title_only": keyword must appear in title only (avoids noisy matches)
TOPIC_GROUPS = {
    "kubernetes": {
        "label": "Kubernetes",
        "sources": {"kubernetes"},
        "keywords": ["kubernetes", "k8s", "etcd", "kubectl", "kubelet", "kube"],
    },
    "linux-kernel": {
        "label": "Linux Kernel",
        "sources": {"ubuntu", "debian"},
        "keywords": ["linux kernel", "kernel", "kvm", "bpf", "ebpf", "netfilter", "nftables"],
    },
    "ubuntu": {
        "label": "Ubuntu",
        "sources": {"ubuntu"},
        "keywords": [],
    },
    "debian": {
        "label": "Debian",
        "sources": {"debian"},
        "keywords": [],
    },
    "windows": {
        "label": "Windows",
        "sources": {"microsoft"},
        "keywords": ["windows"],
        "title_only": True,
    },
    "openstack": {
        "label": "OpenStack",
        "sources": {"openstack", "oss-security"},
        "keywords": ["openstack", "nova", "neutron", "keystone", "cinder", "glance", "ironic"],
    },
    "macos": {
        "label": "macOS / Apple",
        "sources": {"apple"},
        "keywords": [],
    },
    "cisco": {
        "label": "Cisco",
        "sources": {"cisco"},
        "keywords": [],
    },
    "fortinet": {
        "label": "Fortinet",
        "sources": {"fortinet"},
        "keywords": [],
    },
    "vmware": {
        "label": "VMware / Broadcom",
        "sources": {"vmware"},
        "keywords": ["vmware", "vsphere", "vcenter", "esxi", "horizon", "aria"],
    },
    "android": {
        "label": "Android",
        "sources": {"android"},
        "keywords": [],
    },
    "nginx": {
        "label": "nginx",
        "sources": set(),
        "keywords": ["nginx", "traefik"],
        "title_only": True,
    },
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


def top_cves(vulns, n=TOP_N):
    # KEV (exploited) first, then by severity, then EPSS, then CVSS
    return sorted(
        [v for v in vulns if v["id"].startswith("CVE-")],
        key=lambda v: (
            0 if v.get("kev") else 1,
            SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4),
            -(v.get("epss") or 0),
            -(v.get("score") or 0),
        ),
    )[:n]


def build_tldr(vulns, week_end):
    """One-paragraph TLDR summary of the week."""
    n_total = len([v for v in vulns if v["id"].startswith("CVE-")])
    n_crit  = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    n_kev   = sum(1 for v in vulns if v.get("kev"))
    top3    = top_cves(vulns, 3)

    notable = []
    for v in top3:
        cve_id = v["id"]
        title  = (v.get("title") or "").strip()
        # extract the most meaningful part of the title
        short  = title.split("—")[0].split(" in ")[-1].split(" via ")[0].strip()
        score  = f'CVSS {v["score"]:.1f}' if v.get("score") else ""
        kev    = "actively exploited" if v.get("kev") else ""
        parts  = ", ".join(p for p in [short[:60], score, kev] if p)
        notable.append(f"<strong>{xe(cve_id)}</strong> ({xe(parts)})")

    notable_str = "; ".join(notable) if notable else ""
    kev_str = f" <strong>{n_kev} are actively exploited</strong> (CISA KEV)." if n_kev else "."

    return (
        f"{n_total:,} CVEs tracked this week &mdash; "
        f"<span style='color:#dc2626;font-weight:700'>{n_crit} critical</span>{kev_str}"
        + (f" Notable: {notable_str}." if notable_str else "")
    )


def xe(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def cve_card(v):
    """Render a single CVE as a compact card row."""
    sev     = v.get("severity", "UNKNOWN")
    color   = SEV_COLOR.get(sev, "#6b7280")
    score   = f'CVSS {v["score"]:.1f}' if v.get("score") is not None else ""
    epss    = f'EPSS {v["epss"]*100:.1f}%' if v.get("epss") else ""
    kev_tag = ('<span style="background:#7c3aed;color:#fff;font-size:.6rem;font-weight:700;'
               'padding:.05rem .3rem;border-radius:3px;margin-left:.3rem">KEV</span>'
               if v.get("kev") else "")
    meta    = " &middot; ".join(p for p in [score, epss] if p)
    url     = f"{BASE_URL}/cve/{v['id']}.html"
    title   = xe((v.get("title") or v["id"])[:110])
    return (
        f'<div style="border-left:3px solid {color};padding:.6rem .9rem;margin-bottom:.6rem;background:#f8fafc;border-radius:0 6px 6px 0">'
        f'<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.2rem">'
        f'<a href="{url}" style="font-family:monospace;font-weight:700;font-size:.82rem;color:#2563eb;text-decoration:none">{xe(v["id"])}</a>'
        f'<span style="background:{color};color:#fff;font-size:.6rem;font-weight:700;padding:.05rem .3rem;border-radius:3px;text-transform:uppercase">{xe(sev)}</span>'
        f'{kev_tag}'
        f'</div>'
        f'<div style="font-size:.8rem;color:#1e293b;line-height:1.4">{title}</div>'
        + (f'<div style="font-size:.72rem;color:#64748b;margin-top:.15rem">{meta}</div>' if meta else '')
        + f'</div>'
    )


def vendor_mini_section(display_name, slug, vulns, keywords, n=5, title_only=False, score_idx=None):
    """Top N CVEs for a vendor as a compact block. Returns empty string if no matches."""
    pool = [enrich(v, score_idx) for v in vulns] if score_idx else vulns
    matched = sorted(
        [v for v in pool if match_vendor(v, keywords, title_only=title_only)],
        key=lambda v: (
            0 if v.get("kev") else 1,
            SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4),
            -(v.get("score") or 0),
        ),
    )[:n]
    if not matched:
        return ""
    cards = "".join(cve_card(v) for v in matched)
    vendor_url = f"{BASE_URL}/vendor/{slug}.html"
    return (
        f'<div style="margin-top:1.6rem">'
        f'<div style="font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;'
        f'letter-spacing:.08em;margin-bottom:.6rem">'
        f'<a href="{vendor_url}" style="color:#2563eb;text-decoration:none">{xe(display_name)}</a>'
        f' &mdash; {len(matched)} CVE{"s" if len(matched) != 1 else ""} this week</div>'
        f'{cards}'
        f'</div>'
    )


def build_email_html(vulns, week_end):
    score_idx  = build_score_index(vulns)
    tldr       = build_tldr(vulns, week_end)
    highlights = top_cves(vulns, TOP_N)
    digest_url = f"{BASE_URL}/digest/{week_end}.html"

    highlight_cards = "".join(cve_card(v) for v in highlights)

    # Only official Kubernetes CVEs (source=Kubernetes) to avoid Azure/Fission/golang noise
    k8s_vulns    = [v for v in vulns if v.get("source", "").lower() == "kubernetes"]
    k8s_section  = vendor_mini_section("Kubernetes",  "kubernetes",  k8s_vulns,
                                       ["kubernetes", "k8s", "etcd", "kubectl", "kubelet", "kube"],
                                       score_idx=score_idx)
    osp_vulns    = [v for v in vulns if v.get("source", "").lower() in {"openstack", "oss-security"}]
    osp_section  = vendor_mini_section("OpenStack",   "openstack",   osp_vulns,
                                       ["openstack", "nova", "neutron", "keystone", "cinder", "glance", "ironic", "cyborg"],
                                       score_idx=score_idx)
    # Only Ubuntu/Debian advisories for kernel — NVD is full of noise (smb, batman-adv, etc.)
    kernel_vulns   = [v for v in vulns if v.get("source", "").lower() in {"ubuntu", "debian"}]
    kernel_section = vendor_mini_section("Linux Kernel", "linux-kernel", kernel_vulns,
                                         ["linux kernel", "kernel", "kvm", "bpf", "ebpf", "netfilter", "nftables"],
                                         score_idx=score_idx)
    # nginx/Traefik: title-only match to avoid Apache, TLS noise
    nginx_section  = vendor_mini_section("nginx / Traefik", "nginx-traefik", vulns,
                                         ["nginx", "traefik"], title_only=True, score_idx=score_idx)

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;margin:0;padding:0">
<div style="max-width:640px;margin:0 auto;padding:2rem 1rem">

  <div style="background:#0f172a;padding:1.2rem 1.8rem;border-radius:10px 10px 0 0">
    <span style="font-size:1.3rem;font-weight:800;color:#f1f5f9">vuln<span style="color:#60a5fa">feed</span></span>
    <span style="font-size:.75rem;color:#94a3b8;margin-left:1rem">Weekly digest &mdash; {xe(week_end)}</span>
  </div>

  <div style="background:#fff;border:1px solid #e2e8f0;border-top:none;padding:1.5rem 1.8rem">

    <!-- TLDR -->
    <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:.85rem 1.1rem;
                margin-bottom:1.5rem;font-size:.85rem;color:#1e3a8a;line-height:1.6">
      <strong>TL;DR &mdash;</strong> {tldr}
    </div>

    <!-- highlights -->
    <div style="font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;
                letter-spacing:.08em;margin-bottom:.6rem">Must-patch this week</div>
    {highlight_cards}

    <!-- kubernetes -->
    {k8s_section}

    <!-- openstack -->
    {osp_section}

    <!-- linux kernel -->
    {kernel_section}

    <!-- nginx / traefik -->
    {nginx_section}

    <p style="margin:1.6rem 0 0;font-size:.82rem;color:#64748b;text-align:center;border-top:1px solid #e2e8f0;padding-top:1rem">
      <a href="{digest_url}" style="color:#2563eb;font-weight:600;text-decoration:none">Full digest &rarr;</a>
      &nbsp;&middot;&nbsp;
      <a href="{BASE_URL}/" style="color:#2563eb;font-weight:600;text-decoration:none">Live feed</a>
      &nbsp;&middot;&nbsp;
      <a href="{BASE_URL}/feed.xml" style="color:#2563eb;font-weight:600;text-decoration:none">RSS</a>
    </p>
  </div>

  <div style="background:#f1f5f9;border:1px solid #e2e8f0;border-top:none;padding:.75rem 1.8rem;
              border-radius:0 0 10px 10px;text-align:center">
    <span style="font-size:.7rem;color:#94a3b8">
      vulnfeed weekly digest.
      <a href="{{{{ unsubscribe_url }}}}" style="color:#94a3b8">Unsubscribe</a>
    </span>
  </div>

</div>
</body>
</html>"""


def build_score_index(vulns):
    """Return {cve_id: best_entry} using the highest-scoring version across all sources."""
    idx = {}
    for v in vulns:
        vid = v["id"]
        if not vid.startswith("CVE-"):
            continue
        if vid not in idx or (v.get("score") or 0) > (idx[vid].get("score") or 0):
            idx[vid] = v
    return idx


def enrich(v, score_idx):
    """Return v with score/severity/epss/kev filled from the best known entry for that CVE."""
    if v.get("score") is not None and v.get("severity") not in (None, "UNKNOWN"):
        return v
    best = score_idx.get(v["id"])
    if not best:
        return v
    merged = dict(v)
    for field in ("score", "severity", "epss", "kev", "epss_pct", "badge"):
        if merged.get(field) in (None, "UNKNOWN", "") and best.get(field) not in (None, "UNKNOWN", ""):
            merged[field] = best[field]
    return merged


def topic_match(v, topic):
    """Return True if vuln v belongs to the given topic config dict."""
    sources = topic.get("sources") or set()
    keywords = topic.get("keywords") or []
    title_only = topic.get("title_only", False)
    src_ok = (not sources) or (v.get("source", "").lower() in sources)
    if not keywords:
        return src_ok
    if title_only:
        hay = (v.get("title") or "").lower()
    else:
        hay = " ".join([
            v.get("id", ""), v.get("title", ""), v.get("description", ""),
            *v.get("affected", []),
        ]).lower()
    kw_ok = any(kw in hay for kw in keywords)
    return src_ok and kw_ok if sources else kw_ok


def build_topic_email_html(vulns, week_end, slug):
    """Build a filtered digest email for a single topic."""
    topic = TOPIC_GROUPS[slug]
    score_idx = build_score_index(vulns)
    pool = [enrich(v, score_idx) for v in vulns]
    matched = sorted(
        [v for v in pool if topic_match(v, topic)],
        key=lambda v: (
            0 if v.get("kev") else 1,
            SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4),
            -(v.get("epss") or 0),
            -(v.get("score") or 0),
        ),
    )[:20]

    if not matched:
        return None

    n_crit = sum(1 for v in matched if v.get("severity") == "CRITICAL")
    n_kev  = sum(1 for v in matched if v.get("kev"))
    kev_str = f" &mdash; <strong>{n_kev} actively exploited</strong>" if n_kev else ""
    digest_url = f"{BASE_URL}/digest/{week_end}.html"
    cards = "".join(cve_card(v) for v in matched)
    label = xe(topic["label"])

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;margin:0;padding:0">
<div style="max-width:640px;margin:0 auto;padding:2rem 1rem">

  <div style="background:#0f172a;padding:1.2rem 1.8rem;border-radius:10px 10px 0 0">
    <span style="font-size:1.3rem;font-weight:800;color:#f1f5f9">vuln<span style="color:#60a5fa">feed</span></span>
    <span style="font-size:.75rem;color:#94a3b8;margin-left:1rem">{label} digest &mdash; {xe(week_end)}</span>
  </div>

  <div style="background:#fff;border:1px solid #e2e8f0;border-top:none;padding:1.5rem 1.8rem">
    <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:.85rem 1.1rem;
                margin-bottom:1.5rem;font-size:.85rem;color:#1e3a8a;line-height:1.6">
      <strong>TL;DR &mdash;</strong> {len(matched)} <strong>{label}</strong> CVEs this week
      &mdash; <span style="color:#dc2626;font-weight:700">{n_crit} critical</span>{kev_str}.
    </div>
    <div style="font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;
                letter-spacing:.08em;margin-bottom:.6rem">{label} &mdash; top CVEs</div>
    {cards}
    <p style="margin:1.6rem 0 0;font-size:.82rem;color:#64748b;text-align:center;border-top:1px solid #e2e8f0;padding-top:1rem">
      <a href="{digest_url}" style="color:#2563eb;font-weight:600;text-decoration:none">Full digest &rarr;</a>
      &nbsp;&middot;&nbsp;
      <a href="{BASE_URL}/" style="color:#2563eb;font-weight:600;text-decoration:none">Live feed</a>
      &nbsp;&middot;&nbsp;
      <a href="{BASE_URL}/feed.xml" style="color:#2563eb;font-weight:600;text-decoration:none">RSS</a>
    </p>
  </div>

  <div style="background:#f1f5f9;border:1px solid #e2e8f0;border-top:none;padding:.75rem 1.8rem;
              border-radius:0 0 10px 10px;text-align:center">
    <span style="font-size:.7rem;color:#94a3b8">
      vulnfeed {label} digest. You subscribed to this topic.
      <a href="{{{{ unsubscribe_url }}}}" style="color:#94a3b8">Unsubscribe</a>
    </span>
  </div>

</div>
</body>
</html>"""


def match_vendor(v, keywords, title_only=False):
    if title_only:
        haystack = (v.get("title") or "").lower()
    else:
        haystack = " ".join([
            v.get("id", ""), v.get("title", ""), v.get("description", ""),
            *v.get("affected", []),
        ]).lower()
    return any(kw in haystack for kw in keywords)


def build_vendor_section(display_name, slug, vulns, keywords, title_only=False, score_idx=None):
    """Return an HTML section string for one vendor group (up to 10 CVEs)."""
    pool = [enrich(v, score_idx) for v in vulns] if score_idx else vulns
    matched = sorted(
        [v for v in pool if match_vendor(v, keywords, title_only=title_only)],
        key=lambda v: (
            0 if v.get("kev") else 1,
            SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4),
            -(v.get("score") or 0),
        ),
    )[:10]

    if not matched:
        return ""

    rows = ""
    for v in matched:
        sev   = v.get("severity", "UNKNOWN")
        color = SEV_COLOR.get(sev, "#6b7280")
        score = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
        epss  = f'{v["epss"] * 100:.1f}%' if v.get("epss") else "—"
        kev   = ' <span style="color:#7c3aed;font-weight:700;font-size:.7rem">KEV</span>' if v.get("kev") else ""
        url   = f"{BASE_URL}/cve/{v['id']}.html"
        title = xe((v.get("title") or "")[:110])
        rows += (
            f'<tr>'
            f'<td style="padding:.45rem .7rem;border-bottom:1px solid #e2e8f0;white-space:nowrap">'
            f'<a href="{url}" style="color:#2563eb;font-family:monospace;font-weight:700;font-size:.78rem;text-decoration:none">'
            f'{xe(v["id"])}</a></td>'
            f'<td style="padding:.45rem .7rem;border-bottom:1px solid #e2e8f0">'
            f'<span style="background:{color};color:#fff;padding:.06rem .35rem;border-radius:3px;font-size:.63rem;font-weight:700;text-transform:uppercase">{xe(sev)}</span>'
            f'</td>'
            f'<td style="padding:.45rem .7rem;border-bottom:1px solid #e2e8f0;font-size:.77rem;color:#1e293b">{title}{kev}</td>'
            f'<td style="padding:.45rem .7rem;border-bottom:1px solid #e2e8f0;font-size:.77rem;color:#475569;text-align:right;white-space:nowrap">{xe(score)}</td>'
            f'<td style="padding:.45rem .7rem;border-bottom:1px solid #e2e8f0;font-size:.77rem;color:#7c3aed;text-align:right;white-space:nowrap">{xe(epss)}</td>'
            f'</tr>'
        )

    vendor_url = f"{BASE_URL}/vendor/{slug}.html"
    return (
        f'<div style="font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;'
        f'letter-spacing:.08em;margin:1.75rem 0 .6rem">'
        f'<a href="{vendor_url}" style="color:#2563eb;text-decoration:none">{xe(display_name)}</a>'
        f' &mdash; {len(matched)} CVE{"s" if len(matched) != 1 else ""}</div>'
        f'<table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;margin-bottom:.5rem">'
        f'<thead><tr style="background:#f8fafc">'
        f'<th style="text-align:left;padding:.45rem .7rem;border-bottom:2px solid #e2e8f0;font-size:.66rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">CVE</th>'
        f'<th style="text-align:left;padding:.45rem .7rem;border-bottom:2px solid #e2e8f0;font-size:.66rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">Sev</th>'
        f'<th style="text-align:left;padding:.45rem .7rem;border-bottom:2px solid #e2e8f0;font-size:.66rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">Description</th>'
        f'<th style="text-align:right;padding:.45rem .7rem;border-bottom:2px solid #e2e8f0;font-size:.66rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">CVSS</th>'
        f'<th style="text-align:right;padding:.45rem .7rem;border-bottom:2px solid #e2e8f0;font-size:.66rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em">EPSS</th>'
        f'</tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )


def build_vendor_email_html(vulns, week_end):
    """Build a combined infrastructure digest email with per-product sections."""
    score_idx = build_score_index(vulns)
    sections = ""
    total_matched = 0
    for display_name, slug, keywords in VENDOR_GROUPS:
        allowed_sources = VENDOR_AUTHORITATIVE_SOURCES.get(slug)
        pool = [v for v in vulns if v.get("source", "").lower() in allowed_sources] if allowed_sources else vulns
        title_only = slug in VENDOR_TITLE_ONLY
        section = build_vendor_section(display_name, slug, pool, keywords,
                                       title_only=title_only, score_idx=score_idx)
        if section:
            sections += section
            total_matched += sum(1 for v in vulns if match_vendor(v, keywords))

    if not sections:
        return None, 0

    digest_url = f"{BASE_URL}/digest/{week_end}.html"
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;margin:0;padding:0">
<div style="max-width:700px;margin:0 auto;padding:2rem 1rem">

  <div style="background:#0f172a;padding:1.2rem 1.8rem;border-radius:10px 10px 0 0">
    <span style="font-size:1.3rem;font-weight:800;color:#f1f5f9">vuln<span style="color:#60a5fa">feed</span></span>
    <span style="font-size:.75rem;color:#94a3b8;margin-left:1rem">Infrastructure Digest &mdash; {xe(week_end)}</span>
  </div>

  <div style="background:#fff;border:1px solid #e2e8f0;border-top:none;padding:1.5rem 1.8rem">
    <p style="font-size:.84rem;color:#475569;margin:0 0 .25rem">
      Vulnerabilities affecting <strong style="color:#0f172a">Kubernetes, OpenStack, Linux Kernel, nginx &amp; Traefik</strong>
      from the past 7 days.
    </p>
    {sections}
    <p style="margin:1.5rem 0 0;font-size:.82rem;color:#64748b;text-align:center">
      <a href="{digest_url}" style="color:#2563eb;font-weight:600;text-decoration:none">Full digest &rarr;</a>
      &nbsp;&middot;&nbsp;
      <a href="{BASE_URL}/" style="color:#2563eb;font-weight:600;text-decoration:none">Live feed</a>
    </p>
  </div>

  <div style="background:#f1f5f9;border:1px solid #e2e8f0;border-top:none;padding:.75rem 1.8rem;
              border-radius:0 0 10px 10px;text-align:center">
    <span style="font-size:.7rem;color:#94a3b8">
      vulnfeed infrastructure digest. <a href="{{{{ unsubscribe_url }}}}" style="color:#94a3b8">Unsubscribe</a>
    </span>
  </div>
</div>
</body>
</html>""", total_matched


def send(api_key, subject, html_body, tag=None):
    data = {
        "subject": subject,
        "body": html_body,
        "status": "about_to_send",
    }
    if tag:
        data["filters"] = [{"type": "tag", "value": tag}]
    payload = json.dumps(data).encode()
    req = Request(
        BUTTONDOWN_API,
        data=payload,
        headers={
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json",
            "X-Buttondown-Live-Dangerously": "true",
        },
    )
    try:
        with urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
            print(f"[ok] Email queued — id={resp.get('id')} status={resp.get('status')}")
            return True
    except HTTPError as e:
        body = e.read().decode()
        try:
            err = json.loads(body)
        except Exception:
            err = {}
        if err.get("code") == "email_duplicate":
            print("[warn] Buttondown reports duplicate — email was already sent, skipping.")
            return True
        print(f"[error] HTTP {e.code}: {body}", file=sys.stderr)
        return False


def main():
    dry_run     = "--dry-run" in sys.argv
    vendor_mode = "--vendors" in sys.argv
    topic_slug  = None
    for i, arg in enumerate(sys.argv):
        if arg == "--topic" and i + 1 < len(sys.argv):
            topic_slug = sys.argv[i + 1]

    api_key = os.environ.get("BUTTONDOWN_API_KEY")
    if not api_key and not dry_run:
        print("[error] BUTTONDOWN_API_KEY env var not set", file=sys.stderr)
        sys.exit(1)

    vulns, week_end = load_week()
    if not vulns:
        print("[error] No historical data found — run build.py at least once", file=sys.stderr)
        sys.exit(1)

    print(f"[digest] {len(vulns)} vulns from last 7 days, week ending {week_end}")

    if topic_slug:
        if topic_slug not in TOPIC_GROUPS:
            print(f"[error] Unknown topic '{topic_slug}'. Valid: {', '.join(TOPIC_GROUPS)}", file=sys.stderr)
            sys.exit(1)
        html_body = build_topic_email_html(vulns, week_end, topic_slug)
        if not html_body:
            print(f"[topic:{topic_slug}] No CVEs matched — skipping")
            return
        label = TOPIC_GROUPS[topic_slug]["label"]
        subject = f"vulnfeed {label} digest — {week_end}"
        preview_path = f"/tmp/digest_{topic_slug}_preview.html"
        tag = topic_slug
        print(f"[topic:{topic_slug}] Subject: {subject}")
    elif vendor_mode:
        html_body, n_matched = build_vendor_email_html(vulns, week_end)
        if not html_body:
            print("[vendors] No CVEs matched any vendor group — skipping")
            return
        subject = f"vulnfeed infra digest: Kubernetes · OpenStack · Kernel · nginx — {week_end}"
        print(f"[vendors] {n_matched} CVEs across {len(VENDOR_GROUPS)} vendor groups")
        preview_path = "/tmp/digest_vendors_preview.html"
        tag = None
    else:
        n_crit = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
        subject = f"vulnfeed weekly: {len(vulns)} CVEs · {n_crit} critical — {week_end}"
        html_body = build_email_html(vulns, week_end)
        preview_path = "/tmp/digest_preview.html"
        tag = None
        print(f"[digest] Subject: {subject}")

    if dry_run:
        with open(preview_path, "w", encoding="utf-8") as f:
            f.write(html_body)
        print(f"[dry-run] HTML written to {preview_path}")
        return

    ok = send(api_key, subject, html_body, tag=tag)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
