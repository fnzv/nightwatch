#!/usr/bin/env python3
"""Push CVE notifications to ntfy.sh topics.

Topics published:
  vulnfeed-critical     — all KEV (CISA) + CVSS ≥ 9.0
  vulnfeed-<product>    — per-product (CVSS ≥ 7.0 or KEV)

Dedup: X-Message-Id = "{cve_id}-YYYYMMDD" — clients see each CVE once
per day even if the script runs multiple times in the same build window.

Usage:
  python3 notify_ntfy.py
  NTFY_TOKEN=xxx python3 notify_ntfy.py   # bearer auth for self-hosted
"""
import datetime
import json
import os
import urllib.request

VULNS_URL    = "https://vulnfeed.it/vulns.json"
NTFY_BASE    = "https://ntfy.sh"
WINDOW_HOURS = 5  # slightly > 4h build interval to tolerate schedule drift

# Mirrors send_digest.py TOPIC_GROUPS + notify_ntfy PRODUCTS
PRODUCTS = {
    "kubernetes":   {
        "sources":  {"kubernetes"},
        "keywords": ["kubernetes", "k8s", "etcd", "kubelet", "kube"],
    },
    "ubuntu":       {"sources": {"ubuntu"},                   "keywords": []},
    "debian":       {"sources": {"debian"},                   "keywords": []},
    "openstack":    {
        "sources":  {"openstack", "oss-security"},
        "keywords": ["openstack", "nova", "neutron", "keystone", "cinder", "glance"],
    },
    "linux-kernel": {
        "sources":  {"ubuntu", "debian"},
        "keywords": ["linux kernel", "kernel", "kvm", "bpf", "ebpf", "netfilter"],
    },
    "windows":      {
        "sources":    {"microsoft"},
        "keywords":   ["windows"],
        "title_only": True,
    },
    "nginx":        {
        "sources":    set(),
        "keywords":   ["nginx", "traefik"],
        "title_only": True,
    },
    "cisco":        {"sources": {"cisco"},    "keywords": []},
    "fortinet":     {"sources": {"fortinet"}, "keywords": []},
    "vmware":       {
        "sources":  {"vmware"},
        "keywords": ["vmware", "vsphere", "vcenter", "esxi"],
    },
    "android":      {"sources": {"android"}, "keywords": []},
    "macos":        {"sources": {"apple"},   "keywords": []},
}


def load_vulns():
    print(f"[ntfy] Fetching {VULNS_URL}", flush=True)
    with urllib.request.urlopen(VULNS_URL, timeout=30) as r:
        return json.loads(r.read())


def is_new(v, now):
    pub = (v.get("published") or "").strip().rstrip("Z") + "+00:00"
    try:
        dt  = datetime.datetime.fromisoformat(pub)
        age = (now - dt).total_seconds()
        return 0 < age < WINDOW_HOURS * 3600
    except Exception:
        return False


def product_matches(v, cfg):
    sources    = cfg.get("sources") or set()
    keywords   = cfg.get("keywords") or []
    title_only = cfg.get("title_only", False)
    src_ok     = (not sources) or (v.get("source", "").lower() in sources)
    if not keywords:
        return src_ok
    hay = (
        (v.get("title") or "") if title_only
        else " ".join([
            v.get("id", ""), v.get("title", ""),
            v.get("description", ""), *v.get("affected", []),
        ])
    )
    kw_ok = any(kw in hay.lower() for kw in keywords)
    return src_ok and kw_ok


def _ascii(s):
    """Strip non-ASCII so header encoding never raises latin-1 errors."""
    return s.encode("ascii", "replace").decode("ascii")


def ntfy_post(topic, title, body, tags=None, priority=3, msg_id=None):
    req = urllib.request.Request(
        f"{NTFY_BASE}/{topic}",
        data=body.encode("utf-8"),
        method="POST",
    )
    req.add_header("Title", _ascii(title))
    req.add_header("Priority", str(priority))
    if tags:
        req.add_header("Tags", ",".join(tags))
    if msg_id:
        req.add_header("X-Message-Id", msg_id)
    token = os.environ.get("NTFY_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        urllib.request.urlopen(req, timeout=15)
        print(f"  ✓ {topic}: {title}", flush=True)
    except Exception as e:
        print(f"  ✗ {topic}: {e}", flush=True)


def run():
    now   = datetime.datetime.now(datetime.timezone.utc)
    today = now.strftime("%Y%m%d")

    vulns   = load_vulns()
    new_all = [v for v in vulns if is_new(v, now)]
    print(f"[ntfy] {len(new_all)} CVEs in last {WINDOW_HOURS}h  (feed total: {len(vulns)})")

    # ── global critical channel (KEV + CVSS ≥ 9.0) ─────────────────────────
    critical = [
        v for v in new_all
        if v.get("badge") == "ACTIVELY EXPLOITED" or (v.get("score") or 0) >= 9.0
    ]
    print(f"[ntfy] {len(critical)} critical/KEV → vulnfeed-critical")

    for v in critical[:20]:
        cve_id = v.get("id", "unknown")
        score  = v.get("score") or 0
        is_kev = v.get("badge") == "ACTIVELY EXPLOITED"
        poc    = v.get("poc", False)
        desc   = (v.get("description") or "")[:220].strip()

        tags = ["warning", "rotating_light"] if is_kev else ["warning"]
        if poc:
            tags.append("bomb")

        ntfy_post(
            "vulnfeed-critical",
            f"{'[KEV]' if is_kev else '[CVSS ' + str(score) + ']'} {cve_id}",
            f"{desc}\n\nhttps://vulnfeed.it/cve/{cve_id}.html",
            tags=tags,
            priority=5 if is_kev else 4,
            msg_id=f"{cve_id}-{today}",
        )

    # ── per-product channels ─────────────────────────────────────────────────
    for product, cfg in PRODUCTS.items():
        pool = [
            v for v in new_all
            if product_matches(v, cfg)
            and ((v.get("score") or 0) >= 7.0 or v.get("badge") == "ACTIVELY EXPLOITED")
        ]
        if not pool:
            continue

        n_kev  = sum(1 for v in pool if v.get("badge") == "ACTIVELY EXPLOITED")
        n_crit = sum(1 for v in pool if (v.get("score") or 0) >= 9.0)
        title  = f"{len(pool)} new {product} CVE{'s' if len(pool) != 1 else ''}"
        if n_kev:
            title = f"[KEV] {title} ({n_kev} actively exploited)"
        elif n_crit:
            title = f"[CRIT] {title} ({n_crit} critical)"

        lines = [
            "• {id}  CVSS {score}{kev}{poc}".format(
                id=v.get("id", ""),
                score=v.get("score") or "?",
                kev=" [KEV]" if v.get("badge") == "ACTIVELY EXPLOITED" else "",
                poc=" [PoC]" if v.get("poc") else "",
            )
            for v in pool[:8]
        ]

        ntfy_post(
            f"vulnfeed-{product}",
            title,
            "\n".join(lines) + "\n\nhttps://vulnfeed.it",
            tags=[product, "warning"],
            priority=4 if n_kev else 3,
            msg_id=f"{product}-{now.strftime('%Y%m%d%H')}",
        )

    print("[ntfy] Done", flush=True)


if __name__ == "__main__":
    run()
