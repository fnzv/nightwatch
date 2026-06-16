#!/usr/bin/env python3
"""
TLDR Security Daily — build.py
Aggregates CVEs from NVD, Ubuntu, Debian, CISA KEV, and OSS-Security.

Usage:  python3 build.py
Output: index.html
Serve:  python3 -m http.server 8080
"""

import gzip
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
import xml.etree.ElementTree as ET

HISTORICAL_DIR = "historical"
BASE_URL = "https://nightwatch.sami.pw"


def _xe(s):
    """Escape text for HTML content / attribute values."""
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def http_get(url, timeout=30, headers=None):
    h = {"User-Agent": "tldr-security-aggregator/1.0"}
    if headers:
        h.update(headers)
    req = Request(url, headers=h)
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.read()
    except HTTPError as e:
        log(f"  HTTP {e.code} — {url}")
    except URLError as e:
        log(f"  Network error — {url}: {e.reason}")
    except Exception as e:
        log(f"  Error — {url}: {e}")
    return None


def http_post(url, payload, timeout=60, headers=None):
    h = {"User-Agent": "tldr-security-aggregator/1.0", "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    data = payload if isinstance(payload, bytes) else payload.encode()
    req = Request(url, data=data, headers=h)
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.read()
    except HTTPError as e:
        log(f"  HTTP {e.code} — {url}")
    except URLError as e:
        log(f"  Network error — {url}: {e.reason}")
    except Exception as e:
        log(f"  Error — {url}: {e}")
    return None


def strip_html(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()


def cutoff_utc(hours=24):
    return datetime.now(timezone.utc) - timedelta(hours=hours)


# ---------------------------------------------------------------------------
# GitHub Advisories: ecosystems to watch (covers Go, Python, npm, Rust, Java, .NET, Ruby)
# The affects= filter doesn't work for C libraries (curl, openssl etc) — those come via NVD.
# Querying by ecosystem + date is more reliable and covers all packages in each ecosystem.
# ---------------------------------------------------------------------------

GITHUB_ECOSYSTEMS = ["go", "pip", "npm", "rust", "maven", "nuget", "rubygems"]


# ---------------------------------------------------------------------------
# Source: GitHub Security Advisories (by ecosystem)
# ---------------------------------------------------------------------------

def fetch_github_advisories(days=7):
    log(f"Fetching GitHub Security Advisories ({len(GITHUB_ECOSYSTEMS)} ecosystems)...")
    now_dt = datetime.now(timezone.utc)
    start = (now_dt - timedelta(days=days)).strftime("%Y-%m-%d")
    end   = now_dt.strftime("%Y-%m-%d")
    pub_range = f"{start}..{end}"
    SEV_MAP = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
    gh_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    seen = set()
    results = []

    for eco in GITHUB_ECOSYSTEMS:
        url = (
            "https://api.github.com/advisories"
            f"?ecosystem={eco}&published={pub_range}&type=reviewed&per_page=100"
        )
        raw = http_get(url, headers=gh_headers)
        if not raw:
            time.sleep(2)
            continue

        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            time.sleep(2)
            continue

        if not isinstance(items, list):
            log(f"  GitHub [{eco}]: unexpected response")
            time.sleep(2)
            continue

        log(f"  GitHub [{eco}]: {len(items)} advisories")

        for item in items:
            ghsa = item.get("ghsa_id", "")
            if not ghsa or ghsa in seen:
                continue
            seen.add(ghsa)

            cve_id = item.get("cve_id") or ghsa
            severity = SEV_MAP.get((item.get("severity") or "").lower(), "UNKNOWN")

            score = None
            cvss = item.get("cvss") or {}
            try:
                score = float(cvss["score"]) if cvss.get("score") else None
            except (ValueError, TypeError):
                pass

            affected = []
            for vuln in (item.get("vulnerabilities") or [])[:6]:
                ep = vuln.get("package") or {}
                name = ep.get("name", "")
                eco2 = ep.get("ecosystem", "")
                vrange = vuln.get("vulnerable_version_range", "")
                if name:
                    label = f"{eco2}/{name}" if eco2 else name
                    if vrange:
                        label += f" {vrange}"
                    affected.append(label)

            pub = item.get("published_at", "")
            html_url = item.get("html_url") or f"https://github.com/advisories/{ghsa}"
            refs = ([html_url] + [r for r in (item.get("references") or []) if r])[:4]

            results.append({
                "id": cve_id,
                "title": (item.get("summary") or cve_id)[:160],
                "description": (item.get("description") or "")[:500],
                "score": score,
                "severity": severity,
                "source": "GitHub",
                "published": pub,
                "references": refs,
                "affected": affected[:8],
                "url": html_url,
            })

        time.sleep(2)  # stay within 60 req/hour unauthenticated

    log(f"  GitHub Advisories: {len(results)} total")
    return results


# ---------------------------------------------------------------------------
# Source: NVD
# ---------------------------------------------------------------------------

def fetch_nvd(hours=168):  # 7 days
    log("Fetching NVD CVEs (last 24 h)...")
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    fmt = "%Y-%m-%dT%H:%M:%S.000"

    results = []
    start_index = 0
    total = None

    while total is None or start_index < total:
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={start.strftime(fmt)}"
            f"&pubEndDate={now.strftime(fmt)}"
            f"&resultsPerPage=2000"
            f"&startIndex={start_index}"
        )
        raw = http_get(url)
        if raw is None:
            break

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as ex:
            log(f"  NVD JSON error: {ex}")
            break

        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                ""
            )

            score, severity = None, "UNKNOWN"
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                entries = metrics.get(key, [])
                if entries:
                    cd = entries[0].get("cvssData", {})
                    score = cd.get("baseScore")
                    severity = (cd.get("baseSeverity") or "UNKNOWN").upper()
                    break
            if score is None:
                for entry in metrics.get("cvssMetricV2", []):
                    s = entry.get("cvssData", {}).get("baseScore")
                    if s is not None:
                        score = s
                        severity = "HIGH" if s >= 7 else ("MEDIUM" if s >= 4 else "LOW")
                        break

            refs = [r["url"] for r in cve.get("references", [])[:5] if r.get("url")]

            affected = set()
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for cpe_m in node.get("cpeMatch", []):
                        parts = cpe_m.get("criteria", "").split(":")
                        if len(parts) > 4:
                            vendor, product = parts[3], parts[4]
                            if vendor not in ("*", "") and product not in ("*", ""):
                                affected.add(f"{vendor}/{product}")

            results.append({
                "id": cve_id,
                "title": (desc[:160] if desc else cve_id),
                "description": desc,
                "score": score,
                "severity": severity,
                "source": "NVD",
                "published": cve.get("published", ""),
                "references": refs,
                "affected": sorted(affected)[:8],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        start_index += len(vulns)
        if len(vulns) < 2000:
            break

        time.sleep(6)  # NVD rate limit: 5 req / 30 s without API key

    log(f"  NVD: {len(results)} CVEs (total in window: {total})")
    return results


# ---------------------------------------------------------------------------
# Source: Ubuntu Security Notices
# ---------------------------------------------------------------------------

def fetch_ubuntu():
    log("Fetching Ubuntu Security Notices...")
    raw = http_get("https://ubuntu.com/security/notices/rss.xml")
    if not raw:
        return []

    cut = cutoff_utc(hours=24 * 7)
    results = []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as ex:
        log(f"  Ubuntu XML error: {ex}")
        return []

    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link  = (item.findtext("link")  or "").strip()
        desc  = (item.findtext("description") or "").strip()
        pub   = (item.findtext("pubDate") or "").strip()

        try:
            if parsedate_to_datetime(pub).astimezone(timezone.utc) < cut:
                continue
        except Exception:
            pass  # include if date unparseable

        cves = re.findall(r"CVE-\d{4}-\d+", desc + " " + title)

        results.append({
            "id": (title.split(":")[0] if ":" in title else title).strip(),
            "title": title,
            "description": strip_html(desc)[:600],
            "score": None,
            "severity": "UNKNOWN",
            "source": "Ubuntu",
            "published": pub,
            "references": [link],
            "affected": list(dict.fromkeys(cves))[:8],
            "url": link,
        })

    log(f"  Ubuntu: {len(results)} advisories")
    return results


# ---------------------------------------------------------------------------
# Source: Debian Security Advisories (debian-security-announce mailing list)
# ---------------------------------------------------------------------------

def fetch_debian():
    log("Fetching Debian DSAs...")
    year = datetime.now(timezone.utc).year
    index_url = f"https://lists.debian.org/debian-security-announce/{year}/threads.html"
    raw = http_get(index_url)
    if not raw:
        return []

    content = raw.decode("utf-8", errors="replace")
    # Links are: <a name="NNNNN" href="msgNNNNN.html">subject</a>
    msgs = re.findall(
        r'<a name="\d+" href="(msg\d+\.html)">(\[SECURITY\][^<]+)</a>',
        content
    )
    if not msgs:
        log("  Debian: no messages found on index page")
        return []

    cut = cutoff_utc(hours=24 * 7)
    results = []
    base = f"https://lists.debian.org/debian-security-announce/{year}/"

    for href, subject in msgs[-60:]:
        msg_raw = http_get(base + href)
        if not msg_raw:
            continue

        msg = msg_raw.decode("utf-8", errors="replace")

        # Date: Sat, 13 Jun 2026 17:12:10 +0000
        date_m = re.search(r"<em>Date</em>:\s*([^\n<]+)", msg)
        pub = date_m.group(1).strip() if date_m else ""
        try:
            pub_dt = parsedate_to_datetime(pub).astimezone(timezone.utc)
            if pub_dt < cut:
                continue
        except Exception:
            pass  # include if date unparseable

        cves = re.findall(r"CVE-\d{4}-\d+", msg)
        # Extract DSA ID from subject: [SECURITY] [DSA 6344-1] chromium ...
        dsa_m = re.search(r"\[DSA[^\]]+\]", subject)
        dsa_id = dsa_m.group(0).strip("[]") if dsa_m else subject.split()[0]
        msg_url = base + href

        results.append({
            "id": dsa_id,
            "title": subject.strip(),
            "description": strip_html(subject.strip()),
            "score": None,
            "severity": "UNKNOWN",
            "source": "Debian",
            "published": pub,
            "references": [msg_url],
            "affected": list(dict.fromkeys(cves))[:8],
            "url": msg_url,
        })

        time.sleep(0.5)  # polite crawling

    log(f"  Debian: {len(results)} advisories")
    return results


# ---------------------------------------------------------------------------
# Source: CISA Known Exploited Vulnerabilities
# ---------------------------------------------------------------------------

def fetch_cisa():
    log("Fetching CISA Known Exploited Vulnerabilities...")
    raw = http_get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as ex:
        log(f"  CISA JSON error: {ex}")
        return []

    cutoff_date = datetime.now(timezone.utc).date() - timedelta(days=7)
    results = []

    for v in data.get("vulnerabilities", []):
        try:
            added = datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d").date()
        except ValueError:
            continue
        if added < cutoff_date:
            continue

        cve_id = v.get("cveID", "")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")

        results.append({
            "id": cve_id,
            "title": v.get("vulnerabilityName", cve_id),
            "description": v.get("shortDescription", ""),
            "score": None,
            "severity": "HIGH",
            "source": "CISA-KEV",
            "published": v.get("dateAdded", ""),
            "references": [
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            ],
            "affected": [f"{vendor}: {product}"] if vendor else [],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "badge": "ACTIVELY EXPLOITED",
        })

    log(f"  CISA KEV: {len(results)} entries")
    return results


# ---------------------------------------------------------------------------
# Source: OSS-Security mailing list
# ---------------------------------------------------------------------------

_SEC_KW = frozenset([
    "cve", "vuln", "exploit", "overflow", "injection", "bypass",
    "disclosure", "rce", "lpe", "dos", "advisory", "security",
    "patch", "flaw", "attack", "corruption", "xss", "ssrf",
    "privilege", "escalation", "unauthenticated", "arbitrary",
    "heap", "stack", "use-after-free", "uaf", "integer overflow",
])


def fetch_oss_security(days=7):
    log(f"Fetching OSS-Security mailing list (last {days} days)...")
    results = []
    seen = set()
    now = datetime.now(timezone.utc)

    for offset in range(days):
        day = now - timedelta(days=offset)
        url = f"https://www.openwall.com/lists/oss-security/{day.strftime('%Y/%m/%d')}/"
        raw = http_get(url)
        if not raw:
            continue

        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            continue

        # openwall archive: <a href="N">Subject text</a>
        for m in re.finditer(r'href="(\d+)">([^<]+)</a>', content):
            num, subject = m.group(1), m.group(2).strip()
            if not subject:
                continue

            uid = f"{day.strftime('%Y%m%d')}-{num}"
            if uid in seen:
                continue
            seen.add(uid)

            cves = re.findall(r"CVE-\d{4}-\d+", subject, re.IGNORECASE)
            is_sec = bool(cves) or any(k in subject.lower() for k in _SEC_KW)
            if not is_sec:
                continue

            thread_url = (
                f"https://www.openwall.com/lists/oss-security/"
                f"{day.strftime('%Y/%m/%d')}/{num}"
            )
            results.append({
                "id": cves[0].upper() if cves else f"OSS-{day.strftime('%Y%m%d')}-{num}",
                "title": subject,
                "description": subject,
                "score": None,
                "severity": "UNKNOWN",
                "source": "OSS-Security",
                "published": day.strftime("%Y-%m-%dT00:00:00Z"),
                "references": [thread_url],
                "affected": [c.upper() for c in cves[:5]],
                "url": thread_url,
            })

        time.sleep(1)  # be polite to openwall.com

    log(f"  OSS-Security: {len(results)} posts")
    return results


# ---------------------------------------------------------------------------
# Source: Kubernetes official CVE feed
# ---------------------------------------------------------------------------

def fetch_kubernetes(days=90):  # CVEs are infrequent; 90-day window catches recent ones
    log("Fetching Kubernetes CVEs...")
    url = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
    raw = http_get(url)
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as ex:
        log(f"  Kubernetes JSON error: {ex}")
        return []

    cut = cutoff_utc(hours=days * 24)
    results = []

    for item in data.get("items", []):
        pub = item.get("date_published", "")
        try:
            if datetime.fromisoformat(pub.replace("Z", "+00:00")) < cut:
                continue
        except Exception:
            pass

        cve_id = item.get("id", "")
        summary = item.get("summary", "")
        content = item.get("content_text", "")

        # Extract CVSS score and severity from content
        score, severity = None, "UNKNOWN"
        cvss_m = re.search(
            r"\*\*(Critical|High|Medium|Low)\s+\((\d+\.?\d*)\)\*\*",
            content, re.IGNORECASE
        )
        if cvss_m:
            severity = cvss_m.group(1).upper()
            score = float(cvss_m.group(2))

        # Affected versions block
        aff_m = re.search(r"#### Affected Versions\s*(.+?)(?=\n###|\Z)", content, re.DOTALL)
        aff_text = re.sub(r"[\*\n]+", " ", aff_m.group(1)).strip()[:150] if aff_m else ""

        results.append({
            "id": cve_id,
            "title": summary or cve_id,
            "description": re.sub(r"\*\*|#+|\[([^\]]+)\]\([^)]+\)", r"\1", content).strip()[:500],
            "score": score,
            "severity": severity,
            "source": "Kubernetes",
            "published": pub,
            "references": [
                item.get("url", ""),
                item.get("external_url", ""),
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            ],
            "affected": [aff_text] if aff_text else [],
            "url": item.get("url", f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
        })

    log(f"  Kubernetes: {len(results)} CVEs")
    return results


# ---------------------------------------------------------------------------
# Source: Exploit-DB
# ---------------------------------------------------------------------------

def fetch_exploitdb(days=7):
    log("Fetching Exploit-DB...")
    # Use their JSON search API — RSS is often blocked by Cloudflare
    after = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    url = (
        "https://www.exploit-db.com/search"
        f"?date_from={after}&type=exploits&order_by=date_published&order=desc&draw=1&start=0&length=100"
    )
    raw = http_get(url, headers={
        "Accept": "application/json, text/javascript, */*",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://www.exploit-db.com/",
    })
    if not raw:
        log("  Exploit-DB: no response, skipping")
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as ex:
        log(f"  Exploit-DB JSON error: {ex}")
        return []

    results = []
    for item in data.get("data", []):
        eid   = str(item.get("id", ""))
        title = strip_html(item.get("description_main") or item.get("description") or "").strip()
        date  = (item.get("date_published") or item.get("date") or "")[:10]
        cve   = (item.get("codes") or "").strip()  # may be "CVE-XXXX-YYYY"
        etype = (item.get("type", {}) or {}).get("name", "") if isinstance(item.get("type"), dict) else ""
        platform = (item.get("platform", {}) or {}).get("name", "") if isinstance(item.get("platform"), dict) else ""

        cve_ids = re.findall(r"CVE-\d{4}-\d+", cve + " " + title)
        link = f"https://www.exploit-db.com/exploits/{eid}" if eid else ""
        pub  = f"{date}T00:00:00Z" if date else ""

        results.append({
            "id": cve_ids[0] if cve_ids else (f"EDB-{eid}" if eid else title[:20]),
            "title": title[:160],
            "description": f"[{etype}] [{platform}] {title}".strip("[] ") if (etype or platform) else title,
            "score": None,
            "severity": "HIGH",
            "source": "Exploit-DB",
            "published": pub,
            "references": [link] if link else [],
            "affected": ([etype] if etype else []) + ([platform] if platform else []) + cve_ids[:2],
            "url": link,
            "badge": "PUBLIC EXPLOIT",
        })

    log(f"  Exploit-DB: {len(results)} exploits")
    return results


# ---------------------------------------------------------------------------
# Source: Red Hat Security Advisories
# ---------------------------------------------------------------------------

def fetch_redhat(days=7):
    log(f"Fetching Red Hat CVEs (last {days} days)...")
    after = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    # Primary: new API endpoint (old /labs/securitydataapi/ is deprecated)
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=100&after={after}"
    raw = http_get(url, headers={"Accept": "application/json"})
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as ex:
        log(f"  Red Hat JSON error: {ex}")
        return []

    SEV_MAP = {"critical": "CRITICAL", "important": "HIGH", "moderate": "MEDIUM", "low": "LOW"}
    results = []

    for item in data:
        cve_id = item.get("CVE", "")
        if not cve_id:
            continue

        sev_raw = (item.get("severity") or "").lower()
        severity = SEV_MAP.get(sev_raw, "UNKNOWN")

        score = None
        cvss3 = item.get("cvss3", {}) or {}
        s3 = cvss3.get("cvss3_base_score")
        if s3:
            try:
                score = float(s3)
            except (ValueError, TypeError):
                pass
        if score is None:
            cvss2 = item.get("cvss", {}) or {}
            s2 = cvss2.get("cvss_base_score")
            if s2:
                try:
                    score = float(s2)
                except (ValueError, TypeError):
                    pass

        pub = item.get("public_date", "")
        bugzilla = item.get("bugzilla") or {}
        if not isinstance(bugzilla, dict):
            bugzilla = {}
        desc = bugzilla.get("description", "")

        # Affected packages from advisories
        affected = []
        for rel in (item.get("affected_release") or [])[:6]:
            pkg = rel.get("package", "")
            if pkg:
                affected.append(pkg)

        rhsa_refs = []
        for rhsa in (item.get("advisories") or [])[:3]:
            rhsa_id = rhsa if isinstance(rhsa, str) else rhsa.get("name", "")
            if rhsa_id:
                rhsa_refs.append(f"https://access.redhat.com/errata/{rhsa_id}")

        results.append({
            "id": cve_id,
            "title": desc[:160] if desc else cve_id,
            "description": desc,
            "score": score,
            "severity": severity,
            "source": "Red Hat",
            "published": pub,
            "references": [f"https://access.redhat.com/security/cve/{cve_id}"] + rhsa_refs,
            "affected": list(dict.fromkeys(affected))[:8],
            "url": f"https://access.redhat.com/security/cve/{cve_id}",
        })

    log(f"  Red Hat: {len(results)} CVEs")
    return results


# ---------------------------------------------------------------------------
# Source: OpenStack Security Notes (OSSNs)
# ---------------------------------------------------------------------------

def fetch_openstack_ossn(months=3):
    log(f"Fetching OpenStack Security Notes (last {months} months)...")
    cutoff = datetime.now(timezone.utc) - timedelta(days=months * 31)

    # Step 1: get the full OSSN list from the wiki index page
    list_url = (
        "https://wiki.openstack.org/w/api.php"
        "?action=query&titles=Security_Notes&prop=revisions&rvprop=content&format=json"
    )
    raw = http_get(list_url)
    if not raw:
        return []

    try:
        data = json.loads(raw)
        pages = data["query"]["pages"]
        list_content = next(iter(pages.values()))["revisions"][0]["*"]
    except (KeyError, StopIteration, json.JSONDecodeError) as ex:
        log(f"  OSSN list parse error: {ex}")
        return []

    # Extract OSSN IDs (highest numbers = most recent), e.g. OSSN-0099
    ossn_ids = list(dict.fromkeys(re.findall(r"OSSN-(\d{4})", list_content)))
    ossn_ids.sort(key=int, reverse=True)

    # Step 2: batch-fetch content + timestamp via API (10 per request)
    base_wiki = "https://wiki.openstack.org"
    results = []

    for i in range(0, min(len(ossn_ids), 60), 10):
        batch = ossn_ids[i:i + 10]
        titles = "|".join(f"OSSN/OSSN-{n}" for n in batch)
        api_url = (
            f"{base_wiki}/w/api.php"
            f"?action=query&titles={titles}"
            f"&prop=revisions&rvprop=timestamp|content&format=json"
        )
        raw2 = http_get(api_url)
        if not raw2:
            continue

        try:
            batch_data = json.loads(raw2)
        except json.JSONDecodeError:
            continue

        any_in_range = False
        for page in batch_data["query"]["pages"].values():
            if "revisions" not in page:
                continue

            rev = page["revisions"][0]
            ts_str = rev.get("timestamp", "")
            wikitext = rev.get("*", "")

            try:
                pub_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                pub_dt = None

            if pub_dt and pub_dt < cutoff:
                continue
            if pub_dt:
                any_in_range = True

            title = page.get("title", "")  # "OSSN/OSSN-0099"
            ossn_id = title.split("/")[-1]  # "OSSN-0099"

            # Extract summary section
            summary_m = re.search(
                r"=== Summary ===\s*(.+?)(?===)", wikitext, re.DOTALL
            )
            desc = summary_m.group(1).strip()[:500] if summary_m else ""

            # Extract title from first heading
            heading_m = re.search(r"^=\s*(.+?)\s*=$", wikitext, re.MULTILINE)
            note_title = heading_m.group(1).strip() if heading_m else ossn_id

            # Affected services
            aff_m = re.search(
                r"=== Affected Services[^=]*===\s*(.+?)(?===)", wikitext, re.DOTALL
            )
            aff_raw = aff_m.group(1).strip() if aff_m else ""
            # Strip wiki markup (* ironic: >=32.0.0 → "ironic: >=32.0.0")
            affected = [
                re.sub(r"[\*\[\]']", "", line).strip()
                for line in aff_raw.splitlines()
                if line.strip().startswith("*")
            ][:6]

            cves = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d+", wikitext)))
            ossn_url = f"{base_wiki}/wiki/OSSN/{ossn_id}"
            pub = pub_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if pub_dt else ""

            results.append({
                "id": cves[0] if cves else ossn_id,
                "title": f"{ossn_id}: {note_title}",
                "description": desc,
                "score": None,
                "severity": "UNKNOWN",
                "source": "OpenStack",
                "published": pub,
                "references": [ossn_url] + [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:2]],
                "affected": affected + cves[:3],
                "url": ossn_url,
            })

        time.sleep(0.5)
        # If none of this batch are in the cutoff window, stop — list is newest-first
        if not any_in_range and i > 0:
            break

    log(f"  OpenStack OSSN: {len(results)} notes")
    return results


# ---------------------------------------------------------------------------
# Source: OpenStack Security Advisories (OSSAs)
# ---------------------------------------------------------------------------

def fetch_openstack_ossa(months=3):
    log(f"Fetching OpenStack OSSAs (last {months} months)...")
    base = "https://security.openstack.org/"
    raw = http_get(base + "ossalist.html")
    if not raw:
        return []

    content = raw.decode("utf-8", errors="replace")

    # Build deduplicated list of (ossa_id, year, href)
    seen_hrefs = set()
    candidates = []
    for ossa_id, year in re.findall(r"ossa/(OSSA-(\d{4})-\d+)\.html", content):
        href = f"ossa/{ossa_id}.html"
        if href not in seen_hrefs:
            seen_hrefs.add(href)
            candidates.append((ossa_id, int(year), href))

    cutoff = datetime.now(timezone.utc) - timedelta(days=months * 31)
    current_year = datetime.now(timezone.utc).year
    # Pre-filter: only current year and previous year
    candidates = [(i, y, h) for i, y, h in candidates if y >= current_year - 1]

    results = []
    for ossa_id, year, href in candidates:
        raw2 = http_get(base + href)
        if not raw2:
            continue

        clean = re.sub(r"<[^>]+>", " ", raw2.decode("utf-8", errors="replace"))
        clean = re.sub(r"\s+", " ", clean).strip()

        # Date: "Date : June 04, 2026"
        pub = ""
        date_m = re.search(r"Date\s*:\s*(\w+ \d{1,2},?\s*\d{4})", clean)
        if date_m:
            try:
                date_str = re.sub(r"\s+", " ", date_m.group(1)).strip()
                pub_dt = datetime.strptime(date_str, "%B %d, %Y").replace(tzinfo=timezone.utc)
                if pub_dt < cutoff:
                    continue
                pub = pub_dt.strftime("%Y-%m-%dT00:00:00Z")
            except ValueError:
                pass

        cves = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d+", clean)))

        # Title: text immediately after "OSSA-YYYY-NNN: "
        title_m = re.search(rf"{re.escape(ossa_id)}:\s*([^¶\n]{{10,200}}?)(?:\s+{re.escape(ossa_id)}|¶)", clean)
        title = title_m.group(1).strip() if title_m else ossa_id

        # Description block (between "Description ¶" and next section header)
        desc_m = re.search(
            r"Description\s*¶\s*(.+?)(?=\s+(?:Errata|Affects|Affected|References|Acknowledgements)\s+¶)",
            clean, re.DOTALL
        )
        if not desc_m:
            desc_m = re.search(r"Description\s*¶\s*(.{50,})", clean, re.DOTALL)
        desc = (desc_m.group(1).strip()[:500] if desc_m else title)

        # Affected versions block
        aff_m = re.search(
            r"Affects\s*¶\s*(.+?)(?=\s+(?:Description|References|CVE|Errata)\s+¶)",
            clean, re.DOTALL
        )
        aff_text = aff_m.group(1).strip()[:150] if aff_m else ""

        ossa_url = base + href
        results.append({
            "id": cves[0] if cves else ossa_id,
            "title": f"{ossa_id}: {title}",
            "description": desc,
            "score": None,
            "severity": "UNKNOWN",
            "source": "OpenStack",
            "published": pub,
            "references": [ossa_url] + [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:2]],
            "affected": ([aff_text] if aff_text else []) + cves[:3],
            "url": ossa_url,
        })

        time.sleep(0.5)

    log(f"  OpenStack OSSA: {len(results)} advisories")
    return results


# ---------------------------------------------------------------------------
# Dedup & sort
# ---------------------------------------------------------------------------

def merge(vulns):
    """Deduplicate by CVE ID (highest CVSS wins); merge CISA badge into NVD entry."""
    by_cve = {}
    others = []

    for v in vulns:
        vid = v["id"]
        if not vid.startswith("CVE-"):
            others.append(v)
            continue
        if vid not in by_cve:
            by_cve[vid] = dict(v)
        else:
            existing = by_cve[vid]
            new_score = v.get("score") or 0
            old_score = existing.get("score") or 0
            if new_score > old_score:
                badge = existing.get("badge") or v.get("badge")
                by_cve[vid] = dict(v)
                if badge:
                    by_cve[vid]["badge"] = badge
            elif v.get("badge") and not existing.get("badge"):
                existing["badge"] = v["badge"]

    SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    combined = list(by_cve.values()) + others
    combined.sort(key=lambda v: (SEV.get(v.get("severity", "UNKNOWN"), 4), -(v.get("score") or 0)))
    return combined


# ---------------------------------------------------------------------------
# Individual CVE page template
# ---------------------------------------------------------------------------

_CVE_PAGE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>__CVE_TITLE_TAG__</title>
<meta name="description" content="__CVE_META_DESC__">
<meta property="og:title" content="__CVE_OG_TITLE__">
<meta property="og:description" content="__CVE_META_DESC__">
<meta property="og:type" content="article">
<meta name="twitter:card" content="summary">
<link rel="canonical" href="__CVE_CANONICAL__">
<link rel="alternate" type="application/rss+xml" title="vulnfeed" href="__BASE_URL__/feed.xml">
<script type="application/ld+json">__CVE_JSON_LD__</script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#f8fafc;color:#1e293b;line-height:1.6}
a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}
nav{background:#0f172a;padding:.75rem 2rem;display:flex;align-items:center;gap:1rem}
.nav-logo{font-size:1rem;font-weight:700;color:#f1f5f9}
.nav-logo em{color:#60a5fa;font-style:normal}
.nav-back{font-size:.8rem;color:#94a3b8}
.nav-back:hover{color:#cbd5e1;text-decoration:none}
main{max-width:820px;margin:2rem auto;padding:0 1.5rem 4rem}
.badges{display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:.8rem}
.b{display:inline-block;padding:.18rem .55rem;border-radius:5px;font-size:.72rem;
  font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#fff}
.bCRITICAL{background:#dc2626}.bHIGH{background:#ea580c}
.bMEDIUM{background:#d97706}.bLOW{background:#16a34a}.bUNKNOWN{background:#6b7280}
.bscore{background:#1e293b;font-family:ui-monospace,monospace}
.bsrc{background:#334155}.bkev{background:#7c3aed}
h1{font-size:1.55rem;font-weight:800;letter-spacing:-.02em;margin-bottom:.4rem;line-height:1.25}
.subtitle{font-size:.98rem;color:#475569;margin-bottom:1.3rem;font-weight:500}
.desc-box{background:#fff;border:1px solid #e2e8f0;border-radius:10px;
  padding:1.1rem 1.3rem;margin-bottom:1.4rem;font-size:.94rem;line-height:1.65;color:#334155}
h2{font-size:.85rem;font-weight:700;color:#64748b;text-transform:uppercase;
  letter-spacing:.06em;margin:1.3rem 0 .45rem;padding-bottom:.3rem;border-bottom:1px solid #e2e8f0}
ul.ref-list{list-style:none;display:flex;flex-direction:column;gap:.28rem}
ul.ref-list li{font-size:.85rem}
ul.ref-list li a{word-break:break-all}
ul.aff-list{list-style:none;display:flex;flex-direction:column;gap:.25rem}
ul.aff-list li{font-family:ui-monospace,monospace;font-size:.82rem;background:#f1f5f9;
  border:1px solid #e2e8f0;border-radius:4px;padding:.2rem .45rem;color:#334155}
.meta-line{font-size:.76rem;color:#94a3b8;margin-top:1.4rem;padding-top:.7rem;
  border-top:1px solid #e2e8f0}
.meta-line strong{color:#475569}
.cta{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;
  padding:.85rem 1.1rem;margin-top:1.4rem;font-size:.88rem;color:#1e3a8a;line-height:1.5}
.cta a{color:#2563eb;font-weight:600}
</style>
</head>
<body>
<nav>
  <a href="__BASE_URL__/" class="nav-logo">vuln<em>feed</em></a>
  <a href="__BASE_URL__/" class="nav-back">&#8592; all vulnerabilities</a>
</nav>
<main>
  <div class="badges">__CVE_BADGES__</div>
  <h1>__CVE_ID_ESC__</h1>
  <p class="subtitle">__CVE_TITLE_ESC__</p>
  <div class="desc-box">__CVE_DESC_ESC__</div>
__CVE_AFFECTED_HTML__
__CVE_REFS_HTML__
  <div class="meta-line">
    Published: <strong>__CVE_DATE__</strong> &middot;
    Source: <strong>__CVE_SRC_ESC__</strong> &middot;
    Feed updated: <strong>__BUILD_DATE__</strong>
  </div>
  <div class="cta">
    <a href="__BASE_URL__/">vulnfeed</a> aggregates __TOTAL_COUNT__ vulnerabilities from NVD, CISA KEV,
    Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, OSS-Security, GitHub and OpenStack &mdash; updated every 4 hours.
  </div>
</main>
</body>
</html>
"""


def write_cve_pages(vulns, date_str, base_url=BASE_URL):
    """Generate individual HTML pages for all proper CVE-YYYY-NNNNN entries."""
    candidates = [v for v in vulns if v["id"].startswith("CVE-")]
    seen, unique = set(), []
    for v in candidates:
        if v["id"] not in seen:
            seen.add(v["id"])
            unique.append(v)

    os.makedirs("cve", exist_ok=True)
    total = len(vulns)

    for v in unique:
        cve_id = v["id"]
        title  = v.get("title") or cve_id
        desc   = v.get("description") or title
        sev    = v.get("severity") or "UNKNOWN"
        score  = v.get("score")
        src    = v.get("source") or ""
        pub    = v.get("published") or ""
        badge  = v.get("badge") or ""
        refs   = [r for r in (v.get("references") or []) if r][:8]
        aff    = (v.get("affected") or [])[:12]

        try:
            pub_fmt = datetime.fromisoformat(pub.replace("Z", "+00:00")).strftime("%Y-%m-%d")
        except Exception:
            pub_fmt = pub[:10] if len(pub) >= 10 else "unknown"

        title_short = title[:80] + ("…" if len(title) > 80 else "")
        meta_desc   = _xe((desc[:157] + "…") if len(desc) > 157 else desc)

        badges_html  = f'<span class="b b{_xe(sev)}">{_xe(sev)}</span>'
        if score is not None:
            badges_html += f' <span class="b bscore">{score:.1f}</span>'
        badges_html += f' <span class="b bsrc">{_xe(src)}</span>'
        if badge:
            badges_html += f' <span class="b bkev">{_xe(badge)}</span>'

        if aff:
            aff_html = "  <h2>Affected Products</h2><ul class='aff-list'>" + \
                       "".join(f"<li>{_xe(a)}</li>" for a in aff) + "</ul>"
        else:
            aff_html = ""

        if refs:
            refs_html = "  <h2>References</h2><ul class='ref-list'>" + \
                        "".join(f'  <li><a href="{_xe(r)}" rel="noopener noreferrer" target="_blank">{_xe(r[:90])}</a></li>' for r in refs) + \
                        "</ul>"
        else:
            refs_html = ""

        ld = {
            "@context": "https://schema.org",
            "@type": "Article",
            "headline": f"{cve_id}: {title_short}",
            "description": desc[:200],
            "datePublished": pub_fmt,
            "url": f"{base_url}/cve/{cve_id}.html",
            "publisher": {"@type": "Organization", "name": "vulnfeed", "url": base_url},
        }

        page = _CVE_PAGE_HTML
        page = page.replace("__CVE_TITLE_TAG__",      _xe(f"{cve_id}: {title_short} | vulnfeed"))
        page = page.replace("__CVE_META_DESC__",       meta_desc)
        page = page.replace("__CVE_OG_TITLE__",        _xe(f"{cve_id}: {title_short}"))
        page = page.replace("__CVE_CANONICAL__",       f"{base_url}/cve/{cve_id}.html")
        page = page.replace("__CVE_JSON_LD__",         json.dumps(ld, ensure_ascii=False))
        page = page.replace("__CVE_BADGES__",          badges_html)
        page = page.replace("__CVE_ID_ESC__",          _xe(cve_id))
        page = page.replace("__CVE_TITLE_ESC__",       _xe(title))
        page = page.replace("__CVE_DESC_ESC__",        _xe(desc))
        page = page.replace("__CVE_AFFECTED_HTML__",   aff_html)
        page = page.replace("__CVE_REFS_HTML__",       refs_html)
        page = page.replace("__CVE_DATE__",            pub_fmt)
        page = page.replace("__CVE_SRC_ESC__",         _xe(src))
        page = page.replace("__BUILD_DATE__",          date_str)
        page = page.replace("__TOTAL_COUNT__",         str(total))
        page = page.replace("__BASE_URL__",            base_url)

        with open(os.path.join("cve", f"{cve_id}.html"), "w", encoding="utf-8") as f:
            f.write(page)

    log(f"  Written: {len(unique)} CVE pages → cve/")
    return unique


def write_sitemap(cve_pages, date_str, base_url=BASE_URL, vendor_pages=None):
    def url_entry(loc, freq, pri):
        return (
            f"  <url><loc>{loc}</loc>"
            f"<lastmod>{date_str}</lastmod>"
            f"<changefreq>{freq}</changefreq>"
            f"<priority>{pri}</priority></url>"
        )

    entries = [url_entry(f"{base_url}/", "hourly", "1.0")]
    entries.append(url_entry(f"{base_url}/stats.html", "daily", "0.7"))
    for vp in (vendor_pages or []):
        entries.append(url_entry(f"{base_url}/vendor/{vp['slug']}.html", "daily", "0.7"))
    for v in cve_pages:
        entries.append(url_entry(f"{base_url}/cve/{v['id']}.html", "weekly", "0.8"))

    with open("sitemap.xml", "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
        f.write("\n".join(entries))
        f.write("\n</urlset>")
    log(f"  Written: sitemap.xml ({len(entries)} URLs)")


def write_robots(base_url=BASE_URL):
    with open("robots.txt", "w", encoding="utf-8") as f:
        f.write(f"User-agent: *\nAllow: /\nSitemap: {base_url}/sitemap.xml\n")
    log("  Written: robots.txt")


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>vulnfeed &mdash; __DATE__</title>
<link rel="alternate" type="application/rss+xml" title="vulnfeed" href="/feed.xml">
<meta name="description" content="vulnfeed — __COUNT__ security vulnerabilities aggregated from NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, OSS-Security, GitHub and OpenStack. Updated every 4 hours.">
<meta property="og:title" content="vulnfeed — daily CVE digest">
<meta property="og:description" content="__COUNT__ vulnerabilities aggregated from NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes and more. Updated every 4 hours.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://nightwatch.sami.pw/">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="vulnfeed — daily CVE digest">
<meta name="twitter:description" content="__COUNT__ CVEs from NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, OSS-Security, GitHub and OpenStack. Updated every 4 hours.">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"vulnfeed","url":"https://nightwatch.sami.pw","description":"Daily security vulnerability feed aggregating NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, OSS-Security, GitHub and OpenStack."}</script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;
  --accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9;
  --crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--unk:#6b7280;
  --sha:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.04);
}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:var(--bg);color:var(--text);line-height:1.5}

header{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem}
.logo{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}
.logo em{color:#60a5fa;font-style:normal}
.hmeta{font-size:.78rem;color:#94a3b8}
.hsel{background:#1e293b;color:#cbd5e1;border:1px solid #334155;border-radius:5px;
  padding:.22rem .5rem;font-size:.74rem;cursor:pointer;outline:none}
.hsel:hover,.hsel:focus{border-color:#475569}
.hlink{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;
  border:1px solid #334155;border-radius:4px;white-space:nowrap;font-weight:600}
.hlink:hover{border-color:#60a5fa;background:rgba(96,165,250,.08)}

.bar{background:#fff;border-bottom:1px solid var(--border);padding:.7rem 2rem;
  position:sticky;top:0;z-index:20;box-shadow:0 2px 8px rgba(0,0,0,.05)}
.srow{display:flex;align-items:center;gap:.6rem;margin-bottom:.55rem}
#search{flex:1;max-width:580px;padding:.5rem .9rem .5rem 2.3rem;font-size:.92rem;
  border:2px solid var(--border);border-radius:7px;outline:none;
  background:var(--bg) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%2364748b' stroke-width='2'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' d='M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z'/%3E%3C/svg%3E") no-repeat .6rem center/.9rem;
  transition:border-color .15s}
#search:focus{border-color:var(--accent)}
#clear{display:none;font-size:.78rem;color:var(--accent);cursor:pointer;border:none;background:none;padding:0;white-space:nowrap}
#clear:hover{text-decoration:underline}

.pills{display:flex;flex-wrap:wrap;gap:.3rem;align-items:center;margin-bottom:.4rem}
.pills:last-child{margin-bottom:0}
.sep{width:1px;height:16px;background:var(--border);margin:0 .1rem}
.plabel{font-size:.7rem;color:var(--muted);font-weight:600;white-space:nowrap;margin-right:.1rem}
.pill{display:inline-flex;align-items:center;padding:.18rem .6rem;border-radius:999px;
  border:1.5px solid var(--border);font-size:.73rem;font-weight:600;cursor:pointer;
  color:var(--muted);background:var(--bg);transition:all .12s;user-select:none}
.pill:hover{border-color:var(--accent);color:var(--accent)}
.pill.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.pill[data-sev="CRITICAL"].on{background:var(--crit);border-color:var(--crit)}
.pill[data-sev="HIGH"].on{background:var(--high);border-color:var(--high)}
.pill[data-sev="MEDIUM"].on{background:var(--med);border-color:var(--med)}
.pill[data-sev="LOW"].on{background:var(--low);border-color:var(--low)}

.stats{padding:.35rem 2rem;font-size:.76rem;color:var(--muted);
  display:flex;justify-content:space-between;align-items:center}
.stats strong{color:var(--text)}
kbd{background:#f1f5f9;padding:.1rem .3rem;border-radius:3px;border:1px solid #cbd5e1;font-size:.73rem}

#grid{padding:.75rem 2rem 3rem;display:grid;
  grid-template-columns:repeat(auto-fill,minmax(370px,1fr));gap:.85rem}

.card{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--border);
  border-radius:10px;padding:.85rem 1rem;box-shadow:var(--sha);
  display:flex;flex-direction:column;gap:.4rem;transition:box-shadow .15s}
.card:hover{box-shadow:0 4px 14px rgba(0,0,0,.1)}
.card[data-sev="CRITICAL"]{border-left-color:var(--crit)}
.card[data-sev="HIGH"]{border-left-color:var(--high)}
.card[data-sev="MEDIUM"]{border-left-color:var(--med)}
.card[data-sev="LOW"]{border-left-color:var(--low)}

.ctop{display:flex;align-items:flex-start;justify-content:space-between;gap:.4rem;flex-wrap:wrap}
.cid{font-family:ui-monospace,"Cascadia Code",monospace;font-size:.78rem;font-weight:700;
  color:var(--accent);text-decoration:none}
.cid:hover{text-decoration:underline}
.share-btn{background:none;border:none;padding:.15rem .2rem;cursor:pointer;
  color:#94a3b8;border-radius:3px;display:inline-flex;align-items:center;
  transition:color .12s,background .12s;vertical-align:middle;flex-shrink:0}
.share-btn:hover{color:var(--accent);background:#f1f5f9}
.bdgs{display:flex;gap:.28rem;flex-wrap:wrap;align-items:center}
.b{display:inline-block;padding:.1rem .42rem;border-radius:4px;font-size:.65rem;
  font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#fff}
.bCRITICAL{background:var(--crit)}.bHIGH{background:var(--high)}
.bMEDIUM{background:var(--med)}.bLOW{background:var(--low)}.bUNKNOWN{background:var(--unk)}
.bsrc{background:#334155;font-size:.62rem}
.bxpl{background:#7c3aed}
.bsc{background:#1e293b;font-family:ui-monospace,monospace}
.bepss{background:#0d9488;font-size:.62rem}
.bnew{background:#059669;animation:npulse 2s ease-in-out infinite}
@keyframes npulse{0%,100%{opacity:1}50%{opacity:.6}}
.src-dot{display:inline-block;width:5px;height:5px;border-radius:50%;margin-left:3px;vertical-align:middle;flex-shrink:0}

.ctitle{font-size:.85rem;font-weight:600;line-height:1.4}
.cdesc{font-size:.78rem;color:var(--muted);line-height:1.55;
  display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.chips{display:flex;flex-wrap:wrap;gap:.22rem;margin-top:.02rem}
.chip{background:#f1f5f9;color:#475569;border-radius:4px;padding:.07rem .38rem;
  font-size:.68rem;font-family:ui-monospace,monospace;font-weight:500}
.refs{font-size:.71rem;color:var(--muted);display:flex;flex-wrap:wrap;gap:.35rem;margin-top:.02rem}
.refs a{color:var(--accent);text-decoration:none}.refs a:hover{text-decoration:underline}
.cdate{font-size:.67rem;color:#94a3b8;margin-top:.08rem}

.today-badge{display:inline-flex;align-items:center;gap:.4rem;background:#0c2340;
  border:1px solid #2563eb;border-radius:6px;padding:.28rem .65rem;font-size:.8rem;font-weight:700;color:#60a5fa}
.today-dot{width:7px;height:7px;border-radius:50%;background:#22d3ee;flex-shrink:0;
  box-shadow:0 0 6px #22d3ee;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.sev-brk{font-size:.69rem;color:#475569;margin-top:.28rem;display:flex;gap:.55rem;flex-wrap:wrap}
.sev-brk b{font-weight:700}
.sc{color:#f87171}.sh{color:#fb923c}.sm{color:#fbbf24}.sl{color:#4ade80}

#hist-banner{display:none;background:#1e3a5f;color:#93c5fd;font-size:.79rem;font-weight:600;
  padding:.38rem 2rem;border-bottom:1px solid #1d4ed8;text-align:center}

.view-btn{padding:.22rem .65rem;border-radius:5px;border:1.5px solid var(--border);
  font-size:.74rem;font-weight:600;cursor:pointer;color:var(--muted);background:var(--bg);
  transition:all .12s}
.view-btn.on{background:var(--accent);color:#fff;border-color:var(--accent)}
#news-badge{background:#334155;color:#fff;border-radius:10px;padding:.04rem .32rem;
  font-size:.63rem;margin-left:.2rem}

#news-panel{display:none;padding:.75rem 2rem 3rem}
.news-item{background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:.6rem .9rem;margin-bottom:.4rem}
.news-row{display:flex;align-items:center;gap:.4rem;flex-wrap:wrap}
.news-title{font-size:.84rem;font-weight:600;color:var(--text);text-decoration:none;flex:1;min-width:0}
.news-title:hover{color:var(--accent);text-decoration:underline}
.news-meta{display:flex;gap:.5rem;align-items:center;white-space:nowrap;font-size:.68rem;color:#94a3b8}
.news-meta a{color:var(--accent);text-decoration:none}
.news-meta a:hover{text-decoration:underline}
.news-desc{font-size:.75rem;color:var(--muted);margin-top:.25rem;line-height:1.45}

#chart-wrap{background:var(--hdr);padding:.6rem 2rem .7rem;border-bottom:1px solid #1e293b}
#chart-title{font-size:.65rem;color:#475569;margin-bottom:.55rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase}
#chart{position:relative;height:64px}
#chart svg{position:absolute;inset:0;width:100%;height:100%;overflow:visible}
.chart-lbl-row{display:flex;margin-top:3px}
.chart-lbl-row span{flex:1;text-align:center;font-size:.6rem;color:#334155}

.card{cursor:pointer}
.card.expanded .cdesc{display:block!important;-webkit-line-clamp:unset!important;overflow:visible!important}

#empty{display:none;text-align:center;padding:4rem 2rem;color:var(--muted)}
#empty h2{font-size:1.05rem;margin-bottom:.35rem;color:var(--text)}
#sentinel{height:1px}

#seo-index{padding:1rem 2rem 2rem;border-top:1px solid var(--border);margin-top:.5rem}
#seo-index h2{font-size:.72rem;font-weight:700;color:var(--muted);text-transform:uppercase;
  letter-spacing:.07em;margin-bottom:.55rem}
#seo-index ul{list-style:none;display:grid;
  grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:.2rem}
#seo-index li{font-size:.72rem;color:var(--muted);padding:.15rem .2rem;line-height:1.4}
#seo-index li a{color:var(--accent);font-family:ui-monospace,monospace;font-size:.7rem;font-weight:600}
#seo-index small{color:#94a3b8;margin-left:.25rem}

/* Watchlist */
.card.watched{outline:2px solid #f59e0b;outline-offset:-1px}
.bwl{background:#f59e0b;color:#1e293b!important}
#wl-panel{display:none;background:#1c1917;border-bottom:1px solid #292524;padding:.45rem 2rem;align-items:center;gap:.5rem;flex-wrap:wrap}
#wl-panel.open{display:flex}
#wl-input{background:#292524;border:1px solid #44403c;border-radius:5px;color:#e7e5e4;
  font-size:.78rem;padding:.28rem .6rem;outline:none;width:220px}
#wl-input:focus{border-color:#f59e0b}
#wl-add{background:#f59e0b;color:#1e293b;border:none;border-radius:5px;padding:.28rem .65rem;
  font-size:.78rem;font-weight:700;cursor:pointer}
#wl-add:hover{background:#fbbf24}
.wl-tag{display:inline-flex;align-items:center;gap:.3rem;background:#292524;border:1px solid #44403c;
  border-radius:999px;padding:.15rem .55rem;font-size:.72rem;color:#e7e5e4}
.wl-tag button{background:none;border:none;color:#78716c;cursor:pointer;font-size:.8rem;
  padding:0 .1rem;line-height:1}
.wl-tag button:hover{color:#f87171}
#wl-hits{font-size:.72rem;color:#a8a29e;margin-left:.3rem}
#wl-only{font-size:.72rem;color:#f59e0b;cursor:pointer;background:none;border:1px solid #f59e0b;
  border-radius:5px;padding:.2rem .55rem;font-weight:600}
#wl-only.on{background:#f59e0b;color:#1e293b}

@media(max-width:640px){
  header,#chart-wrap,.bar,.stats,#grid,#wl-panel{padding-left:1rem;padding-right:1rem}
  #grid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">vuln<em>feed</em></div>
    <div class="hmeta">__DATE__ &middot; __COUNT__ vulnerabilities</div>
    <div class="sev-brk" id="sevBrk"></div>
  </div>
  <div style="text-align:right">
    <div class="today-badge"><span class="today-dot"></span><span id="todayN">&#8203;</span> new today &nbsp;<span id="todayDelta" style="font-size:.7rem;font-weight:500;opacity:.85"></span></div>
    <div class="hmeta" style="margin-top:.35rem">NVD &middot; Ubuntu &middot; Debian &middot; CISA KEV &middot; OSS-Security &middot; OpenStack &middot; Kubernetes &middot; Exploit-DB &middot; Red Hat &middot; GitHub &middot; OSV</div>
    <div style="margin-top:.5rem;display:flex;gap:.4rem;align-items:center;justify-content:flex-end;flex-wrap:wrap">
      <select id="datePicker" class="hsel"><option value="">Today (live)</option></select>
      <a class="hlink" href="/stats.html">Stats</a>
      <a class="hlink" href="/feed.xml">&#9656;&nbsp;RSS</a>
      <a class="hlink" href="/vulns.json">{&nbsp;}&nbsp;JSON</a>
    </div>
  </div>
</header>
<div id="hist-banner"></div>
<div id="wl-panel">
  <span style="font-size:.72rem;color:#a8a29e;font-weight:600;white-space:nowrap">&#9733; Watchlist keywords:</span>
  <div id="wl-tags" style="display:flex;flex-wrap:wrap;gap:.3rem"></div>
  <input id="wl-input" type="text" placeholder="add keyword…" autocomplete="off" spellcheck="false">
  <button id="wl-add">Add</button>
  <button id="wl-only">Show only</button>
  <span id="wl-hits"></span>
</div>

<div id="chart-wrap">
  <div id="chart-title">Vulnerabilities — last 14 days</div>
  <div id="chart"></div>
</div>

<div class="bar">
  <div class="srow">
    <input id="search" type="search" placeholder="Search: nginx, openstack, kernel, apache, log4j..." autocomplete="off" spellcheck="false">
    <button id="clear">Clear</button>
  </div>
  <div class="pills">
    <button class="pill on" data-sev="ALL">All Severity</button>
    <button class="pill" data-sev="CRITICAL">Critical</button>
    <button class="pill" data-sev="HIGH">High</button>
    <button class="pill" data-sev="MEDIUM">Medium</button>
    <button class="pill" data-sev="LOW">Low</button>
    <button class="pill" data-sev="UNKNOWN">Unknown</button>
    <div class="sep"></div>
    <button class="pill on" data-src="ALL">All Sources</button>
    <button class="pill" data-src="NVD">NVD</button>
    <button class="pill" data-src="Ubuntu">Ubuntu</button>
    <button class="pill" data-src="Debian">Debian</button>
    <button class="pill" data-src="CISA-KEV">CISA KEV</button>
    <button class="pill" data-src="OSS-Security">OSS-Security</button>
    <button class="pill" data-src="OpenStack">OpenStack</button>
    <button class="pill" data-src="Kubernetes">Kubernetes</button>
    <button class="pill" data-src="Exploit-DB">Exploit-DB</button>
    <button class="pill" data-src="Red Hat">Red Hat</button>
    <button class="pill" data-src="GitHub">GitHub</button>
    <button class="pill" data-src="OSV">OSV</button>
  </div>
  <div class="pills">
    <span class="plabel">Period:</span>
    <button class="pill" data-range="ALL">All time</button>
    <button class="pill on" data-range="24H">Last 24h</button>
    <button class="pill" data-range="7D">Last 7 days</button>
    <button class="pill" data-range="30D">Last 30 days</button>
    <button class="pill" data-range="1Y">Last year</button>
    <div class="sep"></div>
    <button class="pill" id="newPill">New since yesterday</button>
    <button class="pill" id="wlPill">&#9733;&nbsp;Watchlist</button>
    <div class="sep"></div>
    <span class="plabel">Sort:</span>
    <button class="pill" data-sort="SEVERITY">Severity</button>
    <button class="pill on" data-sort="DATE">Newest first</button>
    <button class="pill" data-sort="SCORE">Score</button>
    <button class="pill" data-sort="EPSS">EPSS</button>
  </div>
</div>

<div class="stats">
  <span>Showing <strong id="vis">0</strong> of <strong>__COUNT__</strong> &nbsp;<span id="shint" style="display:none">— Press <kbd>Esc</kbd> to clear</span></span>
  <div style="display:flex;gap:.35rem;align-items:center">
    <button class="view-btn on" data-view="vulns">Vulnerabilities</button>
    <button class="view-btn" data-view="news">Security News <span id="news-badge">0</span></button>
  </div>
</div>

<div id="grid"></div>
<div id="empty"><h2>No results</h2><p>Try a different keyword or clear the filters.</p></div>
<div id="sentinel"></div>
<div id="news-panel"></div>

<script>
let D=__JSON__;
const D_TODAY=D;
const DATES=__DATES_JSON__;
const NEWS=__NEWS_JSON__;
const HEALTH=__HEALTH__;

D.forEach(v=>{v._ts=v.published?new Date(v.published).getTime()||0:0});
NEWS.forEach(n=>{n._ts=n.published?new Date(n.published).getTime()||0:0});

const SEV=v=>v.severity||"UNKNOWN";
function esc(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}
function host(u){try{return new URL(u).hostname}catch(_){return String(u).slice(0,30)}}
function timeAgo(ts){
  if(!ts)return"";
  const d=Date.now()-ts,m=Math.floor(d/60000);
  if(m<2)return"just now";if(m<60)return m+"m ago";
  const h=Math.floor(m/60);if(h<24)return h+"h ago";
  const dy=Math.floor(h/24);if(dy<7)return dy+"d ago";
  const w=Math.floor(dy/7);if(w<5)return w+"w ago";
  return new Date(ts).toLocaleDateString(undefined,{month:"short",day:"numeric",year:"numeric"});
}

const DAY=864e5,now=Date.now();

// Today badge (always live data)
(function(){
  const tc=D_TODAY.filter(v=>v._ts&&(now-v._ts)<DAY).length;
  const yc=D_TODAY.filter(v=>v._ts&&(now-v._ts)>=DAY&&(now-v._ts)<2*DAY).length;
  document.getElementById("todayN").textContent=tc;
  if(yc>0){
    const pct=Math.round((tc-yc)/yc*100),sign=pct>=0?"+":"";
    const col=pct>0?"#4ade80":pct<0?"#f87171":"#94a3b8";
    document.getElementById("todayDelta").innerHTML=`<span style="color:${col}">${sign}${pct}% vs yesterday</span>`;
  }
})();

function updateSevBrk(){
  const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  D.forEach(v=>{const s=SEV(v);if(s in cnt)cnt[s]++;});
  document.getElementById("sevBrk").innerHTML=
    `<b class="sc">CRIT ${cnt.CRITICAL}</b><b class="sh">HIGH ${cnt.HIGH}</b>`+
    `<b class="sm">MED ${cnt.MEDIUM}</b><b class="sl">LOW ${cnt.LOW}</b>`;
}
updateSevBrk();

// 14-day multi-severity chart (always live data)
(function(){
  const DAYS=14,VW=600,VH=64,PAD=6;
  const SERIES=[
    {sev:"CRITICAL", color:"#dc2626", label:"Critical"},
    {sev:"HIGH",     color:"#ea580c", label:"High"},
    {sev:"MEDIUM",   color:"#d97706", label:"Medium"},
  ];
  const labels=Array.from({length:DAYS},(_,i)=>
    new Date(now-(DAYS-1-i)*DAY).toLocaleDateString(undefined,{weekday:"short"})
  );
  const xs=Array.from({length:DAYS},(_,i)=>PAD+(i/(DAYS-1))*(VW-PAD*2));

  SERIES.forEach(s=>{
    const c=Array(DAYS).fill(0);
    D_TODAY.forEach(v=>{
      if(!v._ts||SEV(v)!==s.sev)return;
      const i=Math.floor((now-v._ts)/DAY);
      if(i>=0&&i<DAYS)c[i]++;
    });
    s.vals=c.slice().reverse();
  });

  const maxV=Math.max(...SERIES.flatMap(s=>s.vals),1);

  let paths="";
  SERIES.forEach(s=>{
    const ys=s.vals.map(n=>PAD+(1-n/maxV)*(VH-PAD*2));
    // Use M (moveto) for zero-count days so lines don't connect through them
    let line="";
    xs.forEach((x,i)=>{
      const y=ys[i].toFixed(1);
      if(s.vals[i]===0){line+=`M${x.toFixed(1)},${y} `;}
      else if(i===0||s.vals[i-1]===0){line+=`M${x.toFixed(1)},${y} `;}
      else{line+=`L${x.toFixed(1)},${y} `;}
    });
    // Only draw dots for non-zero days
    const dots=xs.map((x,i)=>{
      if(s.vals[i]===0)return"";
      const t=i===DAYS-1;
      return `<circle cx="${x.toFixed(1)}" cy="${ys[i].toFixed(1)}" r="${t?3.5:2}" fill="${s.color}" fill-opacity="${t?1:.65}"><title>${labels[i]}: ${s.vals[i]} ${s.label}</title></circle>`;
    }).join("");
    paths+=`<path d="${line}" fill="none" stroke="${s.color}" stroke-width="1.8" stroke-opacity="0.85" stroke-linejoin="round" stroke-linecap="round"/>${dots}`;
  });

  const legend=SERIES.map(s=>
    `<span style="display:inline-flex;align-items:center;gap:.3rem;font-size:.6rem;color:${s.color};font-weight:600">
      <svg width="14" height="3" viewBox="0 0 14 3"><line x1="0" y1="1.5" x2="14" y2="1.5" stroke="${s.color}" stroke-width="2"/></svg>${s.label}</span>`
  ).join("");

  document.getElementById("chart").innerHTML=
    `<svg viewBox="0 0 ${VW} ${VH}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">${paths}</svg>`+
    '<div class="chart-lbl-row">'+labels.map((l,i)=>`<span style="${i===DAYS-1?"color:#94a3b8;font-weight:600":""}">${l}</span>`).join("")+'</div>'+
    `<div style="display:flex;gap:.85rem;margin-top:.3rem;padding-left:${PAD}px">${legend}</div>`;
})();

function hasCvePage(v){
  return v.id.startsWith("CVE-");
}
function copyLink(btn,path){
  const url=location.origin+path;
  navigator.clipboard.writeText(url).then(()=>{
    const prev=btn.innerHTML;
    btn.textContent="✓";btn.style.color="#4ade80";
    setTimeout(()=>{btn.innerHTML=prev;btn.style.color="";},1500);
  }).catch(()=>prompt("Copy link:",url));
}

function isWatched(v){
  if(!watchlist.length)return false;
  const hay=[v.id,v.title,v.description,...(v.affected||[])].join(" ").toLowerCase();
  return watchlist.some(kw=>hay.includes(kw));
}
function card(v){
  const sc=v.score!=null?`<span class="b bsc">${v.score.toFixed(1)}</span>`:"";
  const sv=`<span class="b b${SEV(v)}">${SEV(v)}</span>`;
  const sr=`<span class="b bsrc">${esc(v.source)}</span>`;
  const xp=v.badge?`<span class="b bxpl">${esc(v.badge)}</span>`:"";
  const ep=v.epss!=null?`<span class="b bepss" title="EPSS score: ${(v.epss*100).toFixed(2)}% probability of exploitation">EPSS ${v.epss_pct}%ile</span>`:"";
  const nw=v._new?`<span class="b bnew">NEW</span>`:"";
  const wl=isWatched(v)?`<span class="b bwl">&#9733;</span>`:"";
  const aff=(v.affected||[]).slice(0,6).map(a=>`<span class="chip">${esc(a)}</span>`).join("");
  const rfs=(v.references||[]).filter(Boolean).slice(0,3).map(u=>`<a href="${esc(u)}" target="_blank" rel="noopener">${esc(host(u))}</a>`).join(" &middot; ");
  const ttl=v.title&&v.title!==v.description?`<div class="ctitle">${esc(v.title)}</div>`:"";
  const dsc=v.description?`<div class="cdesc">${esc(v.description)}</div>`:"";
  const dt=v._ts?`<div class="cdate">${timeAgo(v._ts)}</div>`:"";
  const sharePath=hasCvePage(v)?`/cve/${v.id}.html`:`/#q=${encodeURIComponent(v.id)}`;
  const shareBtn=`<button class="share-btn" title="Copy link" onclick="event.stopPropagation();copyLink(this,'${sharePath}')" aria-label="Copy link"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></button>`;
  const watchedCls=isWatched(v)?" watched":"";
  return `<div class="card${watchedCls}" data-sev="${SEV(v)}" onclick="this.classList.toggle('expanded')"><div class="ctop"><div style="display:flex;align-items:center;gap:.3rem"><a class="cid" href="${esc(v.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(v.id)}</a>${shareBtn}</div><div class="bdgs">${wl}${nw}${sc}${sv}${sr}${ep}${xp}</div></div>${ttl}${dsc}${aff?`<div class="chips">${aff}</div>`:""}${rfs?`<div class="refs">${rfs}</div>`:""}${dt}</div>`;
}

function newsItem(n){
  const src=`<span class="b bsrc" style="flex-shrink:0">${esc(n.source)}</span>`;
  const sc=n.score!=null?`${n.score}pts`:""
  const cmt=n.comments_url?`<a href="${esc(n.comments_url)}" target="_blank" rel="noopener">${n.comments} comments</a>`:"";
  const dt=n._ts?timeAgo(n._ts):"";
  const meta=[sc,cmt,dt].filter(Boolean).join(" · ");
  const desc=n.description?`<div class="news-desc">${esc(n.description)}</div>`:"";
  return `<div class="news-item"><div class="news-row">${src}<a class="news-title" href="${esc(n.url)}" target="_blank" rel="noopener">${esc(n.title)}</a><div class="news-meta">${meta}</div></div>${desc}</div>`;
}

// Tier 2 — core OS/runtime: compromise = everything below it is suspect
const BOOST2=[
  "linux kernel","glibc","openssl","openssh","sudo","polkit","systemd","dbus",
  "kerberos","bind9","ntp ","gnutls","nss ","libssl","pam ","libc "
];
// Tier 1 — widely-deployed infrastructure
const BOOST1=[
  "kubernetes","k8s","nginx","apache httpd","apache2","httpd","docker",
  "containerd","runc","openstack","traefik","envoy","istio","etcd","cilium",
  "helm","redis","postgresql","mysql","mariadb","mongodb","elasticsearch",
  "kafka","rabbitmq","grafana","prometheus","alertmanager","loki",
  "vault","terraform","ansible","jenkins","gitlab","github enterprise",
  "log4j","log4shell","spring framework","spring boot","openshift",
  "rancher","harbor","argo","flux","trivy","falco","curl","python",
  "ruby on rails","node.js","django","flask","express"
];
// Tier -1 — real CVEs but low signal for infrastructure teams
const DEMOTE=[
  // WordPress ecosystem plugins (not WP core itself)
  "woocommerce","elementor","wpforms","contact form 7","yoast","w3 total cache",
  "wordfence","ninja forms","gravity forms","wpdiscuz","litespeed cache",
  "all in one seo","wp statistics","wp super cache","jetpack","akismet",
  "wp-file-manager","advanced custom fields","forminator",
  // CMS extensions
  "joomla extension","joomla plugin","joomla component",
  "drupal module","magento extension","prestashop module",
  // Intentionally-vulnerable training apps
  "multijuicer","juiceshop","juice shop","dvwa","webgoat","bodgeit",
  // Niche consumer software unlikely to be in server infrastructure
  "itunes","winamp","vlc media"
];

function priority(v){
  const hay=[v.id,v.title,v.description,...(v.affected||[])].join(" ").toLowerCase();
  if(DEMOTE.some(t=>hay.includes(t)))return -1;
  if(BOOST2.some(t=>hay.includes(t)))return 2;
  if(BOOST1.some(t=>hay.includes(t)))return 1;
  return 0;
}

const RANGES={"24H":864e5,"7D":6048e5,"30D":2592e6,"1Y":31536e6,"ALL":Infinity};
const SEV_ORDER={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"UNKNOWN":4};
let aSev="ALL",aSrc="ALL",aRange="24H",aSort="DATE",aNew=false,aWlOnly=false,q="";

// --- Watchlist ---
let watchlist=JSON.parse(localStorage.getItem("vf_watchlist")||"[]");
function saveWl(){localStorage.setItem("vf_watchlist",JSON.stringify(watchlist));}
function renderWlTags(){
  const ct=document.getElementById("wl-tags");
  ct.innerHTML=watchlist.map((kw,i)=>
    `<span class="wl-tag">${esc(kw)}<button onclick="removeWl(${i})" title="Remove">&#10005;</button></span>`
  ).join("");
  updateWlHits();
}
function updateWlHits(){
  const hits=watchlist.length?D.filter(isWatched).length:0;
  document.getElementById("wl-hits").textContent=watchlist.length?`${hits} match${hits!==1?"es":""}${aWlOnly?" (filtered)":""}` :"";
}
function removeWl(i){watchlist.splice(i,1);saveWl();renderWlTags();applyFilters();}
const wlOnlyBtn=document.getElementById("wl-only");
const wlPanel=document.getElementById("wl-panel");
const wlPill=document.getElementById("wlPill");
wlPill.addEventListener("click",()=>{
  const open=wlPanel.classList.toggle("open");
  wlPill.classList.toggle("on",open);
  if(open)document.getElementById("wl-input").focus();
});
document.getElementById("wl-add").addEventListener("click",()=>{
  const inp=document.getElementById("wl-input");
  const kw=inp.value.trim().toLowerCase();
  if(kw&&!watchlist.includes(kw)){watchlist.push(kw);saveWl();renderWlTags();applyFilters();}
  inp.value="";inp.focus();
});
document.getElementById("wl-input").addEventListener("keydown",ev=>{
  if(ev.key==="Enter"){document.getElementById("wl-add").click();}
});
wlOnlyBtn.addEventListener("click",()=>{
  aWlOnly=!aWlOnly;wlOnlyBtn.classList.toggle("on",aWlOnly);applyFilters();
});
renderWlTags();

// --- Source health dots ---
document.querySelectorAll('.pill[data-src]').forEach(b=>{
  const src=b.dataset.src;
  if(src==="ALL")return;
  const count=HEALTH[src]||0;
  const dot=document.createElement("span");
  dot.className="src-dot";
  dot.style.background=count>0?"#22c55e":"#ef4444";
  dot.title=count>0?`${count} entries this run`:"No data this run";
  b.appendChild(dot);
});

const grid=document.getElementById("grid");
const emptyEl=document.getElementById("empty");
const visEl=document.getElementById("vis");
const shint=document.getElementById("shint");
const clearBtn=document.getElementById("clear");
const histBanner=document.getElementById("hist-banner");
const newsPanel=document.getElementById("news-panel");
const sentinelEl=document.getElementById("sentinel");

// --- URL hash state ---
function pushHash(){
  const p=new URLSearchParams();
  if(q)p.set("q",q);if(aSev!=="ALL")p.set("sev",aSev);if(aSrc!=="ALL")p.set("src",aSrc);
  if(aRange!=="24H")p.set("range",aRange);if(aSort!=="DATE")p.set("sort",aSort);
  if(aNew)p.set("new","1");
  const s=p.toString();history.replaceState(null,"",s?"#"+s:"#");
}
function applyHash(){
  const h=location.hash.slice(1);if(!h)return;
  const p=new URLSearchParams(h);
  q=p.get("q")||"";aSev=p.get("sev")||"ALL";aSrc=p.get("src")||"ALL";
  aRange=p.get("range")||(p.get("q")?"ALL":"24H");aSort=p.get("sort")||"DATE";
  aNew=p.get("new")==="1";
  document.getElementById("search").value=q;
  document.getElementById("newPill").classList.toggle("on",aNew);
  ["data-sev","data-src","data-range","data-sort"].forEach(attr=>{
    const key=attr.replace("data-","");
    const val={sev:aSev,src:aSrc,range:aRange,sort:aSort}[key];
    document.querySelectorAll(`.pill[${attr}]`).forEach(b=>b.classList.toggle("on",b.dataset[key]===val));
  });
}

// --- Virtual scroll ---
let visData=[],rendered=0;
const BATCH=60;

function applyFilters(){
  const now2=Date.now(),maxAge=RANGES[aRange];
  visData=D.filter(v=>{
    if(aNew&&!v._new)return false;
    if(aWlOnly&&!isWatched(v))return false;
    if(aSev!=="ALL"&&SEV(v)!==aSev)return false;
    if(aSrc!=="ALL"&&v.source!==aSrc)return false;
    if(maxAge!==Infinity&&(now2-(v._ts||0))>maxAge)return false;
    if(q){
      const hay=[v.id,v.title,v.description,...(v.affected||[]),...(v.references||[])].join(" ").toLowerCase();
      return q.trim().split(/\\s+/).every(w=>hay.includes(w));
    }
    return true;
  });
  updateWlHits();
  visData.sort((a,b)=>{
    const pd=priority(b)-priority(a);if(pd!==0)return pd;
    if(aSort==="DATE")return(b._ts||0)-(a._ts||0);
    if(aSort==="SCORE")return(b.score||0)-(a.score||0);
    if(aSort==="EPSS")return(b.epss||0)-(a.epss||0);
    return(SEV_ORDER[SEV(a)]??4)-(SEV_ORDER[SEV(b)]??4)||(b.score||0)-(a.score||0);
  });
  visEl.textContent=visData.length;
  shint.style.display=q?"inline":"none";
  clearBtn.style.display=q?"inline":"none";
  rendered=0;grid.innerHTML="";
  emptyEl.style.display=visData.length===0?"block":"none";
  renderBatch();pushHash();
}

function renderBatch(){
  if(rendered>=visData.length)return;
  const end=Math.min(rendered+BATCH,visData.length);
  const frag=document.createDocumentFragment();
  for(let i=rendered;i<end;i++){
    const tmp=document.createElement("div");
    tmp.innerHTML=card(visData[i]);
    frag.appendChild(tmp.firstChild);
  }
  grid.appendChild(frag);
  rendered=end;
}

new IntersectionObserver(
  entries=>{if(entries[0].isIntersecting)renderBatch();},
  {rootMargin:"300px"}
).observe(sentinelEl);

// --- Pill filters ---
function bindPills(attr,setter){
  document.querySelectorAll(`.pill[${attr}]`).forEach(b=>b.addEventListener("click",()=>{
    setter(b.dataset[attr.replace("data-","")]);
    document.querySelectorAll(`.pill[${attr}]`).forEach(x=>x.classList.remove("on"));
    b.classList.add("on");applyFilters();
  }));
}
bindPills("data-sev",v=>aSev=v);bindPills("data-src",v=>aSrc=v);
bindPills("data-range",v=>aRange=v);bindPills("data-sort",v=>aSort=v);

// New-since-yesterday toggle
const newPill=document.getElementById("newPill");
newPill.addEventListener("click",()=>{aNew=!aNew;newPill.classList.toggle("on",aNew);applyFilters();});

// --- Search ---
let t;
const srchEl=document.getElementById("search");
srchEl.addEventListener("input",function(){clearTimeout(t);t=setTimeout(()=>{q=this.value.toLowerCase();applyFilters();},100);});
srchEl.addEventListener("keydown",ev=>{if(ev.key==="Escape"){srchEl.value="";q="";applyFilters();}});
clearBtn.addEventListener("click",()=>{srchEl.value="";q="";applyFilters();});

// --- Historical date picker ---
const TODAY_STR="__DATE__";
const datePicker=document.getElementById("datePicker");
DATES.forEach(d=>{
  if(d===TODAY_STR)return;
  const opt=document.createElement("option");
  opt.value=d;
  opt.textContent=new Date(d+"T12:00:00Z").toLocaleDateString(undefined,{weekday:"short",month:"short",day:"numeric",year:"numeric"});
  datePicker.appendChild(opt);
});
datePicker.addEventListener("change",async()=>{
  const val=datePicker.value;
  if(!val){
    D=D_TODAY;histBanner.style.display="none";updateSevBrk();applyFilters();return;
  }
  histBanner.style.display="block";histBanner.textContent="Loading "+val+"…";
  try{
    const resp=await fetch("historical/"+val+".json");
    if(!resp.ok)throw new Error("HTTP "+resp.status);
    const data=await resp.json();
    data.forEach(v=>{v._ts=v.published?new Date(v.published).getTime()||0:0;});
    D=data;
    histBanner.textContent="Snapshot: "+val+" — "+data.length.toLocaleString()+" entries";
    if(aRange!=="ALL"){
      aRange="ALL";
      document.querySelectorAll(".pill[data-range]").forEach(b=>b.classList.remove("on"));
      document.querySelector(".pill[data-range='ALL']").classList.add("on");
    }
    updateSevBrk();applyFilters();
  }catch(e){histBanner.textContent="Failed to load "+val+": "+e.message;}
});

// --- View switcher (Vulnerabilities / News) ---
document.getElementById("news-badge").textContent=NEWS.length;
let newsRendered=false;
function renderNews(){
  if(newsRendered)return;
  const sorted=[...NEWS].sort((a,b)=>(b._ts||0)-(a._ts||0));
  newsPanel.innerHTML=sorted.length?sorted.map(newsItem).join(""):"<p style='padding:2rem;color:var(--muted)'>No news items available.</p>";
  newsRendered=true;
}
function setView(view){
  const isNews=view==="news";
  grid.style.display=isNews?"none":"grid";
  emptyEl.style.display=isNews?"none":(visData.length===0?"block":"none");
  sentinelEl.style.display=isNews?"none":"block";
  newsPanel.style.display=isNews?"block":"none";
  document.querySelector(".bar").style.display=isNews?"none":"block";
  document.querySelector(".stats .view-btn[data-view='vulns']").classList.toggle("on",!isNews);
  document.querySelector(".stats .view-btn[data-view='news']").classList.toggle("on",isNews);
  if(isNews)renderNews();
}
document.querySelectorAll(".view-btn[data-view]").forEach(b=>b.addEventListener("click",()=>setView(b.dataset.view)));

applyHash();
applyFilters();
</script>
__STATIC_CVE_HTML__
</body>
</html>
"""


# ---------------------------------------------------------------------------
# News feeds
# ---------------------------------------------------------------------------

def fetch_news(days=3):
    log(f"Fetching security news (last {days} days)...")
    cut = cutoff_utc(hours=days * 24)
    results = []

    rss_sources = [
        ("Bleeping Computer",  "https://www.bleepingcomputer.com/feed/"),
        ("The Hacker News",    "https://thehackernews.com/feeds/posts/default"),
        ("Krebs on Security",  "https://krebsonsecurity.com/feed/"),
        ("Security Week",      "https://www.securityweek.com/feed/"),
    ]

    for src_name, feed_url in rss_sources:
        raw = http_get(feed_url)
        if not raw:
            continue
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as ex:
            log(f"  {src_name} XML error: {ex}")
            continue

        # Support both RSS <item> and Atom <entry>
        ns_atom = "http://www.w3.org/2005/Atom"
        items = list(root.iter("item")) or list(root.iter(f"{{{ns_atom}}}entry"))
        for item in items:
            def _t(tag):
                return (item.findtext(tag) or item.findtext(f"{{{ns_atom}}}{tag}") or "").strip()

            title = _t("title")
            link  = _t("link")
            # Atom link is an attribute
            if not link:
                el = item.find(f"{{{ns_atom}}}link")
                link = (el.get("href", "") if el is not None else "").strip()
            pub   = _t("pubDate") or _t("published") or _t("updated")
            desc  = strip_html(_t("description") or _t("summary"))[:300]

            if not title or not link:
                continue
            try:
                raw_dt = pub.replace("Z", "+00:00")
                try:
                    dt = datetime.fromisoformat(raw_dt)
                except ValueError:
                    dt = parsedate_to_datetime(pub).astimezone(timezone.utc)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt < cut:
                    continue
                pub_iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pub_iso = pub

            results.append({
                "title": title,
                "url": link,
                "source": src_name,
                "description": desc,
                "published": pub_iso,
                "score": None,
                "comments": None,
                "comments_url": None,
            })

        time.sleep(0.5)

    # Hacker News security stories via Algolia
    hn_after = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
    raw = http_get(
        "https://hn.algolia.com/api/v1/search"
        "?query=security+vulnerability+CVE&tags=story"
        f"&numericFilters=created_at_i%3E{hn_after}&hitsPerPage=30"
    )
    if raw:
        try:
            for hit in json.loads(raw).get("hits", []):
                oid = hit.get("objectID", "")
                url = hit.get("url") or f"https://news.ycombinator.com/item?id={oid}"
                results.append({
                    "title": hit.get("title", ""),
                    "url": url,
                    "source": "Hacker News",
                    "description": "",
                    "published": hit.get("created_at", ""),
                    "score": hit.get("points"),
                    "comments": hit.get("num_comments"),
                    "comments_url": f"https://news.ycombinator.com/item?id={oid}" if oid else None,
                })
        except json.JSONDecodeError:
            pass

    log(f"  News: {len(results)} items")
    return results


# ---------------------------------------------------------------------------
# API outputs
# ---------------------------------------------------------------------------

def write_json_api(vulns):
    with open("vulns.json", "w", encoding="utf-8") as f:
        json.dump(vulns, f, ensure_ascii=False, separators=(",", ":"))
    log(f"  Written: vulns.json ({len(vulns)} entries)")


def _rfc822(pub):
    if not pub:
        return ""
    for parse in (
        lambda s: datetime.fromisoformat(s.replace("Z", "+00:00")),
        lambda s: parsedate_to_datetime(s).astimezone(timezone.utc),
        lambda s: datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc),
    ):
        try:
            dt = parse(pub)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")
        except Exception:
            continue
    return ""


def write_rss(vulns, base_url="https://nightwatch.sami.pw"):
    def xe(s):
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    recent = sorted(
        [v for v in vulns if v.get("published")],
        key=lambda v: v.get("published", ""),
        reverse=True,
    )[:100]

    def _item_xml(v):
        title = xe(("[%s] %s: %s" % (v.get("severity", "?"), v["id"], v.get("title", "")))[:200])
        link  = xe(v.get("url", ""))
        desc  = xe((v.get("description") or "")[:500])
        pub   = _rfc822(v.get("published", ""))
        guid  = xe(v.get("url") or v["id"])
        return (
            "  <item>\n"
            f"    <title>{title}</title>\n"
            f"    <link>{link}</link>\n"
            f"    <description>{desc}</description>\n"
            f"    <pubDate>{pub}</pubDate>\n"
            f'    <guid isPermaLink="false">{guid}</guid>\n'
            "  </item>"
        )

    items_xml = "\n".join(_item_xml(v) for v in recent)

    now_rfc = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    with open("feed.xml", "w", encoding="utf-8") as f:
        f.write(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
            "  <channel>\n"
            "    <title>vulnfeed</title>\n"
            f"    <link>{base_url}</link>\n"
            "    <description>Daily security vulnerability feed — NVD, CISA KEV, Ubuntu, Debian, "
            "Red Hat, Kubernetes, Exploit-DB, OSS-Security, GitHub, OpenStack</description>\n"
            "    <language>en-us</language>\n"
            f"    <lastBuildDate>{now_rfc}</lastBuildDate>\n"
            f'    <atom:link href="{base_url}/feed.xml" rel="self" type="application/rss+xml"/>\n'
            f"{items_xml}\n"
            "  </channel>\n"
            "</rss>"
        )
    log(f"  Written: feed.xml ({len(recent)} entries)")


def build_historical_index():
    if not os.path.isdir(HISTORICAL_DIR):
        return []
    dates = sorted(
        [f[:-5] for f in os.listdir(HISTORICAL_DIR)
         if re.match(r"^\d{4}-\d{2}-\d{2}\.json$", f)],
        reverse=True,
    )
    with open(os.path.join(HISTORICAL_DIR, "index.json"), "w", encoding="utf-8") as f:
        json.dump({"dates": dates}, f)
    log(f"  Written: historical/index.json ({len(dates)} dates)")
    return dates


# ---------------------------------------------------------------------------
# Source: OSV.dev (Open Source Vulnerabilities)
# ---------------------------------------------------------------------------

# (ecosystem, package_name) — one batch request covers all of these
OSV_PACKAGES = [
    # Python
    ("PyPI", "django"), ("PyPI", "flask"), ("PyPI", "fastapi"),
    ("PyPI", "cryptography"), ("PyPI", "paramiko"), ("PyPI", "pillow"),
    ("PyPI", "urllib3"), ("PyPI", "requests"), ("PyPI", "setuptools"),
    ("PyPI", "pyjwt"), ("PyPI", "werkzeug"), ("PyPI", "jinja2"),
    ("PyPI", "ansible"), ("PyPI", "apache-airflow"),
    # Go — cloud-native infra
    ("Go", "k8s.io/kubernetes"),
    ("Go", "github.com/containerd/containerd"),
    ("Go", "github.com/docker/docker"),
    ("Go", "helm.sh/helm/v3"),
    ("Go", "github.com/hashicorp/vault"),
    ("Go", "github.com/traefik/traefik"),
    ("Go", "github.com/cilium/cilium"),
    ("Go", "istio.io/istio"),
    ("Go", "github.com/argoproj/argo-cd"),
    ("Go", "github.com/grafana/grafana"),
    ("Go", "github.com/etcd-io/etcd"),
    # npm
    ("npm", "express"), ("npm", "axios"), ("npm", "lodash"),
    ("npm", "next"), ("npm", "webpack"), ("npm", "node-fetch"),
    ("npm", "jsonwebtoken"), ("npm", "semver"),
    # Rust
    ("crates.io", "openssl"), ("crates.io", "tokio"), ("crates.io", "rustls"),
    # Java
    ("Maven", "org.apache.logging.log4j:log4j-core"),
    ("Maven", "org.springframework:spring-core"),
    ("Maven", "org.apache.struts:struts2-core"),
    ("Maven", "com.fasterxml.jackson.core:jackson-databind"),
]


def fetch_osv(days=7):
    log(f"Fetching OSV.dev ({len(OSV_PACKAGES)} packages, one batch request)...")
    cut = cutoff_utc(hours=days * 24)
    SEV_MAP = {
        "CRITICAL": "CRITICAL", "HIGH": "HIGH",
        "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW",
    }

    queries = [{"package": {"name": name, "ecosystem": eco}} for eco, name in OSV_PACKAGES]
    payload = json.dumps({"queries": queries})

    raw = http_post("https://api.osv.dev/v1/querybatch", payload, timeout=60)
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as ex:
        log(f"  OSV JSON error: {ex}")
        return []

    seen = set()
    results = []

    for batch in data.get("results", []):
        for vuln in batch.get("vulns", []):
            osv_id = vuln.get("id", "")
            if not osv_id or osv_id in seen:
                continue

            # Filter by modified date — batch returns all historical vulns for each package
            modified = vuln.get("modified", "")
            try:
                if datetime.fromisoformat(modified.replace("Z", "+00:00")) < cut:
                    continue
            except Exception:
                pass

            seen.add(osv_id)

            # Prefer CVE alias as ID so dedup with NVD works
            aliases = vuln.get("aliases") or []
            cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
            vid = cve_id or osv_id

            # Severity from database_specific (GitHub/PyPA populate this)
            db_spec = vuln.get("database_specific") or {}
            sev_str = (db_spec.get("severity") or "").upper()
            severity = SEV_MAP.get(sev_str, "UNKNOWN")

            # Numeric score from database_specific.cvss
            score = None
            cvss_info = db_spec.get("cvss") or {}
            if isinstance(cvss_info, dict):
                try:
                    score = float(cvss_info.get("baseScore") or cvss_info.get("score") or 0) or None
                except (ValueError, TypeError):
                    pass

            # Affected packages with fixed version
            affected = []
            for aff in (vuln.get("affected") or [])[:5]:
                pkg = aff.get("package") or {}
                pname = pkg.get("name", "")
                peco  = pkg.get("ecosystem", "")
                fixed = None
                for rng in (aff.get("ranges") or []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed = ev["fixed"]
                            break
                    if fixed:
                        break
                if pname:
                    label = f"{peco}/{pname}" if peco else pname
                    if fixed:
                        label += f" → fix {fixed}"
                    affected.append(label)

            refs = [r["url"] for r in (vuln.get("references") or []) if r.get("url")][:3]
            pub = vuln.get("published", modified)

            results.append({
                "id": vid,
                "title": (vuln.get("summary") or vid)[:160],
                "description": (vuln.get("details") or vuln.get("summary") or "")[:500],
                "score": score,
                "severity": severity,
                "source": "OSV",
                "published": pub,
                "references": refs + [f"https://osv.dev/vulnerability/{osv_id}"],
                "affected": affected[:8],
                "url": f"https://osv.dev/vulnerability/{osv_id}",
            })

    log(f"  OSV: {len(results)} recent vulnerabilities")
    return results


# ---------------------------------------------------------------------------
# Source: EPSS (Exploit Prediction Scoring System)
# ---------------------------------------------------------------------------

def fetch_epss():
    log("Fetching EPSS scores (full dataset)...")
    raw = http_get("https://epss.cyentia.com/epss_scores-current.csv.gz", timeout=90)
    if not raw:
        return {}
    try:
        text = gzip.decompress(raw).decode("utf-8", errors="replace")
    except Exception as ex:
        log(f"  EPSS decompress error: {ex}")
        return {}
    scores = {}
    for line in text.splitlines():
        if line.startswith("#") or line.startswith("cve,"):
            continue
        parts = line.split(",")
        if len(parts) >= 3 and parts[0].startswith("CVE-"):
            try:
                scores[parts[0]] = {
                    "epss": float(parts[1]),
                    "percentile": float(parts[2]),
                }
            except ValueError:
                pass
    log(f"  EPSS: {len(scores)} scores loaded")
    return scores


# ---------------------------------------------------------------------------
# Historical persistence
# ---------------------------------------------------------------------------

def save_historical(vulns, date_str):
    os.makedirs(HISTORICAL_DIR, exist_ok=True)
    path = os.path.join(HISTORICAL_DIR, f"{date_str}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vulns, f, ensure_ascii=False, separators=(",", ":"))
    log(f"  Saved {len(vulns)} entries → {path}")


def load_historical(days=30):
    """Load the last `days` daily snapshots, excluding today (already in fresh fetch)."""
    if not os.path.isdir(HISTORICAL_DIR):
        return []
    now = datetime.now(timezone.utc)
    results = []
    for i in range(1, days + 1):
        date_str = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        path = os.path.join(HISTORICAL_DIR, f"{date_str}.json")
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            results.extend(data)
            log(f"  Loaded {len(data)} entries ← {path}")
        except Exception as ex:
            log(f"  Error loading {path}: {ex}")
    return results


# ---------------------------------------------------------------------------
# Stats page
# ---------------------------------------------------------------------------

_STATS_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>vulnfeed stats &mdash; __DATE__</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--unk:#6b7280}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
header{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem}
.logo{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}.logo em{color:#60a5fa;font-style:normal}
.hlink{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}
.hlink:hover{border-color:#60a5fa;background:rgba(96,165,250,.08)}
.wrap{max-width:1100px;margin:0 auto;padding:2rem}
h2{font-size:.7rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem;margin-bottom:2.5rem}
.stat-box{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem 1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.stat-val{font-size:2rem;font-weight:800;letter-spacing:-.04em}
.stat-lbl{font-size:.75rem;color:var(--muted);margin-top:.15rem}
.crit-val{color:var(--crit)}.high-val{color:var(--high)}.epss-val{color:#0d9488}
.section{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.hbar-row{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem}
.hbar-label{width:110px;font-size:.78rem;font-weight:600;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hbar-track{flex:1;background:#f1f5f9;border-radius:4px;height:18px;overflow:hidden}
.hbar-fill{height:100%;border-radius:4px;transition:width .3s}
.hbar-count{font-size:.74rem;color:var(--muted);min-width:40px;text-align:right}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{text-align:left;font-size:.68rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:.4rem .6rem;border-bottom:2px solid var(--border)}
td{padding:.45rem .6rem;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafc}
.sev{display:inline-block;padding:.08rem .35rem;border-radius:3px;font-size:.65rem;font-weight:700;color:#fff;text-transform:uppercase}
.sCRITICAL{background:var(--crit)}.sHIGH{background:var(--high)}.sMEDIUM{background:var(--med)}.sLOW{background:var(--low)}.sUNKNOWN{background:var(--unk)}
@media(max-width:640px){.wrap{padding:1rem}.hbar-label{width:80px}}
</style>
</head>
<body>
<header>
  <div><div class="logo">vuln<em>feed</em> &mdash; Stats</div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="/">&#8592; Back to feed</a>
    <span style="font-size:.72rem;color:#475569">__DATE__</span>
  </div>
</header>
<div class="wrap">

<div class="stat-grid">
  <div class="stat-box"><div class="stat-val">__TOTAL__</div><div class="stat-lbl">Total vulnerabilities (30 days)</div></div>
  <div class="stat-box"><div class="stat-val crit-val">__N_CRIT__</div><div class="stat-lbl">Critical severity</div></div>
  <div class="stat-box"><div class="stat-val high-val">__N_EXPL__</div><div class="stat-lbl">Actively exploited (CISA KEV)</div></div>
  <div class="stat-box"><div class="stat-val epss-val">__N_EPSS__</div><div class="stat-lbl">High EPSS (&gt;50th %ile)</div></div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem">

<div class="section">
  <h2>By severity</h2>
  __SEV_BARS__
</div>

<div class="section">
  <h2>By source</h2>
  __SRC_BARS__
</div>

</div>

<div class="section">
  <h2>CVSS score distribution</h2>
  __CVSS_BARS__
</div>

<div class="section">
  <h2>Top affected products / packages</h2>
  <table>
    <tr><th>Product</th><th style="text-align:right">CVEs</th><th style="text-align:right">Max CVSS</th><th>Worst severity</th></tr>
    __TOP_PRODUCTS__
  </table>
</div>

<div class="section">
  <h2>Highest EPSS scores (top 20)</h2>
  <table>
    <tr><th>CVE ID</th><th>Title</th><th style="text-align:right">EPSS %ile</th><th style="text-align:right">CVSS</th><th>Severity</th></tr>
    __TOP_EPSS__
  </table>
</div>

</div>
</body>
</html>
"""


def _hbar(label, count, max_count, color):
    pct = int(count / max_count * 100) if max_count else 0
    lbl_esc = _xe(str(label))
    return (
        f'<div class="hbar-row">'
        f'<div class="hbar-label" title="{lbl_esc}">{lbl_esc}</div>'
        f'<div class="hbar-track"><div class="hbar-fill" style="width:{pct}%;background:{color}"></div></div>'
        f'<div class="hbar-count">{count:,}</div>'
        f'</div>'
    )


def write_stats_page(vulns, date_str, base_url=BASE_URL):
    sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#16a34a", "UNKNOWN": "#6b7280"}
    src_color = "#334155"

    sev_counts = {}
    src_counts = {}
    cvss_bins = [0] * 20   # 0.0-0.5, 0.5-1.0, …, 9.5-10.0
    product_map = {}        # product -> {count, max_cvss, worst_sev}
    epss_high = 0
    exploited = 0

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        src_counts[v.get("source", "?")] = src_counts.get(v.get("source", "?"), 0) + 1
        if v.get("badge") == "ACTIVELY EXPLOITED":
            exploited += 1
        if v.get("epss_pct") and v["epss_pct"] >= 50:
            epss_high += 1
        sc = v.get("score")
        if sc is not None:
            bin_i = min(int(sc / 0.5), 19)
            cvss_bins[bin_i] += 1
        for prod in (v.get("affected") or []):
            prod = prod.split(" ")[0][:40]
            if prod not in product_map:
                product_map[prod] = {"count": 0, "max_cvss": None, "worst_sev": "UNKNOWN"}
            product_map[prod]["count"] += 1
            if sc and (product_map[prod]["max_cvss"] is None or sc > product_map[prod]["max_cvss"]):
                product_map[prod]["max_cvss"] = sc
            if SEV_ORDER.get(sev, 4) < SEV_ORDER.get(product_map[prod]["worst_sev"], 4):
                product_map[prod]["worst_sev"] = sev

    # severity bars
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    max_sev = max((sev_counts.get(s, 0) for s in sev_order), default=1)
    sev_bars = "".join(_hbar(s, sev_counts.get(s, 0), max_sev, sev_colors[s]) for s in sev_order)

    # source bars
    sorted_src = sorted(src_counts.items(), key=lambda x: -x[1])
    max_src = sorted_src[0][1] if sorted_src else 1
    src_bars = "".join(_hbar(s, c, max_src, src_color) for s, c in sorted_src)

    # CVSS bars
    max_cvss_bin = max(cvss_bins) if any(cvss_bins) else 1
    cvss_bars = "".join(
        _hbar(f"{i*0.5:.1f}–{i*0.5+0.5:.1f}", cvss_bins[i], max_cvss_bin, "#2563eb")
        for i in range(len(cvss_bins))
    )

    # top products
    top_prods = sorted(product_map.items(), key=lambda x: -x[1]["count"])[:30]
    rows = []
    for prod, info in top_prods:
        sc_str = f'{info["max_cvss"]:.1f}' if info["max_cvss"] else "—"
        sev = info["worst_sev"]
        rows.append(
            f'<tr><td style="font-family:ui-monospace,monospace;font-size:.75rem">{_xe(prod)}</td>'
            f'<td style="text-align:right">{info["count"]}</td>'
            f'<td style="text-align:right">{sc_str}</td>'
            f'<td><span class="sev s{sev}">{sev}</span></td></tr>'
        )
    top_products_html = "".join(rows)

    # top EPSS
    epss_vulns = sorted(
        [v for v in vulns if v.get("epss_pct") is not None],
        key=lambda v: -(v["epss_pct"] or 0),
    )[:20]
    epss_rows = []
    for v in epss_vulns:
        sev = v.get("severity", "UNKNOWN")
        sc_str = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
        ttl = _xe((v.get("title") or v["id"])[:80])
        url = _xe(v.get("url", ""))
        epss_rows.append(
            f'<tr><td><a href="{url}" target="_blank" rel="noopener" style="font-family:ui-monospace,monospace;font-size:.75rem;color:#2563eb">{_xe(v["id"])}</a></td>'
            f'<td style="font-size:.75rem">{ttl}</td>'
            f'<td style="text-align:right">{v["epss_pct"]:.1f}%</td>'
            f'<td style="text-align:right">{sc_str}</td>'
            f'<td><span class="sev s{sev}">{sev}</span></td></tr>'
        )
    top_epss_html = "".join(epss_rows)

    html = _STATS_HTML
    html = html.replace("__DATE__", date_str)
    html = html.replace("__TOTAL__", f"{len(vulns):,}")
    html = html.replace("__N_CRIT__", str(sev_counts.get("CRITICAL", 0)))
    html = html.replace("__N_EXPL__", str(exploited))
    html = html.replace("__N_EPSS__", str(epss_high))
    html = html.replace("__SEV_BARS__", sev_bars)
    html = html.replace("__SRC_BARS__", src_bars)
    html = html.replace("__CVSS_BARS__", cvss_bars)
    html = html.replace("__TOP_PRODUCTS__", top_products_html)
    html = html.replace("__TOP_EPSS__", top_epss_html)

    with open("stats.html", "w", encoding="utf-8") as f:
        f.write(html)
    log("  Written: stats.html")


# ---------------------------------------------------------------------------
# Vendor pages
# ---------------------------------------------------------------------------

VENDOR_PAGES = [
    # (slug, display_name, search_keyword)
    ("kubernetes",   "Kubernetes",       "kubernetes"),
    ("nginx",        "nginx",             "nginx"),
    ("openssl",      "OpenSSL",           "openssl"),
    ("openssh",      "OpenSSH",           "openssh"),
    ("linux-kernel", "Linux Kernel",      "linux kernel"),
    ("docker",       "Docker",            "docker"),
    ("openstack",    "OpenStack",         "openstack"),
    ("apache",       "Apache HTTP",       "apache httpd"),
    ("redis",        "Redis",             "redis"),
    ("postgresql",   "PostgreSQL",        "postgresql"),
    ("django",       "Django",            "django"),
    ("flask",        "Flask",             "flask"),
    ("log4j",        "Log4j",             "log4j"),
    ("spring",       "Spring Framework",  "spring"),
    ("grafana",      "Grafana",           "grafana"),
    ("vault",        "HashiCorp Vault",   "vault"),
    ("traefik",      "Traefik",           "traefik"),
    ("cilium",       "Cilium",            "cilium"),
    ("containerd",   "containerd",        "containerd"),
    ("curl",         "curl",              "curl"),
    ("ansible",      "Ansible",           "ansible"),
    ("jenkins",      "Jenkins",           "jenkins"),
    ("gitlab",       "GitLab",            "gitlab"),
]

_VENDOR_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>__VENDOR__ vulnerabilities &mdash; vulnfeed</title>
<meta name="description" content="__COUNT__ recent vulnerabilities for __VENDOR__ aggregated from NVD, CISA KEV, Ubuntu, Debian, Red Hat and more.">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--unk:#6b7280}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
header{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem}
.logo{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}.logo em{color:#60a5fa;font-style:normal}
.hlink{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}
.hlink:hover{border-color:#60a5fa;background:rgba(96,165,250,.08)}
.wrap{max-width:1100px;margin:0 auto;padding:2rem}
h1{font-size:1.35rem;font-weight:800;margin-bottom:.25rem}
.sub{font-size:.8rem;color:var(--muted);margin-bottom:1.75rem}
.sub a{color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:.8rem;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)}
th{text-align:left;font-size:.68rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:.55rem .75rem;border-bottom:2px solid var(--border);background:#f8fafc}
td{padding:.5rem .75rem;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafc}
.cve-id{font-family:ui-monospace,"Cascadia Code",monospace;font-size:.77rem;font-weight:700;color:var(--accent);text-decoration:none;white-space:nowrap}
.cve-id:hover{text-decoration:underline}
.sev{display:inline-block;padding:.08rem .35rem;border-radius:3px;font-size:.65rem;font-weight:700;color:#fff;text-transform:uppercase}
.sCRITICAL{background:var(--crit)}.sHIGH{background:var(--high)}.sMEDIUM{background:var(--med)}.sLOW{background:var(--low)}.sUNKNOWN{background:var(--unk)}
.src-tag{display:inline-block;background:#334155;color:#fff;padding:.06rem .35rem;border-radius:3px;font-size:.63rem;font-weight:600}
.epss-tag{display:inline-block;background:#0d9488;color:#fff;padding:.06rem .35rem;border-radius:3px;font-size:.63rem;font-weight:600}
.ttl{font-size:.78rem;color:var(--text)}
.empty{text-align:center;padding:4rem 2rem;color:var(--muted)}
@media(max-width:640px){.wrap{padding:1rem}th:nth-child(4),td:nth-child(4),th:nth-child(6),td:nth-child(6){display:none}}
</style>
</head>
<body>
<header>
  <div><div class="logo">vuln<em>feed</em></div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="/">&#8592; Back to feed</a>
    <a class="hlink" href="/#q=__KEYWORD__">Search feed</a>
  </div>
</header>
<div class="wrap">
  <h1>__VENDOR__ vulnerabilities</h1>
  <p class="sub">__COUNT__ entries matching <code>__KEYWORD__</code> &mdash; updated __DATE__ &middot; <a href="/">vulnfeed</a></p>
  __TABLE__
</div>
</body>
</html>
"""


def write_vendor_pages(vulns, date_str, base_url=BASE_URL):
    os.makedirs("vendor", exist_ok=True)
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    pages = []

    for slug, display_name, keyword in VENDOR_PAGES:
        kw = keyword.lower()
        matched = [
            v for v in vulns
            if kw in " ".join([v.get("id", ""), v.get("title", ""), v.get("description", ""),
                                *v.get("affected", [])]).lower()
        ]
        matched.sort(key=lambda v: (
            SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4),
            -(v.get("score") or 0),
        ))

        if not matched:
            continue

        rows = []
        for v in matched:
            sev = v.get("severity", "UNKNOWN")
            cve_url = v.get("url", "")
            sc_str = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
            epss_str = f'{v["epss_pct"]:.0f}%ile' if v.get("epss_pct") is not None else "—"
            pub = (v.get("published") or "")[:10]
            ttl = _xe((v.get("title") or v["id"])[:120])
            rows.append(
                f'<tr>'
                f'<td><a class="cve-id" href="{_xe(cve_url)}" target="_blank" rel="noopener">{_xe(v["id"])}</a></td>'
                f'<td class="ttl">{ttl}</td>'
                f'<td><span class="sev s{sev}">{sev}</span></td>'
                f'<td>{sc_str}</td>'
                f'<td>{epss_str}</td>'
                f'<td><span class="src-tag">{_xe(v.get("source","?"))}</span></td>'
                f'<td>{pub}</td>'
                f'</tr>'
            )

        table_html = (
            '<table>'
            '<tr><th>CVE / ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Source</th><th>Date</th></tr>'
            + "".join(rows) +
            '</table>'
        ) if rows else '<div class="empty">No matching vulnerabilities found.</div>'

        html = _VENDOR_HTML
        html = html.replace("__VENDOR__", _xe(display_name))
        html = html.replace("__KEYWORD__", _xe(keyword))
        html = html.replace("__COUNT__", str(len(matched)))
        html = html.replace("__DATE__", date_str)
        html = html.replace("__TABLE__", table_html)

        path = os.path.join("vendor", f"{slug}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        pages.append({"slug": slug, "display_name": display_name, "count": len(matched)})

    log(f"  Written: {len(pages)} vendor pages → vendor/")
    return pages


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log("=== TLDR Security Daily ===")
    date_str = datetime.now().strftime("%Y-%m-%d")
    log(f"Date: {date_str}")

    # --- Fresh fetch ---
    fresh = []
    fresh += fetch_nvd()

    time.sleep(2)

    fresh += fetch_ubuntu()
    fresh += fetch_debian()
    fresh += fetch_cisa()
    fresh += fetch_oss_security()
    fresh += fetch_github_advisories()
    fresh += fetch_osv()
    fresh += fetch_kubernetes()
    fresh += fetch_exploitdb()
    fresh += fetch_redhat()
    fresh += fetch_openstack_ossa(months=3)
    fresh += fetch_openstack_ossn(months=3)

    log(f"Fresh total: {len(fresh)}")

    # --- Persist today's snapshot + build historical index ---
    log("Saving historical snapshot...")
    save_historical(fresh, date_str)
    log("Building historical index...")
    hist_dates = build_historical_index()

    # --- Supplement with historical data ---
    log("Loading historical data (last 30 days)...")
    historical = load_historical(days=30)
    log(f"Historical entries loaded: {len(historical)}")

    vulns = merge(fresh + historical)
    log(f"After dedup/merge: {len(vulns)}")

    # --- Diff vs yesterday ---
    yesterday_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    yesterday_path = os.path.join(HISTORICAL_DIR, f"{yesterday_str}.json")
    yesterday_ids = set()
    if os.path.exists(yesterday_path):
        try:
            with open(yesterday_path, encoding="utf-8") as f:
                yesterday_ids = {v["id"] for v in json.load(f)}
            log(f"Yesterday snapshot: {len(yesterday_ids)} IDs")
        except Exception as ex:
            log(f"  Error loading yesterday: {ex}")

    fresh_ids = {v["id"] for v in fresh}
    for v in vulns:
        if v["id"] in fresh_ids and v["id"] not in yesterday_ids:
            v["_new"] = True
    new_count = sum(1 for v in vulns if v.get("_new"))
    log(f"New since yesterday: {new_count}")

    # --- EPSS annotation ---
    log("Annotating EPSS scores...")
    epss_data = fetch_epss()
    epss_hits = 0
    for v in vulns:
        ep = epss_data.get(v["id"])
        if ep:
            v["epss"] = round(ep["epss"], 4)
            v["epss_pct"] = round(ep["percentile"] * 100, 1)
            epss_hits += 1
    log(f"  EPSS annotations: {epss_hits}/{len(vulns)}")

    # --- Source health (per-source counts from fresh fetch) ---
    source_counts = {}
    for v in fresh:
        src = v.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1

    # --- News ---
    news = fetch_news(days=3)

    # --- API outputs ---
    log("Writing API outputs...")
    write_json_api(vulns)
    write_rss(vulns)
    write_robots()

    # --- CVE pages + stats + vendor pages + sitemap ---
    log("Writing CVE pages...")
    cve_pages = write_cve_pages(vulns, date_str)
    log("Writing stats page...")
    write_stats_page(vulns, date_str)
    log("Writing vendor pages...")
    vendor_pages = write_vendor_pages(vulns, date_str)
    write_sitemap(cve_pages, date_str, vendor_pages=vendor_pages)

    # --- Static HTML for SEO pre-render ---
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

    json_blob     = json.dumps(vulns,         ensure_ascii=False, separators=(",", ":"))
    news_blob     = json.dumps(news,          ensure_ascii=False, separators=(",", ":"))
    dates_blob    = json.dumps(hist_dates)
    health_blob   = json.dumps(source_counts)

    html = _HTML
    html = html.replace("__DATE__",            date_str)
    html = html.replace("__COUNT__",           str(len(vulns)))
    html = html.replace("__JSON__",            json_blob)
    html = html.replace("__DATES_JSON__",      dates_blob)
    html = html.replace("__NEWS_JSON__",       news_blob)
    html = html.replace("__HEALTH__",          health_blob)
    html = html.replace("__STATIC_CVE_HTML__", static_html)

    out = "index.html"
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)

    size_kb = len(html.encode()) // 1024
    log(f"Written: {out} ({size_kb} KB, {len(vulns)} entries)")
    log("")
    log("To view:  python3 -m http.server 8080")
    log("Then open: http://localhost:8080")


if __name__ == "__main__":
    main()
