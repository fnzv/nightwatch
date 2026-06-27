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
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

HISTORICAL_DIR = "historical"
BASE_URL = "https://vulnfeed.it"


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


def _parse_pub_date(s):
    """Parse a published date string (ISO-8601 or RFC-822) to a UTC datetime.
    Returns None on failure."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc)
    except Exception:
        return None


def _pub_ymd(s):
    """Return YYYY-MM-DD string from any date format, or '' on failure."""
    dt = _parse_pub_date(s)
    return dt.strftime("%Y-%m-%d") if dt else (s or "")[:10]


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

def _parse_nvd_metrics(cve):
    """Return (score, severity) from an NVD CVE dict."""
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
    return score, severity


def _parse_nvd_entry(cve):
    """Convert a raw NVD CVE dict into our internal record format."""
    cve_id = cve.get("id", "")
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    score, severity = _parse_nvd_metrics(cve)
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
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for wd in weakness.get("description", []):
            val = wd.get("value", "")
            if re.match(r"^CWE-\d+$", val) and val not in cwes:
                cwes.append(val)
    return {
        "id": cve_id,
        "title": (desc[:160] if desc else cve_id),
        "description": desc,
        "score": score,
        "severity": severity,
        "source": "NVD",
        "published": (cve.get("published", "") or "").rstrip("Z") + "Z",
        "references": refs,
        "affected": sorted(affected)[:8],
        "cwes": cwes[:4],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _http_get_retry(url, retries=3, backoff=10, **kwargs):
    """http_get with exponential backoff retries (for flaky APIs like NVD)."""
    for attempt in range(retries):
        raw = http_get(url, **kwargs)
        if raw is not None:
            return raw
        if attempt < retries - 1:
            wait = backoff * (2 ** attempt)
            log(f"  Retrying in {wait}s (attempt {attempt + 1}/{retries})...")
            time.sleep(wait)
    return None


def fetch_nvd(hours=168):  # 7 days
    log("Fetching NVD CVEs (last 7 days)...")
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
        raw = _http_get_retry(url, retries=3, backoff=15)
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
            results.append(_parse_nvd_entry(item.get("cve", {})))

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

        # Extract package name(s) from title: "USN-1234-1: openssl, curl vulnerabilities"
        fix_cmd = None
        if ":" in title:
            pkg_text = title.split(":", 1)[1].strip()
            pkg_text = re.sub(r"\s+vulnerabilit(?:y|ies)\s*$", "", pkg_text, flags=re.IGNORECASE)
            pkg_text = re.sub(r"\s*\([^)]+\)", "", pkg_text).strip()  # remove (OEM), (Azure)…
            if pkg_text:
                # Split "openssl, curl" → ["openssl", "curl"], hyphenate multi-word names
                parts = re.split(r",\s*|\s+and\s+", pkg_text)
                parts = [re.sub(r"\s+", "-", p.strip().lower()) for p in parts if p.strip()]
                if parts:
                    fix_cmd = f"sudo apt install --only-upgrade {' '.join(parts)}"

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
            "fix": fix_cmd,
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

        # Extract package name: "[SECURITY] [DSA 6344-1] chromium security update"
        fix_cmd = None
        pkg_m = re.search(r"\[DSA[^\]]+\]\s+(.+?)(?:\s+(?:security )?update)?\s*$",
                          subject, re.IGNORECASE)
        if pkg_m:
            pkg = pkg_m.group(1).strip().lower()
            if pkg:
                fix_cmd = f"sudo apt install --only-upgrade {pkg}"

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
            "fix": fix_cmd,
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
        pkg_base_names = []
        for rel in (item.get("affected_release") or [])[:6]:
            pkg = rel.get("package", "")
            if pkg:
                affected.append(pkg)
                # Strip arch then extract name: "runc-1.1.12-1.el9.x86_64" → "runc"
                p = re.sub(r"\.(x86_64|noarch|i686|aarch64|s390x|ppc64le)$", "", pkg)
                parts = p.split("-")
                name_parts = []
                for part in parts:
                    if re.match(r"^\d[\d\.]*$", part):  # pure version like "1.1.12"
                        break
                    name_parts.append(part)
                base = "-".join(name_parts) if name_parts else parts[0]
                if base and base not in pkg_base_names:
                    pkg_base_names.append(base)

        fix_cmd = None
        if pkg_base_names:
            fix_cmd = f"sudo dnf update {' '.join(pkg_base_names[:3])}"

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
            "fix": fix_cmd,
        })

    log(f"  Red Hat: {len(results)} CVEs")
    return results


# ---------------------------------------------------------------------------
# Source: Cisco PSIRT (public RSS)
# ---------------------------------------------------------------------------

def fetch_cisco():
    log("Fetching Cisco PSIRT advisories...")
    raw = http_get("https://sec.cloudapps.cisco.com/security/center/rss/advisory.xml")
    if not raw:
        return []

    cut = cutoff_utc(hours=24 * 365)
    results = []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as ex:
        log(f"  Cisco XML error: {ex}")
        return []

    ns = {"cvss": "http://scap.nist.gov/schema/cvss-v2/0.2"}

    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link  = (item.findtext("link")  or "").strip()
        desc  = (item.findtext("description") or "").strip()
        pub   = (item.findtext("pubDate") or "").strip()

        try:
            if parsedate_to_datetime(pub).astimezone(timezone.utc) < cut:
                continue
        except Exception:
            pass

        cves  = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d+", desc + " " + title)))
        score_raw = item.findtext("cvss:score", namespaces=ns)
        score = None
        try:
            score = float(score_raw) if score_raw else None
        except (ValueError, TypeError):
            pass

        sev = "UNKNOWN"
        if score is not None:
            if score >= 9.0:   sev = "CRITICAL"
            elif score >= 7.0: sev = "HIGH"
            elif score >= 4.0: sev = "MEDIUM"
            else:              sev = "LOW"

        advisory_id = re.search(r"cisco-sa-[\w-]+", link)
        vid = advisory_id.group(0).upper() if advisory_id else (cves[0] if cves else title[:60])

        results.append({
            "id": vid,
            "title": title,
            "description": strip_html(desc)[:600],
            "score": score,
            "severity": sev,
            "source": "Cisco",
            "published": pub,
            "references": [link] + [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:2]],
            "affected": cves[:8],
            "url": link,
        })

    log(f"  Cisco: {len(results)} advisories")
    return results


# ---------------------------------------------------------------------------
# Source: Arista Security Advisories (RSS feed)
# ---------------------------------------------------------------------------

def fetch_arista():
    log("Fetching Arista Security Advisories (RSS)...")
    raw = http_get("https://www.arista.com/en/support/advisories-notices/security-advisory-rss")
    if not raw:
        log("  Arista: RSS fetch failed")
        return []

    content = raw.decode("utf-8", errors="replace")
    items = re.findall(r"<item>(.*?)</item>", content, re.DOTALL)
    if not items:
        log("  Arista: no items in RSS feed")
        return []

    def _tag(xml, tag):
        m = re.search(rf"<{tag}[^>]*>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</{tag}>", xml, re.DOTALL)
        return m.group(1).strip() if m else ""

    results = []
    seen = set()
    for item in items:
        url   = _tag(item, "link") or _tag(item, "guid")
        title = _tag(item, "title")
        desc  = re.sub(r"<[^>]+>", " ", _tag(item, "description")).strip()
        pub   = _tag(item, "pubDate")

        # Parse date
        pub_iso = ""
        if pub:
            try:
                from email.utils import parsedate_to_datetime
                pub_iso = parsedate_to_datetime(pub).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pub_iso = pub

        # Extract CVEs and CVSS from description
        cves  = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d+", title + " " + desc)))
        score_m = re.search(r"CVSSv?\d*\s*(?:Base\s+)?[Ss]core[:\s]+(\d+(?:\.\d+)?)", desc, re.I)
        score = None
        try:
            score = float(score_m.group(1)) if score_m else None
        except (ValueError, TypeError):
            pass

        sev = "UNKNOWN"
        if score is not None:
            if score >= 9.0:   sev = "CRITICAL"
            elif score >= 7.0: sev = "HIGH"
            elif score >= 4.0: sev = "MEDIUM"
            else:              sev = "LOW"

        # Derive a stable ID from URL slug or first CVE
        slug_m = re.search(r"/((?:SA|EoSA)-[\w-]+)(?:\.html)?", url or "", re.I)
        vid = slug_m.group(1).upper() if slug_m else (cves[0] if cves else title[:60])

        if vid in seen:
            continue
        seen.add(vid)

        results.append({
            "id":          vid,
            "title":       title,
            "description": desc[:800],
            "score":       score,
            "severity":    sev,
            "source":      "Arista",
            "published":   pub_iso,
            "references":  ([url] if url else []) + [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:2]],
            "affected":    cves[:8],
            "url":         url or "",
        })

    log(f"  Arista: {len(results)} advisories from RSS")
    return results


# ---------------------------------------------------------------------------
# Source: Microsoft Security Response Center (MSRC) — Patch Tuesday
# ---------------------------------------------------------------------------

def fetch_msrc():
    log("Fetching Microsoft MSRC (Patch Tuesday)...")

    raw = http_get(
        "https://api.msrc.microsoft.com/cvrf/v2.0/updates",
        headers={"Accept": "application/json"},
    )
    if not raw:
        return []

    try:
        data = json.loads(raw)
        updates = data.get("value") or data.get("@value") or []
    except Exception as ex:
        log(f"  MSRC updates list error: {ex}")
        return []

    # Take the 2 most recent months
    updates = sorted(updates, key=lambda u: u.get("CurrentReleaseDate", ""), reverse=True)[:12]

    sev_map = {"critical": "CRITICAL", "important": "HIGH", "moderate": "MEDIUM", "low": "LOW"}
    results = []

    for update in updates:
        update_id  = update.get("ID", "")
        cvrf_url   = update.get("CvrfUrl") or f"https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{update_id}"
        pub_date   = update.get("InitialReleaseDate", "")

        raw_cvrf = http_get(cvrf_url, headers={"Accept": "application/xml"})
        if not raw_cvrf:
            continue

        try:
            root = ET.fromstring(raw_cvrf)
        except ET.ParseError as ex:
            log(f"  MSRC CVRF parse error ({update_id}): {ex}")
            continue

        # Build product name map (ProductID → display name)
        products = {}
        for el in root.iter():
            if el.tag.endswith("}FullProductName") or el.tag == "FullProductName":
                pid = el.get("ProductID", "")
                if pid:
                    products[pid] = (el.text or "").strip()

        month_count = 0
        for vuln in root.iter():
            if not (vuln.tag.endswith("}Vulnerability") or vuln.tag == "Vulnerability"):
                continue

            cve_id = next(
                (e.text for e in vuln.iter()
                 if (e.tag.endswith("}CVE") or e.tag == "CVE") and e.text),
                None,
            )
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            title = next(
                (e.text for e in vuln.iter()
                 if (e.tag.endswith("}Title") or e.tag == "Title") and e.text),
                cve_id,
            )

            # CVSS score — take highest BaseScore
            score = None
            for e in vuln.iter():
                if e.tag.endswith("}BaseScore") or e.tag == "BaseScore":
                    try:
                        score = max(score or 0, float(e.text))
                    except (ValueError, TypeError):
                        pass
            if score == 0:
                score = None

            # Severity from Threat Type=3
            sev = "UNKNOWN"
            badge = None
            for threat in vuln.iter():
                if not (threat.tag.endswith("}Threat") or threat.tag == "Threat"):
                    continue
                t_type = threat.get("Type", "")
                desc_el = next(
                    (e for e in threat.iter()
                     if e.tag.endswith("}Description") or e.tag == "Description"),
                    None,
                )
                desc = (desc_el.text or "").strip().lower() if desc_el is not None else ""
                if t_type == "3":
                    sev = sev_map.get(desc, "UNKNOWN")
                if t_type == "1" and ("exploited:yes" in desc or "exploitation detected" in desc or "actively exploited" in desc):
                    badge = "ACTIVELY EXPLOITED"

            if sev == "UNKNOWN" and score is not None:
                if score >= 9.0:   sev = "CRITICAL"
                elif score >= 7.0: sev = "HIGH"
                elif score >= 4.0: sev = "MEDIUM"
                else:              sev = "LOW"

            # Affected products
            affected = []
            for ps in vuln.iter():
                if not (ps.tag.endswith("}ProductStatuses") or ps.tag == "ProductStatuses"):
                    continue
                for pid_el in ps.iter():
                    if pid_el.tag.endswith("}ProductID") or pid_el.tag == "ProductID":
                        name = products.get(pid_el.text or "", "")
                        if name and name not in affected:
                            affected.append(name)
                        if len(affected) >= 8:
                            break

            url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"
            entry = {
                "id": cve_id,
                "title": title,
                "description": f"Microsoft Security Update {update_id}: {title}",
                "score": score,
                "severity": sev,
                "source": "Microsoft",
                "published": pub_date,
                "references": [url, f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                "affected": affected[:8],
                "url": url,
            }
            if badge:
                entry["badge"] = badge
            results.append(entry)
            month_count += 1

        log(f"  MSRC {update_id}: {month_count} CVEs")
        time.sleep(1)

    log(f"  MSRC total: {len(results)} CVEs")
    return results


# ---------------------------------------------------------------------------
# Source: Fortinet PSIRT (public RSS)
# ---------------------------------------------------------------------------

def fetch_fortinet():
    log("Fetching Fortinet PSIRT advisories...")
    raw = http_get("https://filestore.fortinet.com/fortiguard/rss/ir.xml")
    if not raw:
        return []

    cut = cutoff_utc(hours=24 * 365)
    results = []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as ex:
        log(f"  Fortinet XML error: {ex}")
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
            pass

        cves  = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d+", desc + " " + title)))
        cvss_m = re.search(r"CVSS[^:]*:\s*(\d+(?:\.\d+)?)", desc, re.I)
        score = None
        try:
            score = float(cvss_m.group(1)) if cvss_m else None
        except (ValueError, TypeError):
            pass

        sev = "UNKNOWN"
        if score is not None:
            if score >= 9.0:   sev = "CRITICAL"
            elif score >= 7.0: sev = "HIGH"
            elif score >= 4.0: sev = "MEDIUM"
            else:              sev = "LOW"

        fsa_m = re.search(r"FG-IR-\d{2}-\d+", title + " " + link)
        vid = fsa_m.group(0) if fsa_m else (cves[0] if cves else title[:60])

        results.append({
            "id": vid,
            "title": title,
            "description": strip_html(desc)[:600],
            "score": score,
            "severity": sev,
            "source": "Fortinet",
            "published": pub,
            "references": [link] + [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:2]],
            "affected": cves[:8],
            "url": link,
        })

    log(f"  Fortinet: {len(results)} advisories")
    return results


# ---------------------------------------------------------------------------
# Source: Juniper Security Advisories (JSA) RSS
# ---------------------------------------------------------------------------

def fetch_juniper():
    log("Fetching Juniper Security Advisories...")
    raw = http_get(
        "https://kb.juniper.net/InfoCenter/index?page=rss&channel=SECURITY_ADVISORIES"
    )
    if not raw:
        return []

    cut = cutoff_utc(hours=24 * 365)
    results = []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as ex:
        log(f"  Juniper XML error: {ex}")
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
            pass

        cves  = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d+", desc + " " + title)))
        cvss_m = re.search(r"CVSS[^:]*:\s*(\d+(?:\.\d+)?)", desc, re.I)
        score = None
        try:
            score = float(cvss_m.group(1)) if cvss_m else None
        except (ValueError, TypeError):
            pass

        sev = "UNKNOWN"
        if score is not None:
            if score >= 9.0:   sev = "CRITICAL"
            elif score >= 7.0: sev = "HIGH"
            elif score >= 4.0: sev = "MEDIUM"
            else:              sev = "LOW"

        jsa_m = re.search(r"JSA\d+", title + " " + link, re.I)
        vid = jsa_m.group(0).upper() if jsa_m else (cves[0] if cves else title[:60])

        results.append({
            "id": vid,
            "title": title,
            "description": strip_html(desc)[:600],
            "score": score,
            "severity": sev,
            "source": "Juniper",
            "published": pub,
            "references": [link] + [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:2]],
            "affected": cves[:8],
            "url": link,
        })

    log(f"  Juniper: {len(results)} advisories")
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
# NVD enrichment — fill in missing CVSS for Ubuntu/Debian/OpenStack CVEs
# ---------------------------------------------------------------------------

def enrich_with_nvd(vulns):
    """Query NVD by CVE ID for entries that still have no CVSS score.
    Requires NVD_API_KEY env var; skips silently without one."""
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        return
    unscored = [v for v in vulns if v.get("score") is None and v["id"].startswith("CVE-")]
    if not unscored:
        return
    log(f"  NVD enrichment: {len(unscored)} unscored CVEs...")
    hdrs = {"apiKey": api_key}
    enriched = 0
    for v in unscored:
        raw = http_get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={v['id']}",
            headers=hdrs,
        )
        if not raw:
            continue
        try:
            items = json.loads(raw).get("vulnerabilities", [])
            if items:
                score, sev = _parse_nvd_metrics(items[0].get("cve", {}))
                if score is not None:
                    v["score"] = score
                    v["severity"] = sev
                    enriched += 1
        except Exception:
            pass
    log(f"  NVD enrichment: {enriched}/{len(unscored)} scored")


# ---------------------------------------------------------------------------
# Patch status — OSV.dev per-CVE lookup
# ---------------------------------------------------------------------------

def _osv_has_fix(data):
    """True if an OSV vuln record has at least one fixed version event."""
    return any(
        "fixed" in evt
        for aff in data.get("affected", [])
        for rng in aff.get("ranges", [])
        for evt in rng.get("events", [])
    )


def fetch_patch_status(cve_ids):
    """Return {cve_id: True/False} via OSV.dev GET /v1/vulns/{id}.
    Capped at 200 IDs per run to keep build time reasonable."""
    if not cve_ids:
        return {}
    ids = list(cve_ids)[:200]
    log(f"  Patch status: querying OSV for {len(ids)} CVEs...")
    result = {}
    for cid in ids:
        raw = http_get(f"https://api.osv.dev/v1/vulns/{cid}")
        if raw is None:
            continue          # 404 = not in OSV, skip
        try:
            result[cid] = _osv_has_fix(json.loads(raw))
        except Exception:
            pass
    patched = sum(1 for v in result.values() if v)
    log(f"  Patch status: {patched}/{len(result)} have a fix")
    return result


def fetch_poc_status(cve_ids):
    """Check nomi-sec/PoC-in-GitHub for public PoC availability.
    Queries raw.githubusercontent.com (no auth needed, CDN-backed).
    404 = no PoC; 200 = PoC repo file exists."""
    if not cve_ids:
        return set()
    ids = list(cve_ids)[:200]
    log(f"  PoC check: querying {len(ids)} CVEs via nomi-sec/PoC-in-GitHub...")
    has_poc = set()
    ua = {"User-Agent": "tldr-security-aggregator/1.0"}
    for cid in ids:
        m = re.match(r"CVE-(\d{4})-", cid)
        if not m:
            continue
        year = m.group(1)
        url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cid}.json"
        try:
            req = Request(url, headers=ua)
            with urlopen(req, timeout=10) as r:
                if r.status == 200:
                    has_poc.add(cid)
        except Exception:
            pass  # 404 or network error = no PoC, silently skip
    log(f"  PoC check: {len(has_poc)}/{len(ids)} have public PoCs")
    return has_poc


# ---------------------------------------------------------------------------
# Individual CVE page template
# ---------------------------------------------------------------------------

_CVE_PAGE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
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
.bpatch{background:#166534}.bnopatch{background:#7f1d1d}.bpoc{background:#dc2626}
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
.fix-box{background:#0c1221;border:1px solid #1e3a5f;border-radius:8px;
  padding:.85rem 1.1rem;margin-top:1.1rem}
.fix-box h2{font-size:.72rem;font-weight:700;color:#64748b;text-transform:uppercase;
  letter-spacing:.07em;margin-bottom:.55rem}
.fix-box code{font-family:ui-monospace,monospace;font-size:.9rem;color:#86efac;display:block;
  word-break:break-all}
.fix-box button{margin-top:.55rem;background:none;border:1px solid #1e3a5f;color:#64748b;
  border-radius:4px;padding:.2rem .6rem;font-size:.78rem;cursor:pointer}
.fix-box button:hover{color:#86efac;border-color:#86efac}
.explainer{background:#f0f9ff;border:1px solid #bae6fd;border-radius:10px;
  padding:1rem 1.2rem;margin-bottom:1.4rem;font-size:.9rem;line-height:1.7;color:#0c4a6e}
.explainer strong{color:#0369a1}
.explainer .expl-kev{color:#6d28d9;font-weight:700}
.explainer .expl-poc{color:#dc2626;font-weight:700}
.deep-dive{margin-top:1.6rem}
.tl{display:flex;flex-direction:column;gap:0;margin:.6rem 0 1.2rem;padding-left:.2rem}
.tl-row{display:flex;gap:.85rem;align-items:flex-start;position:relative;padding-bottom:1rem}
.tl-row:last-child{padding-bottom:0}
.tl-row::before{content:"";position:absolute;left:.55rem;top:1.1rem;bottom:0;width:2px;background:#e2e8f0}
.tl-row:last-child::before{display:none}
.tl-dot{width:1.1rem;height:1.1rem;border-radius:50%;flex-shrink:0;margin-top:.15rem;border:2px solid #fff;box-shadow:0 0 0 2px currentColor;z-index:1}
.tl-body strong{font-size:.82rem;font-weight:700;display:block}
.tl-body span{font-size:.76rem;color:#64748b}
.rem-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:.55rem;margin:.6rem 0 1.2rem}
.rem-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:7px;padding:.65rem .85rem}
.rem-card .rem-lbl{font-size:.63rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#64748b;margin-bottom:.3rem}
.rem-card a{font-size:.76rem;word-break:break-all;color:#2563eb;display:block;line-height:1.4}
.rel-table{width:100%;border-collapse:collapse;font-size:.78rem;margin:.6rem 0}
.rel-table th{text-align:left;font-size:.66rem;color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:.4rem .5rem;border-bottom:2px solid #e2e8f0}
.rel-table td{padding:.4rem .5rem;border-bottom:1px solid #f1f5f9;vertical-align:top}
.rel-table tr:last-child td{border-bottom:none}
.rel-table tr:hover td{background:#f8fafc}
.rel-table .cve-link{font-family:ui-monospace,monospace;font-size:.74rem;font-weight:700;color:#2563eb;text-decoration:none;white-space:nowrap}
.rel-table .cve-link:hover{text-decoration:underline}
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
__CVE_FIX_HTML__
__CVE_REFS_HTML__
  <div class="meta-line">
    Published: <strong>__CVE_DATE__</strong> &middot;
    Source: <strong>__CVE_SRC_ESC__</strong> &middot;
    Feed updated: <strong>__BUILD_DATE__</strong>
  </div>
  __CVE_EXPLAINER_HTML__
__CVE_DEEP_DIVE_HTML__
  <div class="cta">
    <a href="__BASE_URL__/">vulnfeed</a> aggregates __TOTAL_COUNT__ vulnerabilities from NVD, CISA KEV,
    Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, OSS-Security, GitHub and OpenStack &mdash; updated every 4 hours.
  </div>
  <div style="margin-top:2.5rem">
    <script src="https://giscus.app/client.js"
      data-repo="fnzv/nightwatch"
      data-repo-id="R_kgDOS6ts2g"
      data-category="General"
      data-category-id="DIC_kwDOS6ts2s4C_m74"
      data-mapping="pathname"
      data-strict="0"
      data-reactions-enabled="1"
      data-emit-metadata="0"
      data-input-position="bottom"
      data-theme="preferred_color_scheme"
      data-lang="it"
      crossorigin="anonymous"
      async>
    </script>
  </div>
</main>
<script>if("serviceWorker"in navigator)navigator.serviceWorker.register("/sw.js")</script>
</body>
</html>
"""


def _cve_explainer(v, pub_fmt):
    """Generate a plain-English summary paragraph for a CVE page."""
    sev       = (v.get("severity") or "UNKNOWN").lower()
    score     = v.get("score")
    src       = v.get("source") or ""
    badge     = v.get("badge") or ""
    aff       = (v.get("affected") or [])
    fix       = v.get("fix") or ""
    patch     = v.get("patch")
    poc       = v.get("poc")
    epss      = v.get("epss")
    epss_pct  = v.get("epss_pct")

    parts = []

    # Opening — severity + score + date + source
    score_str = f" with a CVSS score of <strong>{score:.1f}</strong>" if score is not None else ""
    src_str   = f" via <strong>{_xe(src)}</strong>" if src else ""
    parts.append(
        f"This <strong>{_xe(sev)}</strong> severity vulnerability{score_str} "
        f"was published on <strong>{_xe(pub_fmt)}</strong>{src_str}."
    )

    # Active exploitation
    if badge == "ACTIVELY EXPLOITED":
        parts.append(
            '<span class="expl-kev">&#9888; This vulnerability is in the CISA Known Exploited '
            'Vulnerabilities (KEV) catalog — it is being actively exploited in the wild.</span>'
        )

    # PoC
    if poc:
        parts.append(
            '<span class="expl-poc">&#128680; A public proof-of-concept exploit is available on GitHub.</span>'
        )

    # EPSS — only mention if meaningful (>=5%)
    if epss is not None and epss_pct is not None and epss >= 0.05:
        parts.append(
            f"EPSS score: <strong>{epss:.1%}</strong> "
            f"(top <strong>{100 - epss_pct:.0f}%</strong> of all CVEs by exploitation probability)."
        )

    # Patch / remediation
    if patch is True and fix:
        parts.append("A patch is available — see the remediation command below.")
    elif patch is True:
        parts.append("A patch is available from the vendor.")
    elif patch is False:
        parts.append("No patch is currently available.")
    elif fix:
        parts.append("A remediation command is available below.")

    # Affected products (first 3, with overflow count)
    if aff:
        shown   = [_xe(a) for a in aff[:3]]
        rest    = len(aff) - 3
        aff_str = ", ".join(shown) + (f" and {rest} more" if rest > 0 else "")
        parts.append(f"Affected: <strong>{aff_str}</strong>.")

    return '<div class="explainer">' + " ".join(parts) + "</div>"


def _cve_deep_dive(v, related, pub_fmt, date_str):
    """Extended deep-dive section for KEV or CVSS ≥9.0 CVEs."""
    is_kev = v.get("badge") == "ACTIVELY EXPLOITED"
    score  = v.get("score") or 0
    if not is_kev and score < 9.0:
        return ""

    # --- Timeline ---
    try:
        pub_dt   = datetime.fromisoformat((v.get("published") or "").replace("Z", "+00:00"))
        today_dt = datetime.strptime(date_str, "%Y-%m-%d")
        days_old = (today_dt - pub_dt.replace(tzinfo=None)).days
        age_str  = f"{days_old} day{'s' if days_old != 1 else ''} ago"
    except Exception:
        age_str = ""

    tl_items = [
        ("#2563eb", "CVE Disclosed", f"{pub_fmt}{(' · ' + age_str) if age_str else ''}"),
    ]
    if v.get("poc"):
        tl_items.append(("#dc2626", "Public PoC Exploit Available",
                         "Weaponised proof-of-concept code is publicly accessible"))
    if is_kev:
        tl_items.append(("#7c3aed", "CISA KEV — Actively Exploited",
                         "U.S. federal agencies required to patch · confirmed threat-actor activity"))

    tl_rows = "".join(
        f'<div class="tl-row">'
        f'<div class="tl-dot" style="color:{c}"></div>'
        f'<div class="tl-body"><strong>{label}</strong><span>{detail}</span></div>'
        f'</div>'
        for c, label, detail in tl_items
    )
    timeline_html = f'<div class="tl">{tl_rows}</div>'

    # --- Remediation resources ---
    refs = [r for r in (v.get("references") or []) if r]
    NVD_HOSTS    = {"nvd.nist.gov", "cve.mitre.org"}
    CISA_HOSTS   = {"cisa.gov", "us-cert.cisa.gov"}
    GH_HOSTS     = {"github.com", "github.advisory-database"}
    PATCH_WORDS  = {"advisory", "security", "bulletin", "patch", "fix", "update",
                    "release", "alert", "vuln", "cve", "errata", "kb", "sa-"}

    buckets = {"Official Advisory": [], "CISA / KEV": [], "GitHub": [], "NVD / MITRE": [], "Analysis & PoC": []}
    for r in refs:
        host = urlparse(r).netloc.lower().lstrip("www.")
        path = r.lower()
        if host in CISA_HOSTS:
            buckets["CISA / KEV"].append(r)
        elif host in NVD_HOSTS:
            buckets["NVD / MITRE"].append(r)
        elif host in GH_HOSTS:
            buckets["GitHub"].append(r)
        elif any(w in path for w in PATCH_WORDS):
            buckets["Official Advisory"].append(r)
        else:
            buckets["Analysis & PoC"].append(r)

    rem_cards = []
    for lbl, urls in buckets.items():
        for u in urls[:2]:
            short = u.split("//", 1)[-1][:70]
            rem_cards.append(
                f'<div class="rem-card"><div class="rem-lbl">{lbl}</div>'
                f'<a href="{_xe(u)}" target="_blank" rel="noopener noreferrer">{_xe(short)}</a></div>'
            )
    rem_html = f'<div class="rem-grid">{"".join(rem_cards)}</div>' if rem_cards else ""

    # --- Related CVEs ---
    rel_rows = []
    for rv in related[:6]:
        rs    = rv.get("severity", "UNKNOWN")
        rsc   = f'{rv["score"]:.1f}' if rv.get("score") is not None else "—"
        rtl   = _xe((rv.get("title") or rv["id"])[:80])
        rid   = _xe(rv["id"])
        rbadge = ' <span style="font-size:.6rem;background:#7c3aed;color:#fff;border-radius:2px;padding:.02rem .25rem;font-weight:700">KEV</span>' if rv.get("badge") == "ACTIVELY EXPLOITED" else ""
        rpoc  = ' <span style="font-size:.6rem;background:#dc2626;color:#fff;border-radius:2px;padding:.02rem .25rem;font-weight:700">PoC</span>' if rv.get("poc") else ""
        rel_rows.append(
            f'<tr>'
            f'<td><a class="cve-link" href="/cve/{rid}.html">{rid}</a>{rbadge}{rpoc}</td>'
            f'<td>{rtl}</td>'
            f'<td><span class="b b{rs}" style="font-size:.62rem;padding:.05rem .3rem">{rs}</span></td>'
            f'<td style="font-family:ui-monospace,monospace;font-size:.74rem">{rsc}</td>'
            f'</tr>'
        )
    rel_html = ""
    if rel_rows:
        rel_html = (
            '<h2>Related Vulnerabilities</h2>'
            '<table class="rel-table">'
            '<tr><th>CVE</th><th>Title</th><th>Severity</th><th>CVSS</th></tr>'
            + "".join(rel_rows) + '</table>'
        )

    sections = []
    sections.append('<div class="deep-dive"><h2>Risk Timeline</h2>' + timeline_html)
    if rem_html:
        sections.append('<h2>Remediation Resources</h2>' + rem_html)
    if rel_html:
        sections.append(rel_html)
    sections.append('</div>')
    return "\n".join(sections)


def _vendor_key(v):
    """Extract a short vendor/product key from the first affected entry."""
    aff = (v.get("affected") or [])
    if not aff:
        return None
    first = aff[0].lower()
    # "vendor/product ..." or "vendor product ..."
    key = first.split("/")[0].split()[0].strip()
    return key if len(key) >= 3 else None


def write_cve_pages(vulns, date_str, base_url=BASE_URL):
    """Generate individual HTML pages for all proper CVE-YYYY-NNNNN entries."""
    candidates = [v for v in vulns if v["id"].startswith("CVE-")]
    seen, unique = set(), []
    for v in candidates:
        if v["id"] not in seen:
            seen.add(v["id"])
            unique.append(v)

    # Build vendor → sorted CVE list for related-CVE lookups
    SEV_ORD = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vendor_map: dict[str, list] = {}
    for u in unique:
        k = _vendor_key(u)
        if k:
            vendor_map.setdefault(k, []).append(u)
    for k in vendor_map:
        vendor_map[k].sort(key=lambda u: (SEV_ORD.get(u.get("severity","UNKNOWN"),4), -(u.get("score") or 0)))

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
        if v.get("patch") is True:
            badges_html += ' <span class="b bpatch">PATCH ✓</span>'
        elif v.get("patch") is False:
            badges_html += ' <span class="b bnopatch">NO FIX</span>'
        if v.get("poc"):
            badges_html += ' <span class="b bpoc" title="Public proof-of-concept exploit exists on GitHub">PoC</span>'

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

        fix_cmd = v.get("fix") or ""
        if fix_cmd:
            fix_html = (
                f'  <div class="fix-box"><h2>Remediation</h2>'
                f'<code>$ {_xe(fix_cmd)}</code>'
                f'<button onclick="navigator.clipboard.writeText({_xe(json.dumps(fix_cmd))})'
                f'.then(()=>{{this.textContent=\'✓ Copied\';setTimeout(()=>this.textContent=\'Copy command\',1500)}})">Copy command</button></div>'
            )
        else:
            fix_html = ""

        ld = {
            "@context": "https://schema.org",
            "@type": "Article",
            "headline": f"{cve_id}: {title_short}",
            "description": desc[:200],
            "datePublished": pub_fmt,
            "url": f"{base_url}/cve/{cve_id}.html",
            "publisher": {"@type": "Organization", "name": "vulnfeed", "url": base_url},
        }

        sev_label   = sev.capitalize()
        score_label = f" {score:.1f}" if score is not None else ""
        title_tag   = f"{cve_id} — {sev_label}{score_label} — {title_short} | vulnfeed"
        explainer   = _cve_explainer(v, pub_fmt)

        vkey    = _vendor_key(v)
        related = [u for u in vendor_map.get(vkey, []) if u["id"] != cve_id][:6] if vkey else []
        deep    = _cve_deep_dive(v, related, pub_fmt, date_str)

        page = _CVE_PAGE_HTML
        page = page.replace("__CVE_TITLE_TAG__",      _xe(title_tag))
        page = page.replace("__CVE_META_DESC__",       meta_desc)
        page = page.replace("__CVE_OG_TITLE__",        _xe(f"{cve_id}: {title_short}"))
        page = page.replace("__CVE_CANONICAL__",       f"{base_url}/cve/{cve_id}.html")
        page = page.replace("__CVE_JSON_LD__",         json.dumps(ld, ensure_ascii=False))
        page = page.replace("__CVE_BADGES__",          badges_html)
        page = page.replace("__CVE_ID_ESC__",          _xe(cve_id))
        page = page.replace("__CVE_TITLE_ESC__",       _xe(title))
        page = page.replace("__CVE_DESC_ESC__",        _xe(desc))
        page = page.replace("__CVE_AFFECTED_HTML__",   aff_html)
        page = page.replace("__CVE_FIX_HTML__",        fix_html)
        page = page.replace("__CVE_REFS_HTML__",       refs_html)
        page = page.replace("__CVE_DATE__",            pub_fmt)
        page = page.replace("__CVE_SRC_ESC__",         _xe(src))
        page = page.replace("__BUILD_DATE__",          date_str)
        page = page.replace("__TOTAL_COUNT__",         str(total))
        page = page.replace("__BASE_URL__",            base_url)
        page = page.replace("__CVE_EXPLAINER_HTML__",  explainer)
        page = page.replace("__CVE_DEEP_DIVE_HTML__",  deep)

        with open(os.path.join("cve", f"{cve_id}.html"), "w", encoding="utf-8") as f:
            f.write(page)

    log(f"  Written: {len(unique)} CVE pages → cve/")
    return unique


def write_sitemap(cve_pages, date_str, base_url=BASE_URL, vendor_pages=None,
                  cwe_pages=None, digest_dates=None, weekly_digest_weeks=None,
                  monthly_archive_months=None):
    def url_entry(loc, freq, pri, lastmod=None):
        lm = lastmod or date_str
        return (
            f"  <url><loc>{loc}</loc>"
            f"<lastmod>{lm}</lastmod>"
            f"<changefreq>{freq}</changefreq>"
            f"<priority>{pri}</priority></url>"
        )

    entries = [url_entry(f"{base_url}/", "hourly", "1.0")]
    entries.append(url_entry(f"{base_url}/trending.html", "hourly", "0.8"))
    entries.append(url_entry(f"{base_url}/patch-now.html", "hourly", "0.9"))
    entries.append(url_entry(f"{base_url}/zero-days.html", "hourly", "0.9"))
    entries.append(url_entry(f"{base_url}/new-this-week.html", "daily", "0.8"))
    entries.append(url_entry(f"{base_url}/grafana.html", "monthly", "0.6"))
    entries.append(url_entry(f"{base_url}/agents.html", "monthly", "0.6"))
    entries.append(url_entry(f"{base_url}/n8n.html", "monthly", "0.6"))
    entries.append(url_entry(f"{base_url}/subscribe.html", "monthly", "0.6"))
    for slug in _PRODUCT_FEED_CFGS:
        entries.append(url_entry(f"{base_url}/feed/{slug}.xml", "hourly", "0.5"))
    entries.append(url_entry(f"{base_url}/stats.html", "daily", "0.7"))
    entries.append(url_entry(f"{base_url}/search.html", "weekly", "0.6"))
    entries.append(url_entry(f"{base_url}/how-to-scan.html", "monthly", "0.5"))
    entries.append(url_entry(f"{base_url}/api.html", "monthly", "0.5"))
    entries.append(url_entry(f"{base_url}/digest/", "daily", "0.6"))
    entries.append(url_entry(f"{base_url}/archive/", "monthly", "0.5"))
    for ym in (monthly_archive_months or []):
        entries.append(url_entry(f"{base_url}/archive/{ym}.html", "monthly", "0.5"))
    for vp in (vendor_pages or []):
        entries.append(url_entry(f"{base_url}/vendor/{vp['slug']}.html", "daily", "0.7"))
    for cp in (cwe_pages or []):
        entries.append(url_entry(f"{base_url}/cwe/{cp['id']}.html", "weekly", "0.7"))
    for d in (digest_dates or []):
        entries.append(url_entry(f"{base_url}/digest/{d}.html", "weekly", "0.5"))
    for w in (weekly_digest_weeks or []):
        entries.append(url_entry(f"{base_url}/digest/week-{w}.html", "weekly", "0.6"))
    for v in cve_pages:
        pub = (v.get("published") or "")[:10]
        lm = pub if len(pub) == 10 else date_str
        entries.append(url_entry(f"{base_url}/cve/{v['id']}.html", "weekly", "0.8", lastmod=lm))

    with open("sitemap.xml", "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
        f.write("\n".join(entries))
        f.write("\n</urlset>")
    log(f"  Written: sitemap.xml ({len(entries)} URLs)")


def write_robots(base_url=BASE_URL):
    with open("robots.txt", "w", encoding="utf-8") as f:
        f.write(
            f"User-agent: *\n"
            f"Allow: /\n"
            f"Disallow: /historical/\n"
            f"Disallow: /vulns.json\n"
            f"Disallow: /vendor/*.xml\n"
            f"Sitemap: {base_url}/sitemap.xml\n"
        )
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
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>vulnfeed &mdash; __DATE__</title>
<link rel="alternate" type="application/rss+xml" title="vulnfeed" href="/feed.xml">
<meta name="description" content="vulnfeed — __COUNT__ security vulnerabilities aggregated from NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, OSS-Security, GitHub and OpenStack. Updated every 4 hours.">
<meta property="og:title" content="vulnfeed — daily CVE digest">
<meta property="og:description" content="__COUNT__ vulnerabilities aggregated from NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes and more. Updated every 4 hours.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://vulnfeed.it/">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="vulnfeed — daily CVE digest">
<meta name="twitter:description" content="__COUNT__ CVEs from NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, OSS-Security, GitHub and OpenStack. Updated every 4 hours.">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"vulnfeed","url":"https://vulnfeed.it","description":"Daily security vulnerability feed aggregating NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, OSS-Security, GitHub and OpenStack."}</script>
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
.pill.excl{background:#fee2e2;color:#dc2626;border-color:#dc2626;text-decoration:line-through}
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
.review-btn{background:none;border:none;padding:.15rem .25rem;cursor:pointer;color:#cbd5e1;font-size:.78rem;line-height:1;border-radius:3px;opacity:0;transition:opacity .15s}
.card:hover .review-btn{opacity:1}
.review-btn:hover{color:#ef4444!important;background:#fee2e2}
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
.btrend{background:#f59e0b;color:#000;font-size:.62rem}
.bpatch{background:#166534;font-size:.62rem}
.bnopatch{background:#7f1d1d;font-size:.62rem}
.bpoc{background:#dc2626;font-size:.62rem}
.bunread{background:#4f46e5;font-size:.62rem}
.fix-cmd{display:flex;align-items:center;gap:.4rem;margin-top:.3rem;background:#0c1221;
  border:1px solid #1e3a5f;border-radius:5px;padding:.28rem .55rem;overflow:hidden}
.fix-cmd code{font-family:ui-monospace,monospace;font-size:.72rem;color:#86efac;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1}
.fix-copy{background:none;border:1px solid #1e3a5f;color:#64748b;border-radius:3px;
  padding:.06rem .28rem;font-size:.63rem;cursor:pointer;flex-shrink:0;white-space:nowrap}
.fix-copy:hover{color:#86efac;border-color:#86efac}
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
#chart{height:64px;overflow:hidden}
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

#vendor-browse{padding:.45rem 2rem;border-bottom:1px solid #1e293b;background:var(--hdr);display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
#vendor-browse h2{font-size:.63rem;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;flex-shrink:0}
.vb-grid{display:flex;flex-wrap:wrap;gap:.3rem}
.vb-link{display:inline-flex;align-items:center;gap:.25rem;padding:.18rem .5rem;border:1px solid #334155;border-radius:12px;font-size:.68rem;font-weight:600;color:#93c5fd;text-decoration:none;background:transparent;transition:border-color .15s,background .15s}
.vb-link:hover{border-color:#60a5fa;background:rgba(96,165,250,.1);text-decoration:none}
.vb-link span{font-size:.6rem;color:#64748b;font-weight:400}
#cwe-browse{padding:.4rem 2rem;border-bottom:1px solid #1e293b;background:#0c1323;display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
#cwe-browse h2{font-size:.63rem;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;flex-shrink:0}
.cwe-link{display:inline-flex;align-items:center;gap:.25rem;padding:.18rem .5rem;border:1px solid #312e81;border-radius:12px;font-size:.67rem;font-weight:600;color:#a5b4fc;text-decoration:none;background:transparent;transition:border-color .15s,background .15s}
.cwe-link:hover{border-color:#818cf8;background:rgba(129,140,248,.1);text-decoration:none}
.cwe-link span{font-size:.6rem;color:#64748b;font-weight:400}

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
/* Subscribe modal */
#sub-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:999;align-items:center;justify-content:center}
#sub-modal.open{display:flex}
#sub-modal-box{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;max-width:420px;width:90%;position:relative;box-shadow:0 20px 60px rgba(0,0,0,.6)}
#sub-close{position:absolute;top:.6rem;right:.85rem;background:none;border:none;color:#94a3b8;font-size:1.4rem;cursor:pointer;line-height:1;padding:0}
#sub-close:hover{color:#f1f5f9}
#sub-modal h2{margin:0 0 .35rem;font-size:1.05rem;color:#f1f5f9}
#sub-modal p{font-size:.8rem;color:#94a3b8;margin:0 0 1rem}
#sub-form{display:flex;flex-direction:column;gap:.5rem}
#sub-form input[type=email]{padding:.5rem .75rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;font-size:.85rem;outline:none}
#sub-form input[type=email]:focus{border-color:#60a5fa}
#sub-form input[type=email]::placeholder{color:#64748b}
#sub-form button{padding:.5rem .9rem;border-radius:6px;background:#2563eb;color:#fff;border:none;font-size:.85rem;font-weight:600;cursor:pointer}
#sub-form button:hover{background:#1d4ed8}
#sub-topics-label{font-size:.73rem;color:#64748b;margin:.6rem 0 .35rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
#sub-topics{display:grid;grid-template-columns:1fr 1fr;gap:.22rem .6rem;margin-bottom:.75rem}
#sub-topics label{display:flex;align-items:center;gap:.38rem;font-size:.78rem;color:#cbd5e1;cursor:pointer;user-select:none}
#sub-topics input[type=checkbox]{accent-color:#2563eb;width:13px;height:13px;flex-shrink:0}
#sub-modal-thanks{font-size:.88rem;color:#4ade80;text-align:center;padding:.5rem 0;display:none}
#sub-open-btn{padding:.22rem .7rem;border-radius:5px;background:transparent;color:#94a3b8;border:1px solid #334155;font-size:.75rem;cursor:pointer;white-space:nowrap}
#sub-open-btn:hover{border-color:#60a5fa;color:#f1f5f9}
/* Subscribe strip */
#sub-strip{background:#eff6ff;border-bottom:1px solid #bfdbfe;padding:.6rem 2rem;display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;font-size:.8rem}
.sstlabel{font-weight:700;color:#1e3a8a;flex-shrink:0}
.sstlinks{display:flex;gap:.4rem;flex-wrap:wrap;flex:1}
.sstbtn{display:inline-flex;align-items:center;padding:.24rem .7rem;border:1px solid #bfdbfe;border-radius:5px;color:#1d4ed8;background:#fff;font-size:.76rem;font-weight:600;text-decoration:none;white-space:nowrap;cursor:pointer}
.sstbtn:hover{border-color:#2563eb;background:#dbeafe}
.sstbtn-main{background:#2563eb;color:#fff;border-color:#2563eb}
.sstbtn-main:hover{background:#1d4ed8;border-color:#1d4ed8;color:#fff}
.sst-x{background:none;border:none;cursor:pointer;color:#93c5fd;font-size:1rem;padding:0;line-height:1;margin-left:auto;flex-shrink:0}
.sst-x:hover{color:#1e3a8a}
@media(max-width:640px){#sub-strip{padding-left:1rem;padding-right:1rem}}
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
      <a class="hlink" href="/patch-now.html" style="border-color:#7c3aed;color:#a78bfa">&#128683;&nbsp;Patch now</a>
      <a class="hlink" href="/zero-days.html" style="border-color:#dc2626;color:#f87171">&#9888;&nbsp;0-days</a>
      <a class="hlink" href="/new-this-week.html">&#128197;&nbsp;New this week</a>
      <a class="hlink" href="/trending.html">&#128200;&nbsp;Trending</a>
      <a class="hlink" href="/stats.html">Stats</a>
      <a class="hlink" href="/search.html">&#128269;&nbsp;Search</a>
      <a class="hlink" href="/archive/">Archive</a>
      <a class="hlink" href="/how-to-scan.html">&#128737;&nbsp;How to scan</a>
      <a class="hlink" href="/grafana.html">&#128202;&nbsp;Grafana</a>
      <a class="hlink" href="/n8n.html">&#9889;&nbsp;n8n</a>
      <a class="hlink" href="/agents.html">&#129302;&nbsp;Agents</a>
      <a class="hlink" href="/subscribe.html" style="border-color:#16a34a;color:#4ade80">&#128276;&nbsp;Subscribe</a>
      <a class="hlink" href="/feed.xml">&#9656;&nbsp;RSS</a>
      <a class="hlink" href="/api.html">API</a>
      <a class="hlink" href="/vulns.json">{&nbsp;}&nbsp;JSON</a>
    </div>
    <div style="margin-top:.45rem;text-align:right">
      <button id="sub-open-btn">&#128231; Weekly digest</button>
    </div>
  </div>
</header>
<div id="hist-banner"></div>
<div id="new-since-banner" style="display:none;background:#eff6ff;border-bottom:1px solid #bfdbfe;padding:.55rem 2rem;font-size:.81rem;color:#1e3a8a;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap">
  <span id="new-since-text"></span>
  <div style="display:flex;gap:.75rem;align-items:center">
    <button onclick="document.getElementById('new-since-banner').style.display='none'" style="background:none;border:none;cursor:pointer;color:#64748b;font-size:.8rem;padding:0">Dismiss</button>
    <button onclick="_clearReviewed()" id="clear-reviewed-btn" style="display:none;background:none;border:1px solid #bfdbfe;border-radius:4px;cursor:pointer;color:#1e3a8a;font-size:.78rem;padding:.1rem .5rem">Clear reviewed</button>
  </div>
</div>
__VENDOR_INDEX_HTML__
__CWE_INDEX_HTML__
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
    <button class="pill" data-src="Cisco">Cisco</button>
    <button class="pill" data-src="Arista">Arista</button>
    <button class="pill" data-src="Microsoft">Microsoft</button>
    <button class="pill" data-src="Fortinet">Fortinet</button>
    <button class="pill" data-src="Juniper">Juniper</button>
  </div>
  <div class="pills">
    <span class="plabel">Period:</span>
    <button class="pill" data-range="ALL">All time</button>
    <button class="pill" data-range="24H">Last 24h</button>
    <button class="pill on" data-range="7D">Last 7 days</button>
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
    <div class="sep"></div>
    <button class="view-btn" id="csvBtn" title="Download visible results as CSV">&#8595;&nbsp;CSV</button>
    <button class="view-btn" id="shareBtn" title="Copy permalink to current filters">&#128279;&nbsp;Share</button>
  </div>
</div>

<div id="sub-strip">
  <span class="sstlabel">&#128276; Get notified about critical CVEs</span>
  <div class="sstlinks">
    <a class="sstbtn" href="#" onclick="document.getElementById('sub-open-btn').click();return false">&#128231;&nbsp;Email digest</a>
    <a class="sstbtn" href="https://ntfy.sh/vulnfeed-critical" target="_blank" rel="noopener">&#128276;&nbsp;Push (ntfy.sh)</a>
    <a class="sstbtn" href="/feed.xml">&#9656;&nbsp;RSS</a>
    <a class="sstbtn sstbtn-main" href="/subscribe.html">All options &rarr;</a>
  </div>
  <button class="sst-x" onclick="dismissSubStrip()" title="Dismiss">&#10005;</button>
</div>
<script>
(function(){
  if(localStorage.getItem('vf_sub_dismissed')||localStorage.getItem('vf_subscribed')){
    document.getElementById('sub-strip').style.display='none';
  }
})();
function dismissSubStrip(){
  document.getElementById('sub-strip').style.display='none';
  try{localStorage.setItem('vf_sub_dismissed','1');}catch(_){}
}
</script>
<div id="vf-loading" style="text-align:center;padding:3rem 1rem;color:#64748b;font-size:.9rem">Loading vulnerabilities…</div>
<div id="grid"></div>
<div id="empty"><h2>No results</h2><p>Try a different keyword or clear the filters.</p></div>
<div id="sentinel"></div>
<div id="news-panel"></div>

<script>
let D=[];
const D_TODAY=D;
const DATES=__DATES_JSON__;
const NEWS=__NEWS_JSON__;
const HEALTH=__HEALTH__;

// Treat bare ISO-8601 (no tz suffix) as UTC so historical entries sort correctly
function _toTS(s){if(!s)return 0;var d=new Date(/Z$|[+-]\d{2}:?\d{2}$/.test(s)?s:s+"Z");return d.getTime()||0;}
NEWS.forEach(n=>{n._ts=_toTS(n.published)});

const _lastVisit=parseInt(localStorage.getItem("vf_lastVisit")||"0");
const _reviewed=new Set(JSON.parse(localStorage.getItem("vf_reviewed")||"[]"));
function _saveReviewed(){localStorage.setItem("vf_reviewed",JSON.stringify([..._reviewed].slice(-3000)));}
function _markReviewed(id,cardEl){
  _reviewed.add(id);_saveReviewed();
  cardEl.style.transition="opacity .2s,transform .2s";
  cardEl.style.opacity="0";cardEl.style.transform="translateX(10px)";
  setTimeout(()=>{cardEl.remove();_syncReviewedBtn();},220);
}
function _syncReviewedBtn(){
  const btn=document.getElementById("clear-reviewed-btn");
  if(btn)btn.style.display=_reviewed.size>0?"":"none";
}
function _clearReviewed(){
  _reviewed.clear();_saveReviewed();_syncReviewedBtn();location.reload();
}
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
function updateTodayBadge(){
  const tc=D_TODAY.filter(v=>v._ts&&(now-v._ts)<DAY).length;
  const yc=D_TODAY.filter(v=>v._ts&&(now-v._ts)>=DAY&&(now-v._ts)<2*DAY).length;
  document.getElementById("todayN").textContent=tc;
  if(yc>0){
    const pct=Math.round((tc-yc)/yc*100),sign=pct>=0?"+":"";
    const col=pct>0?"#4ade80":pct<0?"#f87171":"#94a3b8";
    document.getElementById("todayDelta").innerHTML=`<span style="color:${col}">${sign}${pct}% vs yesterday</span>`;
  }
}
updateTodayBadge();

function updateSevBrk(){
  const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  D.forEach(v=>{const s=SEV(v);if(s in cnt)cnt[s]++;});
  document.getElementById("sevBrk").innerHTML=
    `<b class="sc">CRIT ${cnt.CRITICAL}</b><b class="sh">HIGH ${cnt.HIGH}</b>`+
    `<b class="sm">MED ${cnt.MEDIUM}</b><b class="sl">LOW ${cnt.LOW}</b>`;
}
updateSevBrk();

// 14-day multi-severity chart — canvas-based (no SVG fill/overflow quirks)
try{(function(){
  const DAYS=14,H=64,PAD=6;
  const SERIES=[
    {sev:"CRITICAL", color:"#dc2626", label:"Critical"},
    {sev:"HIGH",     color:"#ea580c", label:"High"},
    {sev:"MEDIUM",   color:"#d97706", label:"Medium"},
  ];
  const labels=Array.from({length:DAYS},(_,i)=>
    new Date(now-(DAYS-1-i)*DAY).toLocaleDateString(undefined,{weekday:"short"})
  );

  SERIES.forEach(s=>{
    const c=Array(DAYS).fill(0);
    D_TODAY.forEach(v=>{
      if(!v._ts||SEV(v)!==s.sev)return;
      const idx=Math.floor((now-v._ts)/DAY);
      if(idx>=0&&idx<DAYS)c[idx]++;
    });
    s.vals=c.slice().reverse();
  });

  const maxV=Math.max(...SERIES.flatMap(s=>s.vals),1);
  const chartEl=document.getElementById("chart");
  if(!chartEl)return;
  const W=chartEl.getBoundingClientRect().width||chartEl.offsetWidth||800;
  const xs=Array.from({length:DAYS},(_,i)=>PAD+(i/(DAYS-1))*(W-PAD*2));

  const canvas=document.createElement("canvas");
  canvas.width=W;
  canvas.height=H;
  canvas.style.cssText="display:block;width:100%;height:"+H+"px";

  const ctx=canvas.getContext("2d");
  if(ctx){
    SERIES.forEach(s=>{
      const ys=s.vals.map(n=>PAD+(1-n/maxV)*(H-PAD*2));
      ctx.strokeStyle=s.color;
      ctx.lineWidth=1.8;
      ctx.globalAlpha=0.85;
      ctx.lineCap="round";
      ctx.lineJoin="round";
      let started=false;
      ctx.beginPath();
      for(let i=0;i<DAYS;i++){
        if(s.vals[i]===0){started=false;continue;}
        if(!started){ctx.moveTo(xs[i],ys[i]);started=true;}
        else ctx.lineTo(xs[i],ys[i]);
      }
      ctx.stroke();
      ctx.globalAlpha=1;
    });
  }

  const legend=SERIES.map(s=>
    `<span style="display:inline-flex;align-items:center;gap:.3rem;font-size:.6rem;color:${s.color};font-weight:600">` +
    `<span style="display:inline-block;width:14px;height:2px;background:${s.color};border-radius:1px;opacity:.85"></span>${s.label}</span>`
  ).join("");

  chartEl.appendChild(canvas);
  chartEl.insertAdjacentHTML("beforeend",
    '<div class="chart-lbl-row">'+labels.map((l,i)=>`<span style="${i===DAYS-1?"color:#94a3b8;font-weight:600":""}">${l}</span>`).join("")+'</div>'+
    `<div style="display:flex;gap:.85rem;margin-top:.3rem;padding-left:${PAD}px">${legend}</div>`
  );
})()}catch(e){console.error("chart:",e);}

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
  if(_reviewed.has(v.id))return"";
  const sc=v.score!=null?`<span class="b bsc">${v.score.toFixed(1)}</span>`:"";
  const sv=`<span class="b b${SEV(v)}">${SEV(v)}</span>`;
  const sr=`<span class="b bsrc">${esc(v.source)}</span>`;
  const xp=v.badge?`<span class="b bxpl">${esc(v.badge)}</span>`:"";
  const ep=v.epss!=null?`<span class="b bepss" title="EPSS score: ${(v.epss*100).toFixed(2)}% probability of exploitation">EPSS ${v.epss_pct}%ile</span>`:"";
  const nw=v._new?`<span class="b bnew">NEW</span>`:"";
  const tr=v._trending?`<span class="b btrend" title="EPSS jumped >5pp in 24h — active exploitation likely">TRENDING</span>`:"";
  const pt=v.patch===true?`<span class="b bpatch">PATCH ✓</span>`:v.patch===false?`<span class="b bnopatch">NO FIX</span>`:"";
  const pc=v.poc?`<span class="b bpoc" title="Public proof-of-concept exploit exists on GitHub">PoC</span>`:"";
  const ur=v._unread?`<span class="b bunread" title="New since your last visit">UNREAD</span>`:"";
  const wl=isWatched(v)?`<span class="b bwl">&#9733;</span>`:"";
  const aff=(v.affected||[]).slice(0,6).map(a=>`<span class="chip">${esc(a)}</span>`).join("");
  const rfs=(v.references||[]).filter(Boolean).slice(0,3).map(u=>`<a href="${esc(u)}" target="_blank" rel="noopener">${esc(host(u))}</a>`).join(" &middot; ");
  const ttl=v.title&&v.title!==v.description?`<div class="ctitle">${esc(v.title)}</div>`:"";
  const dsc=v.description?`<div class="cdesc">${esc(v.description)}</div>`:"";
  const dt=v._ts?`<div class="cdate">${timeAgo(v._ts)}</div>`:"";
  const fixHtml=v.fix?`<div class="fix-cmd"><code>$ ${esc(v.fix)}</code><button class="fix-copy" data-fix="${esc(v.fix)}" onclick="event.stopPropagation();navigator.clipboard.writeText(this.dataset.fix).then(()=>{this.textContent='✓';setTimeout(()=>this.textContent='copy',1500)})">copy</button></div>`:"";
  const sharePath=hasCvePage(v)?`/cve/${v.id}.html`:`/#q=${encodeURIComponent(v.id)}`;
  const shareBtn=`<button class="share-btn" title="Copy link" onclick="event.stopPropagation();copyLink(this,'${sharePath}')" aria-label="Copy link"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></button>`;
  const discussBtn=hasCvePage(v)?`<a class="share-btn" href="/cve/${v.id}.html#giscus-frame" title="Discuss" onclick="event.stopPropagation()" aria-label="Open discussion"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></a>`:"";
  const watchedCls=isWatched(v)?" watched":"";
  const reviewBtn=`<button class="review-btn" title="Mark as reviewed" onclick="event.stopPropagation();_markReviewed('${esc(v.id)}',this.closest('.card'))" aria-label="Mark as reviewed">✕</button>`;
  return `<div class="card${watchedCls}" data-sev="${SEV(v)}" onclick="this.classList.toggle('expanded')"><div class="ctop"><div style="display:flex;align-items:center;gap:.3rem"><a class="cid" href="${esc(v.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(v.id)}</a>${shareBtn}${discussBtn}</div><div class="bdgs">${wl}${ur}${nw}${tr}${pc}${sc}${sv}${sr}${ep}${xp}${pt}</div>${reviewBtn}</div>${ttl}${dsc}${aff?`<div class="chips">${aff}</div>`:""}${fixHtml}${rfs?`<div class="refs">${rfs}</div>`:""}${dt}</div>`;
}

function newsItem(n){
  const srcColors={"Hacker News":"#ff6600","Bleeping Computer":"#1a73e8","The Hacker News":"#e53935","Krebs on Security":"#2e7d32","Security Week":"#6a1b9a"};
  const col=srcColors[n.source]||"#334155";
  const src=`<span class="b bsrc" style="flex-shrink:0;background:${col}">${esc(n.source)}</span>`;
  const sc=n.score!=null?`<strong style="color:#ff6600">▲ ${n.score}</strong>`:"";
  const cmt=n.comments_url?`<a href="${esc(n.comments_url)}" target="_blank" rel="noopener">${n.comments} 💬</a>`:"";
  const dt=n._ts?`<span style="color:var(--muted)">${timeAgo(n._ts)}</span>`:"";
  const meta=[sc,cmt,dt].filter(Boolean).join(" &middot; ");
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
let aSev="ALL",aSrc="ALL",aSrcExcl=null,aRange="7D",aSort="DATE",aNew=false,aWlOnly=false,q="",userPickedRange=false;

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
  if(aSrcExcl)p.set("srcx",aSrcExcl);
  if(aRange!=="24H")p.set("range",aRange);if(aSort!=="DATE")p.set("sort",aSort);
  if(aNew)p.set("new","1");
  const s=p.toString();history.replaceState(null,"",s?"#"+s:"#");
}
function syncSrcPills(){
  document.querySelectorAll(".pill[data-src]").forEach(b=>{
    const s=b.dataset.src;
    b.classList.remove("on","excl");
    if(s==="ALL"){if(aSrc==="ALL"&&!aSrcExcl)b.classList.add("on");}
    else if(s===aSrc)b.classList.add("on");
    else if(s===aSrcExcl)b.classList.add("excl");
  });
}
function applyHash(){
  const h=location.hash.slice(1);if(!h)return;
  const p=new URLSearchParams(h);
  q=p.get("q")||"";aSev=p.get("sev")||"ALL";aSrc=p.get("src")||"ALL";
  aSrcExcl=p.get("srcx")||null;
  aRange=p.get("range")||(p.get("q")?"ALL":"7D");aSort=p.get("sort")||"DATE";
  aNew=p.get("new")==="1";
  document.getElementById("search").value=q;
  document.getElementById("newPill").classList.toggle("on",aNew);
  ["data-sev","data-range","data-sort"].forEach(attr=>{
    const key=attr.replace("data-","");
    const val={sev:aSev,range:aRange,sort:aSort}[key];
    document.querySelectorAll(`.pill[${attr}]`).forEach(b=>b.classList.toggle("on",b.dataset[key]===val));
  });
  syncSrcPills();
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
    if(aSrcExcl&&v.source===aSrcExcl)return false;
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
  // Auto-relax filters when 0 results — overrides visData only, never touches aSrc/aRange
  // so source pills and range pills stay visually highlighted as the user left them.
  if(visData.length===0&&!aNew&&!aWlOnly&&aSev==="ALL"&&!userPickedRange){
    function _matchWords(v,words){
      const hay=[v.id,v.title,v.description,...(v.affected||[]),...(v.references||[])].join(" ").toLowerCase();
      return words.every(w=>hay.includes(w));
    }
    function _matchQ(v){return q?_matchWords(v,q.trim().split(/\s+/)):true;}
    const origRange=aRange;
    // Implied keyword from source name (e.g. "OpenStack" → ["openstack"])
    const impliedW=aSrc!=="ALL"?aSrc.toLowerCase().split(/[\s\-_]+/):null;
    const keyMatch=v=>q?_matchQ(v):(impliedW?_matchWords(v,impliedW):true);

    // Step 1: drop src restriction, keep range — match by query or implied keyword
    if(aSrc!=="ALL"){
      const mx=RANGES[aRange];
      visData=D.filter(v=>{
        if(mx!==Infinity&&(now2-(v._ts||0))>mx)return false;
        return keyMatch(v);
      });
    }
    // Step 2: expand range to ALL — keep src restriction + keyword match
    if(visData.length===0&&(origRange==="24H"||origRange==="7D")){
      aRange="ALL";
      document.querySelectorAll("[data-range]").forEach(b=>b.classList.remove("on"));
      const pAll=document.querySelector("[data-range='ALL']");if(pAll)pAll.classList.add("on");
      visData=D.filter(v=>{
        if(aSrcExcl&&v.source===aSrcExcl)return false;
        if(aSrc!=="ALL"&&v.source!==aSrc)return false;
        return keyMatch(v);
      });
    }
    // Step 3: still 0 — all sources, all time, keyword match only
    if(visData.length===0){
      aRange="ALL";
      document.querySelectorAll("[data-range]").forEach(b=>b.classList.remove("on"));
      const pAll=document.querySelector("[data-range='ALL']");if(pAll)pAll.classList.add("on");
      visData=D.filter(v=>keyMatch(v));
    }
  }
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
bindPills("data-sev",v=>aSev=v);
bindPills("data-range",v=>{aRange=v;userPickedRange=true;});bindPills("data-sort",v=>aSort=v);

// 3-state source pills: click1=include, click2=exclude, click3=reset
document.querySelectorAll(".pill[data-src]").forEach(b=>b.addEventListener("click",()=>{
  const s=b.dataset.src;
  if(s==="ALL"){aSrc="ALL";aSrcExcl=null;}
  else if(aSrc===s){aSrc="ALL";aSrcExcl=s;}  // 2nd click → exclude
  else if(aSrcExcl===s){aSrcExcl=null;}       // 3rd click → reset
  else{aSrc=s;aSrcExcl=null;}                 // 1st click → include
  userPickedRange=false;
  syncSrcPills();applyFilters();
}));

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
    data.forEach(v=>{v._ts=_toTS(v.published);});
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

// --- Export CSV ---
function csvCell(v){return'"'+String(v==null?"":v).replace(/"/g,'""')+'"';}
document.getElementById("csvBtn").addEventListener("click",()=>{
  const cols=["id","severity","score","epss_pct","source","published","badge","title","url"];
  const headers=["CVE ID","Severity","CVSS","EPSS %ile","Source","Published","Badge","Title","URL"];
  const rows=[headers.map(csvCell).join(",")];
  visData.forEach(v=>{
    rows.push(cols.map(k=>csvCell(v[k]??null)).join(","));
  });
  const blob=new Blob([rows.join("\\r\\n")],{type:"text/csv"});
  const a=document.createElement("a");
  a.href=URL.createObjectURL(blob);
  a.download=`vulnfeed-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();URL.revokeObjectURL(a.href);
});

document.getElementById("shareBtn").addEventListener("click",function(){
  const btn=this;
  navigator.clipboard.writeText(location.href).then(()=>{
    const prev=btn.innerHTML;btn.textContent="Copied!";btn.style.color="#4ade80";
    setTimeout(()=>{btn.innerHTML=prev;btn.style.color="";},1800);
  }).catch(()=>prompt("Copy this link:",location.href));
});

// Bootstrap: fetch vuln data then initialise
(function(){
  const loadEl=document.getElementById("vf-loading");
  fetch("vulns.json").then(function(r){
    if(!r.ok)throw new Error(r.status);
    return r.json();
  }).then(function(data){
    data.forEach(function(v){D.push(v);});
    D.forEach(v=>{v._ts=_toTS(v.published)});
    if(_lastVisit>0){
      const unreadCount=D.filter(v=>{if(v._ts&&v._ts>_lastVisit){v._unread=true;return true;}return false;}).length;
      if(unreadCount>0){
        const banner=document.getElementById("new-since-banner");
        const txt=document.getElementById("new-since-text");
        const ago=timeAgo(_lastVisit/1000);
        if(txt)txt.innerHTML=`&#128197; <strong>${unreadCount} new vulnerabilities</strong> since your last visit ${ago}`;
        if(banner)banner.style.display="flex";
      }
    }
    _syncReviewedBtn();
    setTimeout(()=>localStorage.setItem("vf_lastVisit",String(Date.now())),2000);
    const _nNew=D.filter(v=>v._new).length;
    const _np=document.getElementById("newPill");
    if(_np&&_nNew>0)_np.textContent="New ("+_nNew+")";
    if(loadEl)loadEl.style.display="none";
    updateTodayBadge();
    updateSevBrk();
    applyHash();
    applyFilters();
  }).catch(function(e){
    if(loadEl){loadEl.textContent="Failed to load data — please refresh.";loadEl.style.color="#f87171";}
    console.error("vulnfeed: fetch failed",e);
  });
})();


</script>
<div id="sub-modal" role="dialog" aria-modal="true" aria-label="Subscribe to weekly digest">
  <div id="sub-modal-box">
    <button id="sub-close" aria-label="Close">&times;</button>
    <div style="font-size:1.6rem;margin-bottom:.5rem">&#128231;</div>
    <h2>Weekly Digest</h2>
    <p>Top CVEs every Monday. No spam, unsubscribe anytime.</p>
    <form id="sub-form">
      <input type="email" name="email" placeholder="you@company.com" required>
      <div id="sub-topics-label">Topics &mdash; leave blank for everything</div>
      <div id="sub-topics">
        <label><input type="checkbox" value="kubernetes"> Kubernetes</label>
        <label><input type="checkbox" value="windows"> Windows</label>
        <label><input type="checkbox" value="linux-kernel"> Linux Kernel</label>
        <label><input type="checkbox" value="ubuntu"> Ubuntu</label>
        <label><input type="checkbox" value="debian"> Debian</label>
        <label><input type="checkbox" value="openstack"> OpenStack</label>
        <label><input type="checkbox" value="cisco"> Cisco</label>
        <label><input type="checkbox" value="fortinet"> Fortinet</label>
        <label><input type="checkbox" value="vmware"> VMware</label>
        <label><input type="checkbox" value="macos"> macOS</label>
        <label><input type="checkbox" value="android"> Android</label>
        <label><input type="checkbox" value="nginx"> nginx</label>
      </div>
      <button type="submit">Subscribe</button>
    </form>
    <div id="sub-modal-thanks">&#10003; Subscribed &mdash; see you Monday!</div>
  </div>
</div>
<script>
try{(function(){
  const ob=document.getElementById("sub-open-btn");
  if(localStorage.getItem("vf_subscribed")){if(ob)ob.style.display="none";return;}
  const modal=document.getElementById("sub-modal");
  const cls=document.getElementById("sub-close");
  const form=document.getElementById("sub-form");
  const thanks=document.getElementById("sub-modal-thanks");
  function openModal(){if(modal)modal.classList.add("open");}
  function closeModal(){if(modal)modal.classList.remove("open");}
  if(ob)ob.addEventListener("click",openModal);
  if(cls)cls.addEventListener("click",closeModal);
  if(modal)modal.addEventListener("click",function(e){if(e.target===modal)closeModal();});
  document.addEventListener("keydown",function(e){if(e.key==="Escape")closeModal();});
  if(form)form.addEventListener("submit",function(e){
    e.preventDefault();
    const email=form.querySelector('[name=email]').value;
    const btn=form.querySelector('button[type=submit]');
    if(btn){btn.disabled=true;btn.textContent="Sending…";}
    const body=new URLSearchParams({email:email,embed:"1"});
    form.querySelectorAll('#sub-topics input:checked').forEach(cb=>body.append('tag',cb.value));
    function _done(){
      try{localStorage.setItem("vf_subscribed","1");}catch(_){}
      if(form)form.style.display="none";
      if(thanks)thanks.style.display="block";
      if(ob)ob.style.display="none";
      setTimeout(closeModal,1800);
    }
    fetch("https://buttondown.com/api/emails/embed-subscribe/vulnfeed",{method:"POST",body:body})
      .then(_done).catch(_done);
  });
})()}catch(_){}
</script>
__STATIC_CVE_HTML__
<script>if("serviceWorker"in navigator)navigator.serviceWorker.register("/sw.js")</script>
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


def write_rss(vulns, base_url=BASE_URL):
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
            # Ensure all published dates carry UTC Z so browser Date() parses correctly
            for v in data:
                p = v.get("published") or ""
                if p and not (p.endswith("Z") or "+" in p[-7:]):
                    v["published"] = p + "Z"
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
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
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
.heatmap-days{display:flex;gap:3px;flex-wrap:wrap;padding-bottom:.25rem}
.hday{width:20px;height:20px;border-radius:3px;flex-shrink:0;cursor:default}
.heatmap-legend{display:flex;align-items:center;gap:.35rem;margin-top:.6rem;font-size:.72rem;color:var(--muted)}
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
  <h2>Daily severity heatmap</h2>
  __HEATMAP__
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


def write_search_page(vulns, base_url=BASE_URL):
    sources = sorted(set(v.get("source", "") for v in vulns if v.get("source")))
    src_opts = "\n".join(
        f'<option value="{_xe(s)}">{_xe(s)}</option>' for s in sources
    )
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments);}}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>vulnfeed &mdash; Advanced Search</title>
<meta name="description" content="Advanced CVE search — filter by severity, CVSS score, EPSS, source, date range and more.">
<link rel="canonical" href="{base_url}/search.html">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--unk:#6b7280}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;font-size:14px}}
header{{background:var(--hdr);color:var(--htxt);padding:1.1rem 2rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}}
.logo{{font-size:1.2rem;font-weight:800;letter-spacing:-.02em}}.logo em{{color:#60a5fa;font-style:normal}}
.hlink{{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}}
.hlink:hover{{border-color:#60a5fa;background:rgba(96,165,250,.08)}}
.wrap{{max-width:1060px;margin:0 auto;padding:2rem}}
/* Search form */
.sf-panel{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.sf-panel h1{{font-size:.7rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1.1rem}}
.sf-row{{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:.75rem}}
.sf-field{{display:flex;flex-direction:column;gap:.28rem;min-width:160px}}
.sf-field.wide{{flex:1 1 280px}}
.sf-field label{{font-size:.72rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}}
.sf-field input[type=text],.sf-field input[type=number],.sf-field input[type=date],.sf-field select{{padding:.42rem .65rem;border:1px solid var(--border);border-radius:6px;font-size:.84rem;color:var(--text);background:var(--bg);outline:none;transition:border-color .15s}}
.sf-field input:focus,.sf-field select:focus{{border-color:var(--accent)}}
.sf-checks{{display:flex;flex-wrap:wrap;gap:.4rem .9rem;padding-top:.15rem}}
.sf-checks label{{display:flex;align-items:center;gap:.35rem;font-size:.8rem;cursor:pointer;white-space:nowrap}}
.sf-checks input{{accent-color:var(--accent);width:13px;height:13px}}
.sf-actions{{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin-top:.25rem}}
.sf-actions button{{padding:.42rem .9rem;border-radius:6px;font-size:.82rem;font-weight:600;cursor:pointer;border:1px solid var(--border);background:var(--bg);color:var(--text);transition:background .15s,border-color .15s}}
.sf-actions button:hover{{background:#f1f5f9;border-color:#94a3b8}}
#sf-submit{{background:var(--accent);color:#fff;border-color:var(--accent)}}
#sf-submit:hover{{background:#1d4ed8;border-color:#1d4ed8}}
#sf-count{{margin-left:auto;font-size:.78rem;color:var(--muted)}}
/* Result cards */
#sf-results{{display:grid;gap:.6rem}}
.rc{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.85rem 1rem;display:grid;grid-template-columns:auto 1fr;gap:.5rem .9rem;align-items:start;text-decoration:none;color:inherit;transition:border-color .15s,box-shadow .15s;position:relative}}
.rc:hover{{border-color:var(--accent);box-shadow:0 2px 8px rgba(37,99,235,.08)}}
.rc-id{{font-family:ui-monospace,monospace;font-size:.8rem;font-weight:700;color:var(--accent);white-space:nowrap}}
.rc-title{{font-size:.84rem;font-weight:600;line-height:1.4;color:var(--text)}}
.rc-meta{{grid-column:2;display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin-top:.1rem}}
.rb{{display:inline-block;padding:.06rem .32rem;border-radius:3px;font-size:.63rem;font-weight:700;color:#fff;text-transform:uppercase}}
.rbCRITICAL{{background:var(--crit)}}.rbHIGH{{background:var(--high)}}.rbMEDIUM{{background:var(--med)}}.rbLOW{{background:var(--low)}}.rbUNKNOWN{{background:var(--unk)}}
.rb-src{{background:#334155;color:#cbd5e1}}.rb-kev{{background:#7c3aed}}.rb-score{{background:#0369a1}}.rb-epss{{background:#0d9488}}
.rc-desc{{grid-column:2;font-size:.78rem;color:var(--muted);line-height:1.5;margin-top:.1rem;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}}
@media(max-width:600px){{.wrap{{padding:1rem}}.sf-row{{flex-direction:column}}}}
</style>
</head>
<body>
<header>
  <div class="logo">vuln<em>feed</em></div>
  <div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap">
    <a class="hlink" href="/">&#8592; Feed</a>
    <a class="hlink" href="/stats.html">Stats</a>
    <a class="hlink" href="/feed.xml">&#9656;&nbsp;RSS</a>
  </div>
</header>
<div class="wrap">
<div class="sf-panel">
  <h1>Advanced Search</h1>
  <form id="sf" autocomplete="off">
    <div class="sf-row">
      <div class="sf-field wide"><label>Keyword / CVE ID &mdash; <span style="font-weight:400;text-transform:none;letter-spacing:0">results update as you type, all fields optional</span></label>
        <input type="text" id="sf-q" placeholder='e.g. openstack, CVE-2024-1234, nginx'></div>
      <div class="sf-field"><label>Source</label>
        <select id="sf-src"><option value="">All sources</option>{src_opts}</select></div>
    </div>
    <div class="sf-row">
      <div class="sf-field"><label>Severity</label>
        <div class="sf-checks">
          <label><input type="checkbox" name="sev" value="CRITICAL"> Critical</label>
          <label><input type="checkbox" name="sev" value="HIGH"> High</label>
          <label><input type="checkbox" name="sev" value="MEDIUM"> Medium</label>
          <label><input type="checkbox" name="sev" value="LOW"> Low</label>
        </div></div>
      <div class="sf-field"><label>CVSS &ge;</label>
        <input type="number" id="sf-score" min="0" max="10" step="0.1" placeholder="e.g. 7.5" style="width:110px"></div>
      <div class="sf-field"><label>EPSS &ge; %ile</label>
        <input type="number" id="sf-epss" min="0" max="100" step="1" placeholder="e.g. 50" style="width:110px"></div>
    </div>
    <div class="sf-row">
      <div class="sf-field"><label>Published from</label>
        <input type="date" id="sf-from"></div>
      <div class="sf-field"><label>Published to</label>
        <input type="date" id="sf-to"></div>
      <div class="sf-field" style="justify-content:flex-end;padding-bottom:.1rem"><label>&nbsp;</label>
        <div class="sf-checks">
          <label><input type="checkbox" id="sf-kev"> KEV &mdash; actively exploited only</label>
          <label><input type="checkbox" id="sf-new"> New since yesterday only</label>
        </div></div>
    </div>
    <div class="sf-actions">
      <button type="submit" id="sf-submit">Search</button>
      <button type="button" id="sf-clear">Clear</button>
      <button type="button" id="sf-copy">Copy link</button>
      <button type="button" id="sf-csv" style="display:none">Export CSV</button>
      <span id="sf-count"></span>
    </div>
  </form>
</div>
<div id="sf-results"></div>
</div>
<script>
(function(){{
  const BASE="{base_url}";
  let D=[], loaded=false, lastResults=[];

  function esc(s){{return(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}}
  function toTS(s){{if(!s)return 0;try{{return new Date(/Z|[+-]\d\d:/.test(s)?s:s+"Z").getTime();}}catch(_){{return 0;}}}}

  // Read/write URL params
  function getParams(){{
    const p=new URLSearchParams(location.search);
    return {{
      q:p.get("q")||"",
      src:p.get("src")||"",
      sev:(p.get("sev")||"").split(",").filter(Boolean),
      score:p.get("score")||"",
      epss:p.get("epss")||"",
      from:p.get("from")||"",
      to:p.get("to")||"",
      kev:p.get("kev")==="1",
      new_:p.get("new")==="1",
    }};
  }}
  function setParams(f){{
    const p=new URLSearchParams();
    if(f.q)p.set("q",f.q);
    if(f.src)p.set("src",f.src);
    if(f.sev.length)p.set("sev",f.sev.join(","));
    if(f.score)p.set("score",f.score);
    if(f.epss)p.set("epss",f.epss);
    if(f.from)p.set("from",f.from);
    if(f.to)p.set("to",f.to);
    if(f.kev)p.set("kev","1");
    if(f.new_)p.set("new","1");
    const url=location.pathname+(p.toString()?"?"+p:"");
    history.replaceState(null,"",url);
  }}

  function readForm(){{
    return {{
      q:document.getElementById("sf-q").value.trim(),
      src:document.getElementById("sf-src").value,
      sev:[...document.querySelectorAll('[name=sev]:checked')].map(c=>c.value),
      score:document.getElementById("sf-score").value,
      epss:document.getElementById("sf-epss").value,
      from:document.getElementById("sf-from").value,
      to:document.getElementById("sf-to").value,
      kev:document.getElementById("sf-kev").checked,
      new_:document.getElementById("sf-new").checked,
    }};
  }}
  function fillForm(f){{
    document.getElementById("sf-q").value=f.q;
    document.getElementById("sf-src").value=f.src;
    document.querySelectorAll('[name=sev]').forEach(c=>{{c.checked=f.sev.includes(c.value);}});
    document.getElementById("sf-score").value=f.score;
    document.getElementById("sf-epss").value=f.epss;
    document.getElementById("sf-from").value=f.from;
    document.getElementById("sf-to").value=f.to;
    document.getElementById("sf-kev").checked=f.kev;
    document.getElementById("sf-new").checked=f.new_;
  }}

  function match(v,f){{
    if(f.src&&v.source!==f.src)return false;
    if(f.sev.length&&!f.sev.includes(v.severity||"UNKNOWN"))return false;
    if(f.kev&&!v.kev)return false;
    if(f.new_&&!v._new)return false;
    if(f.score){{const mn=parseFloat(f.score);if(isNaN(mn)||(v.score==null||v.score<mn))return false;}}
    if(f.epss){{const mn=parseFloat(f.epss);if(isNaN(mn)||(v.epss_pct==null||v.epss_pct<mn))return false;}}
    if(f.from||f.to){{
      const ts=toTS(v.published);
      if(f.from&&ts<new Date(f.from).getTime())return false;
      if(f.to&&ts>new Date(f.to).getTime()+86399999)return false;
    }}
    if(f.q){{
      const words=f.q.toLowerCase().split(/\s+/);
      const hay=[v.id,v.title,v.description,...(v.affected||[]),...(v.references||[])].join(" ").toLowerCase();
      if(!words.every(w=>hay.includes(w)))return false;
    }}
    return true;
  }}

  function renderCard(v){{
    const sev=v.severity||"UNKNOWN";
    const score=v.score!=null?`<span class="rb rb-score">CVSS ${{v.score.toFixed(1)}}</span>`:"";
    const epss=v.epss_pct!=null?`<span class="rb rb-epss">EPSS ${{v.epss_pct.toFixed(1)}}%</span>`:"";
    const kev=v.kev?`<span class="rb rb-kev">KEV</span>`:"";
    const desc=v.description?`<div class="rc-desc">${{esc(v.description)}}</div>`:"";
    return `<a class="rc" href="${{BASE}}/cve/${{esc(v.id)}}.html" target="_blank" rel="noopener">
      <div class="rc-id">${{esc(v.id)}}</div>
      <div class="rc-title">${{esc(v.title||v.id)}}</div>
      <div class="rc-meta">
        <span class="rb rb${{sev}}">${{sev}}</span>
        <span class="rb rb-src">${{esc(v.source||"")}}</span>
        ${{score}}${{epss}}${{kev}}
        <span style="font-size:.72rem;color:#94a3b8;margin-left:auto">${{esc(v.published||"").slice(0,10)}}</span>
      </div>
      ${{desc}}
    </a>`;
  }}

  function runSearch(){{
    if(!loaded){{document.getElementById("sf-count").textContent="Loading…";return;}}
    const f=readForm();
    setParams(f);
    const hasFilter=f.q||f.src||f.sev.length||f.score||f.epss||f.from||f.to||f.kev||f.new_;
    const resultsEl=document.getElementById("sf-results");
    const countEl=document.getElementById("sf-count");
    const csvBtn=document.getElementById("sf-csv");
    if(!hasFilter){{
      resultsEl.innerHTML="";
      countEl.textContent="";
      csvBtn.style.display="none";
      lastResults=[];
      return;
    }}
    const res=D.filter(v=>match(v,f)).slice(0,500);
    lastResults=res;
    countEl.textContent=res.length===500?`500+ results (showing first 500)`:`${{res.length.toLocaleString()}} result${{res.length!==1?"s":""}}`;
    csvBtn.style.display=res.length?"":"none";
    resultsEl.innerHTML=res.map(renderCard).join("");
  }}

  function exportCSV(){{
    const cols=["id","title","severity","score","epss_pct","kev","source","published","url"];
    const header=cols.join(",");
    const rows=lastResults.map(v=>cols.map(c=>{{
      const val=v[c]??"";;
      return typeof val==="string"?`"${{val.replace(/"/g,'""')}}"`:(typeof val==="boolean"?val?"yes":"":""+val);
    }}).join(","));
    const blob=new Blob([header+"\\n"+rows.join("\\n")],{{type:"text/csv"}});
    const a=document.createElement("a");
    a.href=URL.createObjectURL(blob);
    a.download="vulnfeed-search.csv";
    a.click();
  }}

  // Live search — debounced on any field change
  let _t=null;
  function _debounce(){{clearTimeout(_t);_t=setTimeout(runSearch,220);}}
  document.getElementById("sf-q").addEventListener("input",_debounce);
  document.getElementById("sf-src").addEventListener("change",_debounce);
  document.querySelectorAll('[name=sev],#sf-kev,#sf-new').forEach(el=>el.addEventListener("change",_debounce));
  document.getElementById("sf-score").addEventListener("input",_debounce);
  document.getElementById("sf-epss").addEventListener("input",_debounce);
  document.getElementById("sf-from").addEventListener("change",_debounce);
  document.getElementById("sf-to").addEventListener("change",_debounce);

  // Wire up
  document.getElementById("sf").addEventListener("submit",function(e){{e.preventDefault();runSearch();}});
  document.getElementById("sf-clear").addEventListener("click",function(){{
    fillForm({{q:"",src:"",sev:[],score:"",epss:"",from:"",to:"",kev:false,new_:false}});
    document.getElementById("sf-results").innerHTML="";
    document.getElementById("sf-count").textContent="";
    document.getElementById("sf-csv").style.display="none";
    history.replaceState(null,"",location.pathname);
    lastResults=[];
  }});
  document.getElementById("sf-copy").addEventListener("click",function(){{
    navigator.clipboard.writeText(location.href).then(()=>{{
      const b=document.getElementById("sf-copy");
      const t=b.textContent;b.textContent="Copied!";setTimeout(()=>b.textContent=t,1500);
    }});
  }});
  document.getElementById("sf-csv").addEventListener("click",exportCSV);

  // Load data
  fetch("vulns.json").then(r=>{{if(!r.ok)throw new Error(r.status);return r.json();}})
    .then(data=>{{
      data.forEach(v=>D.push(v));
      loaded=true;
      const init=getParams();
      const hasInit=init.q||init.src||init.sev.length||init.score||init.epss||init.from||init.to||init.kev||init.new_;
      if(hasInit){{fillForm(init);runSearch();}}
    }})
    .catch(e=>document.getElementById("sf-count").textContent="Failed to load data.");
}})();
</script>
</body>
</html>"""
    with open("search.html", "w", encoding="utf-8") as fh:
        fh.write(html)
    log("  Written: search.html")


def write_how_to_scan_page(base_url=BASE_URL):
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments);}}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>How to scan for CVEs &mdash; vulnfeed</title>
<meta name="description" content="Practical guide to scanning your infrastructure for known CVEs using Nuclei, Trivy, Grype, and OpenVAS.">
<link rel="canonical" href="{base_url}/how-to-scan.html">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.7}}
header{{background:var(--hdr);color:var(--htxt);padding:1.1rem 2rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}}
.logo{{font-size:1.2rem;font-weight:800;letter-spacing:-.02em}}.logo em{{color:#60a5fa;font-style:normal}}
.hlink{{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}}
.hlink:hover{{border-color:#60a5fa;background:rgba(96,165,250,.08)}}
.wrap{{max-width:800px;margin:0 auto;padding:2.5rem 1.5rem}}
h1{{font-size:1.7rem;font-weight:800;letter-spacing:-.03em;margin-bottom:.4rem}}
.subtitle{{font-size:.95rem;color:var(--muted);margin-bottom:2.5rem}}
h2{{font-size:1.05rem;font-weight:700;margin:2rem 0 .6rem;padding-top:2rem;border-top:1px solid var(--border)}}
h2:first-of-type{{border-top:none;padding-top:0}}
h3{{font-size:.9rem;font-weight:700;margin:1.2rem 0 .35rem;color:#334155}}
p{{font-size:.88rem;margin-bottom:.75rem}}
ul,ol{{font-size:.88rem;padding-left:1.4rem;margin-bottom:.75rem}}
li{{margin-bottom:.3rem}}
code{{font-family:ui-monospace,monospace;font-size:.8rem;background:#f1f5f9;border:1px solid var(--border);padding:.1rem .35rem;border-radius:4px}}
pre{{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:1.1rem 1.3rem;overflow-x:auto;margin:.6rem 0 1rem;font-size:.8rem;line-height:1.6}}
pre code{{background:none;border:none;padding:0;color:inherit;font-size:inherit}}
.tool-card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.25rem 1.4rem;margin-bottom:1rem;box-shadow:0 1px 3px rgba(0,0,0,.05)}}
.tool-header{{display:flex;align-items:center;gap:.6rem;margin-bottom:.5rem}}
.tool-name{{font-size:.95rem;font-weight:700}}
.tool-tag{{font-size:.65rem;font-weight:700;padding:.08rem .4rem;border-radius:3px;background:#e0f2fe;color:#0369a1;text-transform:uppercase}}
.tool-tag.red{{background:#fee2e2;color:#dc2626}}
.tool-tag.green{{background:#dcfce7;color:#16a34a}}
.tool-tag.purple{{background:#f3e8ff;color:#7c3aed}}
.tip{{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:.85rem 1rem;font-size:.83rem;margin:1rem 0;color:#1e3a8a;line-height:1.6}}
.tip strong{{font-weight:700}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
@media(max-width:600px){{.wrap{{padding:1.5rem 1rem}}h1{{font-size:1.3rem}}}}
</style>
</head>
<body>
<header>
  <div class="logo">vuln<em>feed</em></div>
  <div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap">
    <a class="hlink" href="/">&#8592; Feed</a>
    <a class="hlink" href="/search.html">&#128269;&nbsp;Search</a>
    <a class="hlink" href="/stats.html">Stats</a>
  </div>
</header>
<div class="wrap">

<h1>How to scan your infrastructure for CVEs</h1>
<p class="subtitle">A practical guide to finding known vulnerabilities in your endpoints, containers, and packages — using free, open-source tools.</p>

<h2>1. Scan web endpoints with Nuclei</h2>
<p><a href="https://github.com/projectdiscovery/nuclei" target="_blank" rel="noopener">Nuclei</a> is the fastest way to check if a target is vulnerable to a specific CVE. It uses community-maintained templates — many are added within hours of a disclosure.</p>

<div class="tool-card">
  <div class="tool-header">
    <span class="tool-name">Nuclei</span>
    <span class="tool-tag green">Free</span>
    <span class="tool-tag">Web &amp; API</span>
    <span class="tool-tag purple">Network</span>
  </div>
  <p>Install:</p>
  <pre><code>go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# or via brew:
brew install nuclei</code></pre>
  <p>Scan a host for all CVE templates:</p>
  <pre><code>nuclei -u https://your-target.com -tags cve -o results.txt</code></pre>
  <p>Scan for a specific CVE (e.g. after spotting it on vulnfeed):</p>
  <pre><code>nuclei -u https://your-target.com -id CVE-2024-1234</code></pre>
  <p>Scan a list of hosts, only critical/high severity:</p>
  <pre><code>nuclei -list hosts.txt -tags cve -severity critical,high -o cve-results.json -jsonl</code></pre>
  <p>Update templates to get the latest CVE checks:</p>
  <pre><code>nuclei -update-templates</code></pre>
</div>

<div class="tip"><strong>Tip:</strong> When you see a new CVE on vulnfeed, check the <a href="https://github.com/projectdiscovery/nuclei-templates/tree/main/http/cves" target="_blank" rel="noopener">nuclei-templates CVE directory</a> — search by CVE ID to see if a template exists. If it does, you can test your exposure immediately.</div>

<h2>2. Scan containers and filesystems with Trivy</h2>
<p><a href="https://github.com/aquasecurity/trivy" target="_blank" rel="noopener">Trivy</a> scans container images, filesystems, and code repos for known CVEs in installed packages. Essential for any team running Docker or Kubernetes.</p>

<div class="tool-card">
  <div class="tool-header">
    <span class="tool-name">Trivy</span>
    <span class="tool-tag green">Free</span>
    <span class="tool-tag">Containers</span>
    <span class="tool-tag">Packages</span>
  </div>
  <p>Install:</p>
  <pre><code>brew install aquasecurity/trivy/trivy
# or via apt:
apt install trivy</code></pre>
  <p>Scan a Docker image:</p>
  <pre><code>trivy image nginx:latest
trivy image --severity CRITICAL,HIGH your-app:latest</code></pre>
  <p>Scan the local filesystem (e.g. a Python/Node project):</p>
  <pre><code>trivy fs .
trivy fs --severity CRITICAL /path/to/project</code></pre>
  <p>Scan a running Kubernetes cluster:</p>
  <pre><code>trivy k8s --report summary cluster</code></pre>
  <p>Output as JSON for ingestion into other tools:</p>
  <pre><code>trivy image -f json -o results.json nginx:latest</code></pre>
</div>

<h2>3. Scan installed packages with Grype</h2>
<p><a href="https://github.com/anchore/grype" target="_blank" rel="noopener">Grype</a> is a fast vulnerability scanner for container images and filesystems. Pairs well with Trivy as a second opinion.</p>

<div class="tool-card">
  <div class="tool-header">
    <span class="tool-name">Grype</span>
    <span class="tool-tag green">Free</span>
    <span class="tool-tag">Containers</span>
    <span class="tool-tag">OS packages</span>
  </div>
  <pre><code>curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

grype your-image:latest
grype dir:/path/to/project
grype sbom:/path/to/sbom.json       # scan from an SBOM
grype your-image:latest -o json | jq '.matches[] | select(.vulnerability.severity=="Critical")'</code></pre>
</div>

<h2>4. Scan network services with OpenVAS / Greenbone</h2>
<p><a href="https://www.greenbone.net/en/community-edition/" target="_blank" rel="noopener">Greenbone Community Edition</a> (formerly OpenVAS) is a full network vulnerability scanner. Heavier to set up but covers network-level CVEs that web-only scanners miss.</p>

<div class="tool-card">
  <div class="tool-header">
    <span class="tool-name">Greenbone / OpenVAS</span>
    <span class="tool-tag green">Free</span>
    <span class="tool-tag red">Network scan</span>
  </div>
  <p>Quickest way to run it is via Docker:</p>
  <pre><code>docker run -d -p 9392:9392 --name openvas greenbone/community-edition
# Wait ~10 minutes for feeds to sync, then open:
# https://localhost:9392  (admin / admin)</code></pre>
  <p>Or install on Debian/Ubuntu:</p>
  <pre><code>sudo apt install gvm
sudo gvm-setup
sudo gvm-start
# Open https://localhost:9392</code></pre>
</div>

<div class="tip"><strong>Warning:</strong> Network scanners send real exploit probes. Only scan infrastructure you own or have written permission to test. Running these against third-party services without authorization is illegal.</div>

<h2>5. Check specific CVEs against your OS packages</h2>
<p>If you know a CVE from vulnfeed and want to quickly check if your system is affected:</p>

<div class="tool-card">
  <div class="tool-header">
    <span class="tool-name">Debian / Ubuntu</span>
    <span class="tool-tag green">Built-in</span>
  </div>
  <pre><code># Check if a package version is affected
apt-cache policy &lt;package-name&gt;

# Full security audit with debsecan
sudo apt install debsecan
debsecan --suite $(lsb_release -cs) --format detail | grep CVE-2024-1234

# Or use unattended-upgrades to auto-apply security patches:
sudo unattended-upgrade --dry-run -d</code></pre>
</div>

<div class="tool-card">
  <div class="tool-header">
    <span class="tool-name">RHEL / CentOS / Rocky / AlmaLinux</span>
    <span class="tool-tag green">Built-in</span>
  </div>
  <pre><code># Check for a specific CVE
dnf updateinfo list --cve CVE-2024-1234

# List all available security updates
dnf updateinfo list security

# Apply security updates only
sudo dnf upgrade --security</code></pre>
</div>

<h2>6. Automate: daily CVE checks in CI</h2>
<p>Add CVE scanning to your CI pipeline so every image build is checked before deployment:</p>

<div class="tool-card">
  <div class="tool-header">
    <span class="tool-name">GitHub Actions example</span>
    <span class="tool-tag purple">CI/CD</span>
  </div>
  <pre><code>name: CVE Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t myapp:${{{{ github.sha }}}} .
      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{{{ github.sha }}}}
          severity: CRITICAL,HIGH
          exit-code: 1        # fail the build if found</code></pre>
</div>

<h2>Recommended workflow</h2>
<ol>
  <li>Subscribe to <a href="/">vulnfeed weekly digest</a> to get notified of new critical CVEs.</li>
  <li>When you see a relevant CVE, check if a <a href="https://github.com/projectdiscovery/nuclei-templates" target="_blank" rel="noopener">Nuclei template</a> exists and run it against your endpoints.</li>
  <li>Run <code>trivy image</code> on every container build in CI — fail on CRITICAL.</li>
  <li>Run a weekly <code>nuclei -tags cve -severity critical,high</code> sweep against your public-facing services.</li>
  <li>Subscribe to your distro's security mailing list (Ubuntu USN, Debian DSA, RHEL RHSA) for OS-level patches.</li>
</ol>

</div>
</body>
</html>"""
    with open("how-to-scan.html", "w", encoding="utf-8") as fh:
        fh.write(html)
    log("  Written: how-to-scan.html")


def _build_heatmap_html():
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    SEV_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#16a34a", "UNKNOWN": "#94a3b8"}
    if not os.path.isdir("historical"):
        return "<p style='color:#64748b;font-size:.8rem'>No historical data yet.</p>"
    date_files = sorted(
        f[:-5] for f in os.listdir("historical")
        if f.endswith(".json") and f != "index.json"
    )
    if not date_files:
        return "<p style='color:#64748b;font-size:.8rem'>No historical data yet.</p>"
    squares = []
    for ds in date_files:
        path = os.path.join("historical", f"{ds}.json")
        try:
            with open(path, encoding="utf-8") as f:
                day_vulns = json.load(f)
        except Exception:
            continue
        if not day_vulns:
            color = "#e2e8f0"
            tip = f"{ds}: no data"
        else:
            worst_sev = min(
                (v.get("severity", "UNKNOWN") for v in day_vulns),
                key=lambda s: SEV_ORDER.get(s, 4)
            )
            color = SEV_COLOR.get(worst_sev, "#e2e8f0")
            n_crit = sum(1 for v in day_vulns if v.get("severity") == "CRITICAL")
            tip = f"{ds}: {len(day_vulns):,} CVEs"
            if n_crit:
                tip += f" ({n_crit} critical)"
        squares.append(f'<div class="hday" style="background:{color}" title="{_xe(tip)}"></div>')
    return (
        f'<div class="heatmap-days">{"".join(squares)}</div>'
        f'<div class="heatmap-legend">'
        f'<span>Low</span>'
        f'<div class="hday" style="background:#16a34a"></div>'
        f'<div class="hday" style="background:#d97706"></div>'
        f'<div class="hday" style="background:#ea580c"></div>'
        f'<div class="hday" style="background:#dc2626"></div>'
        f'<span>Critical</span>'
        f'&nbsp;&nbsp;<div class="hday" style="background:#e2e8f0"></div>'
        f'<span>No data</span>'
        f'</div>'
    )


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
    html = html.replace("__HEATMAP__", _build_heatmap_html())
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
    ("cisco",        "Cisco",             "cisco"),
    ("arista",       "Arista",            "arista"),
    ("microsoft",    "Microsoft",         "microsoft"),
    ("windows",      "Windows",           "windows"),
    ("vmware",       "VMware",            "vmware"),
    ("fortinet",     "Fortinet",          "fortinet"),
    ("palo-alto",    "Palo Alto",         "palo alto"),
    ("juniper",      "Juniper",           "juniper"),
    ("ivanti",       "Ivanti",            "ivanti"),
    ("citrix",       "Citrix",            "citrix"),
    ("f5",           "F5",                "f5"),
]

_VENDOR_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>__VENDOR__ vulnerabilities &mdash; vulnfeed</title>
<meta name="description" content="__COUNT__ recent vulnerabilities for __VENDOR__ aggregated from NVD, CISA KEV, Ubuntu, Debian, Red Hat and more.">
<link rel="alternate" type="application/rss+xml" title="vulnfeed — __VENDOR__ vulnerabilities" href="/vendor/__SLUG__.xml">
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
        matched.sort(key=lambda v: _pub_ymd(v.get("published") or ""), reverse=True)

        if not matched:
            continue

        rows = []
        for v in matched:
            sev = v.get("severity", "UNKNOWN")
            cve_url = v.get("url", "")
            sc_str = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
            epss_str = f'{v["epss_pct"]:.0f}%ile' if v.get("epss_pct") is not None else "—"
            pub = _pub_ymd(v.get("published") or "")
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
        html = html.replace("__VENDOR__",   _xe(display_name))
        html = html.replace("__SLUG__",     slug)
        html = html.replace("__KEYWORD__",  _xe(keyword))
        html = html.replace("__COUNT__",    str(len(matched)))
        html = html.replace("__DATE__",     date_str)
        html = html.replace("__TABLE__",    table_html)

        with open(os.path.join("vendor", f"{slug}.html"), "w", encoding="utf-8") as f:
            f.write(html)

        # Per-vendor RSS
        def _xe2(s):
            return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        now_rfc = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        rss_items = []
        for v in matched[:50]:
            t = _xe2(f'[{v.get("severity","?")}] {v["id"]}: {(v.get("title") or "")[:180]}')
            lk = _xe2(v.get("url",""))
            ds = _xe2((v.get("description") or "")[:400])
            pb = _rfc822(v.get("published",""))
            rss_items.append(
                f"  <item><title>{t}</title><link>{lk}</link>"
                f"<description>{ds}</description><pubDate>{pb}</pubDate>"
                f'<guid isPermaLink="false">{_xe2(v.get("url") or v["id"])}</guid></item>'
            )
        rss_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n<channel>\n'
            f'<title>vulnfeed — {_xe2(display_name)} vulnerabilities</title>\n'
            f'<link>{base_url}/vendor/{slug}.html</link>\n'
            f'<description>Recent {_xe2(display_name)} CVEs aggregated by vulnfeed</description>\n'
            f'<lastBuildDate>{now_rfc}</lastBuildDate>\n'
            f'<atom:link href="{base_url}/vendor/{slug}.xml" rel="self" type="application/rss+xml"/>\n'
            + "\n".join(rss_items)
            + "\n</channel>\n</rss>"
        )
        with open(os.path.join("vendor", f"{slug}.xml"), "w", encoding="utf-8") as f:
            f.write(rss_xml)

        pages.append({"slug": slug, "display_name": display_name, "count": len(matched)})

    log(f"  Written: {len(pages)} vendor pages + RSS → vendor/")
    return pages


# ---------------------------------------------------------------------------
# CWE category pages
# ---------------------------------------------------------------------------

CWE_PAGES = [
    # (cwe_id, display_name, keyword)
    ("CWE-89",  "SQL Injection",                     "sql injection"),
    ("CWE-79",  "Cross-Site Scripting (XSS)",         "cross-site scripting"),
    ("CWE-78",  "OS Command Injection",               "command injection"),
    ("CWE-22",  "Path Traversal",                    "path traversal"),
    ("CWE-787", "Out-of-bounds Write",                "out-of-bounds write"),
    ("CWE-125", "Out-of-bounds Read",                 "out-of-bounds read"),
    ("CWE-416", "Use After Free",                    "use after free"),
    ("CWE-94",  "Code Injection",                    "code injection"),
    ("CWE-502", "Deserialization",                   "deserialization"),
    ("CWE-611", "XML External Entity (XXE)",          "xxe"),
    ("CWE-918", "Server-Side Request Forgery (SSRF)", "ssrf"),
    ("CWE-352", "Cross-Site Request Forgery (CSRF)",  "csrf"),
    ("CWE-190", "Integer Overflow",                  "integer overflow"),
    ("CWE-476", "NULL Pointer Dereference",           "null pointer dereference"),
    ("CWE-269", "Privilege Escalation",              "privilege escalat"),
    ("CWE-306", "Missing Authentication",            "missing authentication"),
    ("CWE-20",  "Improper Input Validation",         "input validation"),
    ("CWE-119", "Buffer Overflow",                   "buffer overflow"),
    ("CWE-798", "Hardcoded Credentials",             "hardcoded"),
    ("CWE-434", "Unrestricted File Upload",          "file upload"),
]

_CWE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>__CWE_ID__: __CWE_NAME__ CVEs &mdash; vulnfeed</title>
<meta name="description" content="__COUNT__ CVEs matching __CWE_ID__ (__CWE_NAME__) aggregated from NVD, CISA KEV, Red Hat and more. Updated __DATE__.">
<link rel="canonical" href="__BASE_URL__/cwe/__CWE_ID__.html">
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
.cwe-badge{display:inline-block;background:#6366f1;color:#fff;border-radius:4px;padding:.1rem .4rem;font-size:.75rem;font-family:ui-monospace,monospace;font-weight:700;margin-right:.4rem}
.sub{font-size:.8rem;color:var(--muted);margin-bottom:1.75rem}.sub a{color:var(--accent)}
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
    <a class="hlink" href="/#q=__CWE_ID__">Search feed</a>
  </div>
</header>
<div class="wrap">
  <h1><span class="cwe-badge">__CWE_ID__</span> __CWE_NAME__ vulnerabilities</h1>
  <p class="sub">__COUNT__ CVEs &mdash; updated __DATE__ &middot; <a href="/">vulnfeed</a></p>
  __TABLE__
</div>
</body>
</html>
"""


def write_cwe_pages(vulns, date_str, base_url=BASE_URL):
    os.makedirs("cwe", exist_ok=True)
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    pages = []

    for cwe_id, display_name, keyword in CWE_PAGES:
        kw = keyword.lower()
        matched = [
            v for v in vulns
            if cwe_id in (v.get("cwes") or []) or
               kw in " ".join([v.get("title", ""), v.get("description", "")]).lower()
        ]
        seen_ids: set = set()
        deduped = []
        for v in matched:
            if v["id"] not in seen_ids:
                seen_ids.add(v["id"])
                deduped.append(v)
        matched = sorted(deduped, key=lambda v: (
            SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4), -(v.get("score") or 0)))

        if not matched:
            continue

        rows = []
        for v in matched:
            sev = v.get("severity", "UNKNOWN")
            sc_str = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
            epss_str = f'{v["epss_pct"]:.0f}%ile' if v.get("epss_pct") is not None else "—"
            pub = _pub_ymd(v.get("published") or "")
            ttl = _xe((v.get("title") or v["id"])[:120])
            url = _xe(v.get("url", ""))
            rows.append(
                f'<tr>'
                f'<td><a class="cve-id" href="{url}" target="_blank" rel="noopener">{_xe(v["id"])}</a></td>'
                f'<td class="ttl">{ttl}</td>'
                f'<td><span class="sev s{sev}">{sev}</span></td>'
                f'<td>{sc_str}</td><td>{epss_str}</td>'
                f'<td><span class="src-tag">{_xe(v.get("source","?"))}</span></td>'
                f'<td>{pub}</td></tr>'
            )

        table_html = (
            '<table><tr><th>CVE / ID</th><th>Title</th><th>Severity</th>'
            '<th>CVSS</th><th>EPSS</th><th>Source</th><th>Date</th></tr>'
            + "".join(rows) + '</table>'
        ) if rows else '<div class="empty">No matching vulnerabilities found.</div>'

        html = _CWE_HTML
        html = html.replace("__CWE_ID__",   cwe_id)
        html = html.replace("__CWE_NAME__",  _xe(display_name))
        html = html.replace("__COUNT__",     str(len(matched)))
        html = html.replace("__DATE__",      date_str)
        html = html.replace("__TABLE__",     table_html)
        html = html.replace("__BASE_URL__",  base_url)

        with open(os.path.join("cwe", f"{cwe_id}.html"), "w", encoding="utf-8") as f:
            f.write(html)

        pages.append({"id": cwe_id, "display_name": display_name, "count": len(matched)})

    log(f"  Written: {len(pages)} CWE pages → cwe/")
    return pages


# ---------------------------------------------------------------------------
# Weekly digest pages
# ---------------------------------------------------------------------------

_WEEKLY_DIGEST_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>Top Security Vulnerabilities __WEEK_ISO__ &mdash; __WEEK_LABEL__ | vulnfeed</title>
<meta name="description" content="__TOTAL__ vulnerabilities tracked in __WEEK_LABEL__: __N_CRIT__ critical, __N_HIGH__ high, __N_EXPL__ actively exploited. Weekly CVE digest by vulnfeed.">
<link rel="canonical" href="__BASE_URL__/digest/week-__WEEK_ISO__.html">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","headline":"Top Security Vulnerabilities __WEEK_ISO__","description":"__TOTAL__ vulnerabilities tracked in __WEEK_LABEL__: __N_CRIT__ critical, __N_HIGH__ high severity.","url":"__BASE_URL__/digest/week-__WEEK_ISO__.html","publisher":{"@type":"Organization","name":"vulnfeed","url":"__BASE_URL__"}}</script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--unk:#6b7280}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
header{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem}
.logo{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}.logo em{color:#60a5fa;font-style:normal}
.hlink{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}
.hlink:hover{border-color:#60a5fa;background:rgba(96,165,250,.08)}
.wrap{max-width:1100px;margin:0 auto;padding:2rem}
h1{font-size:1.4rem;font-weight:800;margin-bottom:.25rem}
h2{font-size:.72rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:2rem 0 .75rem}
.date-nav{display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem;font-size:.8rem}
.date-nav a{color:var(--accent);text-decoration:none;font-weight:600}.date-nav a:hover{text-decoration:underline}
.date-nav strong{color:var(--text)}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}
.stat-box{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem 1.2rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.stat-val{font-size:1.8rem;font-weight:800;letter-spacing:-.04em}
.stat-lbl{font-size:.72rem;color:var(--muted);margin-top:.1rem}
.crit-val{color:var(--crit)}.high-val{color:var(--high)}.expl-val{color:#7c3aed}
.daily-links{margin-bottom:2rem;display:flex;flex-wrap:wrap;gap:.5rem}
.daily-links a{font-size:.75rem;color:var(--accent);text-decoration:none;padding:.2rem .6rem;border:1px solid var(--border);border-radius:5px;background:var(--card)}
.daily-links a:hover{border-color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:.8rem;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06);margin-bottom:2rem}
th{text-align:left;font-size:.68rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:.55rem .75rem;border-bottom:2px solid var(--border);background:#f8fafc}
td{padding:.5rem .75rem;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafc}
.cve-id{font-family:ui-monospace,"Cascadia Code",monospace;font-size:.77rem;font-weight:700;color:var(--accent);text-decoration:none;white-space:nowrap}
.cve-id:hover{text-decoration:underline}
.sev{display:inline-block;padding:.08rem .35rem;border-radius:3px;font-size:.65rem;font-weight:700;color:#fff;text-transform:uppercase}
.sCRITICAL{background:var(--crit)}.sHIGH{background:var(--high)}.sMEDIUM{background:var(--med)}.sLOW{background:var(--low)}.sUNKNOWN{background:var(--unk)}
.src-tag{display:inline-block;background:#334155;color:#fff;padding:.06rem .35rem;border-radius:3px;font-size:.63rem;font-weight:600}
.ttl{font-size:.78rem;color:var(--text)}
@media(max-width:640px){.wrap{padding:1rem}th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6){display:none}}
</style>
</head>
<body>
<header>
  <div><div class="logo">vuln<em>feed</em></div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="/">Live feed</a>
    <a class="hlink" href="/digest/">All digests</a>
  </div>
</header>
<div class="wrap">
  <div class="date-nav">
    __PREV_LINK__
    <strong>__WEEK_ISO__</strong>
    __NEXT_LINK__
  </div>
  <h1>Top Security Vulnerabilities &mdash; __WEEK_LABEL__</h1>
  <div class="stat-grid">
    <div class="stat-box"><div class="stat-val">__TOTAL__</div><div class="stat-lbl">Total vulnerabilities</div></div>
    <div class="stat-box"><div class="stat-val crit-val">__N_CRIT__</div><div class="stat-lbl">Critical</div></div>
    <div class="stat-box"><div class="stat-val high-val">__N_HIGH__</div><div class="stat-lbl">High</div></div>
    <div class="stat-box"><div class="stat-val expl-val">__N_EXPL__</div><div class="stat-lbl">Actively exploited</div></div>
  </div>
  <h2>Daily digests this week</h2>
  <div class="daily-links">__DAILY_LINKS__</div>
  <h2>Top vulnerabilities</h2>
  __TOP_TABLE__
</div>
</body>
</html>
"""


def _iso_week_label(week_str):
    """Convert '2026-W25' to human-readable 'June 16–22, 2026'."""
    try:
        year, wnum = int(week_str[:4]), int(week_str[6:])
        mon = datetime.strptime(f"{year}-W{wnum:02d}-1", "%G-W%V-%u")
        sun = mon + timedelta(days=6)
        if mon.month == sun.month:
            return f"{mon.strftime('%B %-d')}–{sun.strftime('%-d, %Y')}"
        return f"{mon.strftime('%B %-d')} – {sun.strftime('%B %-d, %Y')}"
    except Exception:
        return week_str


def _write_single_weekly_digest(week_str, week_vulns, week_dates, all_weeks, base_url=BASE_URL):
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    sev_counts = {}
    exploited = 0
    seen_ids = set()
    deduped = []
    for v in week_vulns:
        if v["id"] not in seen_ids:
            seen_ids.add(v["id"])
            deduped.append(v)
        s = v.get("severity", "UNKNOWN")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        if v.get("badge") == "ACTIVELY EXPLOITED":
            exploited += 1

    top = sorted(deduped, key=lambda v: (
        SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4), -(v.get("score") or 0)))[:60]

    rows = []
    for v in top:
        sev = v.get("severity", "UNKNOWN")
        sc_str = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
        pub = _pub_ymd(v.get("published") or "")
        ttl = _xe((v.get("title") or v["id"])[:120])
        url = _xe(v.get("url", ""))
        rows.append(
            f'<tr><td><a class="cve-id" href="{url}" target="_blank" rel="noopener">{_xe(v["id"])}</a></td>'
            f'<td class="ttl">{ttl}</td>'
            f'<td><span class="sev s{sev}">{sev}</span></td>'
            f'<td>{sc_str}</td>'
            f'<td><span class="src-tag">{_xe(v.get("source","?"))}</span></td>'
            f'<td>{pub}</td></tr>'
        )

    table_html = (
        '<table><tr><th>CVE / ID</th><th>Title</th><th>Severity</th>'
        '<th>CVSS</th><th>Source</th><th>Date</th></tr>'
        + "".join(rows) + '</table>'
    ) if rows else '<p style="color:#64748b">No data for this week.</p>'

    daily_links = "".join(
        f'<a href="/digest/{d}.html">{d}</a>' for d in sorted(week_dates, reverse=True)
    )

    idx = all_weeks.index(week_str) if week_str in all_weeks else -1
    prev_week = all_weeks[idx + 1] if idx >= 0 and idx + 1 < len(all_weeks) else None
    next_week = all_weeks[idx - 1] if idx > 0 else None

    prev_link = f'<a href="/digest/week-{prev_week}.html">&#8592; {prev_week}</a>' if prev_week else ""
    next_link = f'<a href="/digest/week-{next_week}.html">{next_week} &#8594;</a>' if next_week else ""

    week_label = _iso_week_label(week_str)
    html = _WEEKLY_DIGEST_HTML
    html = html.replace("__WEEK_ISO__",   week_str)
    html = html.replace("__WEEK_LABEL__", week_label)
    html = html.replace("__TOTAL__",      str(len(deduped)))
    html = html.replace("__N_CRIT__",     str(sev_counts.get("CRITICAL", 0)))
    html = html.replace("__N_HIGH__",     str(sev_counts.get("HIGH", 0)))
    html = html.replace("__N_EXPL__",     str(exploited))
    html = html.replace("__TOP_TABLE__",  table_html)
    html = html.replace("__DAILY_LINKS__", daily_links)
    html = html.replace("__PREV_LINK__",  prev_link)
    html = html.replace("__NEXT_LINK__",  next_link)
    html = html.replace("__BASE_URL__",   base_url)

    with open(os.path.join("digest", f"week-{week_str}.html"), "w", encoding="utf-8") as f:
        f.write(html)


def write_weekly_digest_pages(hist_dates, date_str, base_url=BASE_URL):
    """Generate one page per ISO week from available historical snapshots."""
    os.makedirs("digest", exist_ok=True)

    # Group dates by ISO week
    week_to_dates = {}
    all_dates = sorted({date_str} | set(hist_dates), reverse=True)
    for d in all_dates:
        try:
            dt = datetime.strptime(d, "%Y-%m-%d")
            iso = dt.isocalendar()
            week_str = f"{iso[0]}-W{iso[1]:02d}"
            week_to_dates.setdefault(week_str, []).append(d)
        except Exception:
            continue

    # Only generate weeks where we have at least 3 days of data
    eligible_weeks = sorted(
        [w for w, dates in week_to_dates.items() if len(dates) >= 3],
        reverse=True,
    )

    for week_str in eligible_weeks:
        out_path = os.path.join("digest", f"week-{week_str}.html")
        week_dates = week_to_dates[week_str]

        # Merge vulns from all days in this week
        week_vulns = []
        for d in week_dates:
            if d == date_str:
                continue  # fresh data already in today's snapshot path
            hist_path = os.path.join(HISTORICAL_DIR, f"{d}.json")
            if not os.path.exists(hist_path):
                continue
            try:
                with open(hist_path, encoding="utf-8") as hf:
                    week_vulns.extend(json.load(hf))
            except Exception:
                pass

        if not week_vulns:
            continue

        _write_single_weekly_digest(week_str, week_vulns, week_dates, eligible_weeks, base_url)

    log(f"  Written: {len(eligible_weeks)} weekly digest pages → digest/")
    return eligible_weeks


# Daily digest pages
# ---------------------------------------------------------------------------

_DIGEST_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>Security Vulnerability Digest &mdash; __DATE__ | vulnfeed</title>
<meta name="description" content="__TOTAL__ vulnerabilities tracked on __DATE__: __N_CRIT__ critical, __N_HIGH__ high severity. Daily CVE digest by vulnfeed.">
<link rel="canonical" href="__BASE_URL__/digest/__DATE__.html">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--unk:#6b7280}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
header{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem}
.logo{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}.logo em{color:#60a5fa;font-style:normal}
.hlink{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}
.hlink:hover{border-color:#60a5fa;background:rgba(96,165,250,.08)}
.wrap{max-width:1100px;margin:0 auto;padding:2rem}
h1{font-size:1.4rem;font-weight:800;margin-bottom:.25rem}
h2{font-size:.72rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:2rem 0 .75rem}
.date-nav{display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem;font-size:.8rem}
.date-nav a{color:var(--accent);text-decoration:none;font-weight:600}.date-nav a:hover{text-decoration:underline}
.date-nav strong{color:var(--text)}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}
.stat-box{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem 1.2rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.stat-val{font-size:1.8rem;font-weight:800;letter-spacing:-.04em}
.stat-lbl{font-size:.72rem;color:var(--muted);margin-top:.1rem}
.crit-val{color:var(--crit)}.high-val{color:var(--high)}.expl-val{color:#7c3aed}
table{width:100%;border-collapse:collapse;font-size:.8rem;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06);margin-bottom:2rem}
th{text-align:left;font-size:.68rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:.55rem .75rem;border-bottom:2px solid var(--border);background:#f8fafc}
td{padding:.5rem .75rem;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafc}
.cve-id{font-family:ui-monospace,"Cascadia Code",monospace;font-size:.77rem;font-weight:700;color:var(--accent);text-decoration:none;white-space:nowrap}
.cve-id:hover{text-decoration:underline}
.sev{display:inline-block;padding:.08rem .35rem;border-radius:3px;font-size:.65rem;font-weight:700;color:#fff;text-transform:uppercase}
.sCRITICAL{background:var(--crit)}.sHIGH{background:var(--high)}.sMEDIUM{background:var(--med)}.sLOW{background:var(--low)}.sUNKNOWN{background:var(--unk)}
.src-tag{display:inline-block;background:#334155;color:#fff;padding:.06rem .35rem;border-radius:3px;font-size:.63rem;font-weight:600}
.ttl{font-size:.78rem;color:var(--text)}
@media(max-width:640px){.wrap{padding:1rem}th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6){display:none}}
</style>
</head>
<body>
<header>
  <div><div class="logo">vuln<em>feed</em></div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="/">Live feed</a>
    <a class="hlink" href="/digest/">All digests</a>
  </div>
</header>
<div class="wrap">
  <div class="date-nav">
    __PREV_LINK__
    <strong>__DATE__</strong>
    __NEXT_LINK__
  </div>
  <h1>Security Digest &mdash; __DATE__</h1>
  <div class="stat-grid">
    <div class="stat-box"><div class="stat-val">__TOTAL__</div><div class="stat-lbl">Total vulnerabilities</div></div>
    <div class="stat-box"><div class="stat-val crit-val">__N_CRIT__</div><div class="stat-lbl">Critical</div></div>
    <div class="stat-box"><div class="stat-val high-val">__N_HIGH__</div><div class="stat-lbl">High</div></div>
    <div class="stat-box"><div class="stat-val expl-val">__N_EXPL__</div><div class="stat-lbl">Actively exploited</div></div>
  </div>
  <h2>Top vulnerabilities</h2>
  __TOP_TABLE__
</div>
</body>
</html>
"""

_DIGEST_INDEX_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>Security Digest Archive — Daily &amp; Weekly CVE Digests | vulnfeed</title>
<meta name="description" content="Archive of daily and weekly security vulnerability digests aggregated from NVD, CISA KEV, Microsoft, Fortinet, Juniper and more.">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
header{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between}
.logo{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}.logo em{color:#60a5fa;font-style:normal}
.hlink{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}
.wrap{max-width:800px;margin:0 auto;padding:2rem}
h1{font-size:1.35rem;font-weight:800;margin-bottom:.5rem}
h2{font-size:.72rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:2rem 0 .75rem}
.sub{font-size:.8rem;color:var(--muted);margin-bottom:2rem}
.digest-list{list-style:none;display:grid;gap:.5rem}
.digest-list li a{display:flex;align-items:center;justify-content:space-between;padding:.65rem 1rem;background:var(--card);border:1px solid var(--border);border-radius:8px;text-decoration:none;color:var(--text);font-weight:600;font-size:.85rem;transition:border-color .15s}
.digest-list li a:hover{border-color:var(--accent)}
.digest-list li a span{font-size:.72rem;color:var(--muted);font-weight:400}
.weekly-badge{display:inline-block;background:#2563eb;color:#fff;font-size:.6rem;font-weight:700;padding:.06rem .3rem;border-radius:3px;margin-left:.4rem;vertical-align:middle}
</style>
</head>
<body>
<header>
  <div class="logo">vuln<em>feed</em></div>
  <a class="hlink" href="/">&#8592; Live feed</a>
</header>
<div class="wrap">
  <h1>Security Digest Archive</h1>
  <p class="sub">Daily and weekly snapshots of vulnerabilities tracked by vulnfeed.</p>
  <h2>Weekly digests</h2>
  <ul class="digest-list">__WEEKLY_LINKS__</ul>
  <h2>Daily digests</h2>
  <ul class="digest-list">__DIGEST_LINKS__</ul>
  <h2>Monthly archive</h2>
  <ul class="digest-list"><li><a href="/archive/"><span style="color:#2563eb;font-weight:700">Browse all months &rarr;</span><span>Monthly CVE summaries</span></a></li></ul>
</div>
</body>
</html>
"""


def _write_single_digest(vulns, date_str, all_dates, base_url=BASE_URL):
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    sev_counts = {}
    exploited = 0
    for v in vulns:
        s = v.get("severity", "UNKNOWN")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        if v.get("badge") == "ACTIVELY EXPLOITED":
            exploited += 1

    top = sorted(vulns, key=lambda v: (
        SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4), -(v.get("score") or 0)))[:40]

    rows = []
    for v in top:
        sev = v.get("severity", "UNKNOWN")
        sc_str = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
        pub = _pub_ymd(v.get("published") or "")
        ttl = _xe((v.get("title") or v["id"])[:120])
        url = _xe(v.get("url", ""))
        rows.append(
            f'<tr><td><a class="cve-id" href="{url}" target="_blank" rel="noopener">{_xe(v["id"])}</a></td>'
            f'<td class="ttl">{ttl}</td>'
            f'<td><span class="sev s{sev}">{sev}</span></td>'
            f'<td>{sc_str}</td>'
            f'<td><span class="src-tag">{_xe(v.get("source","?"))}</span></td>'
            f'<td>{pub}</td></tr>'
        )

    table_html = (
        '<table><tr><th>CVE / ID</th><th>Title</th><th>Severity</th>'
        '<th>CVSS</th><th>Source</th><th>Date</th></tr>'
        + "".join(rows) + '</table>'
    ) if rows else '<p style="color:#64748b">No data for this date.</p>'

    idx = all_dates.index(date_str) if date_str in all_dates else -1
    prev_date = all_dates[idx + 1] if idx >= 0 and idx + 1 < len(all_dates) else None
    next_date = all_dates[idx - 1] if idx > 0 else None

    prev_link = f'<a href="/digest/{prev_date}.html">&#8592; {prev_date}</a>' if prev_date else ""
    next_link = f'<a href="/digest/{next_date}.html">{next_date} &#8594;</a>' if next_date else ""

    html = _DIGEST_HTML
    html = html.replace("__DATE__",      date_str)
    html = html.replace("__TOTAL__",     str(len(vulns)))
    html = html.replace("__N_CRIT__",    str(sev_counts.get("CRITICAL", 0)))
    html = html.replace("__N_HIGH__",    str(sev_counts.get("HIGH", 0)))
    html = html.replace("__N_EXPL__",    str(exploited))
    html = html.replace("__TOP_TABLE__", table_html)
    html = html.replace("__PREV_LINK__", prev_link)
    html = html.replace("__NEXT_LINK__", next_link)
    html = html.replace("__BASE_URL__",  base_url)

    with open(os.path.join("digest", f"{date_str}.html"), "w", encoding="utf-8") as f:
        f.write(html)


def write_digest_pages(fresh, date_str, hist_dates, base_url=BASE_URL):
    os.makedirs("digest", exist_ok=True)
    all_dates = sorted({date_str} | set(hist_dates), reverse=True)

    # Today's digest
    _write_single_digest(fresh, date_str, all_dates, base_url)

    # Backfill historical dates not yet written
    for hist_date in hist_dates:
        digest_path = os.path.join("digest", f"{hist_date}.html")
        if os.path.exists(digest_path):
            continue
        hist_path = os.path.join(HISTORICAL_DIR, f"{hist_date}.json")
        if not os.path.exists(hist_path):
            continue
        try:
            with open(hist_path, encoding="utf-8") as hf:
                hist_vulns = json.load(hf)
            _write_single_digest(hist_vulns, hist_date, all_dates, base_url)
        except Exception as ex:
            log(f"  Digest backfill error ({hist_date}): {ex}")

    # Index page (written later by write_digest_index after weekly pages are ready)
    existing = sorted(
        [f[:-5] for f in os.listdir("digest")
         if re.match(r"^\d{4}-\d{2}-\d{2}\.html$", f)],
        reverse=True,
    )
    log(f"  Written: {len(existing)} digest pages → digest/")
    return existing


def write_digest_index(daily_dates, weekly_weeks, base_url=BASE_URL):
    """Write digest/index.html listing both weekly and daily digests."""
    os.makedirs("digest", exist_ok=True)
    daily_links = "".join(
        f'<li><a href="/digest/{d}.html">{d}<span>daily digest</span></a></li>'
        for d in daily_dates
    )
    weekly_links = "".join(
        f'<li><a href="/digest/week-{w}.html">'
        f'{w} <span class="weekly-badge">WEEKLY</span>'
        f'<span>{_iso_week_label(w)}</span></a></li>'
        for w in weekly_weeks
    )
    idx_html = (
        _DIGEST_INDEX_HTML
        .replace("__DIGEST_LINKS__", daily_links)
        .replace("__WEEKLY_LINKS__", weekly_links or '<li style="color:#64748b;padding:.5rem">No weekly digests yet.</li>')
    )
    with open(os.path.join("digest", "index.html"), "w", encoding="utf-8") as f:
        f.write(idx_html)


# ---------------------------------------------------------------------------
# Trending page
# ---------------------------------------------------------------------------

def write_trending_page(vulns, date_str, base_url=BASE_URL):
    trending = [
        v for v in vulns
        if v.get("_trending") or (v.get("epss_pct") or 0) >= 90
    ]
    trending.sort(key=lambda v: (-(v.get("epss_pct") or 0), -(v.get("score") or 0)))
    count = len(trending)

    rows = []
    for v in trending:
        sev = v.get("severity", "UNKNOWN")
        sc_str = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
        epss_str = f'{v["epss_pct"]:.1f}%ile' if v.get("epss_pct") is not None else "—"
        pub = _pub_ymd(v.get("published") or "")
        ttl = _xe((v.get("title") or v["id"])[:120])
        cve_id = _xe(v["id"])
        # Link to CVE page if it looks like a CVE, else to source URL
        if v["id"].startswith("CVE-"):
            id_link = f'<a class="cve-id" href="{base_url}/cve/{cve_id}.html">{cve_id}</a>'
        else:
            id_link = f'<a class="cve-id" href="{_xe(v.get("url",""))}" target="_blank" rel="noopener">{cve_id}</a>'
        trend_badge = '<span class="trend-badge">TRENDING</span>' if v.get("_trending") else ""
        rows.append(
            f'<tr>'
            f'<td>{id_link} {trend_badge}</td>'
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
    ) if rows else '<div class="empty">No trending vulnerabilities right now.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments);}}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>Trending Vulnerabilities | vulnfeed</title>
<meta name="description" content="CVEs with rising exploitation probability. Updated every 4 hours.">
<link rel="canonical" href="{base_url}/trending.html">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--unk:#6b7280}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}}
header{{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem}}
.logo{{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}}.logo em{{color:#60a5fa;font-style:normal}}
.hlink{{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}}
.hlink:hover{{border-color:#60a5fa;background:rgba(96,165,250,.08)}}
.wrap{{max-width:1100px;margin:0 auto;padding:2rem}}
h1{{font-size:1.35rem;font-weight:800;margin-bottom:.25rem}}
.sub{{font-size:.8rem;color:var(--muted);margin-bottom:1.75rem}}
.count-badge{{display:inline-block;background:#f59e0b;color:#1e293b;border-radius:6px;padding:.2rem .7rem;font-size:.85rem;font-weight:700;margin-bottom:1rem}}
table{{width:100%;border-collapse:collapse;font-size:.8rem;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
th{{text-align:left;font-size:.68rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:.55rem .75rem;border-bottom:2px solid var(--border);background:var(--bg)}}
td{{padding:.5rem .75rem;border-bottom:1px solid var(--border);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:var(--bg)}}
.cve-id{{font-family:ui-monospace,"Cascadia Code",monospace;font-size:.77rem;font-weight:700;color:var(--accent);text-decoration:none;white-space:nowrap}}
.cve-id:hover{{text-decoration:underline}}
.sev{{display:inline-block;padding:.08rem .35rem;border-radius:3px;font-size:.65rem;font-weight:700;color:#fff;text-transform:uppercase}}
.sCRITICAL{{background:var(--crit)}}.sHIGH{{background:var(--high)}}.sMEDIUM{{background:var(--med)}}.sLOW{{background:var(--low)}}.sUNKNOWN{{background:var(--unk)}}
.src-tag{{display:inline-block;background:#334155;color:#fff;padding:.06rem .35rem;border-radius:3px;font-size:.63rem;font-weight:600}}
.trend-badge{{display:inline-block;background:#f59e0b;color:#1e293b;border-radius:3px;padding:.04rem .3rem;font-size:.6rem;font-weight:700;text-transform:uppercase;vertical-align:middle;margin-left:.25rem}}
.ttl{{font-size:.78rem;color:var(--text)}}
.empty{{text-align:center;padding:4rem 2rem;color:var(--muted)}}
@media(max-width:640px){{.wrap{{padding:1rem}}th:nth-child(4),td:nth-child(4),th:nth-child(6),td:nth-child(6){{display:none}}}}
</style>
</head>
<body>
<header>
  <div><div class="logo">vuln<em>feed</em></div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="/">&#8592; Back to feed</a>
    <a class="hlink" href="/stats.html">Stats</a>
  </div>
</header>
<div class="wrap">
  <h1>&#128200; Trending Vulnerabilities</h1>
  <p class="sub">CVEs whose exploitation probability jumped significantly in the last 24 hours, based on EPSS scores.</p>
  <div class="count-badge">{count} CVEs trending right now</div>
  {table_html}
  <p style="margin-top:1.5rem;font-size:.75rem;color:var(--muted)">Updated {date_str}. EPSS = Exploit Prediction Scoring System (FIRST.org). TRENDING = EPSS jumped &ge;5 percentage points since yesterday.</p>
</div>
</body>
</html>"""
    with open("trending.html", "w", encoding="utf-8") as f:
        f.write(html)
    log(f"  Written: trending.html ({count} trending CVEs)")


# ---------------------------------------------------------------------------
# New this week page
# ---------------------------------------------------------------------------

def write_new_this_week_page(vulns, date_str, base_url=BASE_URL):
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    try:
        cutoff = (datetime.strptime(date_str, "%Y-%m-%d") - timedelta(days=7)).strftime("%Y-%m-%d")
    except Exception:
        cutoff = ""

    fresh = [
        v for v in vulns
        if (v.get("published") or "")[:10] >= cutoff
    ]
    fresh.sort(key=lambda v: (
        SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4),
        -(v.get("epss_pct") or 0),
        -(v.get("score") or 0),
    ))

    n_crit  = sum(1 for v in fresh if v.get("severity") == "CRITICAL")
    n_kev   = sum(1 for v in fresh if v.get("badge") == "ACTIVELY EXPLOITED")
    n_poc   = sum(1 for v in fresh if v.get("poc"))
    n_high  = sum(1 for v in fresh if v.get("severity") == "HIGH")

    def reason(v):
        parts = []
        if v.get("badge") == "ACTIVELY EXPLOITED":
            parts.append('<span class="badge-kev">KEV</span>')
        if v.get("poc"):
            parts.append('<span class="badge-poc">PoC</span>')
        if v.get("epss_pct") is not None:
            parts.append(f'<span class="badge-epss">EPSS {v["epss_pct"]:.0f}%ile</span>')
        return "&nbsp;".join(parts) if parts else "—"

    rows = [_vuln_row(v, reason(v)) for v in fresh]
    table = _vuln_table(rows)

    head = _page_head(
        f"New This Week — {len(fresh)} CVEs Published in the Last 7 Days | vulnfeed",
        f"{len(fresh)} new vulnerabilities in the last 7 days: {n_crit} critical, {n_kev} actively exploited, {n_poc} with public exploit code. Updated every 4 hours.",
        f"{base_url}/new-this-week.html",
        date_str,
    )

    html = f"""{head}
<body>
{_page_header(extra_links='<a class="hlink" href="/patch-now.html">Patch now</a><a class="hlink" href="/zero-days.html">Zero-days</a>')}
<div class="wrap">
  <h1>&#128197; New This Week</h1>
  <p class="sub">Vulnerabilities published in the last 7 days ({cutoff} &rarr; {date_str}). Updated every 4 hours.</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:.75rem;margin-bottom:1.75rem">
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:.9rem 1.1rem">
      <div style="font-size:1.7rem;font-weight:800;letter-spacing:-.04em">{len(fresh)}</div>
      <div style="font-size:.72rem;color:#64748b;margin-top:.1rem">Total new CVEs</div>
    </div>
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:.9rem 1.1rem">
      <div style="font-size:1.7rem;font-weight:800;color:#dc2626;letter-spacing:-.04em">{n_crit}</div>
      <div style="font-size:.72rem;color:#64748b;margin-top:.1rem">Critical</div>
    </div>
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:.9rem 1.1rem">
      <div style="font-size:1.7rem;font-weight:800;color:#ea580c;letter-spacing:-.04em">{n_high}</div>
      <div style="font-size:.72rem;color:#64748b;margin-top:.1rem">High</div>
    </div>
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:.9rem 1.1rem">
      <div style="font-size:1.7rem;font-weight:800;color:#7c3aed;letter-spacing:-.04em">{n_kev}</div>
      <div style="font-size:.72rem;color:#64748b;margin-top:.1rem">Actively exploited</div>
    </div>
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:.9rem 1.1rem">
      <div style="font-size:1.7rem;font-weight:800;color:#dc2626;letter-spacing:-.04em">{n_poc}</div>
      <div style="font-size:.72rem;color:#64748b;margin-top:.1rem">Public PoC</div>
    </div>
  </div>
  {table}
  <p style="margin-top:1.5rem;font-size:.75rem;color:#64748b">Updated {date_str}. Sources: NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB and more. <a href="/api.html" style="color:#2563eb">JSON API</a> available for automation.</p>
</div>
</body>
</html>"""

    with open("new-this-week.html", "w", encoding="utf-8") as f:
        f.write(html)
    log(f"  Written: new-this-week.html ({len(fresh)} CVEs, {n_crit} critical, {n_kev} KEV)")


# ---------------------------------------------------------------------------
# Patch Now page
# ---------------------------------------------------------------------------

_PAGE_CSS = """\
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--unk:#6b7280}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
header{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem}
.logo{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}.logo em{color:#60a5fa;font-style:normal}
.hlink{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}
.hlink:hover{border-color:#60a5fa;background:rgba(96,165,250,.08)}
.wrap{max-width:1100px;margin:0 auto;padding:2rem}
h1{font-size:1.35rem;font-weight:800;margin-bottom:.25rem}
h2{font-size:.72rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:2rem 0 .75rem;display:flex;align-items:center;gap:.5rem}
.sub{font-size:.8rem;color:var(--muted);margin-bottom:1.75rem}
table{width:100%;border-collapse:collapse;font-size:.8rem;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)}
th{text-align:left;font-size:.68rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:.55rem .75rem;border-bottom:2px solid var(--border);background:var(--bg)}
td{padding:.5rem .75rem;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--bg)}
.cve-id{font-family:ui-monospace,"Cascadia Code",monospace;font-size:.77rem;font-weight:700;color:var(--accent);text-decoration:none;white-space:nowrap}
.cve-id:hover{text-decoration:underline}
.sev{display:inline-block;padding:.08rem .35rem;border-radius:3px;font-size:.65rem;font-weight:700;color:#fff;text-transform:uppercase}
.sCRITICAL{background:var(--crit)}.sHIGH{background:var(--high)}.sMEDIUM{background:var(--med)}.sLOW{background:var(--low)}.sUNKNOWN{background:var(--unk)}
.src-tag{display:inline-block;background:#334155;color:#fff;padding:.06rem .35rem;border-radius:3px;font-size:.63rem;font-weight:600}
.ttl{font-size:.78rem}
.badge-kev{display:inline-block;background:#7c3aed;color:#fff;border-radius:3px;padding:.04rem .3rem;font-size:.6rem;font-weight:700;text-transform:uppercase;white-space:nowrap}
.badge-poc{display:inline-block;background:#dc2626;color:#fff;border-radius:3px;padding:.04rem .3rem;font-size:.6rem;font-weight:700;text-transform:uppercase;white-space:nowrap}
.badge-epss{display:inline-block;background:#0369a1;color:#fff;border-radius:3px;padding:.04rem .3rem;font-size:.6rem;font-weight:700;white-space:nowrap}
.empty{text-align:center;padding:4rem 2rem;color:var(--muted)}
.info-box{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:1rem 1.25rem;font-size:.8rem;color:#1e3a8a;margin-bottom:1.75rem;line-height:1.7}
.info-box strong{display:block;margin-bottom:.25rem}
@media(max-width:640px){.wrap{padding:1rem}th:nth-child(4),td:nth-child(4){display:none}}"""


def _page_head(title, desc, canonical, date_str, extra_css=""):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments);}}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>{title}</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="{canonical}">
<style>{_PAGE_CSS}{extra_css}</style>
</head>"""


def _page_header(back_href="/", back_label="&#8592; Back to feed", extra_links=""):
    return f"""<header>
  <div><div class="logo">vuln<em>feed</em></div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="{back_href}">{back_label}</a>
    {extra_links}
  </div>
</header>"""


def _vuln_row(v, reason_html):
    sev = v.get("severity", "UNKNOWN")
    sc_str = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
    epss_str = f'{v["epss_pct"]:.0f}%' if v.get("epss_pct") is not None else "—"
    pub = _pub_ymd(v.get("published") or "")
    ttl = _xe((v.get("title") or v["id"])[:120])
    vid = _xe(v["id"])
    href = f'/cve/{v["id"]}.html' if v["id"].startswith("CVE-") else _xe(v.get("url", ""))
    return (
        f'<tr>'
        f'<td><a class="cve-id" href="{href}">{vid}</a></td>'
        f'<td class="ttl">{ttl}</td>'
        f'<td><span class="sev s{sev}">{sev}</span></td>'
        f'<td>{sc_str}</td>'
        f'<td>{epss_str}</td>'
        f'<td>{reason_html}</td>'
        f'<td><span class="src-tag">{_xe(v.get("source","?"))}</span></td>'
        f'<td>{pub}</td>'
        f'</tr>'
    )


def _vuln_table(rows, cols=None):
    if cols is None:
        cols = ["CVE / ID", "Title", "Severity", "CVSS", "EPSS", "Why urgent", "Source", "Date"]
    if not rows:
        return '<div class="empty">No vulnerabilities match these criteria right now.</div>'
    ths = "".join(f"<th>{c}</th>" for c in cols)
    return f'<table><tr>{ths}</tr>{"".join(rows)}</table>'


def write_patch_now_page(vulns, date_str, base_url=BASE_URL):
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    p1, p2 = [], []
    for v in vulns:
        score = v.get("score") or 0
        is_kev = v.get("badge") == "ACTIVELY EXPLOITED"
        has_poc = v.get("poc")
        epss_pct = v.get("epss_pct") or 0

        if score < 7.0 and epss_pct < 85:
            continue
        if is_kev:
            p1.append(v)
        elif has_poc and (score >= 7.0 or epss_pct >= 70):
            p2.append(v)

    def sort_key(v):
        return (
            SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4),
            -(v.get("epss_pct") or 0),
            -(v.get("score") or 0),
        )

    p1.sort(key=sort_key)
    p2.sort(key=sort_key)

    def reason(v):
        parts = []
        if v.get("badge") == "ACTIVELY EXPLOITED":
            parts.append('<span class="badge-kev">KEV</span>')
        if v.get("poc"):
            parts.append('<span class="badge-poc">PoC</span>')
        if v.get("epss_pct") is not None:
            parts.append(f'<span class="badge-epss">EPSS {v["epss_pct"]:.0f}%ile</span>')
        return "&nbsp;".join(parts)

    rows1 = [_vuln_row(v, reason(v)) for v in p1]
    rows2 = [_vuln_row(v, reason(v)) for v in p2]

    total = len(p1) + len(p2)
    head = _page_head(
        f"Patch This Week — {total} Critical Vulnerabilities | vulnfeed",
        f"{total} vulnerabilities requiring immediate attention: {len(p1)} actively exploited (CISA KEV) and {len(p2)} with public exploit code. Updated every 4 hours.",
        f"{base_url}/patch-now.html",
        date_str,
    )

    html = f"""{head}
<body>
{_page_header(extra_links='<a class="hlink" href="/trending.html">Trending</a><a class="hlink" href="/zero-days.html">Zero-days</a>')}
<div class="wrap">
  <h1>&#128683; Patch This Week</h1>
  <p class="sub">Vulnerabilities requiring immediate action — actively exploited in the wild or with public exploit code available. Updated every 4 hours.</p>
  <div class="info-box">
    <strong>How this list is built</strong>
    <b>Tier 1 — Patch now:</b> On CISA Known Exploited Vulnerabilities (KEV) list — confirmed in-the-wild exploitation.<br>
    <b>Tier 2 — Patch soon:</b> Public proof-of-concept exploit exists with CVSS &ge;7.0 or EPSS &ge;70th percentile.
  </div>
  <h2><span style="color:#7c3aed">&#11044;</span> Tier 1 — Patch immediately ({len(p1)} CVEs) <span style="font-size:.65rem;color:#7c3aed;font-weight:600;background:#ede9fe;border-radius:3px;padding:.1rem .4rem">CISA KEV confirmed</span></h2>
  {_vuln_table(rows1)}
  <h2 style="margin-top:2.25rem"><span style="color:#dc2626">&#11044;</span> Tier 2 — Patch soon ({len(p2)} CVEs) <span style="font-size:.65rem;color:#dc2626;font-weight:600;background:#fee2e2;border-radius:3px;padding:.1rem .4rem">public exploit code</span></h2>
  {_vuln_table(rows2)}
  <p style="margin-top:1.5rem;font-size:.75rem;color:var(--muted)">Updated {date_str}. Source: NVD, CISA KEV, EPSS (FIRST.org). <a href="/api.html" style="color:var(--accent)">JSON API available</a> for automation.</p>
</div>
</body>
</html>"""

    with open("patch-now.html", "w", encoding="utf-8") as f:
        f.write(html)
    log(f"  Written: patch-now.html ({len(p1)} KEV, {len(p2)} PoC)")


# ---------------------------------------------------------------------------
# Zero-days page
# ---------------------------------------------------------------------------

def write_zero_days_page(vulns, date_str, base_url=BASE_URL):
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    kev = []
    poc_only = []
    for v in vulns:
        score = v.get("score") or 0
        is_kev = v.get("badge") == "ACTIVELY EXPLOITED"
        has_poc = v.get("poc")
        if is_kev:
            kev.append(v)
        elif has_poc and score >= 6.0:
            poc_only.append(v)

    def sort_key(v):
        return (SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4), -(v.get("epss_pct") or 0), -(v.get("score") or 0))

    kev.sort(key=sort_key)
    poc_only.sort(key=sort_key)

    def reason_kev(v):
        parts = ['<span class="badge-kev">KEV — actively exploited</span>']
        if v.get("poc"):
            parts.append('<span class="badge-poc">PoC public</span>')
        if v.get("epss_pct") is not None:
            parts.append(f'<span class="badge-epss">EPSS {v["epss_pct"]:.0f}%ile</span>')
        return "&nbsp;".join(parts)

    def reason_poc(v):
        parts = ['<span class="badge-poc">PoC public</span>']
        if v.get("epss_pct") is not None:
            parts.append(f'<span class="badge-epss">EPSS {v["epss_pct"]:.0f}%ile</span>')
        return "&nbsp;".join(parts)

    rows_kev = [_vuln_row(v, reason_kev(v)) for v in kev]
    rows_poc = [_vuln_row(v, reason_poc(v)) for v in poc_only]

    total = len(kev) + len(poc_only)
    head = _page_head(
        f"Zero-Days & Active Exploits — {total} CVEs | vulnfeed",
        f"Live tracker of {len(kev)} CVEs actively exploited in the wild (CISA KEV) and {len(poc_only)} with public proof-of-concept exploit code. Updated every 4 hours.",
        f"{base_url}/zero-days.html",
        date_str,
    )

    html = f"""{head}
<body>
{_page_header(extra_links='<a class="hlink" href="/patch-now.html">Patch now</a><a class="hlink" href="/trending.html">Trending</a>')}
<div class="wrap">
  <h1>&#128683; Zero-Days &amp; Active Exploits</h1>
  <p class="sub">Vulnerabilities being actively exploited in the wild right now, plus CVEs with public proof-of-concept code. Updated every 4 hours from CISA KEV and NVD.</p>
  <div class="info-box">
    <strong>Sources</strong>
    <b>CISA KEV:</b> U.S. Cybersecurity &amp; Infrastructure Security Agency Known Exploited Vulnerabilities catalog — confirmed in-the-wild exploitation by threat actors.<br>
    <b>PoC:</b> Public proof-of-concept exploit code exists in the wild (Exploit-DB, GitHub, security research). Exploitation not yet confirmed by CISA but weaponized code is available.
  </div>
  <h2><span style="color:#7c3aed">&#11044;</span> Actively exploited in the wild ({len(kev)} CVEs) <span style="font-size:.65rem;color:#7c3aed;font-weight:600;background:#ede9fe;border-radius:3px;padding:.1rem .4rem">CISA KEV confirmed</span></h2>
  {_vuln_table(rows_kev)}
  <h2 style="margin-top:2.25rem"><span style="color:#dc2626">&#11044;</span> Public exploit code available ({len(poc_only)} CVEs) <span style="font-size:.65rem;color:#dc2626;font-weight:600;background:#fee2e2;border-radius:3px;padding:.1rem .4rem">not yet KEV-listed</span></h2>
  {_vuln_table(rows_poc)}
  <p style="margin-top:1.5rem;font-size:.75rem;color:var(--muted)">Updated {date_str}. KEV source: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" style="color:var(--accent)">CISA KEV catalog</a>. PoC data aggregated from Exploit-DB and GitHub advisories. <a href="/api.html" style="color:var(--accent)">JSON API</a> available.</p>
</div>
</body>
</html>"""

    with open("zero-days.html", "w", encoding="utf-8") as f:
        f.write(html)
    log(f"  Written: zero-days.html ({len(kev)} KEV, {len(poc_only)} PoC-only)")


# ---------------------------------------------------------------------------
# Grafana integration page
# ---------------------------------------------------------------------------

def write_grafana_page(base_url=BASE_URL):
    _JSON_API = f"{base_url}/vulns.json"

    dashboard_json = """{
  "title": "vulnfeed CVE Dashboard",
  "panels": [
    {
      "title": "Critical CVEs",
      "type": "stat",
      "datasource": "vulnfeed-infinity",
      "targets": [{
        "type": "json", "source": "url",
        "url": "VULNFEED_URL",
        "parser": "backend",
        "root_selector": "",
        "columns": [{"selector": "severity","text": "severity","type": "string"}],
        "filters": [{"field":"severity","operator":"==","value":"CRITICAL"}]
      }],
      "options": {"reduceOptions": {"calcs": ["count"]}}
    },
    {
      "title": "All CVEs by Severity",
      "type": "piechart",
      "datasource": "vulnfeed-infinity",
      "targets": [{
        "type": "json", "source": "url",
        "url": "VULNFEED_URL",
        "parser": "backend",
        "columns": [
          {"selector": "severity","text": "Severity","type": "string"},
          {"selector": "score","text": "Score","type": "number"}
        ]
      }],
      "options": {"pieType": "donut"}
    },
    {
      "title": "Top CVEs by EPSS",
      "type": "table",
      "datasource": "vulnfeed-infinity",
      "targets": [{
        "type": "json", "source": "url",
        "url": "VULNFEED_URL",
        "parser": "backend",
        "columns": [
          {"selector": "id","text": "CVE ID","type": "string"},
          {"selector": "title","text": "Title","type": "string"},
          {"selector": "severity","text": "Severity","type": "string"},
          {"selector": "score","text": "CVSS","type": "number"},
          {"selector": "epss_pct","text": "EPSS %ile","type": "number"},
          {"selector": "published","text": "Published","type": "string"}
        ]
      }],
      "transformations": [{"id":"sortBy","options":{"fields":[{"desc":true,"displayName":"EPSS %ile"}]}}]
    }
  ]
}""".replace("VULNFEED_URL", _JSON_API)

    prom_script = f"""#!/bin/bash
# Prometheus textfile exporter for vulnfeed CVE metrics
# Run via cron every 15min, write to node_exporter textfile dir
# cron: */15 * * * * /opt/vulnfeed-exporter.sh > /var/lib/node_exporter/textfile_collector/vulnfeed.prom

OUT=$(curl -sf "{_JSON_API}")
if [ -z "$OUT" ]; then exit 1; fi

CRITICAL=$(echo "$OUT" | jq '[.[] | select(.severity=="CRITICAL")] | length')
HIGH=$(echo "$OUT"     | jq '[.[] | select(.severity=="HIGH")]     | length')
MEDIUM=$(echo "$OUT"   | jq '[.[] | select(.severity=="MEDIUM")]   | length')
KEV=$(echo "$OUT"      | jq '[.[] | select(.badge=="ACTIVELY EXPLOITED")] | length')
POC=$(echo "$OUT"      | jq '[.[] | select(.poc==true)] | length')
TOTAL=$(echo "$OUT"    | jq 'length')

cat <<EOF
# HELP vulnfeed_cves_total Total CVEs tracked by vulnfeed
# TYPE vulnfeed_cves_total gauge
vulnfeed_cves_total $TOTAL

# HELP vulnfeed_cves_by_severity CVEs grouped by severity
# TYPE vulnfeed_cves_by_severity gauge
vulnfeed_cves_by_severity{{severity="CRITICAL"}} $CRITICAL
vulnfeed_cves_by_severity{{severity="HIGH"}} $HIGH
vulnfeed_cves_by_severity{{severity="MEDIUM"}} $MEDIUM

# HELP vulnfeed_kev_total CVEs on CISA KEV (actively exploited)
# TYPE vulnfeed_kev_total gauge
vulnfeed_kev_total $KEV

# HELP vulnfeed_poc_total CVEs with public proof-of-concept exploit
# TYPE vulnfeed_poc_total gauge
vulnfeed_poc_total $POC
EOF"""

    slack_script = f"""#!/bin/bash
# Post new critical KEV CVEs to Slack every 4 hours
# cron: 0 */4 * * * /opt/vulnfeed-slack.sh

SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

NEW_KEV=$(curl -sf "{_JSON_API}" | jq -r '
  [.[] | select(.badge=="ACTIVELY EXPLOITED" and .severity=="CRITICAL")]
  | sort_by(-.score)
  | .[:5][]
  | "• *\\(.id)* (\\(.severity) \\(.score // "?"))\\n  \\(.title[:100])\\n  <https://vulnfeed.it/cve/\\(.id).html|Details>"
' | head -20)

if [ -z "$NEW_KEV" ]; then exit 0; fi

curl -sf -X POST "$SLACK_WEBHOOK" -H 'Content-type: application/json' -d "{{
  \\"text\\": \\":rotating_light: *vulnfeed — Active Exploits*\\",
  \\"blocks\\": [
    {{\\"type\\":\\"header\\",\\"text\\":{{\\"type\\":\\"plain_text\\",\\"text\\":\\":rotating_light: Active CVE Exploits — $(date +%Y-%m-%d)\\"}} }},
    {{\\"type\\":\\"section\\",\\"text\\":{{\\"type\\":\\"mrkdwn\\",\\"text\\":\\"$NEW_KEV\\"}} }},
    {{\\"type\\":\\"section\\",\\"text\\":{{\\"type\\":\\"mrkdwn\\",\\"text\\":\\"<https://vulnfeed.it/patch-now.html|View full patch list>\\"}} }}
  ]
}}"
"""

    curl_examples = f"""# Count critical CVEs
curl -s {_JSON_API} | jq '[.[] | select(.severity=="CRITICAL")] | length'

# List actively exploited CVEs with scores
curl -s {_JSON_API} | jq -r '.[] | select(.badge=="ACTIVELY EXPLOITED") | [.id,.severity,(.score|tostring),.title[:60]] | @tsv'

# Top 10 by EPSS percentile
curl -s {_JSON_API} | jq -r '[.[] | select(.epss_pct != null)] | sort_by(-.epss_pct) | .[:10][] | "\\(.epss_pct)%ile  \\(.id)  \\(.title[:60])"'

# CVEs with public PoC and score >= 9
curl -s {_JSON_API} | jq '[.[] | select(.poc==true and (.score // 0) >= 9)]'

# Filter by product keyword
curl -s {_JSON_API} | jq '[.[] | select(.title | ascii_downcase | contains("nginx"))]'

# Export to CSV
curl -s {_JSON_API} | jq -r '["id","severity","score","epss_pct","title"],(.[] | [.id,.severity,(.score|tostring),(.epss_pct|tostring),.title[:80]]) | @csv' > vulns.csv"""

    python_example = f"""import json, urllib.request

with urllib.request.urlopen("{_JSON_API}") as r:
    vulns = json.load(r)

# Critical + actively exploited
urgent = [
    v for v in vulns
    if v.get("severity") == "CRITICAL"
    and v.get("badge") == "ACTIVELY EXPLOITED"
]

for v in sorted(urgent, key=lambda x: -(x.get("score") or 0)):
    print(f"{{v['id']}} ({{v['score']}}) — {{v['title'][:80]}}")
"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments);}}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>Grafana, Prometheus &amp; Slack Integration — vulnfeed CVE API | vulnfeed</title>
<meta name="description" content="Integrate vulnfeed's CVE JSON API with Grafana (Infinity plugin), Prometheus node_exporter textfile, and Slack webhooks. Copy-paste scripts for security monitoring dashboards.">
<link rel="canonical" href="{base_url}/grafana.html">
<style>
{_PAGE_CSS}
pre{{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:1.1rem 1.25rem;font-size:.75rem;line-height:1.65;overflow-x:auto;margin:.75rem 0;border:1px solid #1e293b;font-family:ui-monospace,"Cascadia Code","Fira Code",monospace}}
.copy-btn{{float:right;background:#334155;color:#94a3b8;border:none;border-radius:4px;padding:.2rem .6rem;font-size:.68rem;cursor:pointer;font-family:inherit;margin-top:-.15rem}}
.copy-btn:hover{{background:#475569;color:#f1f5f9}}
.copy-btn.copied{{background:#16a34a;color:#fff}}
.section{{margin:2.5rem 0 0}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.25rem 1.5rem;margin:.75rem 0}}
.card h3{{font-size:.88rem;font-weight:700;margin-bottom:.4rem;display:flex;align-items:center;gap:.5rem}}
.card p{{font-size:.8rem;color:var(--muted);margin-bottom:.75rem;line-height:1.6}}
.tag{{display:inline-block;background:#334155;color:#94a3b8;border-radius:4px;padding:.1rem .4rem;font-size:.63rem;font-weight:600}}
.tag-green{{background:#14532d;color:#86efac}}.tag-blue{{background:#1e3a8a;color:#93c5fd}}.tag-purple{{background:#4c1d95;color:#c4b5fd}}
.field-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:.5rem;margin:.75rem 0}}
.field-box{{background:#f8fafc;border:1px solid var(--border);border-radius:6px;padding:.6rem .85rem;font-size:.75rem}}
.field-box code{{font-family:ui-monospace,monospace;color:#2563eb;font-weight:700}}
.field-box .fdesc{{color:var(--muted);margin-top:.15rem;font-size:.71rem}}
.steps{{list-style:none;counter-reset:step;display:grid;gap:.5rem;margin:.75rem 0}}
.steps li{{counter-increment:step;display:flex;gap:.75rem;align-items:flex-start;font-size:.8rem;line-height:1.6}}
.steps li::before{{content:counter(step);background:var(--accent);color:#fff;border-radius:50%;width:1.3rem;height:1.3rem;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;flex-shrink:0;margin-top:.1rem}}
</style>
</head>
<body>
<header style="background:#0f172a;color:#f1f5f9;padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem">
  <div><div class="logo" style="font-size:1.25rem;font-weight:700;letter-spacing:-.02em">vuln<em style="color:#60a5fa;font-style:normal">feed</em></div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="/">&#8592; Back to feed</a>
    <a class="hlink" href="/api.html">API docs</a>
    <a class="hlink" href="/patch-now.html">Patch now</a>
  </div>
</header>
<div class="wrap">
  <h1>Grafana, Prometheus &amp; Slack Integration</h1>
  <p class="sub">Bring vulnfeed CVE data into your monitoring stack. The <a href="{_JSON_API}" style="color:var(--accent)">/vulns.json</a> API is open, no auth required.</p>

  <div class="field-grid" style="margin-bottom:2rem">
    <div class="field-box"><code>{_JSON_API}</code><div class="fdesc">JSON endpoint — no auth, CORS open, updated every 4h</div></div>
    <div class="field-box"><code>{base_url}/feed.xml</code><div class="fdesc">RSS 2.0 feed — subscribe in any reader</div></div>
    <div class="field-box"><code>{base_url}/badge/critical-count.svg</code><div class="fdesc">SVG badge — embed in README or docs</div></div>
  </div>

  <!-- Grafana -->
  <div class="section">
    <h2>&#128202; Grafana via Infinity Plugin</h2>
    <div class="card">
      <h3><span class="tag tag-blue">Step-by-step</span> Connect vulnfeed to Grafana</h3>
      <p>The <a href="https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/" style="color:var(--accent)">Infinity data source plugin</a> can query any JSON URL directly — no backend needed.</p>
      <ol class="steps">
        <li>In Grafana: <strong>Connections → Add data source → search "Infinity"</strong> and install if not already present.</li>
        <li>Add a new Infinity data source — no configuration needed (leave URL blank, we set it per-panel).</li>
        <li>Create a new Dashboard. For each panel, set data source to <strong>Infinity</strong>, type = <strong>JSON</strong>, source = <strong>URL</strong>, URL = <code style="font-family:monospace;font-size:.75rem">{_JSON_API}</code>.</li>
        <li>Add column selectors: <code style="font-family:monospace;font-size:.75rem">id</code>, <code style="font-family:monospace;font-size:.75rem">severity</code>, <code style="font-family:monospace;font-size:.75rem">score</code>, <code style="font-family:monospace;font-size:.75rem">epss_pct</code>, <code style="font-family:monospace;font-size:.75rem">title</code>, <code style="font-family:monospace;font-size:.75rem">published</code>.</li>
        <li>Use <strong>Transformations → Filter by value</strong> to filter by severity, or <strong>Sort by</strong> EPSS percentile.</li>
      </ol>
    </div>
    <div class="card">
      <h3><span class="tag tag-blue">Dashboard JSON</span> Paste-ready panel config</h3>
      <p>In Grafana, use <strong>Dashboard settings → JSON model</strong> to paste this starter config (replace with your Infinity datasource UID).</p>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{dashboard_json}</pre>
    </div>
  </div>

  <!-- Prometheus -->
  <div class="section">
    <h2>&#128200; Prometheus / node_exporter textfile</h2>
    <div class="card">
      <h3><span class="tag tag-green">Shell script</span> Textfile collector exporter</h3>
      <p>Run this script via cron every 15 minutes. It writes a <code>.prom</code> file that node_exporter's textfile collector picks up automatically. Then alert on <code>vulnfeed_kev_total &gt; 0</code> or build panels in Grafana from Prometheus.</p>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{prom_script}</pre>
    </div>
    <div class="card">
      <h3><span class="tag tag-green">Prometheus rules</span> Example alerting rules</h3>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>groups:
  - name: vulnfeed
    rules:
      - alert: NewKEVVulnerabilities
        expr: vulnfeed_kev_total &gt; 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "{{{{ $value }}}} CVEs are actively exploited (CISA KEV)"
          runbook: "https://vulnfeed.it/patch-now.html"

      - alert: CriticalCVESpike
        expr: vulnfeed_cves_by_severity{{{{severity="CRITICAL"}}}} &gt; 20
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "{{{{ $value }}}} critical CVEs tracked — review patch list"
          runbook: "https://vulnfeed.it/patch-now.html"</pre>
    </div>
  </div>

  <!-- Slack -->
  <div class="section">
    <h2>&#128172; Slack / PagerDuty webhook</h2>
    <div class="card">
      <h3><span class="tag tag-purple">Shell script</span> Slack alert for KEV CVEs</h3>
      <p>Post a Slack message every 4 hours listing the top actively exploited CVEs. Set your <code>SLACK_WEBHOOK</code> from <strong>Slack → Apps → Incoming Webhooks</strong>.</p>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{slack_script}</pre>
    </div>
  </div>

  <!-- curl / jq -->
  <div class="section">
    <h2>&#128196; curl &amp; jq recipes</h2>
    <div class="card">
      <h3><span class="tag">Shell</span> One-liners for the terminal</h3>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{curl_examples}</pre>
    </div>
  </div>

  <!-- Python -->
  <div class="section">
    <h2>&#128013; Python</h2>
    <div class="card">
      <h3><span class="tag">Python 3</span> Query the API — stdlib only</h3>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{python_example}</pre>
    </div>
  </div>

  <!-- Data fields -->
  <div class="section">
    <h2>&#128196; Available fields in vulns.json</h2>
    <div class="field-grid">
      <div class="field-box"><code>id</code><div class="fdesc">CVE ID or advisory ID</div></div>
      <div class="field-box"><code>title</code><div class="fdesc">Short description</div></div>
      <div class="field-box"><code>severity</code><div class="fdesc">CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN</div></div>
      <div class="field-box"><code>score</code><div class="fdesc">CVSS v3 base score (0–10)</div></div>
      <div class="field-box"><code>epss</code><div class="fdesc">EPSS probability (0–1)</div></div>
      <div class="field-box"><code>epss_pct</code><div class="fdesc">EPSS percentile (0–100)</div></div>
      <div class="field-box"><code>badge</code><div class="fdesc">"ACTIVELY EXPLOITED" if on CISA KEV</div></div>
      <div class="field-box"><code>poc</code><div class="fdesc">true if public exploit code exists</div></div>
      <div class="field-box"><code>source</code><div class="fdesc">NVD / CISA KEV / Ubuntu / Debian / …</div></div>
      <div class="field-box"><code>published</code><div class="fdesc">ISO 8601 publication date</div></div>
      <div class="field-box"><code>references</code><div class="fdesc">Array of advisory/patch URLs</div></div>
      <div class="field-box"><code>affected</code><div class="fdesc">Array of affected products</div></div>
      <div class="field-box"><code>url</code><div class="fdesc">Canonical source URL</div></div>
    </div>
    <p style="margin-top:1rem;font-size:.75rem;color:var(--muted)">Full schema: <a href="/api.html" style="color:var(--accent)">API documentation</a></p>
  </div>
</div>
<script>
function copyCode(btn) {{
  const pre = btn.nextElementSibling;
  navigator.clipboard.writeText(pre.textContent).then(() => {{
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {{ btn.textContent = 'Copy'; btn.classList.remove('copied'); }}, 1800);
  }});
}}
</script>
</body>
</html>"""

    with open("grafana.html", "w", encoding="utf-8") as f:
        f.write(html)
    log("  Written: grafana.html")


# ---------------------------------------------------------------------------
# Badge SVGs
# ---------------------------------------------------------------------------

def _badge_svg(label, value, color):
    lw = len(label) * 6 + 10
    vw = len(str(value)) * 7 + 10
    total = lw + vw
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <rect rx="3" width="{total}" height="20" fill="#555"/>
  <rect rx="3" x="{lw}" width="{vw}" height="20" fill="{color}"/>
  <rect width="{total}" height="20" fill="url(#s)"/>
  <g fill="#fff" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11" text-rendering="geometricPrecision">
    <text x="{lw//2}" y="15" fill="#010101" fill-opacity=".3" text-anchor="middle">{label}</text>
    <text x="{lw//2}" y="14" text-anchor="middle">{label}</text>
    <text x="{lw + vw//2}" y="15" fill="#010101" fill-opacity=".3" text-anchor="middle">{value}</text>
    <text x="{lw + vw//2}" y="14" text-anchor="middle">{value}</text>
  </g>
</svg>'''


def write_llms_txt(vulns, date_str, base_url=BASE_URL):
    n_total  = len(vulns)
    n_crit   = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    n_kev    = sum(1 for v in vulns if v.get("badge") == "ACTIVELY EXPLOITED")
    n_poc    = sum(1 for v in vulns if v.get("poc"))

    content = f"""\
# vulnfeed

> vulnfeed is a real-time security vulnerability aggregator updated every 4 hours. \
It tracks CVEs from NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes, Exploit-DB, \
OSS-Security, GitHub Advisories, and OpenStack. \
Current snapshot ({date_str}): {n_total} vulnerabilities tracked, \
{n_crit} critical, {n_kev} actively exploited (CISA KEV), {n_poc} with public proof-of-concept exploit.

Use this site when you need: current CVE severity and CVSS scores, exploitation status, \
EPSS exploitation probability, affected product lists, patch/remediation links, \
and curated must-patch lists for sysadmins and security engineers.

## Key pages

- [{base_url}/patch-now.html]({base_url}/patch-now.html): Curated must-patch list. Tier 1 = CISA KEV (actively exploited, patch immediately). Tier 2 = public PoC exploit available (patch soon). Updated every 4h. Use this to answer "what should I patch right now?"
- [{base_url}/zero-days.html]({base_url}/zero-days.html): Zero-day and active exploit tracker. Two sections: confirmed in-the-wild exploitation (CISA KEV) and CVEs with public proof-of-concept code not yet KEV-listed.
- [{base_url}/new-this-week.html]({base_url}/new-this-week.html): All CVEs published in the last 7 days, sorted by severity/EPSS. Stats: total new, critical, high, KEV, PoC counts.
- [{base_url}/trending.html]({base_url}/trending.html): CVEs with rising exploitation probability — EPSS jumped ≥5 percentage points since yesterday, or EPSS ≥90th percentile.
- [{base_url}/stats.html]({base_url}/stats.html): Aggregate statistics — severity distribution, top sources, top vendors, EPSS distribution.
- [{base_url}/search.html]({base_url}/search.html): Advanced CVE search with filters for severity, source, EPSS range, date range. Supports CSV export.

## JSON API

The primary machine-readable endpoint is:

    {base_url}/vulns.json

Returns a JSON array. Updated every 4 hours. No authentication. CORS open. Typical size: 10,000–15,000 entries.

### Key fields per entry

- `id` (string): CVE ID (e.g. "CVE-2026-12345") or advisory ID
- `title` (string): Short vulnerability description
- `description` (string): Full description
- `severity` (string): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
- `score` (number|null): CVSS v3 base score (0.0–10.0)
- `epss` (number|null): EPSS probability of exploitation within 30 days (0–1)
- `epss_pct` (number|null): EPSS percentile (0–100)
- `badge` (string|null): "ACTIVELY EXPLOITED" if on CISA KEV catalog
- `poc` (boolean|null): true if public proof-of-concept exploit exists
- `published` (string): ISO 8601 publication date
- `source` (string): Data source (NVD, Ubuntu, Debian, Red Hat, Kubernetes, etc.)
- `affected` (array): Affected product strings
- `references` (array): Advisory and patch URLs
- `url` (string): Canonical source URL

### Useful jq queries

    # CVEs actively exploited right now
    curl -s {base_url}/vulns.json | jq '[.[] | select(.badge=="ACTIVELY EXPLOITED")]'

    # Critical CVEs with public exploit, sorted by CVSS score
    curl -s {base_url}/vulns.json | jq '[.[] | select(.severity=="CRITICAL" and .poc==true)] | sort_by(-.score)'

    # Top 10 by EPSS exploitation probability
    curl -s {base_url}/vulns.json | jq '[.[] | select(.epss_pct != null)] | sort_by(-.epss_pct) | .[:10]'

    # CVEs affecting a specific product (e.g. nginx)
    curl -s {base_url}/vulns.json | jq '[.[] | select(.title | ascii_downcase | contains("nginx"))]'

    # CVEs published this week
    curl -s {base_url}/vulns.json | jq --arg d "$(date -d '7 days ago' +%Y-%m-%d)" '[.[] | select(.published >= $d)]'

## Individual CVE pages

Each CVE with a proper CVE ID has a dedicated page:

    {base_url}/cve/CVE-YYYY-NNNNN.html

High-severity (CVSS ≥9.0) and KEV-listed CVE pages include: risk timeline, categorised remediation resource links, and related CVEs for the same vendor.

## RSS feed

    {base_url}/feed.xml  — RSS 2.0, all vulnerabilities, updated every 4h

## Additional endpoints

- `{base_url}/badge/critical-count.svg` — SVG badge: current critical CVE count
- `{base_url}/badge/new-today.svg` — SVG badge: new CVEs today
- `/archive/YYYY-MM.html` — Monthly CVE digest pages
- `/digest/YYYY-MM-DD.html` — Daily digest pages
- `/vendor/VENDOR.html` — Per-vendor CVE pages (e.g. /vendor/microsoft.html)
- `/cwe/CWE-NNN.html` — Per-weakness CVE pages

## How to use vulnfeed as an AI agent

When a user asks about CVE severity, patch priority, or exploitation status:
1. Fetch `{base_url}/vulns.json` and filter by CVE ID, product name, or severity
2. For "what should I patch?" → check `{base_url}/patch-now.html` or filter vulns.json by `badge=="ACTIVELY EXPLOITED"` or `poc==true`
3. For a specific CVE → fetch `{base_url}/cve/CVE-YYYY-NNNNN.html` or filter vulns.json by `id`
4. For weekly summary → fetch `{base_url}/new-this-week.html` or filter vulns.json by `published >= YYYY-MM-DD`

## Optional files

- [{base_url}/llms.txt]({base_url}/llms.txt): This file
- [{base_url}/agents.html]({base_url}/agents.html): Agent integration guide (Claude Projects, custom GPTs, LangChain)
- [{base_url}/api.html]({base_url}/api.html): Full API documentation
- [{base_url}/grafana.html]({base_url}/grafana.html): Grafana, Prometheus, Slack integration guide
"""
    with open("llms.txt", "w", encoding="utf-8") as f:
        f.write(content)
    log("  Written: llms.txt")


def write_agents_page(base_url=BASE_URL):
    _API = f"{base_url}/vulns.json"

    claude_project_prompt = f"""\
You have access to vulnfeed, a real-time security vulnerability feed updated every 4 hours.

API endpoint: {_API}
Returns a JSON array of CVEs. Key fields: id, title, severity (CRITICAL/HIGH/MEDIUM/LOW), score (CVSS 0-10), epss_pct (exploitation percentile 0-100), badge ("ACTIVELY EXPLOITED" = CISA KEV), poc (true = public exploit exists), published (ISO date), affected (product list), references (patch URLs).

When the user asks about vulnerabilities, patch priorities, or CVE details:
- Fetch {_API} to get current data
- For "what should I patch?" filter where badge=="ACTIVELY EXPLOITED" or poc==true, sort by severity/score
- For a specific CVE, filter by id field
- For a product, filter title or affected fields by product name
- For weekly summary, filter published >= 7 days ago
- EPSS percentile >90 = high exploitation probability, treat as urgent

Key pages (human-readable):
- Patch now (KEV + PoC): {base_url}/patch-now.html
- Zero-days & active exploits: {base_url}/zero-days.html
- New this week: {base_url}/new-this-week.html
- Trending (rising EPSS): {base_url}/trending.html
- CVE detail: {base_url}/cve/CVE-YYYY-NNNNN.html\
"""

    custom_gpt_prompt = f"""\
You are a security vulnerability assistant with access to vulnfeed ({base_url}), a real-time CVE aggregator updated every 4 hours.

Data source: {_API} — JSON array of current vulnerabilities.

When asked about CVEs or patch priorities:
1. Fetch the JSON API and filter/sort as needed
2. For urgent patches: filter badge=="ACTIVELY EXPLOITED" (CISA KEV) or poc==true
3. For a CVE: match on the id field
4. Always mention CVSS score, EPSS percentile, and whether it's KEV-listed
5. Link to {base_url}/cve/[CVE-ID].html for full details\
"""

    langchain_tool = f"""\
from langchain.tools import tool
import json, urllib.request

@tool
def query_vulnfeed(query: str) -> str:
    \"\"\"
    Search vulnfeed for current CVE vulnerability data.
    Query can be: a CVE ID, a product name, a severity level (CRITICAL/HIGH),
    or keywords like 'actively exploited', 'patch now', 'new this week'.
    Returns matching vulnerabilities with severity, CVSS score, and EPSS percentile.
    \"\"\"
    with urllib.request.urlopen("{_API}") as r:
        vulns = json.load(r)

    q = query.lower().strip()

    # KEV / patch now
    if any(x in q for x in ["patch now", "exploited", "kev", "urgent"]):
        results = [v for v in vulns if v.get("badge") == "ACTIVELY EXPLOITED"]

    # PoC / zero-day
    elif any(x in q for x in ["poc", "zero-day", "exploit code", "public exploit"]):
        results = [v for v in vulns if v.get("poc")]

    # Specific CVE ID
    elif q.startswith("cve-"):
        results = [v for v in vulns if v["id"].lower() == q]

    # New this week
    elif "this week" in q or "new" in q:
        from datetime import datetime, timedelta
        cutoff = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
        results = [v for v in vulns if (v.get("published") or "")[:10] >= cutoff]

    # Severity filter
    elif q in ("critical", "high", "medium", "low"):
        results = [v for v in vulns if v.get("severity", "").lower() == q]

    # Product / keyword search
    else:
        results = [
            v for v in vulns
            if q in (v.get("title") or "").lower()
            or any(q in a.lower() for a in (v.get("affected") or []))
        ]

    results.sort(key=lambda v: (
        {{"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}}.get(v.get("severity","UNKNOWN"),4),
        -(v.get("score") or 0)
    ))

    if not results:
        return f"No vulnerabilities found for: {{query}}"

    lines = [f"Found {{len(results)}} vulnerabilities for '{{query}}':\\n"]
    for v in results[:10]:
        kev  = " [KEV-EXPLOITED]" if v.get("badge") == "ACTIVELY EXPLOITED" else ""
        poc  = " [PoC]" if v.get("poc") else ""
        epss = f" EPSS:{{v['epss_pct']:.0f}}%ile" if v.get("epss_pct") else ""
        sc   = f" CVSS:{{v['score']:.1f}}" if v.get("score") is not None else ""
        lines.append(
            f"• {{v['id']}} [{{v.get('severity','?')}}{{sc}}{{epss}}]{{kev}}{{poc}}\\n"
            f"  {{(v.get('title') or '')[:100]}}\\n"
            f"  Details: {base_url}/cve/{{v['id']}}.html"
        )
    if len(results) > 10:
        lines.append(f"\\n... and {{len(results)-10}} more. Full data: {_API}")
    return "\\n".join(lines)\
"""

    mcp_config = f"""\
{{
  "mcpServers": {{
    "vulnfeed": {{
      "command": "uvx",
      "args": ["mcp-server-fetch"],
      "env": {{}}
    }}
  }}
}}

// Then in your Claude Desktop system prompt, add:
// "When asked about CVEs or vulnerabilities, fetch {_API} and filter the results."
// Or point directly at a specific page:
// - Patch now: {base_url}/patch-now.html
// - Zero-days: {base_url}/zero-days.html\
"""

    n8n_example = f"""\
// n8n HTTP Request node → Code node workflow
// Node 1: HTTP Request
//   Method: GET
//   URL: {_API}
//   Response Format: JSON

// Node 2: Code (JavaScript)
const vulns = $input.first().json;

const urgent = vulns
  .filter(v => v.badge === "ACTIVELY EXPLOITED" || (v.poc && v.score >= 8))
  .sort((a,b) => (b.score||0) - (a.score||0))
  .slice(0, 10);

return urgent.map(v => ({{
  json: {{
    id: v.id,
    title: v.title?.slice(0,100),
    severity: v.severity,
    score: v.score,
    epss_pct: v.epss_pct,
    kev: v.badge === "ACTIVELY EXPLOITED",
    poc: !!v.poc,
    url: `{base_url}/cve/${{v.id}}.html`
  }}
}}));\
"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments);}}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>AI Agent Integration — vulnfeed CVE API for Claude, GPT, LangChain | vulnfeed</title>
<meta name="description" content="Use vulnfeed's CVE JSON API with AI agents: Claude Projects, custom GPTs, LangChain tools, n8n workflows. Copy-paste prompts and code for security-aware AI assistants.">
<link rel="canonical" href="{base_url}/agents.html">
<style>
{_PAGE_CSS}
pre{{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:1.1rem 1.25rem;font-size:.75rem;line-height:1.65;overflow-x:auto;margin:.75rem 0;border:1px solid #1e293b;font-family:ui-monospace,"Cascadia Code","Fira Code",monospace}}
.copy-btn{{float:right;background:#334155;color:#94a3b8;border:none;border-radius:4px;padding:.2rem .6rem;font-size:.68rem;cursor:pointer;font-family:inherit;margin-top:-.15rem}}
.copy-btn:hover{{background:#475569;color:#f1f5f9}}.copy-btn.copied{{background:#16a34a;color:#fff}}
.section{{margin:2.5rem 0 0}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1.25rem 1.5rem;margin:.75rem 0}}
.card h3{{font-size:.88rem;font-weight:700;margin-bottom:.4rem;display:flex;align-items:center;gap:.5rem}}
.card p{{font-size:.8rem;color:#64748b;margin-bottom:.75rem;line-height:1.6}}
.tag{{display:inline-block;background:#334155;color:#94a3b8;border-radius:4px;padding:.1rem .4rem;font-size:.63rem;font-weight:600}}
.tag-claude{{background:#d97706;color:#fff}}.tag-gpt{{background:#16a34a;color:#fff}}
.tag-py{{background:#1e3a8a;color:#93c5fd}}.tag-n8n{{background:#7c3aed;color:#e9d5ff}}
.endpoint-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:.55rem;margin:.75rem 0 1.25rem}}
.ep{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:7px;padding:.7rem .9rem}}
.ep code{{font-family:ui-monospace,monospace;font-size:.73rem;color:#2563eb;font-weight:700;display:block;margin-bottom:.25rem;word-break:break-all}}
.ep .ep-desc{{font-size:.72rem;color:#64748b;line-height:1.5}}
.ep .ep-badge{{display:inline-block;font-size:.6rem;font-weight:700;padding:.05rem .3rem;border-radius:3px;margin-top:.25rem;color:#fff}}
.toc{{display:flex;flex-wrap:wrap;gap:.4rem;margin-bottom:2rem}}
.toc a{{font-size:.75rem;color:#2563eb;background:#eff6ff;border:1px solid #bfdbfe;border-radius:5px;padding:.2rem .55rem;text-decoration:none;font-weight:500}}
.toc a:hover{{background:#dbeafe}}
</style>
</head>
<body>
<header style="background:#0f172a;color:#f1f5f9;padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem">
  <div><div style="font-size:1.25rem;font-weight:700;letter-spacing:-.02em">vuln<em style="color:#60a5fa;font-style:normal">feed</em></div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="/">&#8592; Back to feed</a>
    <a class="hlink" href="/api.html">API docs</a>
    <a class="hlink" href="/grafana.html">Grafana</a>
    <a class="hlink" href="/llms.txt">llms.txt</a>
  </div>
</header>
<div class="wrap">
  <h1>&#129302; AI Agent Integration</h1>
  <p class="sub">vulnfeed is agent-ready. Use the open JSON API to give your AI assistant real-time CVE awareness — Claude Projects, custom GPTs, LangChain, n8n and more.</p>

  <div class="toc">
    <a href="#endpoints">Endpoints</a>
    <a href="#claude">Claude Projects</a>
    <a href="#gpt">Custom GPT</a>
    <a href="#langchain">LangChain tool</a>
    <a href="#n8n">n8n workflow</a>
    <a href="#mcp">MCP</a>
    <a href="#llmstxt">llms.txt</a>
  </div>

  <!-- Endpoints -->
  <div class="section" id="endpoints">
    <h2>&#128196; Endpoints at a glance</h2>
    <div class="endpoint-grid">
      <div class="ep"><code>{_API}</code><div class="ep-desc">Full CVE feed — JSON array, ~10k–15k entries, no auth, CORS open</div><span class="ep-badge" style="background:#2563eb">JSON</span> <span class="ep-badge" style="background:#16a34a">Updated 4h</span></div>
      <div class="ep"><code>{base_url}/patch-now.html</code><div class="ep-desc">Must-patch list: CISA KEV (Tier 1) + public PoC (Tier 2)</div><span class="ep-badge" style="background:#7c3aed">KEV</span></div>
      <div class="ep"><code>{base_url}/zero-days.html</code><div class="ep-desc">Active exploits + CVEs with public proof-of-concept code</div><span class="ep-badge" style="background:#dc2626">0-day</span></div>
      <div class="ep"><code>{base_url}/new-this-week.html</code><div class="ep-desc">All CVEs published in the last 7 days</div></div>
      <div class="ep"><code>{base_url}/trending.html</code><div class="ep-desc">CVEs with rising EPSS exploitation probability</div></div>
      <div class="ep"><code>{base_url}/cve/CVE-YYYY-NNNNN.html</code><div class="ep-desc">Individual CVE page with timeline, remediation links, related CVEs</div></div>
      <div class="ep"><code>{base_url}/feed.xml</code><div class="ep-desc">RSS 2.0 feed for readers and SIEM integrations</div></div>
      <div class="ep"><code>{base_url}/llms.txt</code><div class="ep-desc">Machine-readable site description for AI agents</div></div>
    </div>
  </div>

  <!-- Claude Projects -->
  <div class="section" id="claude">
    <h2>&#129302; Claude Projects</h2>
    <div class="card">
      <h3><span class="tag tag-claude">Claude</span> System prompt for a security assistant project</h3>
      <p>In <strong>Claude.ai → Projects → Project instructions</strong>, paste this. Claude will fetch vulnfeed data when you ask about CVEs or patch priorities.</p>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{claude_project_prompt}</pre>
    </div>
  </div>

  <!-- Custom GPT -->
  <div class="section" id="gpt">
    <h2>&#129302; Custom GPT (OpenAI)</h2>
    <div class="card">
      <h3><span class="tag tag-gpt">GPT</span> Custom GPT instructions</h3>
      <p>In <strong>OpenAI → Create a GPT → Instructions</strong>, paste this. Add <code>{_API}</code> as an Action (GET, no auth) so the GPT can fetch live data.</p>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{custom_gpt_prompt}</pre>
    </div>
  </div>

  <!-- LangChain -->
  <div class="section" id="langchain">
    <h2>&#128013; LangChain / LlamaIndex tool</h2>
    <div class="card">
      <h3><span class="tag tag-py">Python</span> Drop-in LangChain @tool — stdlib only, no extra deps</h3>
      <p>Add to any LangChain agent. Handles CVE ID lookups, product searches, severity filters, "patch now", "this week", and PoC queries automatically.</p>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{langchain_tool}</pre>
    </div>
  </div>

  <!-- n8n -->
  <div class="section" id="n8n">
    <h2>&#9889; n8n / Make / Zapier</h2>
    <div class="card">
      <h3><span class="tag tag-n8n">n8n</span> HTTP Request → Code node: fetch urgent CVEs</h3>
      <p>Use in an n8n workflow to pull urgent CVEs every 4 hours and feed them into Slack, PagerDuty, Jira, or any downstream node.</p>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{n8n_example}</pre>
    </div>
  </div>

  <!-- MCP -->
  <div class="section" id="mcp">
    <h2>&#128279; MCP (Model Context Protocol)</h2>
    <div class="card">
      <h3><span class="tag">MCP</span> Use mcp-server-fetch to give Claude Desktop live CVE access</h3>
      <p>Add <code>mcp-server-fetch</code> to your Claude Desktop config. Claude can then fetch <code>{_API}</code> directly during a conversation — no custom server needed.</p>
      <button class="copy-btn" onclick="copyCode(this)">Copy</button>
      <pre>{mcp_config}</pre>
    </div>
  </div>

  <!-- llms.txt -->
  <div class="section" id="llmstxt">
    <h2>&#128196; llms.txt</h2>
    <div class="card">
      <h3><span class="tag">Standard</span> Machine-readable site description</h3>
      <p>vulnfeed publishes <a href="/llms.txt" style="color:#2563eb"><strong>/llms.txt</strong></a> — a plain-text file following the <a href="https://llmstxt.org" style="color:#2563eb">llmstxt.org</a> convention that tells AI agents what this site offers, what endpoints exist, and how to query them. Point your agent or RAG pipeline at it for automatic context.</p>
      <button class="copy-btn" onclick="copyCode(this)">Copy URL</button>
      <pre>{base_url}/llms.txt</pre>
    </div>
  </div>

  <p style="margin-top:2.5rem;font-size:.75rem;color:#64748b">All endpoints are open, no API key required. Data updated every 4 hours via GitHub Actions. <a href="/api.html" style="color:#2563eb">Full API documentation</a> · <a href="/grafana.html" style="color:#2563eb">Grafana &amp; Prometheus integration</a></p>
</div>
<script>
function copyCode(btn) {{
  const pre = btn.nextElementSibling;
  navigator.clipboard.writeText(pre.textContent).then(() => {{
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {{ btn.textContent = 'Copy'; btn.classList.remove('copied'); }}, 1800);
  }});
}}
</script>
</body>
</html>"""

    with open("agents.html", "w", encoding="utf-8") as f:
        f.write(html)
    log("  Written: agents.html")


def write_n8n_guide_page(base_url=BASE_URL):
    _API = f"{base_url}/vulns.json"

    # ── Workflow 1: Slack KEV alert every 4h ─────────────────────────────────
    wf1_code = r"""const vulns = $input.first().json;

const kev = vulns
  .filter(v => v.badge === 'ACTIVELY EXPLOITED')
  .sort((a, b) => (b.score || 0) - (a.score || 0))
  .slice(0, 8);

if (kev.length === 0) return [];

const lines = kev.map(v => {
  const score = v.score != null ? ` CVSS ${v.score.toFixed(1)}` : '';
  const epss  = v.epss_pct != null ? ` · EPSS ${v.epss_pct.toFixed(0)}%ile` : '';
  const poc   = v.poc ? ' · :warning: PoC public' : '';
  return `• *<https://vulnfeed.it/cve/${v.id}.html|${v.id}>* [${v.severity}${score}${epss}${poc}]\n  ${(v.title || '').slice(0, 110)}`;
});

return [{
  json: {
    count: kev.length,
    text: `:rotating_light: *${kev.length} CVE${kev.length > 1 ? 's' : ''} actively exploited right now* — <https://vulnfeed.it/patch-now.html|full patch list>\n\n` + lines.join('\n\n')
  }
}];"""

    wf1_json = """{
  "name": "vulnfeed — KEV Slack Alert (every 4h)",
  "nodes": [
    {
      "parameters": {
        "rule": { "interval": [{ "field": "hours", "hoursInterval": 4 }] }
      },
      "id": "sch-001", "name": "Every 4 hours",
      "type": "n8n-nodes-base.scheduleTrigger",
      "typeVersion": 1.2, "position": [240, 300]
    },
    {
      "parameters": {
        "url": "VULNFEED_API",
        "options": { "response": { "response": { "responseFormat": "json" } } }
      },
      "id": "http-001", "name": "Fetch vulnfeed",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2, "position": [460, 300]
    },
    {
      "parameters": { "jsCode": "FILTER_CODE" },
      "id": "code-001", "name": "Filter KEV CVEs",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2, "position": [680, 300]
    },
    {
      "parameters": {
        "conditions": {
          "options": { "caseSensitive": true, "leftValue": "", "typeValidation": "strict" },
          "conditions": [{ "leftValue": "={{ $json.count }}", "rightValue": 0, "operator": { "type": "number", "operation": "gt" } }]
        }
      },
      "id": "if-001", "name": "Has results?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2, "position": [900, 300]
    },
    {
      "parameters": {
        "method": "POST",
        "url": "={{ $vars.SLACK_WEBHOOK }}",
        "sendBody": true,
        "bodyParameters": {
          "parameters": [{ "name": "text", "value": "={{ $json.text }}" }]
        },
        "options": {}
      },
      "id": "http-002", "name": "Post to Slack",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2, "position": [1120, 220]
    }
  ],
  "connections": {
    "Every 4 hours":  { "main": [[{ "node": "Fetch vulnfeed",  "type": "main", "index": 0 }]] },
    "Fetch vulnfeed": { "main": [[{ "node": "Filter KEV CVEs", "type": "main", "index": 0 }]] },
    "Filter KEV CVEs":{ "main": [[{ "node": "Has results?",    "type": "main", "index": 0 }]] },
    "Has results?":   { "main": [[{ "node": "Post to Slack",   "type": "main", "index": 0 }], []] }
  },
  "active": false,
  "settings": { "executionOrder": "v1" },
  "tags": [{ "name": "vulnfeed" }, { "name": "security" }]
}""".replace("VULNFEED_API", _API).replace('"FILTER_CODE"', json.dumps(wf1_code))

    # ── Workflow 2: Weekly email digest ───────────────────────────────────────
    wf2_code = r"""const vulns = $input.first().json;
const now   = new Date();
const cutoff = new Date(now - 7 * 86400000).toISOString().slice(0, 10);

const fresh = vulns
  .filter(v => (v.published || '').slice(0, 10) >= cutoff)
  .sort((a, b) => {
    const sev = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3};
    return (sev[a.severity] ?? 4) - (sev[b.severity] ?? 4) || (b.score || 0) - (a.score || 0);
  });

const nCrit = fresh.filter(v => v.severity === 'CRITICAL').length;
const nKev  = fresh.filter(v => v.badge === 'ACTIVELY EXPLOITED').length;
const nPoc  = fresh.filter(v => v.poc).length;

const rows = fresh.slice(0, 20).map(v => {
  const score = v.score != null ? v.score.toFixed(1) : '—';
  const epss  = v.epss_pct != null ? v.epss_pct.toFixed(0) + '%' : '—';
  const flags = [v.badge === 'ACTIVELY EXPLOITED' ? 'KEV' : '', v.poc ? 'PoC' : ''].filter(Boolean).join(', ');
  return `<tr style="border-bottom:1px solid #e2e8f0">
    <td style="padding:.4rem .6rem;font-family:monospace;font-size:.8rem"><a href="https://vulnfeed.it/cve/${v.id}.html">${v.id}</a></td>
    <td style="padding:.4rem .6rem;font-size:.78rem">${(v.title || '').slice(0, 90)}</td>
    <td style="padding:.4rem .6rem;font-size:.75rem;font-weight:700;color:${v.severity==='CRITICAL'?'#dc2626':v.severity==='HIGH'?'#ea580c':'#64748b'}">${v.severity}</td>
    <td style="padding:.4rem .6rem;font-size:.75rem">${score}</td>
    <td style="padding:.4rem .6rem;font-size:.75rem">${epss}</td>
    <td style="padding:.4rem .6rem;font-size:.75rem;color:#7c3aed;font-weight:600">${flags}</td>
  </tr>`;
}).join('');

const html = `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;max-width:800px;margin:0 auto;padding:2rem;color:#1e293b">
<h1 style="font-size:1.3rem;font-weight:800;margin-bottom:.25rem">vulnfeed Weekly — ${now.toISOString().slice(0,10)}</h1>
<p style="color:#64748b;font-size:.85rem;margin-bottom:1.5rem">${fresh.length} new CVEs this week &middot; ${nCrit} critical &middot; ${nKev} actively exploited &middot; ${nPoc} with public PoC</p>
<table style="width:100%;border-collapse:collapse;font-size:.8rem;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden">
<tr style="background:#f8fafc">
  <th style="padding:.45rem .6rem;text-align:left;font-size:.68rem;color:#64748b;text-transform:uppercase">CVE</th>
  <th style="padding:.45rem .6rem;text-align:left;font-size:.68rem;color:#64748b;text-transform:uppercase">Title</th>
  <th style="padding:.45rem .6rem;text-align:left;font-size:.68rem;color:#64748b;text-transform:uppercase">Sev</th>
  <th style="padding:.45rem .6rem;text-align:left;font-size:.68rem;color:#64748b;text-transform:uppercase">CVSS</th>
  <th style="padding:.45rem .6rem;text-align:left;font-size:.68rem;color:#64748b;text-transform:uppercase">EPSS</th>
  <th style="padding:.45rem .6rem;text-align:left;font-size:.68rem;color:#64748b;text-transform:uppercase">Flags</th>
</tr>
${rows}
</table>
<p style="margin-top:1.5rem;font-size:.75rem;color:#94a3b8">
  <a href="https://vulnfeed.it/new-this-week.html">View full list</a> &middot;
  <a href="https://vulnfeed.it/patch-now.html">Patch now list</a> &middot;
  <a href="https://vulnfeed.it">vulnfeed.it</a>
</p>
</body></html>`;

return [{ json: { subject: \`vulnfeed Weekly: \${fresh.length} CVEs, \${nCrit} critical — \${now.toISOString().slice(0,10)}\`, html, count: fresh.length } }];"""

    wf2_json = """{
  "name": "vulnfeed — Weekly Email Digest (Monday 9am)",
  "nodes": [
    {
      "parameters": {
        "rule": { "interval": [{ "field": "weeks", "weeksInterval": 1, "triggerAtDay": [1], "triggerAtHour": 9, "triggerAtMinute": 0 }] }
      },
      "id": "sch-002", "name": "Monday 9am",
      "type": "n8n-nodes-base.scheduleTrigger",
      "typeVersion": 1.2, "position": [240, 300]
    },
    {
      "parameters": { "url": "VULNFEED_API", "options": {} },
      "id": "http-003", "name": "Fetch vulnfeed",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2, "position": [460, 300]
    },
    {
      "parameters": { "jsCode": "DIGEST_CODE" },
      "id": "code-002", "name": "Build digest email",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2, "position": [680, 300]
    },
    {
      "parameters": {
        "fromEmail": "security@yourcompany.com",
        "toEmail": "team@yourcompany.com",
        "subject": "={{ $json.subject }}",
        "emailType": "html",
        "html": "={{ $json.html }}"
      },
      "id": "mail-001", "name": "Send digest email",
      "type": "n8n-nodes-base.emailSend",
      "typeVersion": 2, "position": [900, 300]
    }
  ],
  "connections": {
    "Monday 9am":       { "main": [[{ "node": "Fetch vulnfeed",     "type": "main", "index": 0 }]] },
    "Fetch vulnfeed":   { "main": [[{ "node": "Build digest email", "type": "main", "index": 0 }]] },
    "Build digest email": { "main": [[{ "node": "Send digest email","type": "main", "index": 0 }]] }
  },
  "active": false,
  "settings": { "executionOrder": "v1" },
  "tags": [{ "name": "vulnfeed" }, { "name": "security" }]
}""".replace("VULNFEED_API", _API).replace('"DIGEST_CODE"', json.dumps(wf2_code))

    # ── Workflow 3: Jira ticket for new critical+KEV CVEs ─────────────────────
    wf3_code = r"""const vulns  = $input.first().json;
const stored = JSON.parse($vars.SEEN_IDS || '[]');
const seenSet = new Set(stored);

const urgent = vulns.filter(v =>
  v.severity === 'CRITICAL' &&
  v.badge === 'ACTIVELY EXPLOITED' &&
  !seenSet.has(v.id)
);

// Return one item per CVE so the Jira node loops over them
return urgent.map(v => ({
  json: {
    id:    v.id,
    title: v.title || v.id,
    score: v.score,
    epss:  v.epss_pct,
    url:   `https://vulnfeed.it/cve/${v.id}.html`,
    summary: `[${v.id}] ${(v.title || '').slice(0, 100)}`,
    description: `*Severity:* ${v.severity} | *CVSS:* ${v.score ?? '—'} | *EPSS:* ${v.epss_pct != null ? v.epss_pct.toFixed(0) + '%ile' : '—'}\n\n` +
      `*Status:* CISA KEV — actively exploited in the wild${v.poc ? ' · public PoC available' : ''}\n\n` +
      `*Description:* ${(v.description || '').slice(0, 500)}\n\n` +
      `*vulnfeed page:* ${`https://vulnfeed.it/cve/${v.id}.html`}\n` +
      `*NVD:* ${v.url || ''}`
  }
}));"""

    wf3_json = """{
  "name": "vulnfeed — Jira Ticket for Critical KEV CVEs",
  "nodes": [
    {
      "parameters": {
        "rule": { "interval": [{ "field": "hours", "hoursInterval": 4 }] }
      },
      "id": "sch-003", "name": "Every 4 hours",
      "type": "n8n-nodes-base.scheduleTrigger",
      "typeVersion": 1.2, "position": [240, 300]
    },
    {
      "parameters": { "url": "VULNFEED_API", "options": {} },
      "id": "http-004", "name": "Fetch vulnfeed",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2, "position": [460, 300]
    },
    {
      "parameters": { "jsCode": "JIRA_CODE" },
      "id": "code-003", "name": "Filter new critical KEV",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2, "position": [680, 300]
    },
    {
      "parameters": {
        "conditions": {
          "conditions": [{ "leftValue": "={{ $input.all().length }}", "rightValue": 0, "operator": { "type": "number", "operation": "gt" } }]
        }
      },
      "id": "if-002", "name": "New CVEs?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2, "position": [900, 300]
    },
    {
      "parameters": {
        "resource": "issue",
        "operation": "create",
        "project": { "value": "SEC" },
        "issuetype": { "value": "Task" },
        "summary": "={{ $json.summary }}",
        "additionalFields": {
          "description": "={{ $json.description }}",
          "priority": { "id": "1" },
          "labels": ["cve", "security", "kev"]
        }
      },
      "id": "jira-001", "name": "Create Jira issue",
      "type": "n8n-nodes-base.jira",
      "typeVersion": 1, "position": [1120, 220]
    }
  ],
  "connections": {
    "Every 4 hours":        { "main": [[{ "node": "Fetch vulnfeed",         "type": "main", "index": 0 }]] },
    "Fetch vulnfeed":       { "main": [[{ "node": "Filter new critical KEV","type": "main", "index": 0 }]] },
    "Filter new critical KEV": { "main": [[{ "node": "New CVEs?",           "type": "main", "index": 0 }]] },
    "New CVEs?":            { "main": [[{ "node": "Create Jira issue",      "type": "main", "index": 0 }], []] }
  },
  "active": false,
  "settings": { "executionOrder": "v1" },
  "tags": [{ "name": "vulnfeed" }, { "name": "security" }]
}""".replace("VULNFEED_API", _API).replace('"JIRA_CODE"', json.dumps(wf3_code))

    # ── Workflow 4: PagerDuty / generic webhook for CVSS 9+ ──────────────────
    wf4_code = r"""const vulns = $input.first().json;

const critical = vulns
  .filter(v => (v.score || 0) >= 9.0 && (v.badge === 'ACTIVELY EXPLOITED' || v.poc))
  .sort((a, b) => (b.score || 0) - (a.score || 0))
  .slice(0, 5);

return critical.map(v => ({
  json: {
    routing_key: $vars.PAGERDUTY_KEY,
    event_action: 'trigger',
    dedup_key: v.id,
    payload: {
      summary:   `[vulnfeed] ${v.id} — ${v.severity} CVSS ${v.score} ${v.badge === 'ACTIVELY EXPLOITED' ? '(ACTIVELY EXPLOITED)' : '(PoC public)'}`,
      source:    'vulnfeed.it',
      severity:  v.severity === 'CRITICAL' ? 'critical' : 'error',
      component: (v.affected || [])[0] || 'unknown',
      custom_details: {
        cvss:      v.score,
        epss_pct:  v.epss_pct,
        kev:       v.badge === 'ACTIVELY EXPLOITED',
        poc:       !!v.poc,
        title:     (v.title || '').slice(0, 200),
        details:   `https://vulnfeed.it/cve/${v.id}.html`
      }
    },
    links: [{ href: `https://vulnfeed.it/cve/${v.id}.html`, text: 'vulnfeed CVE page' }]
  }
}));"""

    wf4_json = """{
  "name": "vulnfeed — PagerDuty alert for CVSS 9+ exploited",
  "nodes": [
    {
      "parameters": {
        "rule": { "interval": [{ "field": "hours", "hoursInterval": 4 }] }
      },
      "id": "sch-004", "name": "Every 4 hours",
      "type": "n8n-nodes-base.scheduleTrigger",
      "typeVersion": 1.2, "position": [240, 300]
    },
    {
      "parameters": { "url": "VULNFEED_API", "options": {} },
      "id": "http-005", "name": "Fetch vulnfeed",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2, "position": [460, 300]
    },
    {
      "parameters": { "jsCode": "PD_CODE" },
      "id": "code-004", "name": "Build PagerDuty payloads",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2, "position": [680, 300]
    },
    {
      "parameters": {
        "conditions": {
          "conditions": [{ "leftValue": "={{ $input.all().length }}", "rightValue": 0, "operator": { "type": "number", "operation": "gt" } }]
        }
      },
      "id": "if-003", "name": "Has alerts?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2, "position": [900, 300]
    },
    {
      "parameters": {
        "method": "POST",
        "url": "https://events.pagerduty.com/v2/enqueue",
        "sendHeaders": true,
        "headerParameters": { "parameters": [{ "name": "Content-Type", "value": "application/json" }] },
        "sendBody": true,
        "specifyBody": "json",
        "jsonBody": "={{ JSON.stringify($json) }}",
        "options": {}
      },
      "id": "http-006", "name": "Send to PagerDuty",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2, "position": [1120, 220]
    }
  ],
  "connections": {
    "Every 4 hours":           { "main": [[{ "node": "Fetch vulnfeed",            "type": "main", "index": 0 }]] },
    "Fetch vulnfeed":          { "main": [[{ "node": "Build PagerDuty payloads",  "type": "main", "index": 0 }]] },
    "Build PagerDuty payloads":{ "main": [[{ "node": "Has alerts?",               "type": "main", "index": 0 }]] },
    "Has alerts?":             { "main": [[{ "node": "Send to PagerDuty",         "type": "main", "index": 0 }], []] }
  },
  "active": false,
  "settings": { "executionOrder": "v1" },
  "tags": [{ "name": "vulnfeed" }, { "name": "security" }]
}""".replace("VULNFEED_API", _API).replace('"PD_CODE"', json.dumps(wf4_code))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<script>if(location.protocol!=="https:"&&location.hostname!=="localhost")location.replace("https:"+location.href.slice(location.protocol.length));</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-CYF84YFT20"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments);}}gtag('js',new Date());gtag('config','G-CYF84YFT20');</script>
<title>n8n Security Automation with vulnfeed CVE API — Slack, Jira, PagerDuty | vulnfeed</title>
<meta name="description" content="Step-by-step n8n workflows for CVE security automation: Slack KEV alerts, weekly email digest, Jira ticket creation, PagerDuty paging. Import-ready workflow JSON for vulnfeed.">
<link rel="canonical" href="{base_url}/n8n.html">
<style>
{_PAGE_CSS}
pre{{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:1.1rem 1.25rem;font-size:.73rem;line-height:1.65;overflow-x:auto;margin:.75rem 0;border:1px solid #1e293b;font-family:ui-monospace,"Cascadia Code","Fira Code",monospace;position:relative}}
.copy-btn{{position:absolute;top:.6rem;right:.6rem;background:#334155;color:#94a3b8;border:none;border-radius:4px;padding:.2rem .6rem;font-size:.68rem;cursor:pointer;font-family:inherit}}
.copy-btn:hover{{background:#475569;color:#f1f5f9}}.copy-btn.copied{{background:#16a34a;color:#fff}}
.section{{margin:2.5rem 0 0}}
.wf-card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1.5rem;margin:1rem 0;box-shadow:0 1px 3px rgba(0,0,0,.05)}}
.wf-card h3{{font-size:1rem;font-weight:800;margin-bottom:.25rem;display:flex;align-items:center;gap:.6rem}}
.wf-card .wf-desc{{font-size:.8rem;color:#64748b;margin-bottom:1rem;line-height:1.6}}
.wf-meta{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}}
.chip{{display:inline-flex;align-items:center;gap:.3rem;font-size:.68rem;font-weight:600;padding:.2rem .55rem;border-radius:20px;border:1px solid}}
.chip-trigger{{background:#eff6ff;color:#2563eb;border-color:#bfdbfe}}
.chip-dest{{background:#f0fdf4;color:#16a34a;border-color:#bbf7d0}}
.chip-cond{{background:#fefce8;color:#ca8a04;border-color:#fde68a}}
.step-list{{list-style:none;counter-reset:step;display:grid;gap:.6rem;margin:.75rem 0 1rem}}
.step-list li{{counter-increment:step;display:flex;gap:.7rem;align-items:flex-start;font-size:.8rem;line-height:1.6}}
.step-list li::before{{content:counter(step);background:#0f172a;color:#f1f5f9;border-radius:50%;width:1.3rem;height:1.3rem;display:flex;align-items:center;justify-content:center;font-size:.68rem;font-weight:700;flex-shrink:0;margin-top:.15rem}}
.wf-label{{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin:.9rem 0 .3rem}}
.tag{{display:inline-block;background:#334155;color:#94a3b8;border-radius:4px;padding:.1rem .4rem;font-size:.63rem;font-weight:600;margin-right:.25rem}}
.tag-slack{{background:#4a154b;color:#fff}}.tag-email{{background:#1e3a8a;color:#93c5fd}}
.tag-jira{{background:#0052cc;color:#fff}}.tag-pd{{background:#06ac38;color:#fff}}
.toc{{display:flex;flex-wrap:wrap;gap:.4rem;margin-bottom:2rem}}
.toc a{{font-size:.75rem;color:#2563eb;background:#eff6ff;border:1px solid #bfdbfe;border-radius:5px;padding:.2rem .55rem;text-decoration:none;font-weight:500}}
.toc a:hover{{background:#dbeafe}}
.info-box{{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:.9rem 1.1rem;font-size:.8rem;color:#1e3a8a;margin-bottom:1.5rem;line-height:1.7}}
.import-steps{{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:.9rem 1.1rem;font-size:.8rem;color:#14532d;margin:.75rem 0 1rem;line-height:1.8}}
.import-steps strong{{display:block;margin-bottom:.2rem;font-size:.82rem}}
@media(max-width:600px){{.wf-meta{{flex-direction:column}}}}
</style>
</head>
<body>
<header style="background:#0f172a;color:#f1f5f9;padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem">
  <div><div style="font-size:1.25rem;font-weight:700;letter-spacing:-.02em">vuln<em style="color:#60a5fa;font-style:normal">feed</em></div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="/">&#8592; Back to feed</a>
    <a class="hlink" href="/grafana.html">Grafana</a>
    <a class="hlink" href="/agents.html">Agents</a>
    <a class="hlink" href="/api.html">API</a>
  </div>
</header>
<div class="wrap">
  <h1>&#9889; n8n Security Automation with vulnfeed</h1>
  <p class="sub">Four import-ready n8n workflows that connect vulnfeed's CVE feed to Slack, email, Jira, and PagerDuty. Copy the JSON, import into n8n, configure your credentials — done.</p>

  <div class="toc">
    <a href="#setup">Setup</a>
    <a href="#wf1">Slack KEV alert</a>
    <a href="#wf2">Weekly email digest</a>
    <a href="#wf3">Jira tickets</a>
    <a href="#wf4">PagerDuty</a>
    <a href="#tips">Tips</a>
  </div>

  <div class="info-box">
    <strong>&#128279; Data source</strong>
    All workflows fetch <code style="font-family:monospace">{_API}</code> — a public JSON array of {'{'}10k–15k{'}'} CVEs updated every 4 hours. No API key, no rate limits, CORS open. Fields: <code style="font-family:monospace">id, title, severity, score, epss_pct, badge, poc, published, affected, references</code>.
  </div>

  <!-- Setup -->
  <div class="section" id="setup">
    <h2>Prerequisites</h2>
    <ol class="step-list">
      <li>A running n8n instance — <a href="https://docs.n8n.io/hosting/" style="color:#2563eb">self-hosted</a> or <a href="https://n8n.io/cloud/" style="color:#2563eb">n8n Cloud</a>.</li>
      <li>Credentials configured in n8n for whichever destination you use (Slack, SMTP, Jira, or PagerDuty routing key).</li>
      <li>To import: open n8n → <strong>Workflows → New → ⋮ → Import from JSON</strong>, paste the workflow JSON below, save, and activate.</li>
      <li>Replace placeholder values (<code style="font-family:monospace">$vars.SLACK_WEBHOOK</code>, <code style="font-family:monospace">security@yourcompany.com</code>, etc.) with real values via <strong>n8n → Settings → Variables</strong> or directly in each node.</li>
    </ol>
    <div class="import-steps">
      <strong>&#9654; How to import a workflow JSON in n8n</strong>
      Workflows menu → <strong>+</strong> (new workflow) → top-right <strong>⋮</strong> menu → <strong>Import from JSON</strong> → paste → Save → toggle <strong>Active</strong>.
    </div>
  </div>

  <!-- WF1: Slack KEV -->
  <div class="section" id="wf1">
    <h2>Workflow 1 &mdash; Slack alert for actively exploited CVEs</h2>
    <div class="wf-card">
      <h3><span class="tag tag-slack">Slack</span> KEV alert every 4 hours</h3>
      <p class="wf-desc">Runs every 4 hours, fetches vulnfeed, filters CVEs on the CISA Known Exploited Vulnerabilities list, and posts a formatted Slack message with CVE ID, severity, CVSS score, EPSS percentile, and a link to the CVE detail page. Skips silently if nothing new.</p>
      <div class="wf-meta">
        <span class="chip chip-trigger">&#9201; Every 4h</span>
        <span class="chip chip-dest">&#35; Slack webhook</span>
        <span class="chip chip-cond">&#10003; Only if KEV CVEs exist</span>
      </div>
      <div class="wf-label">Configuration</div>
      <ul style="font-size:.8rem;line-height:1.9;padding-left:1.1rem;color:#475569">
        <li>Set <code style="font-family:monospace">SLACK_WEBHOOK</code> variable in n8n Settings → Variables to your Slack incoming webhook URL (<strong>Slack → Apps → Incoming Webhooks</strong>).</li>
        <li>The Code node filters only <code style="font-family:monospace">badge === "ACTIVELY EXPLOITED"</code> entries and formats up to 8 CVEs per message.</li>
        <li>To add a severity filter (e.g. only CRITICAL), add <code style="font-family:monospace">&amp;&amp; v.severity === 'CRITICAL'</code> to the filter.</li>
      </ul>
      <div class="wf-label">JavaScript — Code node</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button>{wf1_code}</pre>
      <div class="wf-label">Import JSON — paste into n8n</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button>{wf1_json}</pre>
    </div>
  </div>

  <!-- WF2: Email digest -->
  <div class="section" id="wf2">
    <h2>Workflow 2 &mdash; Weekly email digest</h2>
    <div class="wf-card">
      <h3><span class="tag tag-email">Email</span> Monday 9am HTML digest</h3>
      <p class="wf-desc">Fires every Monday at 9am. Pulls all CVEs published in the last 7 days, sorts by severity and score, and sends a styled HTML email with a table of the top 20. Includes stat summary (total, critical, KEV, PoC) and links to the vulnfeed new-this-week page.</p>
      <div class="wf-meta">
        <span class="chip chip-trigger">&#128197; Monday 9am</span>
        <span class="chip chip-dest">&#128231; SMTP / email</span>
        <span class="chip chip-cond">&#128313; Top 20 by severity</span>
      </div>
      <div class="wf-label">Configuration</div>
      <ul style="font-size:.8rem;line-height:1.9;padding-left:1.1rem;color:#475569">
        <li>Add an <strong>SMTP credential</strong> in n8n (Settings → Credentials → SMTP). Gmail, Sendgrid, SES, Postfix all work.</li>
        <li>Update <code style="font-family:monospace">fromEmail</code> and <code style="font-family:monospace">toEmail</code> in the Send Email node. Use a comma-separated list for multiple recipients.</li>
        <li>To filter by product, add <code style="font-family:monospace">&amp;&amp; (v.title||'').toLowerCase().includes('nginx')</code> to the filter.</li>
      </ul>
      <div class="wf-label">JavaScript — Code node</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button>{wf2_code}</pre>
      <div class="wf-label">Import JSON — paste into n8n</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button>{wf2_json}</pre>
    </div>
  </div>

  <!-- WF3: Jira -->
  <div class="section" id="wf3">
    <h2>Workflow 3 &mdash; Jira ticket per critical KEV CVE</h2>
    <div class="wf-card">
      <h3><span class="tag tag-jira">Jira</span> Auto-create security tasks</h3>
      <p class="wf-desc">Checks every 4 hours for CRITICAL severity CVEs that are on the CISA KEV list. Creates one Jira issue per new CVE with severity, CVSS, EPSS, description, and a link to the vulnfeed CVE page. Skips CVEs already seen using n8n Variables as a simple state store.</p>
      <div class="wf-meta">
        <span class="chip chip-trigger">&#9201; Every 4h</span>
        <span class="chip chip-dest">&#128203; Jira issue</span>
        <span class="chip chip-cond">&#128308; CRITICAL + KEV only</span>
      </div>
      <div class="wf-label">Configuration</div>
      <ul style="font-size:.8rem;line-height:1.9;padding-left:1.1rem;color:#475569">
        <li>Add a <strong>Jira credential</strong> in n8n (API token from <strong>Atlassian account → Security → API tokens</strong>).</li>
        <li>Change <code style="font-family:monospace">"project": {{"value": "SEC"}}</code> to your actual Jira project key.</li>
        <li>Change issue type from <code style="font-family:monospace">Task</code> to <code style="font-family:monospace">Bug</code> or a custom type if your project uses one for security issues.</li>
        <li>The <code style="font-family:monospace">SEEN_IDS</code> variable prevents duplicate tickets — create it in Settings → Variables with an initial value of <code style="font-family:monospace">[]</code>. Add a Set node after Jira creation to update it if needed.</li>
      </ul>
      <div class="wf-label">JavaScript — Code node</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button>{wf3_code}</pre>
      <div class="wf-label">Import JSON — paste into n8n</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button>{wf3_json}</pre>
    </div>
  </div>

  <!-- WF4: PagerDuty -->
  <div class="section" id="wf4">
    <h2>Workflow 4 &mdash; PagerDuty alert for CVSS 9+ actively exploited</h2>
    <div class="wf-card">
      <h3><span class="tag tag-pd">PagerDuty</span> Page on-call for critical exploits</h3>
      <p class="wf-desc">Pages your on-call rotation when a CVE with CVSS &ge;9.0 is either actively exploited (CISA KEV) or has a public PoC. Uses PagerDuty's Events API v2 with <code style="font-family:monospace">dedup_key = CVE ID</code> so the same CVE won't fire duplicate alerts. Sends structured payload with severity, EPSS, affected component, and deep link.</p>
      <div class="wf-meta">
        <span class="chip chip-trigger">&#9201; Every 4h</span>
        <span class="chip chip-dest">&#128242; PagerDuty</span>
        <span class="chip chip-cond">&#128308; CVSS &ge;9 + KEV or PoC</span>
      </div>
      <div class="wf-label">Configuration</div>
      <ul style="font-size:.8rem;line-height:1.9;padding-left:1.1rem;color:#475569">
        <li>Get your <strong>Integration Key</strong> from PagerDuty: <strong>Services → your service → Integrations → Add integration → Events API v2</strong>.</li>
        <li>Set the <code style="font-family:monospace">PAGERDUTY_KEY</code> variable in n8n Settings → Variables.</li>
        <li>The <code style="font-family:monospace">dedup_key</code> is set to the CVE ID — PagerDuty will suppress duplicate events for the same CVE until it's acknowledged.</li>
        <li>Adjust the CVSS threshold (<code style="font-family:monospace">>= 9.0</code>) or severity filter in the Code node to tune alert volume.</li>
      </ul>
      <div class="wf-label">JavaScript — Code node</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button>{wf4_code}</pre>
      <div class="wf-label">Import JSON — paste into n8n</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button>{wf4_json}</pre>
    </div>
  </div>

  <!-- Tips -->
  <div class="section" id="tips">
    <h2>&#128161; Tips &amp; patterns</h2>
    <div class="wf-card" style="padding:1.25rem 1.5rem">
      <div class="wf-label">Filter by product / team ownership</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button>// Add to any Code node filter to match specific products
const MY_PRODUCTS = ['nginx', 'kubernetes', 'openssh', 'postgres', 'redis'];
const relevant = vulns.filter(v =>
  MY_PRODUCTS.some(p =>
    (v.title || '').toLowerCase().includes(p) ||
    (v.affected || []).some(a => a.toLowerCase().includes(p))
  )
);</pre>

      <div class="wf-label">Deduplicate with n8n Variables (avoid repeat alerts)</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button">// At the start of your Code node
const seen = new Set(JSON.parse($vars.SEEN_CVE_IDS || '[]'));
const fresh = vulns.filter(v => !seen.has(v.id));

// After processing, update the seen set (add a Set Variable node after)
// Set SEEN_CVE_IDS = JSON.stringify([...seen, ...fresh.map(v => v.id)].slice(-500))</pre>

      <div class="wf-label">EPSS-based filtering (exploitation probability)</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button">// EPSS percentile: 90 = top 10% most likely to be exploited
// Good thresholds: 70 for "watch", 90 for "act now"
const highRisk = vulns.filter(v =>
  (v.epss_pct || 0) >= 90 &&
  (v.score     || 0) >= 7.0
).sort((a, b) => (b.epss_pct || 0) - (a.epss_pct || 0));</pre>

      <div class="wf-label">Post to Microsoft Teams instead of Slack</div>
      <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button">// Teams uses Adaptive Cards via webhook — replace the Slack HTTP Request node with:
// Method: POST, URL: $vars.TEAMS_WEBHOOK
// Body (JSON):
{{
  "type": "message",
  "attachments": [{{
    "contentType": "application/vnd.microsoft.card.adaptive",
    "content": {{
      "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
      "type": "AdaptiveCard", "version": "1.4",
      "body": [
        {{"type":"TextBlock","text":"🚨 vulnfeed KEV Alert","weight":"Bolder","size":"Medium"}},
        {{"type":"TextBlock","text":"={{ $json.text }}","wrap":true}}
      ],
      "actions": [{{"type":"Action.OpenUrl","title":"View patch list","url":"https://vulnfeed.it/patch-now.html"}}]
    }}
  }}]
}}</pre>
    </div>
  </div>

  <p style="margin-top:2.5rem;font-size:.75rem;color:#64748b">
    vulnfeed JSON API: <a href="{_API}" style="color:#2563eb">{_API}</a> — open, no auth, updated every 4h.<br>
    More integrations: <a href="/grafana.html" style="color:#2563eb">Grafana &amp; Prometheus</a> · <a href="/agents.html" style="color:#2563eb">AI agents</a> · <a href="/api.html" style="color:#2563eb">API docs</a>
  </p>
</div>
<script>
function copyCode(btn) {{
  const pre = btn.parentElement;
  const text = pre.childNodes[pre.childNodes.length - 1].textContent;
  navigator.clipboard.writeText(text).then(() => {{
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {{ btn.textContent = 'Copy'; btn.classList.remove('copied'); }}, 1800);
  }});
}}
</script>
</body>
</html>"""

    with open("n8n.html", "w", encoding="utf-8") as f:
        f.write(html)
    log("  Written: n8n.html")


_PRODUCT_FEED_CFGS = {
    "kubernetes":   {"label": "Kubernetes",        "sources": {"kubernetes"},               "keywords": ["kubernetes","k8s","etcd","kubelet","kube"]},
    "ubuntu":       {"label": "Ubuntu",            "sources": {"ubuntu"},                   "keywords": []},
    "debian":       {"label": "Debian",            "sources": {"debian"},                   "keywords": []},
    "openstack":    {"label": "OpenStack",         "sources": {"openstack","oss-security"}, "keywords": ["openstack","nova","neutron","keystone","cinder","glance"]},
    "linux-kernel": {"label": "Linux Kernel",      "sources": {"ubuntu","debian"},          "keywords": ["linux kernel","kernel","kvm","bpf","ebpf","netfilter"]},
    "windows":      {"label": "Windows",           "sources": {"microsoft"},                "keywords": ["windows"],          "title_only": True},
    "nginx":        {"label": "nginx / Traefik",   "sources": set(),                        "keywords": ["nginx","traefik"],   "title_only": True},
    "cisco":        {"label": "Cisco",             "sources": {"cisco"},                    "keywords": []},
    "fortinet":     {"label": "Fortinet",          "sources": {"fortinet"},                 "keywords": []},
    "vmware":       {"label": "VMware / Broadcom", "sources": {"vmware"},                   "keywords": ["vmware","vsphere","vcenter","esxi"]},
    "android":      {"label": "Android",           "sources": {"android"},                  "keywords": []},
    "macos":        {"label": "macOS / Apple",     "sources": {"apple"},                    "keywords": []},
}

_NTFY_TOPICS = [
    ("vulnfeed-critical",     "🚨", "All KEV (CISA) + CVSS ≥ 9.0",        "all sources"),
    ("vulnfeed-kubernetes",   "⚙️", "Kubernetes CVEs (CVSS ≥ 7 or KEV)",   "kubernetes advisory feed"),
    ("vulnfeed-ubuntu",       "🐧", "Ubuntu security advisories",           "ubuntu"),
    ("vulnfeed-debian",       "🐧", "Debian security advisories",           "debian"),
    ("vulnfeed-openstack",    "☁️", "OpenStack vulnerabilities",            "openstack, oss-security"),
    ("vulnfeed-linux-kernel", "🐧", "Linux kernel CVEs",                    "ubuntu + debian advisories"),
    ("vulnfeed-windows",      "🪟", "Windows vulnerabilities",              "microsoft MSRC"),
    ("vulnfeed-nginx",        "🌐", "nginx / Traefik CVEs",                 "all sources (title match)"),
    ("vulnfeed-cisco",        "🔧", "Cisco security advisories",            "cisco"),
    ("vulnfeed-fortinet",     "🛡", "Fortinet vulnerabilities",             "fortinet"),
    ("vulnfeed-vmware",       "💾", "VMware / Broadcom CVEs",               "vmware"),
    ("vulnfeed-android",      "📱", "Android security bulletins",           "android"),
    ("vulnfeed-macos",        "🍎", "Apple / macOS vulnerabilities",        "apple"),
]


def _rss_product_matches(v, cfg):
    sources    = cfg.get("sources") or set()
    keywords   = cfg.get("keywords") or []
    title_only = cfg.get("title_only", False)
    src_ok     = (not sources) or (v.get("source", "").lower() in sources)
    if not keywords:
        return src_ok
    hay = (
        (v.get("title") or "") if title_only
        else " ".join([v.get("id",""), v.get("title",""), v.get("description",""), *v.get("affected",[])])
    )
    kw_ok = any(kw in hay.lower() for kw in keywords)
    return src_ok and kw_ok


def write_product_rss_feeds(vulns, date_str, base_url=BASE_URL):
    os.makedirs("feed", exist_ok=True)

    def xe(s):
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    now_rfc = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")

    for slug, cfg in _PRODUCT_FEED_CFGS.items():
        label   = cfg["label"]
        matched = sorted(
            [v for v in vulns if v.get("published") and _rss_product_matches(v, cfg)],
            key=lambda v: v.get("published",""),
            reverse=True,
        )[:100]

        items = []
        for v in matched:
            title = xe(f'[{v.get("severity","?")}] {v["id"]}: {v.get("title","")}')[:200]
            link  = xe(v.get("url",""))
            desc  = xe((v.get("description") or "")[:500])
            pub   = _rfc822(v.get("published",""))
            guid  = xe(v.get("url") or v["id"])
            items.append(
                "  <item>\n"
                f"    <title>{title}</title>\n"
                f"    <link>{link}</link>\n"
                f"    <description>{desc}</description>\n"
                f"    <pubDate>{pub}</pubDate>\n"
                f'    <guid isPermaLink="false">{guid}</guid>\n'
                "  </item>"
            )

        feed_url = f"{base_url}/feed/{slug}.xml"
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
            "  <channel>\n"
            f"    <title>vulnfeed — {xe(label)}</title>\n"
            f"    <link>{base_url}</link>\n"
            f"    <description>{xe(label)} security vulnerabilities — vulnfeed.it</description>\n"
            "    <language>en-us</language>\n"
            f"    <lastBuildDate>{now_rfc}</lastBuildDate>\n"
            f'    <atom:link href="{feed_url}" rel="self" type="application/rss+xml"/>\n'
            + "\n".join(items)
            + "\n  </channel>\n</rss>"
        )
        path = os.path.join("feed", f"{slug}.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(xml)

    log(f"  Written: feed/{{}}.xml × {len(_PRODUCT_FEED_CFGS)} product feeds")


def write_subscribe_page(base_url=BASE_URL):
    extra_css = """
.sub-wrap{max-width:860px;margin:0 auto;padding:2rem 1.5rem 4rem}
.sub-hero{margin-bottom:2rem}
.sub-hero h1{font-size:1.5rem;font-weight:800;color:#0f172a;margin-bottom:.35rem}
.sub-hero p{font-size:.9rem;color:#475569;max-width:560px}
.sub-section{margin-bottom:2.5rem;background:#fff;border:1px solid #e2e8f0;border-radius:10px;overflow:hidden}
.sub-section-head{background:#0f172a;padding:.85rem 1.2rem;display:flex;align-items:center;gap:.6rem}
.sub-section-head h2{font-size:.95rem;font-weight:700;color:#f1f5f9;margin:0}
.sub-section-body{padding:1.2rem 1.4rem}
.sub-section-desc{font-size:.83rem;color:#475569;margin-bottom:1.1rem}
.sub-form-row{display:flex;gap:.6rem;margin-bottom:.9rem;flex-wrap:wrap}
#sub-email-input{flex:1;min-width:220px;padding:.55rem .9rem;border:2px solid #e2e8f0;
  border-radius:7px;font-size:.9rem;outline:none;transition:border-color .15s}
#sub-email-input:focus{border-color:#2563eb}
.sub-btn{padding:.55rem 1.4rem;background:#2563eb;color:#fff;border:none;border-radius:7px;
  font-size:.88rem;font-weight:700;cursor:pointer;white-space:nowrap}
.sub-btn:hover{background:#1d4ed8}
.topic-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:.4rem;margin-bottom:.8rem}
.topic-label{display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:#374151;cursor:pointer;
  padding:.3rem .5rem;border:1px solid #e2e8f0;border-radius:6px;transition:all .12s}
.topic-label:hover{border-color:#2563eb;color:#2563eb}
.topic-label input{accent-color:#2563eb;cursor:pointer}
.sub-thanks{display:none;font-size:.88rem;color:#16a34a;padding:.5rem;background:#f0fdf4;
  border-radius:6px;border:1px solid #bbf7d0}
.ntfy-table{width:100%;border-collapse:collapse;font-size:.82rem}
.ntfy-table th{text-align:left;padding:.45rem .7rem;border-bottom:2px solid #e2e8f0;
  font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em;background:#f8fafc}
.ntfy-table td{padding:.5rem .7rem;border-bottom:1px solid #f1f5f9;vertical-align:middle}
.ntfy-table tr:last-child td{border-bottom:none}
.topic-name{font-family:monospace;font-weight:700;color:#0f172a;font-size:.8rem}
.ntfy-btn{display:inline-flex;align-items:center;gap:.25rem;padding:.22rem .65rem;
  border-radius:5px;font-size:.73rem;font-weight:600;text-decoration:none;border:1px solid #e2e8f0;
  color:#374151;background:#f8fafc;cursor:pointer;white-space:nowrap}
.ntfy-btn:hover{border-color:#2563eb;color:#2563eb}
.ntfy-btn-copy{background:none;border:1px solid #e2e8f0;cursor:pointer}
.ntfy-btn-copy.copied{color:#16a34a;border-color:#bbf7d0}
.rss-table{width:100%;border-collapse:collapse;font-size:.82rem}
.rss-table th{text-align:left;padding:.45rem .7rem;border-bottom:2px solid #e2e8f0;
  font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em;background:#f8fafc}
.rss-table td{padding:.5rem .7rem;border-bottom:1px solid #f1f5f9;vertical-align:middle}
.rss-table tr:last-child td{border-bottom:none}
.feed-url{font-family:monospace;font-size:.77rem;color:#2563eb;text-decoration:none}
.feed-url:hover{text-decoration:underline}
.code-block{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:.9rem 1.1rem;
  font-family:monospace;font-size:.78rem;line-height:1.6;overflow-x:auto;margin:.7rem 0 0;
  white-space:pre;position:relative}
.code-cp{position:absolute;top:.5rem;right:.6rem;background:#1e293b;border:1px solid #334155;
  color:#94a3b8;border-radius:4px;padding:.15rem .5rem;font-size:.68rem;cursor:pointer}
.code-cp:hover{color:#f1f5f9}
.ntfy-install{display:flex;gap:.6rem;flex-wrap:wrap;margin:.5rem 0 1rem}
.install-link{display:inline-flex;align-items:center;gap:.3rem;padding:.32rem .75rem;
  border:1px solid #e2e8f0;border-radius:6px;font-size:.78rem;color:#374151;text-decoration:none;font-weight:600}
.install-link:hover{border-color:#2563eb;color:#2563eb}
"""

    # build ntfy topic rows
    ntfy_rows = ""
    for topic, icon, desc, source in _NTFY_TOPICS:
        web_url = f"https://ntfy.sh/{topic}"
        ntfy_rows += (
            f'<tr>'
            f'<td><span class="topic-name">{topic}</span></td>'
            f'<td>{icon} {_xe(desc)}</td>'
            f'<td><small style="color:#64748b">{_xe(source)}</small></td>'
            f'<td style="white-space:nowrap">'
            f'<a class="ntfy-btn" href="{web_url}" target="_blank" rel="noopener">Web ↗</a> '
            f'<button class="ntfy-btn ntfy-btn-copy" onclick="cpTopic(this,\'{topic}\')" title="Copy ntfy topic URL">Copy</button>'
            f'</td>'
            f'</tr>'
        )

    # build RSS feed rows
    rss_rows = (
        '<tr>'
        '<td><strong>All CVEs</strong></td>'
        f'<td><a class="feed-url" href="{base_url}/feed.xml">/feed.xml</a></td>'
        '<td><button class="ntfy-btn ntfy-btn-copy" onclick="cpFeed(this,\'/feed.xml\')">Copy</button></td>'
        '</tr>'
    )
    for slug, cfg in _PRODUCT_FEED_CFGS.items():
        feed_path = f"/feed/{slug}.xml"
        rss_rows += (
            f'<tr>'
            f'<td><strong>{_xe(cfg["label"])}</strong></td>'
            f'<td><a class="feed-url" href="{base_url}{feed_path}">{feed_path}</a></td>'
            f'<td><button class="ntfy-btn ntfy-btn-copy" onclick="cpFeed(this,\'{feed_path}\')" >Copy</button></td>'
            f'</tr>'
        )

    # build email topic checkboxes
    topic_checks = ""
    email_topics = [
        ("kubernetes",   "Kubernetes"),
        ("ubuntu",       "Ubuntu"),
        ("debian",       "Debian"),
        ("openstack",    "OpenStack"),
        ("linux-kernel", "Linux Kernel"),
        ("windows",      "Windows"),
        ("cisco",        "Cisco"),
        ("fortinet",     "Fortinet"),
        ("vmware",       "VMware"),
        ("android",      "Android"),
        ("macos",        "macOS"),
        ("nginx",        "nginx"),
    ]
    for slug, label in email_topics:
        topic_checks += (
            f'<label class="topic-label">'
            f'<input type="checkbox" class="topic-check" value="{slug}"> {_xe(label)}'
            f'</label>'
        )

    html = _page_head(
        "Subscribe — vulnfeed",
        "Get real-time CVE notifications via email digest, ntfy.sh push, or RSS. "
        "No account required for push and RSS.",
        f"{base_url}/subscribe.html",
        "",
        extra_css=extra_css,
    ) + _page_header(extra_links='<a class="hlink" href="/feed.xml">&#9656;&nbsp;RSS</a>') + f"""
<div class="sub-wrap">
  <div class="sub-hero">
    <h1>&#128276; Subscribe to vulnfeed</h1>
    <p>Choose how you want to be notified when critical CVEs drop — email digests, push notifications, or RSS. Updated every 4 hours.</p>
  </div>

  <!-- ── EMAIL ─────────────────────────────────────────── -->
  <div class="sub-section">
    <div class="sub-section-head">
      <span style="font-size:1.15rem">&#128231;</span>
      <h2>Email digest (via Buttondown)</h2>
    </div>
    <div class="sub-section-body">
      <p class="sub-section-desc">
        Weekly digest every Monday with top CVEs, CISA KEV alerts, and per-product sections.
        Tick any products below to receive a <strong>filtered digest</strong> for that technology in addition to the general one.
      </p>

      <div class="sub-form-row">
        <input type="email" id="sub-email-input" placeholder="your@email.com" autocomplete="email">
        <button class="sub-btn" onclick="doSubscribe()">Subscribe</button>
      </div>

      <div style="font-size:.75rem;color:#64748b;margin-bottom:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em">
        Optional — product-specific digests:
      </div>
      <div class="topic-grid">
        {topic_checks}
      </div>
      <div style="font-size:.74rem;color:#64748b;margin-top:.4rem">
        No spam. Unsubscribe any time.
      </div>
      <div class="sub-thanks" id="sub-thanks">&#10003; Subscribed! See you Monday.</div>
    </div>
  </div>

  <!-- ── NTFY PUSH ──────────────────────────────────────── -->
  <div class="sub-section">
    <div class="sub-section-head">
      <span style="font-size:1.15rem">&#128276;</span>
      <h2>Push notifications (ntfy.sh)</h2>
    </div>
    <div class="sub-section-body">
      <p class="sub-section-desc">
        <a href="https://ntfy.sh" target="_blank" rel="noopener" style="color:#2563eb;font-weight:600">ntfy.sh</a>
        is a free open-source push notification service. No account required.
        Subscribe to a topic and get push alerts the moment a matching CVE is published.
      </p>

      <div style="font-size:.78rem;font-weight:600;color:#374151;margin-bottom:.4rem">Install the ntfy app:</div>
      <div class="ntfy-install">
        <a class="install-link" href="https://apps.apple.com/us/app/ntfy/id1625396347" target="_blank" rel="noopener">&#127822; iOS App</a>
        <a class="install-link" href="https://play.google.com/store/apps/details?id=io.heckel.ntfy" target="_blank" rel="noopener">&#129474; Android</a>
        <a class="install-link" href="https://ntfy.sh/app" target="_blank" rel="noopener">&#127760; Web</a>
        <a class="install-link" href="https://docs.ntfy.sh/subscribe/phone/" target="_blank" rel="noopener">&#128196; CLI &amp; Desktop</a>
      </div>

      <table class="ntfy-table">
        <tr>
          <th>Topic</th>
          <th>Covers</th>
          <th>Source</th>
          <th>Subscribe</th>
        </tr>
        {ntfy_rows}
      </table>

      <div style="margin-top:1.1rem;font-size:.78rem;font-weight:600;color:#374151">Test in terminal:</div>
      <div class="code-block">curl -s https://ntfy.sh/vulnfeed-critical/json<button class="code-cp" onclick="cp(this,'curl -s https://ntfy.sh/vulnfeed-critical/json')">Copy</button></div>

      <div style="margin-top:.9rem;font-size:.78rem;font-weight:600;color:#374151">Subscribe via CLI:</div>
      <div class="code-block">ntfy subscribe vulnfeed-critical<button class="code-cp" onclick="cp(this,'ntfy subscribe vulnfeed-critical')">Copy</button></div>
    </div>
  </div>

  <!-- ── RSS ───────────────────────────────────────────── -->
  <div class="sub-section">
    <div class="sub-section-head">
      <span style="font-size:1.15rem">&#9656;</span>
      <h2>RSS feeds</h2>
    </div>
    <div class="sub-section-body">
      <p class="sub-section-desc">
        Subscribe in any RSS reader — Feedly, NetNewsWire, Miniflux, Thunderbird, etc.
        Per-product feeds update every 4 hours with the latest vulnerabilities for that technology.
      </p>
      <table class="rss-table">
        <tr>
          <th>Feed</th>
          <th>URL</th>
          <th></th>
        </tr>
        {rss_rows}
      </table>
      <div style="margin-top:.9rem;font-size:.78rem;font-weight:600;color:#374151">Add to Feedly:</div>
      <div class="code-block">https://feedly.com/i/subscription/feed%2F{base_url}%2Ffeed%2Fkubernetes.xml<button class="code-cp" onclick="cp(this,'https://feedly.com/i/subscription/feed%2F{base_url}%2Ffeed%2Fkubernetes.xml')">Copy</button></div>
    </div>
  </div>
</div>

<script>
function doSubscribe() {{
  const email = document.getElementById('sub-email-input').value.trim();
  if (!email || !email.includes('@')) {{
    document.getElementById('sub-email-input').focus();
    return;
  }}
  const checks = document.querySelectorAll('.topic-check:checked');
  const tags   = Array.from(checks).map(c => c.value).join(',');
  const body   = new FormData();
  body.append('email', email);
  if (tags) body.append('tag', tags);
  fetch('https://buttondown.com/api/emails/embed-subscribe/vulnfeed', {{method:'POST',body}})
    .then(r => {{
      if (r.ok || r.status === 200 || r.status === 201) {{
        document.getElementById('sub-thanks').style.display = 'block';
        document.querySelector('.sub-form-row').style.display = 'none';
        document.querySelector('.topic-grid').style.display = 'none';
        try {{ localStorage.setItem('vf_subscribed','1'); }} catch(_) {{}}
      }} else {{
        window.open('https://buttondown.com/vulnfeed','_blank');
      }}
    }})
    .catch(() => window.open('https://buttondown.com/vulnfeed','_blank'));
}}
document.getElementById('sub-email-input').addEventListener('keydown', e => {{
  if (e.key === 'Enter') doSubscribe();
}});
function cpTopic(btn, topic) {{
  const url = 'https://ntfy.sh/' + topic;
  navigator.clipboard.writeText(url).then(() => {{
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {{ btn.textContent = 'Copy'; btn.classList.remove('copied'); }}, 1800);
  }});
}}
function cpFeed(btn, path) {{
  navigator.clipboard.writeText('{base_url}' + path).then(() => {{
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {{ btn.textContent = 'Copy'; btn.classList.remove('copied'); }}, 1800);
  }});
}}
function cp(btn, text) {{
  navigator.clipboard.writeText(text).then(() => {{
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => {{ btn.textContent = orig; }}, 1500);
  }});
}}
</script>
</html>
"""
    with open("subscribe.html", "w", encoding="utf-8") as f:
        f.write(html)
    log("  Written: subscribe.html")


def write_monthly_archive_pages(hist_dates, date_str, base_url=BASE_URL):
    """Generate /archive/YYYY-MM.html per month + /archive/index.html."""
    os.makedirs("archive", exist_ok=True)
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    # Group available dates by month
    month_to_dates = {}
    for d in sorted({date_str} | set(hist_dates)):
        try:
            ym = d[:7]  # YYYY-MM
            month_to_dates.setdefault(ym, []).append(d)
        except Exception:
            continue

    written = []
    for ym, dates in sorted(month_to_dates.items(), reverse=True):
        vulns_month = []
        for d in dates:
            if d == date_str:
                continue
            p = os.path.join(HISTORICAL_DIR, f"{d}.json")
            if not os.path.exists(p):
                continue
            try:
                with open(p, encoding="utf-8") as f:
                    vulns_month.extend(json.load(f))
            except Exception:
                pass
        if not vulns_month:
            continue

        seen, unique = set(), []
        sev_counts = {}
        exploited = 0
        for v in vulns_month:
            if v["id"] not in seen:
                seen.add(v["id"])
                unique.append(v)
            s = v.get("severity", "UNKNOWN")
            sev_counts[s] = sev_counts.get(s, 0) + 1
            if v.get("badge") == "ACTIVELY EXPLOITED":
                exploited += 1

        top = sorted(unique, key=lambda v: (
            SEV_ORDER.get(v.get("severity", "UNKNOWN"), 4), -(v.get("score") or 0)))[:80]

        rows = []
        for v in top:
            sev = v.get("severity", "UNKNOWN")
            sc_str = f'{v["score"]:.1f}' if v.get("score") is not None else "—"
            pub = _pub_ymd(v.get("published") or "")
            ttl = _xe((v.get("title") or v["id"])[:120])
            vid = _xe(v["id"])
            href = f'/cve/{v["id"]}.html' if v["id"].startswith("CVE-") else _xe(v.get("url",""))
            rows.append(
                f'<tr><td><a class="cve-id" href="{href}">{vid}</a></td>'
                f'<td class="ttl">{ttl}</td>'
                f'<td><span class="sev s{sev}">{sev}</span></td>'
                f'<td>{sc_str}</td>'
                f'<td><span class="src-tag">{_xe(v.get("source","?"))}</span></td>'
                f'<td>{pub}</td></tr>'
            )

        month_label = datetime.strptime(ym, "%Y-%m").strftime("%B %Y")
        table = (
            '<table><tr><th>CVE / ID</th><th>Title</th><th>Severity</th>'
            '<th>CVSS</th><th>Source</th><th>Date</th></tr>'
            + "".join(rows) + '</table>'
        ) if rows else '<p style="color:#64748b">No data.</p>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<title>Security Vulnerabilities {month_label} | vulnfeed</title>
<meta name="description" content="{len(unique)} vulnerabilities tracked in {month_label}: {sev_counts.get('CRITICAL',0)} critical, {sev_counts.get('HIGH',0)} high severity. Monthly CVE digest by vulnfeed.">
<link rel="canonical" href="{base_url}/archive/{ym}.html">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9;--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#16a34a;--unk:#6b7280}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}}
header{{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem}}
.logo{{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}}.logo em{{color:#60a5fa;font-style:normal}}
.hlink{{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}}
.hlink:hover{{border-color:#60a5fa}}
.wrap{{max-width:1100px;margin:0 auto;padding:2rem}}
h1{{font-size:1.4rem;font-weight:800;margin-bottom:.25rem}}
h2{{font-size:.72rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:2rem 0 .75rem}}
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:1rem;margin-bottom:2rem}}
.stat-box{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem 1.2rem}}
.stat-val{{font-size:1.8rem;font-weight:800;letter-spacing:-.04em}}
.stat-lbl{{font-size:.72rem;color:var(--muted);margin-top:.1rem}}
.crit-val{{color:var(--crit)}}.high-val{{color:var(--high)}}.expl-val{{color:#7c3aed}}
table{{width:100%;border-collapse:collapse;font-size:.8rem;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
th{{text-align:left;font-size:.68rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:.55rem .75rem;border-bottom:2px solid var(--border);background:#f8fafc}}
td{{padding:.5rem .75rem;border-bottom:1px solid var(--border);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#f8fafc}}
.cve-id{{font-family:ui-monospace,monospace;font-size:.77rem;font-weight:700;color:var(--accent);text-decoration:none;white-space:nowrap}}
.cve-id:hover{{text-decoration:underline}}
.sev{{display:inline-block;padding:.08rem .35rem;border-radius:3px;font-size:.65rem;font-weight:700;color:#fff;text-transform:uppercase}}
.sCRITICAL{{background:var(--crit)}}.sHIGH{{background:var(--high)}}.sMEDIUM{{background:var(--med)}}.sLOW{{background:var(--low)}}.sUNKNOWN{{background:var(--unk)}}
.src-tag{{display:inline-block;background:#334155;color:#fff;padding:.06rem .35rem;border-radius:3px;font-size:.63rem;font-weight:600}}
.ttl{{font-size:.78rem}}
@media(max-width:640px){{.wrap{{padding:1rem}}th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6){{display:none}}}}
</style>
</head>
<body>
<header>
  <div><div class="logo">vuln<em>feed</em></div></div>
  <div style="display:flex;gap:.5rem;align-items:center">
    <a class="hlink" href="/">Live feed</a>
    <a class="hlink" href="/archive/">All months</a>
  </div>
</header>
<div class="wrap">
  <h1>Security Vulnerabilities &mdash; {month_label}</h1>
  <div class="stat-grid">
    <div class="stat-box"><div class="stat-val">{len(unique)}</div><div class="stat-lbl">Total vulnerabilities</div></div>
    <div class="stat-box"><div class="stat-val crit-val">{sev_counts.get('CRITICAL',0)}</div><div class="stat-lbl">Critical</div></div>
    <div class="stat-box"><div class="stat-val high-val">{sev_counts.get('HIGH',0)}</div><div class="stat-lbl">High</div></div>
    <div class="stat-box"><div class="stat-val expl-val">{exploited}</div><div class="stat-lbl">Actively exploited</div></div>
  </div>
  <h2>Top vulnerabilities</h2>
  {table}
</div>
</body>
</html>"""
        with open(os.path.join("archive", f"{ym}.html"), "w", encoding="utf-8") as f:
            f.write(html)
        written.append(ym)

    # Index page
    links = "".join(
        f'<li><a href="/archive/{ym}.html">'
        f'<span>{datetime.strptime(ym,"%Y-%m").strftime("%B %Y")}</span>'
        f'<span style="font-size:.72rem;color:#64748b;font-weight:400">monthly digest</span>'
        f'</a></li>'
        for ym in written
    )
    idx = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<title>Monthly Security Vulnerability Archive | vulnfeed</title>
<meta name="description" content="Monthly archive of CVE digests from vulnfeed — all vulnerabilities by month.">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}}
header{{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between}}
.logo{{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}}.logo em{{color:#60a5fa;font-style:normal}}
.hlink{{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}}
.wrap{{max-width:700px;margin:0 auto;padding:2rem}}
h1{{font-size:1.35rem;font-weight:800;margin-bottom:.5rem}}
.sub{{font-size:.8rem;color:#64748b;margin-bottom:2rem}}
ul{{list-style:none;display:grid;gap:.5rem}}
li a{{display:flex;align-items:center;justify-content:space-between;padding:.65rem 1rem;background:var(--card);border:1px solid var(--border);border-radius:8px;text-decoration:none;color:var(--text);font-weight:600;font-size:.85rem;transition:border-color .15s}}
li a:hover{{border-color:var(--accent)}}
</style>
</head>
<body>
<header>
  <div class="logo">vuln<em>feed</em></div>
  <a class="hlink" href="/">&#8592; Live feed</a>
</header>
<div class="wrap">
  <h1>Monthly Archive</h1>
  <p class="sub">Security vulnerability digests by month, aggregated from NVD, CISA KEV, Ubuntu, Debian, Red Hat, Kubernetes and more.</p>
  <ul>{links}</ul>
</div>
</body>
</html>"""
    with open(os.path.join("archive", "index.html"), "w", encoding="utf-8") as f:
        f.write(idx)
    log(f"  Written: {len(written)} monthly archive pages → archive/")
    return written


def write_badges(vulns, date_str):
    os.makedirs("badge", exist_ok=True)
    crit = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    new_today = sum(1 for v in vulns if v.get("_new"))
    with open("badge/critical-count.svg", "w") as f:
        f.write(_badge_svg("critical CVEs", crit, "#dc2626"))
    with open("badge/new-today.svg", "w") as f:
        f.write(_badge_svg("new today", new_today, "#2563eb"))
    log(f"  Written: badge/critical-count.svg ({crit} critical), badge/new-today.svg ({new_today} new)")


# ---------------------------------------------------------------------------
# API docs page
# ---------------------------------------------------------------------------

def write_api_docs_page(base_url=BASE_URL):
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0f172a">
<title>API Documentation | vulnfeed</title>
<meta name="description" content="vulnfeed public API — access 10,000+ CVEs as JSON. Free, no auth, updated every 4 hours.">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;--accent:#2563eb;--hdr:#0f172a;--htxt:#f1f5f9}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}}
a{{color:var(--accent)}}
header{{background:var(--hdr);color:var(--htxt);padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between}}
.logo{{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}}.logo em{{color:#60a5fa;font-style:normal}}
.hlink{{font-size:.71rem;color:#60a5fa;text-decoration:none;padding:.18rem .5rem;border:1px solid #334155;border-radius:4px;font-weight:600}}
.wrap{{max-width:860px;margin:0 auto;padding:2rem 1.5rem 4rem}}
h1{{font-size:1.5rem;font-weight:800;margin-bottom:.4rem}}
h2{{font-size:1rem;font-weight:700;margin:2rem 0 .5rem;color:var(--text)}}
h3{{font-size:.85rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin:1.5rem 0 .4rem}}
p{{margin-bottom:.75rem;font-size:.93rem;color:var(--text)}}
.sub{{color:var(--muted);font-size:.9rem;margin-bottom:2rem}}
pre{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;overflow-x:auto;font-size:.82rem;font-family:ui-monospace,monospace;margin-bottom:1rem}}
code{{font-family:ui-monospace,monospace;font-size:.85em;background:var(--card);border:1px solid var(--border);padding:.1rem .35rem;border-radius:3px}}
table{{width:100%;border-collapse:collapse;font-size:.83rem;margin-bottom:1.5rem;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}}
th{{text-align:left;padding:.5rem .75rem;background:var(--bg);font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;border-bottom:2px solid var(--border)}}
td{{padding:.45rem .75rem;border-bottom:1px solid var(--border);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
.badge{{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.7rem;font-weight:700;color:#fff;background:#16a34a}}
</style>
</head>
<body>
<header>
  <div class="logo">vuln<em>feed</em></div>
  <a class="hlink" href="/">&#8592; Live feed</a>
</header>
<div class="wrap">
  <h1>Public API</h1>
  <p class="sub">Free, unauthenticated JSON API. No rate limits. Updated every 4 hours by GitHub Actions.</p>

  <h2>Endpoints</h2>

  <h3>All vulnerabilities</h3>
  <pre>GET {base_url}/vulns.json</pre>
  <p>Returns an array of all vulnerability objects tracked in the last 30 days (~10,000+ entries). No authentication required.</p>

  <h3>Individual CVE page</h3>
  <pre>GET {base_url}/cve/{{CVE-ID}}.html</pre>
  <p>Human-readable page for a specific CVE with explainer text, severity, CVSS, EPSS, affected products, fix command, and references.</p>

  <h3>RSS feed</h3>
  <pre>GET {base_url}/feed.xml</pre>
  <p>RSS 2.0 feed of the latest vulnerabilities. Subscribe in any feed reader.</p>

  <h3>Vendor RSS feeds</h3>
  <pre>GET {base_url}/vendor/{{vendor}}.xml</pre>
  <p>Per-vendor RSS feeds. Available vendors: kubernetes, nginx, openssl, cisco, fortinet, vmware, ubuntu, debian, and more — see the <a href="/vendor/">vendor index</a>.</p>

  <h3>Embeddable badges</h3>
  <pre>GET {base_url}/badge/critical-count.svg
GET {base_url}/badge/new-today.svg</pre>
  <p>SVG badges for embedding in READMEs or dashboards. Updated every 4 hours.</p>
  <p><img src="/badge/critical-count.svg" alt="critical CVE count" style="vertical-align:middle"> &nbsp; <img src="/badge/new-today.svg" alt="new today" style="vertical-align:middle"></p>

  <h2>Data schema</h2>
  <p>Each object in <code>vulns.json</code> has the following fields:</p>
  <table>
    <tr><th>Field</th><th>Type</th><th>Description</th></tr>
    <tr><td><code>id</code></td><td>string</td><td>CVE ID (e.g. <code>CVE-2024-1234</code>) or advisory ID (USN-xxx, DSA-xxx)</td></tr>
    <tr><td><code>title</code></td><td>string</td><td>Short human-readable title</td></tr>
    <tr><td><code>description</code></td><td>string</td><td>Full vulnerability description</td></tr>
    <tr><td><code>severity</code></td><td>string</td><td>CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN</td></tr>
    <tr><td><code>score</code></td><td>number|null</td><td>CVSS v3 base score (0.0&ndash;10.0)</td></tr>
    <tr><td><code>epss</code></td><td>number|null</td><td>EPSS exploitation probability (0&ndash;1)</td></tr>
    <tr><td><code>epss_pct</code></td><td>number|null</td><td>EPSS percentile (0&ndash;100)</td></tr>
    <tr><td><code>source</code></td><td>string</td><td>Data source: NVD, Ubuntu, Debian, Microsoft, Cisco, Fortinet, etc.</td></tr>
    <tr><td><code>published</code></td><td>string</td><td>ISO 8601 publish date</td></tr>
    <tr><td><code>url</code></td><td>string</td><td>Canonical advisory URL</td></tr>
    <tr><td><code>badge</code></td><td>string</td><td>"ACTIVELY EXPLOITED" if in CISA KEV catalog, else empty</td></tr>
    <tr><td><code>poc</code></td><td>bool</td><td>true if a public PoC exploit exists on GitHub</td></tr>
    <tr><td><code>patch</code></td><td>bool|null</td><td>true = patch available, false = no fix, null = unknown</td></tr>
    <tr><td><code>fix</code></td><td>string</td><td>Shell command to apply the fix (e.g. <code>apt-get install --only-upgrade nginx</code>)</td></tr>
    <tr><td><code>affected</code></td><td>array</td><td>List of affected package/product strings</td></tr>
    <tr><td><code>references</code></td><td>array</td><td>List of reference URLs</td></tr>
    <tr><td><code>_new</code></td><td>bool</td><td>true if this entry is new since yesterday&apos;s snapshot</td></tr>
    <tr><td><code>_trending</code></td><td>bool</td><td>true if EPSS score jumped &ge;5pp since yesterday</td></tr>
  </table>

  <h2>Usage examples</h2>

  <h3>curl + jq</h3>
  <pre># All critical CVEs
curl -s {base_url}/vulns.json | jq '[.[] | select(.severity=="CRITICAL")]'

# CVEs with public exploits
curl -s {base_url}/vulns.json | jq '[.[] | select(.poc==true)] | sort_by(-.score)'

# Top 10 by EPSS score
curl -s {base_url}/vulns.json | jq '[.[] | select(.epss!=null)] | sort_by(-.epss) | .[:10]'

# New CVEs since yesterday
curl -s {base_url}/vulns.json | jq '[.[] | select(._new==true)]'

# Actively exploited
curl -s {base_url}/vulns.json | jq '[.[] | select(.badge=="ACTIVELY EXPLOITED")]'</pre>

  <h3>Python</h3>
  <pre>import urllib.request, json

with urllib.request.urlopen("{base_url}/vulns.json") as r:
    vulns = json.load(r)

critical = [v for v in vulns if v.get("severity") == "CRITICAL"]
exploited = [v for v in vulns if v.get("badge") == "ACTIVELY EXPLOITED"]
print(f"{{len(critical)}} critical, {{len(exploited)}} actively exploited")</pre>

  <h2>Embed a badge</h2>
  <p>Copy into any GitHub README or Markdown document:</p>
  <pre>[![critical CVEs]({base_url}/badge/critical-count.svg)]({base_url})
[![new today]({base_url}/badge/new-today.svg)]({base_url})</pre>

  <p style="margin-top:2rem;font-size:.8rem;color:var(--muted)">Data sourced from NVD, CISA KEV, Ubuntu Security Notices, Debian Security Announcements, Red Hat, Microsoft MSRC, Cisco, Fortinet, Juniper, Kubernetes, Exploit-DB, OSS-Security, GitHub Advisory Database, and OSV. Updated every 4 hours.</p>
</div>
</body>
</html>"""
    with open("api.html", "w", encoding="utf-8") as f:
        f.write(html)
    log("  Written: api.html")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log("=== TLDR Security Daily ===")
    date_str = datetime.now().strftime("%Y-%m-%d")
    log(f"Date: {date_str}")

    # --- Fresh fetch ---
    fresh = []
    nvd_results = fetch_nvd()
    if not nvd_results:
        # NVD was unreachable — pull recent NVD entries from yesterday's snapshot
        # so the 24h view doesn't go empty during outages.
        log("  NVD returned 0 — falling back to yesterday's NVD entries...")
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        yday_path = os.path.join(HISTORICAL_DIR, f"{yesterday}.json")
        if os.path.exists(yday_path):
            try:
                with open(yday_path, encoding="utf-8") as f:
                    yday_data = json.load(f)
                cutoff = datetime.now(timezone.utc) - timedelta(hours=48)
                for v in yday_data:
                    if v.get("source") != "NVD":
                        continue
                    try:
                        # Ensure UTC-aware comparison (NVD dates may lack Z suffix)
                        pub_s = (v.get("published") or "").rstrip("Z") + "Z"
                        pub = datetime.fromisoformat(pub_s.replace("Z", "+00:00"))
                        if pub >= cutoff:
                            nvd_results.append(v)
                    except Exception:
                        pass
                log(f"  NVD fallback: {len(nvd_results)} entries from {yesterday}")
            except Exception as ex:
                log(f"  NVD fallback error: {ex}")
    fresh += nvd_results

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
    fresh += fetch_cisco()
    fresh += fetch_arista()
    fresh += fetch_msrc()
    fresh += fetch_fortinet()
    fresh += fetch_juniper()
    fresh += fetch_openstack_ossa(months=3)
    fresh += fetch_openstack_ossn(months=3)

    log(f"Fresh total: {len(fresh)}")

    # --- EPSS annotation on fresh (stored in snapshot for trending delta) ---
    log("Annotating EPSS scores...")
    epss_data = fetch_epss()
    epss_hits = 0
    for v in fresh:
        ep = epss_data.get(v["id"])
        if ep:
            v["epss"] = round(ep["epss"], 4)
            v["epss_pct"] = round(ep["percentile"] * 100, 1)
            epss_hits += 1
    log(f"  EPSS annotations (fresh): {epss_hits}/{len(fresh)}")

    # --- Persist today's snapshot (includes EPSS for future trending delta) ---
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

    # Fill EPSS on any historical entries that lacked it (older snapshots)
    for v in vulns:
        if v.get("epss") is None:
            ep = epss_data.get(v["id"])
            if ep:
                v["epss"] = round(ep["epss"], 4)
                v["epss_pct"] = round(ep["percentile"] * 100, 1)

    # --- Diff vs yesterday + EPSS trending ---
    yesterday_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    yesterday_path = os.path.join(HISTORICAL_DIR, f"{yesterday_str}.json")
    yesterday_ids = set()
    yesterday_epss = {}   # {cve_id: epss_score} from yesterday's snapshot
    if os.path.exists(yesterday_path):
        try:
            with open(yesterday_path, encoding="utf-8") as f:
                yday = json.load(f)
            yesterday_ids = {v["id"] for v in yday}
            yesterday_epss = {v["id"]: v["epss"] for v in yday if v.get("epss") is not None}
            log(f"Yesterday snapshot: {len(yesterday_ids)} IDs, {len(yesterday_epss)} EPSS")
        except Exception as ex:
            log(f"  Error loading yesterday: {ex}")

    fresh_ids = {v["id"] for v in fresh}
    trending_count = 0
    for v in vulns:
        if v["id"] in fresh_ids and v["id"] not in yesterday_ids:
            v["_new"] = True
        # Trending: EPSS jumped >5pp since yesterday (rapid exploitation escalation)
        cur_epss = v.get("epss")
        prev_epss = yesterday_epss.get(v["id"])
        if cur_epss is not None and prev_epss is not None:
            if (cur_epss - prev_epss) >= 0.05 and cur_epss >= 0.01:
                v["_trending"] = True
                trending_count += 1
    new_count = sum(1 for v in vulns if v.get("_new"))
    log(f"New since yesterday: {new_count}  |  Trending (EPSS +5pp): {trending_count}")

    # --- NVD enrichment for unscored CVEs (needs NVD_API_KEY) ---
    log("NVD enrichment for unscored CVEs...")
    enrich_with_nvd(vulns)

    # --- Score propagation: advisory entries (USN/DSA/RHSA) get max CVSS from their CVEs ---
    # Ubuntu/Debian/vendor advisories use advisory IDs (not CVE IDs) so enrich_with_nvd
    # skips them. Build a score index from all scored CVE entries and propagate to advisories.
    cve_score_index = {
        v["id"]: (v["score"], v["severity"])
        for v in vulns
        if v["id"].startswith("CVE-") and v.get("score") is not None
    }
    advisory_scored = 0
    for v in vulns:
        if v.get("score") is not None:
            continue
        if not v.get("affected"):
            continue
        best = max(
            (cve_score_index[cid] for cid in v["affected"] if cid in cve_score_index),
            key=lambda t: t[0],
            default=None,
        )
        if best:
            v["score"], v["severity"] = best
            advisory_scored += 1
    log(f"  Advisory score propagation: {advisory_scored} entries scored")

    # --- PoC availability via nomi-sec/PoC-in-GitHub ---
    log("Checking PoC availability...")
    epss_by_id = {v["id"]: v.get("epss") or 0 for v in vulns}
    epss_sorted_cves = sorted(
        [vid for vid in epss_by_id if vid.startswith("CVE-")],
        key=lambda cid: epss_by_id[cid],
        reverse=True,
    )[:200]
    poc_set = fetch_poc_status(epss_sorted_cves)
    for v in vulns:
        if v["id"] in poc_set:
            v["poc"] = True
    poc_count = sum(1 for v in vulns if v.get("poc"))
    log(f"  PoC available: {poc_count}")

    # --- Vendor fix commands: propagate from advisories to CVE entries ---
    # Ubuntu/Debian advisories have USN/DSA ids and carry fix cmds; Red Hat entries
    # already have CVE ids. Build an index so NVD/GitHub CVE cards also show the fix.
    fix_index = {}
    for v in fresh:
        fc = v.get("fix")
        if not fc:
            continue
        if v["id"].startswith("CVE-"):
            fix_index.setdefault(v["id"], fc)
        else:
            for cve_ref in v.get("affected", []):
                if cve_ref.startswith("CVE-"):
                    fix_index.setdefault(cve_ref, fc)
    for v in vulns:
        if not v.get("fix") and v["id"] in fix_index:
            v["fix"] = fix_index[v["id"]]
    fix_count = sum(1 for v in vulns if v.get("fix"))
    log(f"  Fix commands available: {fix_count}")

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
    write_badges(vulns, date_str)
    write_robots()

    # --- CVE pages + stats + vendor pages + sitemap ---
    log("Writing CVE pages...")
    cve_pages = write_cve_pages(vulns, date_str)
    log("Writing stats page...")
    write_stats_page(vulns, date_str)
    write_trending_page(vulns, date_str)
    write_patch_now_page(vulns, date_str)
    write_zero_days_page(vulns, date_str)
    write_new_this_week_page(vulns, date_str)
    write_search_page(vulns)
    write_how_to_scan_page()
    write_api_docs_page()
    write_grafana_page()
    write_n8n_guide_page()
    write_agents_page()
    write_llms_txt(vulns, date_str)
    write_product_rss_feeds(vulns, date_str)
    write_subscribe_page()
    log("Writing vendor pages...")
    vendor_pages = write_vendor_pages(vulns, date_str)
    log("Writing CWE pages...")
    cwe_pages = write_cwe_pages(vulns, date_str)
    log("Writing digest pages...")
    digest_dates = write_digest_pages(fresh, date_str, hist_dates)
    log("Writing weekly digest pages...")
    weekly_weeks = write_weekly_digest_pages(hist_dates, date_str)
    write_digest_index(digest_dates, weekly_weeks)
    log("Writing monthly archive pages...")
    monthly_months = write_monthly_archive_pages(hist_dates, date_str)
    write_sitemap(cve_pages, date_str, vendor_pages=vendor_pages,
                  cwe_pages=cwe_pages, digest_dates=digest_dates,
                  weekly_digest_weeks=weekly_weeks,
                  monthly_archive_months=monthly_months)

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

    vendor_index_html = (
        '<section id="vendor-browse">'
        '<h2>Browse by product</h2>'
        '<div class="vb-grid">'
        + "".join(
            f'<a class="vb-link" href="/vendor/{_xe(p["slug"])}.html">'
            f'{_xe(p["display_name"])} <span>{p["count"]}</span></a>'
            for p in vendor_pages
        )
        + '</div></section>'
    )

    cwe_index_html = (
        '<section id="cwe-browse">'
        '<h2>Browse by weakness</h2>'
        '<div class="vb-grid">'
        + "".join(
            f'<a class="cwe-link" href="/cwe/{_xe(p["id"])}.html">'
            f'{_xe(p["display_name"])} <span>{p["count"]}</span></a>'
            for p in cwe_pages
        )
        + '</div></section>'
    )

    news_blob     = (json.dumps(news, ensure_ascii=False, separators=(",", ":"))
                     .replace("<!--", "\\u003C!--").replace("<script", "\\u003Cscript"))
    dates_blob    = json.dumps(hist_dates)
    health_blob   = json.dumps(source_counts)

    html = _HTML
    html = html.replace("__DATE__",              date_str)
    html = html.replace("__COUNT__",             str(len(vulns)))
    html = html.replace("__DATES_JSON__",        dates_blob)
    html = html.replace("__NEWS_JSON__",         news_blob)
    html = html.replace("__HEALTH__",            health_blob)
    html = html.replace("__VENDOR_INDEX_HTML__", vendor_index_html)
    html = html.replace("__CWE_INDEX_HTML__",    cwe_index_html)
    html = html.replace("__STATIC_CVE_HTML__",   static_html)

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
