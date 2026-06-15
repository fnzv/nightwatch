#!/usr/bin/env python3
"""
TLDR Security Daily — build.py
Aggregates CVEs from NVD, Ubuntu, Debian, CISA KEV, and OSS-Security.

Usage:  python3 build.py
Output: index.html
Serve:  python3 -m http.server 8080
"""

import json
import re
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
import xml.etree.ElementTree as ET


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


def strip_html(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()


def cutoff_utc(hours=24):
    return datetime.now(timezone.utc) - timedelta(hours=hours)


# ---------------------------------------------------------------------------
# GitHub Advisories watchlist — edit this list to track specific projects
# ---------------------------------------------------------------------------

GITHUB_WATCHLIST = [
    "curl", "openssl", "openssh", "nginx", "traefik",
    "kubernetes", "containerd", "docker", "runc",
    "linux", "glibc", "python", "openstack",
    "gitlab", "jenkins", "grafana", "vault", "terraform",
    "envoy", "istio", "helm", "etcd", "cilium",
]


# ---------------------------------------------------------------------------
# Source: GitHub Security Advisories (watchlist)
# ---------------------------------------------------------------------------

def fetch_github_advisories(days=7):
    log(f"Fetching GitHub Security Advisories ({len(GITHUB_WATCHLIST)} packages)...")
    cut = cutoff_utc(hours=days * 24)
    SEV_MAP = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
    seen = set()
    results = []
    gh_headers = {"Accept": "application/vnd.github+json"}

    for pkg in GITHUB_WATCHLIST:
        url = (
            "https://api.github.com/advisories"
            f"?affects={pkg}&per_page=100&type=reviewed"
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
            time.sleep(2)
            continue

        for item in items:
            ghsa = item.get("ghsa_id", "")
            if not ghsa or ghsa in seen:
                continue

            pub = item.get("published_at", "")
            try:
                if datetime.fromisoformat(pub.replace("Z", "+00:00")) < cut:
                    continue
            except Exception:
                pass

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
                eco = ep.get("ecosystem", "")
                vrange = vuln.get("vulnerable_version_range", "")
                if name:
                    label = f"{eco}/{name}" if eco else name
                    if vrange:
                        label += f" {vrange}"
                    affected.append(label)

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

        time.sleep(1.5)  # stay well within 60 req/hour unauthenticated limit

    log(f"  GitHub Advisories: {len(results)} advisories")
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

def fetch_kubernetes(days=7):
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
    raw = http_get("https://www.exploit-db.com/rss.xml")
    if not raw:
        return []

    cut = cutoff_utc(hours=days * 24)
    results = []

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as ex:
        log(f"  Exploit-DB XML error: {ex}")
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

        # Category from title: "[webapps] Title" → "webapps"
        cat_m = re.match(r"\[([^\]]+)\]\s*(.+)", title)
        category = cat_m.group(1) if cat_m else ""
        clean_title = cat_m.group(2) if cat_m else title

        cves = re.findall(r"CVE-\d{4}-\d+", desc + " " + title)

        results.append({
            "id": cves[0] if cves else re.search(r"/(\d+)$", link or "").group(1) if link else title[:20],
            "title": clean_title,
            "description": f"[{category}] {clean_title}" if category else clean_title,
            "score": None,
            "severity": "HIGH",
            "source": "Exploit-DB",
            "published": pub,
            "references": [link],
            "affected": ([category] if category else []) + cves[:3],
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
    url = f"https://access.redhat.com/labs/securitydataapi/cve.json?per_page=100&after={after}"
    raw = http_get(url)
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
        bugzilla = item.get("bugzilla", {}) or {}
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
# HTML template
# ---------------------------------------------------------------------------

_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>vulnfeed &mdash; __DATE__</title>
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
.bdgs{display:flex;gap:.28rem;flex-wrap:wrap;align-items:center}
.b{display:inline-block;padding:.1rem .42rem;border-radius:4px;font-size:.65rem;
  font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#fff}
.bCRITICAL{background:var(--crit)}.bHIGH{background:var(--high)}
.bMEDIUM{background:var(--med)}.bLOW{background:var(--low)}.bUNKNOWN{background:var(--unk)}
.bsrc{background:#334155;font-size:.62rem}
.bxpl{background:#7c3aed}
.bsc{background:#1e293b;font-family:ui-monospace,monospace}

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

#chart-wrap{background:var(--hdr);padding:.6rem 2rem .7rem;border-bottom:1px solid #1e293b}
#chart-title{font-size:.65rem;color:#475569;margin-bottom:.55rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase}
#chart{position:relative;height:54px}
#chart svg{position:absolute;inset:0;width:100%;height:100%;overflow:visible}
.chart-lbl-row{display:flex;margin-top:3px}
.chart-lbl-row span{flex:1;text-align:center;font-size:.6rem;color:#334155}

.card{cursor:pointer}
.card.expanded .cdesc{display:block!important;-webkit-line-clamp:unset!important;overflow:visible!important}

#empty{display:none;text-align:center;padding:4rem 2rem;color:var(--muted);grid-column:1/-1}
#empty h2{font-size:1.05rem;margin-bottom:.35rem;color:var(--text)}

@media(max-width:640px){
  header,#chart-wrap,.bar,.stats,#grid{padding-left:1rem;padding-right:1rem}
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
    <div class="hmeta" style="margin-top:.35rem">NVD &middot; Ubuntu &middot; Debian &middot; CISA KEV &middot; OSS-Security &middot; OpenStack &middot; Kubernetes &middot; Exploit-DB &middot; Red Hat &middot; GitHub</div>
  </div>
</header>

<div id="chart-wrap">
  <div id="chart-title">Vulnerabilities — last 7 days</div>
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
  </div>
  <div class="pills">
    <span class="plabel">Period:</span>
    <button class="pill" data-range="ALL">All time</button>
    <button class="pill on" data-range="24H">Last 24h</button>
    <button class="pill" data-range="7D">Last 7 days</button>
    <button class="pill" data-range="30D">Last 30 days</button>
    <button class="pill" data-range="1Y">Last year</button>
    <div class="sep"></div>
    <span class="plabel">Sort:</span>
    <button class="pill" data-sort="SEVERITY">Severity</button>
    <button class="pill on" data-sort="DATE">Newest first</button>
    <button class="pill" data-sort="SCORE">Score</button>
  </div>
</div>

<div class="stats">
  <span>Showing <strong id="vis">0</strong> of <strong>__COUNT__</strong></span>
  <span id="shint" style="display:none">Press <kbd>Esc</kbd> to clear</span>
</div>

<div id="grid">
  <div id="empty"><h2>No results</h2><p>Try a different keyword or clear the filters.</p></div>
</div>

<script>
const D=__JSON__;

// Precompute timestamps once
D.forEach(v=>{v._ts=v.published?new Date(v.published).getTime()||0:0});

const SEV=v=>v.severity||"UNKNOWN";
function esc(s){
  return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function host(u){try{return new URL(u).hostname}catch(_){return String(u).slice(0,30)}}
function timeAgo(ts){
  if(!ts)return"";
  const d=Date.now()-ts,m=Math.floor(d/60000);
  if(m<2)return"just now";
  if(m<60)return m+"m ago";
  const h=Math.floor(m/60);
  if(h<24)return h+"h ago";
  const dy=Math.floor(h/24);
  if(dy<7)return dy+"d ago";
  const w=Math.floor(dy/7);
  if(w<5)return w+"w ago";
  return new Date(ts).toLocaleDateString(undefined,{month:"short",day:"numeric",year:"numeric"});
}

// --- Today badge + day-over-day delta ---
const DAY=864e5,now=Date.now();
const todayCount=D.filter(v=>v._ts&&(now-v._ts)<DAY).length;
const ydayCount=D.filter(v=>v._ts&&(now-v._ts)>=DAY&&(now-v._ts)<2*DAY).length;
document.getElementById("todayN").textContent=todayCount;
if(ydayCount>0){
  const pct=Math.round((todayCount-ydayCount)/ydayCount*100);
  const sign=pct>=0?"+":"";
  const col=pct>0?"#4ade80":pct<0?"#f87171":"#94a3b8";
  document.getElementById("todayDelta").innerHTML=
    `<span style="color:${col}">${sign}${pct}% vs yesterday</span>`;
}

// --- Severity breakdown ---
(function(){
  const cnt={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  D.forEach(v=>{const s=SEV(v);if(s in cnt)cnt[s]++;});
  document.getElementById("sevBrk").innerHTML=
    `<b class="sc">CRIT ${cnt.CRITICAL}</b><b class="sh">HIGH ${cnt.HIGH}</b>`+
    `<b class="sm">MED ${cnt.MEDIUM}</b><b class="sl">LOW ${cnt.LOW}</b>`;
})();

// --- 7-day area chart (SVG) ---
(function(){
  const DAYS=7, VW=600, VH=54, PAD=6;
  const counts=Array(DAYS).fill(0);
  D.forEach(v=>{if(!v._ts)return;const i=Math.floor((now-v._ts)/DAY);if(i>=0&&i<DAYS)counts[i]++;});
  const vals=counts.slice().reverse(); // oldest left → newest right
  const maxV=Math.max(...vals,1);
  const labels=vals.map((_,i)=>{
    const d=new Date(now-(DAYS-1-i)*DAY);
    return d.toLocaleDateString(undefined,{weekday:"short"});
  });
  const xs=vals.map((_,i)=>PAD+(i/(DAYS-1))*(VW-PAD*2));
  const ys=vals.map(n=>PAD+(1-n/maxV)*(VH-PAD*2));
  const line=xs.map((x,i)=>(i===0?`M${x.toFixed(1)},${ys[i].toFixed(1)}`:`L${x.toFixed(1)},${ys[i].toFixed(1)}`)).join(" ");
  const area=line+` L${xs[DAYS-1].toFixed(1)},${VH} L${xs[0].toFixed(1)},${VH} Z`;
  const dots=xs.map((x,i)=>{
    const today=i===DAYS-1;
    return `<circle cx="${x.toFixed(1)}" cy="${ys[i].toFixed(1)}" r="${today?3.5:2}" fill="${today?"#60a5fa":"#3b82f6"}" fill-opacity="${today?1:.7}"><title>${labels[i]}: ${vals[i]}</title></circle>`;
  }).join("");
  const svg=`<svg viewBox="0 0 ${VW} ${VH}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
<defs><linearGradient id="cg" x1="0" y1="0" x2="0" y2="1">
<stop offset="0%" stop-color="#3b82f6" stop-opacity="0.28"/>
<stop offset="100%" stop-color="#3b82f6" stop-opacity="0.02"/>
</linearGradient></defs>
<path d="${area}" fill="url(#cg)"/>
<path d="${line}" fill="none" stroke="#3b82f6" stroke-width="2" stroke-opacity="0.65" stroke-linejoin="round" stroke-linecap="round"/>
${dots}</svg>`;
  const wrap=document.getElementById("chart");
  wrap.innerHTML=svg+'<div class="chart-lbl-row">'+
    labels.map((l,i)=>`<span style="${i===DAYS-1?"color:#60a5fa;font-weight:600":""}">${l}</span>`).join("")+
    '</div>';
})();

function card(v){
  const sc=v.score!=null?`<span class="b bsc">${v.score.toFixed(1)}</span>`:"";
  const sv=`<span class="b b${SEV(v)}">${SEV(v)}</span>`;
  const sr=`<span class="b bsrc">${esc(v.source)}</span>`;
  const xp=v.badge?`<span class="b bxpl">${esc(v.badge)}</span>`:"";
  const aff=(v.affected||[]).slice(0,6).map(a=>`<span class="chip">${esc(a)}</span>`).join("");
  const rfs=(v.references||[]).filter(Boolean).slice(0,3)
    .map(u=>`<a href="${esc(u)}" target="_blank" rel="noopener">${esc(host(u))}</a>`)
    .join(" &middot; ");
  const ttl=v.title&&v.title!==v.description?`<div class="ctitle">${esc(v.title)}</div>`:"";
  const dsc=v.description?`<div class="cdesc">${esc(v.description)}</div>`:"";
  const dt=v._ts?`<div class="cdate">${timeAgo(v._ts)}</div>`:"";
  return `<div class="card" data-sev="${SEV(v)}" onclick="this.classList.toggle('expanded')">
<div class="ctop"><a class="cid" href="${esc(v.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(v.id)}</a>
<div class="bdgs">${sc}${sv}${sr}${xp}</div></div>
${ttl}${dsc}
${aff?`<div class="chips">${aff}</div>`:""}
${rfs?`<div class="refs">${rfs}</div>`:""}
${dt}</div>`;
}

// Software that always floats to the top when matched
const PRIORITY=[
  "kubernetes","k8s","nginx","openstack","traefik","apache httpd","apache2",
  "openssh","docker","containerd","linux kernel","glibc","openssl","log4j",
  "gitlab","jenkins","grafana","prometheus","istio","vault","terraform"
];

function priority(v){
  const hay=[v.id,v.title,v.description,...(v.affected||[])].join(" ").toLowerCase();
  return PRIORITY.some(t=>hay.includes(t))?1:0;
}

const RANGES={"24H":864e5,"7D":6048e5,"30D":2592e6,"1Y":31536e6,"ALL":Infinity};
const SEV_ORDER={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"UNKNOWN":4};
let aSev="ALL",aSrc="ALL",aRange="24H",aSort="DATE",q="";
const grid=document.getElementById("grid");
const visEl=document.getElementById("vis");
const shint=document.getElementById("shint");
const clearBtn=document.getElementById("clear");

// --- URL hash state ---
function pushHash(){
  const p=new URLSearchParams();
  if(q)p.set("q",q);
  if(aSev!=="ALL")p.set("sev",aSev);
  if(aSrc!=="ALL")p.set("src",aSrc);
  if(aRange!=="24H")p.set("range",aRange);
  if(aSort!=="DATE")p.set("sort",aSort);
  const s=p.toString();
  history.replaceState(null,"",s?"#"+s:"#");
}

function applyHash(){
  const h=location.hash.slice(1);
  if(!h)return;
  const p=new URLSearchParams(h);
  const qv=p.get("q")||"";
  const sevv=p.get("sev")||"ALL";
  const srcv=p.get("src")||"ALL";
  const rangev=p.get("range")||"24H";
  const sortv=p.get("sort")||"DATE";
  q=qv; aSev=sevv; aSrc=srcv; aRange=rangev; aSort=sortv;
  const srchEl=document.getElementById("search");
  srchEl.value=qv;
  ["data-sev","data-src","data-range","data-sort"].forEach(attr=>{
    const key=attr.replace("data-","");
    const val={sev:sevv,src:srcv,range:rangev,sort:sortv}[key];
    document.querySelectorAll(`.pill[${attr}]`).forEach(b=>{
      b.classList.toggle("on",b.dataset[key]===val);
    });
  });
}

function render(){
  const now=Date.now(),maxAge=RANGES[aRange];
  let vis=D.filter(v=>{
    if(aSev!=="ALL"&&SEV(v)!==aSev)return false;
    if(aSrc!=="ALL"&&v.source!==aSrc)return false;
    if(maxAge!==Infinity&&(now-(v._ts||0))>maxAge)return false;
    if(q){
      const hay=[v.id,v.title,v.description,...(v.affected||[]),...(v.references||[])].join(" ").toLowerCase();
      return q.trim().split(/\s+/).every(w=>hay.includes(w));
    }
    return true;
  });

  // Priority items always float to the top, then apply chosen sort within each tier
  vis=[...vis].sort((a,b)=>{
    const pd=priority(b)-priority(a);
    if(pd!==0)return pd;
    if(aSort==="DATE")   return (b._ts||0)-(a._ts||0);
    if(aSort==="SCORE")  return (b.score||0)-(a.score||0);
    return (SEV_ORDER[SEV(a)]??4)-(SEV_ORDER[SEV(b)]??4)||(b.score||0)-(a.score||0);
  });

  visEl.textContent=vis.length;
  const hasQ=!!q;
  shint.style.display=hasQ?"inline":"none";
  clearBtn.style.display=hasQ?"inline":"none";
  grid.innerHTML=vis.map(card).join("")
    +`<div id="empty" style="display:${vis.length===0?"block":"none"}"><h2>No results</h2><p>Try a different keyword or clear the filters.</p></div>`;
  pushHash();
}

function bindPills(attr,setter){
  document.querySelectorAll(`.pill[${attr}]`).forEach(b=>b.addEventListener("click",()=>{
    setter(b.dataset[attr.replace("data-","")]);
    document.querySelectorAll(`.pill[${attr}]`).forEach(x=>x.classList.remove("on"));
    b.classList.add("on"); render();
  }));
}
bindPills("data-sev",v=>aSev=v);
bindPills("data-src",v=>aSrc=v);
bindPills("data-range",v=>aRange=v);
bindPills("data-sort",v=>aSort=v);

let t;
const srchEl=document.getElementById("search");
srchEl.addEventListener("input",function(){
  clearTimeout(t); t=setTimeout(()=>{ q=this.value.toLowerCase(); render(); },100);
});
srchEl.addEventListener("keydown",ev=>{
  if(ev.key==="Escape"){srchEl.value="";q="";render();}
});
clearBtn.addEventListener("click",()=>{srchEl.value="";q="";render();});

applyHash();
render();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log("=== TLDR Security Daily ===")
    date_str = datetime.now().strftime("%Y-%m-%d")
    log(f"Date: {date_str}")

    vulns = []
    vulns += fetch_nvd()

    time.sleep(2)  # brief pause before hitting more servers

    vulns += fetch_ubuntu()
    vulns += fetch_debian()
    vulns += fetch_cisa()
    vulns += fetch_oss_security()
    vulns += fetch_github_advisories()
    vulns += fetch_kubernetes()
    vulns += fetch_exploitdb()
    vulns += fetch_redhat()
    vulns += fetch_openstack_ossa(months=3)
    vulns += fetch_openstack_ossn(months=3)

    log(f"Raw total: {len(vulns)}")
    vulns = merge(vulns)
    log(f"After dedup/sort: {len(vulns)}")

    json_blob = json.dumps(vulns, ensure_ascii=False, separators=(",", ":"))

    html = _HTML
    html = html.replace("__DATE__", date_str)
    html = html.replace("__COUNT__", str(len(vulns)))
    html = html.replace("__JSON__", json_blob)

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
