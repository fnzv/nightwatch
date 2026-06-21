# vulnfeed

Security vulnerability aggregator — live at **[vulnfeed.it](https://vulnfeed.it)**

Scrapes multiple security sources every 4 hours and builds a single static HTML page with client-side search and filtering. No backend, no database.

## Sources

| Source | What it covers | Window |
|---|---|---|
| NVD | NIST CVE database | 7 days |
| Ubuntu | Ubuntu Security Notices (USN) | 7 days |
| Debian | debian-security-announce mailing list | 7 days |
| CISA KEV | Known Exploited Vulnerabilities catalog | 7 days |
| OSS-Security | Openwall oss-security mailing list | 7 days |
| Kubernetes | Official Kubernetes CVE feed | 7 days |
| Exploit-DB | Public exploits RSS | 7 days |
| Red Hat | Red Hat Security Data API | 7 days |
| OpenStack OSSA | OpenStack Security Advisories | 3 months |
| OpenStack OSSN | OpenStack Security Notes (wiki) | 3 months |

## Usage

```bash
pip install -r requirements.txt  # no deps, stdlib only
python3 build.py
# open index.html in your browser
```

## How it works

- `build.py` fetches all sources, deduplicates by CVE ID (merges CISA "ACTIVELY EXPLOITED" badge into NVD entries), and writes a self-contained `index.html` with all data embedded as a JSON blob.
- The page has client-side search, severity/source/period filters, and sort controls.
- Priority software (kubernetes, nginx, openstack, traefik, openssh, etc.) floats to the top of results.
- GitHub Actions runs `build.py` every 4 hours and deploys to GitHub Pages.

## Deployment

The repo uses GitHub Pages + a Cloudflare DNS CNAME (DNS-only, no proxy) pointing `vulnfeed.it` → `fnzv.github.io`.

`index.html` is in `.gitignore` — it's generated at build time by the workflow.
