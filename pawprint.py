#!/usr/bin/env python3
"""Pawprint: turn an nmap scan of your OWN network into a clean HTML report.

Usage:
    python pawprint.py 192.168.1.0/24 -o report.html       # live scan
    python pawprint.py --xml scan.xml  -o report.html       # existing nmap -oX file
    python pawprint.py 192.168.1.0/24 --os --ports 1-1024   # with OS detection + port range
    python pawprint.py 192.168.1.0/24 --json out.json       # also write JSON
    python pawprint.py 192.168.1.0/24 --cve                 # fetch CVE hints (needs internet)

Only scan networks and devices you own or have permission to test.
For safety, the tool refuses non-private targets unless --allow-public is given.
"""

import argparse
import datetime
import ipaddress
import json
import logging
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
from html import escape

__version__ = "1.1.0"

try:
    from defusedxml import ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET  # fallback; install defusedxml for safety

# ---------------------------------------------------------------------------
# Risk database
# ---------------------------------------------------------------------------
RISKY: dict[int, str] = {
    21:    "FTP: unencrypted, prefer SFTP",
    22:    "SSH: ensure key-based auth only",
    23:    "Telnet: unencrypted, replace with SSH",
    25:    "SMTP: verify relay is closed",
    69:    "TFTP: no authentication",
    80:    "HTTP: prefer HTTPS",
    110:   "POP3: unencrypted mail",
    139:   "NetBIOS: legacy SMB exposure",
    445:   "SMB: restrict to trusted hosts",
    1433:  "MSSQL exposed",
    3306:  "MySQL exposed",
    3389:  "RDP: expose only via VPN",
    5432:  "PostgreSQL exposed",
    5900:  "VNC: often weak authentication",
    6379:  "Redis: often unauthenticated",
    8006:  "Proxmox web UI",
    8080:  "HTTP alt: check if intentional",
    27017: "MongoDB exposed",
}

log = logging.getLogger("pawprint")


# ---------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------
def check_target(target: str, allow_public: bool) -> None:
    """Refuse targets that are not private ranges (unless explicitly allowed)."""
    if allow_public:
        return
    for part in target.split():
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            sys.exit(f"Target '{part}' is not a valid IP/CIDR. Use an IP, range, or --xml.")
        if not (net.is_private or net.is_loopback or net.is_link_local):
            sys.exit(
                f"Refusing public target '{part}'. "
                "Use --allow-public only on systems you own."
            )


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
def run_nmap(target: str, ports: str | None, timing: int, detect_os: bool) -> str:
    if not shutil.which("nmap"):
        sys.exit("nmap not found. Install nmap or pass an existing scan with --xml.")
    cmd = ["nmap", "-sV", f"-T{timing}", "--open", "-oX", "-"]
    if detect_os:
        cmd.append("-O")
    if ports:
        cmd += ["-p", ports]
    cmd += target.split()
    log.info("Running: %s", " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"nmap failed: {res.stderr.strip()}")
    return res.stdout


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------
def parse(xml_text: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_text)
    except Exception as exc:
        sys.exit(f"Failed to parse nmap XML: {exc}")

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = mac = vendor = ""
        for addr in host.findall("address"):
            t = addr.get("addrtype")
            if t in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
            elif t == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        hn = host.find("hostnames/hostname")
        name = hn.get("name", "") if hn is not None else ""

        osm = host.find("os/osmatch")
        os_guess = osm.get("name", "") if osm is not None else ""
        os_accuracy = osm.get("accuracy", "") if osm is not None else ""

        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            service = svc.get("name", "") if svc is not None else ""
            version = (
                " ".join(
                    v for v in [
                        svc.get("product"), svc.get("version"), svc.get("extrainfo")
                    ] if v
                )
                if svc is not None else ""
            )
            ports.append({
                "port":    int(port.get("portid", 0)),
                "proto":   port.get("protocol", "tcp"),
                "service": service,
                "version": version,
            })
        ports.sort(key=lambda p: p["port"])

        hosts.append({
            "ip":       ip,
            "name":     name,
            "mac":      mac,
            "vendor":   vendor,
            "os":       os_guess,
            "os_acc":   os_accuracy,
            "ports":    ports,
        })

    # Sort by IP address numerically
    hosts.sort(key=lambda h: (
        ipaddress.ip_address(h["ip"]) if h["ip"] else ipaddress.ip_address("0.0.0.0")
    ))
    return hosts


# ---------------------------------------------------------------------------
# Optional CVE hints via NIST NVD API
# ---------------------------------------------------------------------------
_NVD_LAST_CALL: float = 0.0
_NVD_RATE = 6.0  # seconds between calls without API key


def fetch_cve_hint(service: str, version: str, api_key: str = "") -> str:
    """Return a short CVE summary string or empty string.

    Respects NVD rate limits: 5 req/30s without key (~6s gap), 50 req/30s with key.
    """
    import time
    import urllib.parse

    global _NVD_LAST_CALL

    if not service or not version:
        return ""

    wait = 0.6 if api_key else _NVD_RATE
    elapsed = time.monotonic() - _NVD_LAST_CALL
    if elapsed < wait:
        time.sleep(wait - elapsed)

    keyword = f"{service} {version}".strip()[:80]
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=1"
    )
    headers = {"apiKey": api_key} if api_key else {}

    try:
        req = urllib.request.Request(url, headers=headers)
        _NVD_LAST_CALL = time.monotonic()
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        vulns = data.get("vulnerabilities", [])
        if vulns:
            cve_id = vulns[0]["cve"]["id"]
            desc = vulns[0]["cve"]["descriptions"][0]["value"][:100]
            return f"{cve_id}: {desc}…"
    except Exception as exc:
        log.debug("CVE lookup failed for %s %s: %s", service, version, exc)
    return ""


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------
CSS = """
:root{
  --bg:#f5f5f7;--fg:#1c1c1e;--card:#fff;--mut:#6b7280;
  --line:#e5e7eb;--acc:#2563eb;--warn:#b45309;--warnbg:#fef3c7;
}
@media(prefers-color-scheme:dark){
  :root{--bg:#0b0b0d;--fg:#f3f4f6;--card:#17171a;--mut:#9ca3af;
        --line:#2e2e33;--acc:#60a5fa;--warn:#fbbf24;--warnbg:#292016;}
}
*{box-sizing:border-box}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);
     font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto}
h1{margin:0 0 4px;font-size:1.5rem}
.sub{color:var(--mut);margin-bottom:20px;font-size:.9rem}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;
      padding:10px 16px;min-width:110px}
.stat b{display:block;font-size:1.4rem}
.stat span{color:var(--mut);font-size:.85rem}
details.host{background:var(--card);border:1px solid var(--line);
             border-radius:10px;padding:0;margin-bottom:12px;overflow:hidden}
details.host summary{cursor:pointer;padding:12px 16px;list-style:none;
                      display:flex;align-items:center;gap:8px;font-weight:600}
details.host summary::-webkit-details-marker{display:none}
details.host summary::before{content:"▶";font-size:.7rem;color:var(--mut);
                              transition:transform .15s;flex-shrink:0}
details.host[open] summary::before{transform:rotate(90deg)}
.host-body{padding:0 16px 14px}
.meta{color:var(--mut);font-size:.85rem;margin:0 0 8px}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:500;font-size:.82rem;white-space:nowrap}
tr:last-child td{border-bottom:none}
.flag{background:var(--warnbg);color:var(--warn);border-radius:6px;
      padding:1px 7px;font-size:.78rem;white-space:nowrap}
.cve{color:var(--mut);font-size:.78rem;display:block;margin-top:2px}
.overflow{overflow-x:auto}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center}
.filters input,.filters select{
  background:var(--card);color:var(--fg);border:1px solid var(--line);
  border-radius:6px;padding:4px 10px;font-size:.88rem}
#no-results{display:none;color:var(--mut);padding:12px 0}
"""

# ---------------------------------------------------------------------------
# JS (filter + sort)
# ---------------------------------------------------------------------------
JS = """
(function(){
  const q   = document.getElementById('q');
  const sel = document.getElementById('risk-filter');
  const rows = Array.from(document.querySelectorAll('tr[data-host]'));
  const noRes = document.getElementById('no-results');

  function filter(){
    const txt  = q.value.toLowerCase();
    const risk = sel.value;
    let shown = 0;
    rows.forEach(r => {
      const match =
        (!txt  || r.dataset.search.includes(txt)) &&
        (!risk || r.dataset.risk === risk);
      r.style.display = match ? '' : 'none';
      if(match) shown++;
      // keep parent details open/visible
      const det = r.closest('details');
      if(det){
        const anyVisible = det.querySelectorAll('tr[data-host]:not([style*="none"])').length > 0;
        det.style.display = anyVisible || !txt && !risk ? '' : 'none';
      }
    });
    noRes.style.display = shown === 0 ? 'block' : 'none';
  }

  q.addEventListener('input', filter);
  sel.addEventListener('change', filter);

  // Sort table columns
  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.style.cursor = 'pointer';
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      const tbody = th.closest('table').querySelector('tbody');
      const trows = Array.from(tbody.querySelectorAll('tr'));
      const asc = th.dataset.asc !== 'true';
      th.dataset.asc = asc;
      trows.sort((a,b) => {
        const av = a.cells[parseInt(col)].textContent.trim();
        const bv = b.cells[parseInt(col)].textContent.trim();
        const an = parseFloat(av), bn = parseFloat(bv);
        if(!isNaN(an) && !isNaN(bn)) return asc ? an-bn : bn-an;
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      trows.forEach(r => tbody.appendChild(r));
    });
  });
})();
"""


# ---------------------------------------------------------------------------
# Render HTML
# ---------------------------------------------------------------------------
def render(hosts: list[dict], target: str, cve: bool = False, nvd_key: str = "") -> str:
    total_ports = sum(len(h["ports"]) for h in hosts)
    flagged     = sum(1 for h in hosts for p in h["ports"] if p["port"] in RISKY)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    out = [
        f"<!doctype html><html lang='en'><head>"
        f"<meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>Pawprint — Network Report</title>"
        f"<style>{CSS}</style></head><body><main>",
        f"<h1>🐾 Pawprint — Network Report</h1>",
        f"<div class='sub'>{escape(target)} &middot; generated {now}</div>",
        "<div class='stats'>",
        f"<div class='stat'><b>{len(hosts)}</b><span>hosts up</span></div>",
        f"<div class='stat'><b>{total_ports}</b><span>open ports</span></div>",
        f"<div class='stat'><b>{flagged}</b><span>ports to review</span></div>",
        "</div>",
        "<div class='filters'>",
        "<input id='q' type='search' placeholder='Filter by IP, host, service…' style='flex:1;min-width:180px'>",
        "<select id='risk-filter'>",
        "<option value=''>All ports</option>",
        "<option value='1'>⚠️ Risky only</option>",
        "</select>",
        "</div>",
        "<div id='no-results'>No results match your filter.</div>",
    ]

    for h in hosts:
        title = escape(h["ip"])
        if h["name"]:
            title += f" &mdash; {escape(h['name'])}"
        badge = ""
        if any(p["port"] in RISKY for p in h["ports"]):
            badge = " <span class='flag'>⚠️ review</span>"

        meta_parts = []
        if h["mac"]:
            mac_str = f"MAC {escape(h['mac'])}"
            if h["vendor"]:
                mac_str += f" ({escape(h['vendor'])})"
            meta_parts.append(mac_str)
        if h["os"]:
            acc = f" {h['os_acc']}%" if h["os_acc"] else ""
            meta_parts.append(f"OS: {escape(h['os'])}{acc}")
        meta = " &middot; ".join(meta_parts) or "no extra info"

        out.append(f"<details class='host'><summary>{title}{badge}</summary><div class='host-body'>")
        out.append(f"<div class='meta'>{meta}</div>")

        if h["ports"]:
            out.append(
                "<div class='overflow'><table>"
                "<thead><tr>"
                "<th data-sort='0'>Port</th>"
                "<th data-sort='1'>Service</th>"
                "<th data-sort='2'>Version</th>"
                "<th>Note</th>"
                "</tr></thead><tbody>"
            )
            for p in h["ports"]:
                note = RISKY.get(p["port"], "")
                flag = f"<span class='flag'>⚠️ {escape(note)}</span>" if note else ""
                cve_hint = ""
                if cve and p["service"] and p["version"]:
                    hint = fetch_cve_hint(p["service"], p["version"], api_key=nvd_key)
                    if hint:
                        cve_hint = f"<span class='cve'>🔎 {escape(hint)}</span>"
                risk_attr = "1" if note else "0"
                search = f"{h['ip']} {h['name']} {p['port']} {p['service']} {p['version']}".lower()
                out.append(
                    f"<tr data-host='1' data-risk='{risk_attr}' data-search='{escape(search)}'>"
                    f"<td>{p['port']}/{escape(p['proto'])}</td>"
                    f"<td>{escape(p['service'])}</td>"
                    f"<td>{escape(p['version'])}</td>"
                    f"<td>{flag}{cve_hint}</td>"
                    f"</tr>"
                )
            out.append("</tbody></table></div>")
        else:
            out.append("<div class='meta'>No open ports found.</div>")

        out.append("</div></details>")

    out.append(f"<script>{JS}</script>")
    out.append("</main></body></html>")
    return "".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an HTML (and optionally JSON) report from an nmap scan."
    )
    parser.add_argument("target", nargs="?", help="IP or CIDR, e.g. 192.168.1.0/24")
    parser.add_argument("--xml",   help="Parse an existing nmap -oX file instead of scanning")
    parser.add_argument("-o", "--output", default="", help="Output HTML file (default: pawprint_<timestamp>.html)")
    parser.add_argument("--json",  help="Also write a JSON file at this path")
    parser.add_argument("--ports", help="Port range(s) to scan, e.g. 1-1024 or 22,80,443")
    parser.add_argument("--timing", type=int, default=4, choices=range(0, 6),
                        metavar="{0-5}", help="nmap timing template (default: 4)")
    parser.add_argument("--os",   action="store_true", help="Enable OS detection (requires root/sudo)")
    parser.add_argument("--cve",  action="store_true", help="Fetch CVE hints from NVD (requires internet)")
    parser.add_argument("--nvd-key", default="", metavar="KEY", help="NVD API key (higher rate limit)")
    parser.add_argument("--allow-public", action="store_true",
                        help="Allow non-private targets (only your own systems!)")
    parser.add_argument("--verbose", action="store_true", help="Show debug output")
    parser.add_argument("--quiet",   action="store_true", help="Suppress all output except errors")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logging.basicConfig(format="%(levelname)s %(message)s", level=level)

    # Determine output filename
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
    out_html = args.output or f"pawprint_{timestamp}.html"

    # Get XML source
    if args.xml:
        with open(args.xml, encoding="utf-8") as f:
            xml_text = f.read()
        label = args.xml
    elif args.target:
        check_target(args.target, args.allow_public)
        xml_text = run_nmap(args.target, args.ports, args.timing, args.os)
        label = args.target
    else:
        parser.error("Provide a target IP/CIDR or --xml <file>")
        return  # unreachable

    hosts = parse(xml_text)

    # Write HTML
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(render(hosts, label, cve=args.cve, nvd_key=getattr(args, "nvd_key", "")))
    log.info("Report written to %s (%d hosts)", out_html, len(hosts))

    # Write JSON (optional)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"target": label, "generated": timestamp, "hosts": hosts}, f, indent=2)
        log.info("JSON written to %s", args.json)


if __name__ == "__main__":
    main()
