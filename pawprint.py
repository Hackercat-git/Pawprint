#!/usr/bin/env python3
"""Pawprint: turn an nmap scan of your OWN network into a clean HTML report.

Usage:
  python pawprint.py 192.168.1.0/24 -o report.html      # runs nmap, needs nmap installed
  python pawprint.py --xml scan.xml -o report.html       # parse an existing `nmap -oX` file

Only scan networks and devices you own or have permission to test.
For safety, the tool refuses non-private targets unless --allow-public is given.
"""
import argparse
import datetime as dt
import ipaddress
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from html import escape

RISKY = {
    21: "FTP: unencrypted, prefer SFTP",
    23: "Telnet: unencrypted, replace with SSH",
    69: "TFTP: no authentication",
    110: "POP3: unencrypted mail",
    139: "NetBIOS: legacy SMB exposure",
    445: "SMB: restrict to trusted hosts",
    1433: "MSSQL exposed",
    3306: "MySQL exposed",
    3389: "RDP: expose only via VPN",
    5432: "PostgreSQL exposed",
    5900: "VNC: often weak authentication",
    6379: "Redis: often unauthenticated",
    8006: "Proxmox web UI",
    27017: "MongoDB exposed",
}


def check_target(target, allow_public):
    """Refuse targets that are not private ranges (unless explicitly allowed)."""
    if allow_public:
        return
    for part in target.split():
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            sys.exit(f"Target '{part}' is not an IP/CIDR. Use an IP or range, or --xml.")
        if not (net.is_private or net.is_loopback):
            sys.exit(f"Refusing public target {part}. Use --allow-public only for systems you own.")


def run_nmap(target):
    if not shutil.which("nmap"):
        sys.exit("nmap not found. Install nmap or pass an existing scan with --xml.")
    cmd = ["nmap", "-sV", "-T4", "--open", "-oX", "-", *target.split()]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"nmap failed: {res.stderr.strip()}")
    return res.stdout


def parse(xml_text):
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ip = mac = vendor = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr"), a.get("vendor", "")
        name = ""
        hn = h.find("hostnames/hostname")
        if hn is not None:
            name = hn.get("name", "")
        os_guess = ""
        om = h.find("os/osmatch")
        if om is not None:
            os_guess = om.get("name", "")
        ports = []
        for p in h.findall("ports/port"):
            state = p.find("state").get("state")
            if state != "open":
                continue
            svc = p.find("service")
            version = ""
            service = ""
            if svc is not None:
                service = svc.get("name", "")
                version = " ".join(x for x in (svc.get("product"), svc.get("version"), svc.get("extrainfo")) if x)
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": service,
                "version": version,
            })
        ports.sort(key=lambda x: x["port"])
        hosts.append({"ip": ip, "name": name, "mac": mac, "vendor": vendor, "os": os_guess, "ports": ports})
    hosts.sort(key=lambda x: ipaddress.ip_address(x["ip"]) if x["ip"] else 0)
    return hosts


CSS = """
:root{--bg:#f5f5f7;--fg:#1c1c1e;--card:#fff;--mut:#6b7280;--line:#e5e7eb;--acc:#2563eb;--warn:#b45309;--warnbg:#fef3c7}
@media(prefers-color-scheme:dark){:root{--bg:#0b0b0d;--fg:#f3f4f6;--card:#17171a;--mut:#9ca3af;--line:#2a2a30;--acc:#60a5fa;--warn:#fbbf24;--warnbg:#3a2a08}}
*{box-sizing:border-box}body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto}h1{margin:0 0 4px;font-size:1.5rem}.sub{color:var(--mut);margin-bottom:20px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:130px}
.stat b{display:block;font-size:1.4rem}.stat span{color:var(--mut);font-size:.85rem}
.host{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px}
.host h2{margin:0;font-size:1.05rem}.meta{color:var(--mut);font-size:.85rem;margin:2px 0 8px}
table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:5px 8px;border-top:1px solid var(--line)}th{color:var(--mut);font-weight:500}
.flag{background:var(--warnbg);color:var(--warn);border-radius:6px;padding:1px 7px;font-size:.78rem;white-space:nowrap}
.overflow{overflow-x:auto}
"""


def render(hosts, target):
    total_ports = sum(len(h["ports"]) for h in hosts)
    flagged = sum(1 for h in hosts for p in h["ports"] if p["port"] in RISKY)
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>Network report</title><style>{CSS}</style></head><body><main>",
           f"<h1>Network report</h1><div class='sub'>{escape(target)} &middot; generated {now}</div>",
           "<div class='stats'>",
           f"<div class='stat'><b>{len(hosts)}</b><span>hosts up</span></div>",
           f"<div class='stat'><b>{total_ports}</b><span>open ports</span></div>",
           f"<div class='stat'><b>{flagged}</b><span>ports to review</span></div></div>"]
    for h in hosts:
        title = escape(h["ip"]) + (f" &mdash; {escape(h['name'])}" if h["name"] else "")
        meta = " &middot; ".join(escape(x) for x in (
            f"MAC {h['mac']}" if h["mac"] else "", h["vendor"], h["os"]) if x)
        out.append(f"<section class='host'><h2>{title}</h2><div class='meta'>{meta or 'no extra info'}</div>")
        if h["ports"]:
            out.append("<div class='overflow'><table><tr><th>Port</th><th>Service</th><th>Version</th><th>Note</th></tr>")
            for p in h["ports"]:
                note = RISKY.get(p["port"])
                flag = f"<span class='flag'>{escape(note)}</span>" if note else ""
                out.append(f"<tr><td>{p['port']}/{escape(p['proto'])}</td><td>{escape(p['service'])}</td><td>{escape(p['version'])}</td><td>{flag}</td></tr>")
            out.append("</table></div>")
        else:
            out.append("<div class='meta'>No open ports found.</div>")
        out.append("</section>")
    out.append("</main></body></html>")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Generate an HTML report from an nmap scan of your own network.")
    ap.add_argument("target", nargs="?", help="IP or CIDR, e.g. 192.168.1.0/24")
    ap.add_argument("--xml", help="parse an existing nmap XML file instead of scanning")
    ap.add_argument("-o", "--output", default="report.html")
    ap.add_argument("--allow-public", action="store_true", help="allow non-private targets (only your own systems!)")
    args = ap.parse_args()

    if args.xml:
        with open(args.xml, encoding="utf-8") as f:
            xml_text, label = f.read(), args.xml
    elif args.target:
        check_target(args.target, args.allow_public)
        xml_text, label = run_nmap(args.target), args.target
    else:
        ap.error("give a target or --xml")

    hosts = parse(xml_text)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(render(hosts, label))
    print(f"Report written to {args.output} ({len(hosts)} hosts)")


if __name__ == "__main__":
    main()
