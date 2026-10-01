# 🐾 Pawprint

**Pawprint** turns an nmap scan of your own network into a clean, self-contained HTML report — with light/dark mode, mobile-friendly layout, collapsible hosts, live filtering, sortable columns, and automatic flagging of risky open ports.

> ⚠️ Only scan networks and devices **you own or are authorised to test.**

---

## Features

- 🔍 **Live scan or existing XML** — run nmap directly or parse a saved `-oX` file
- 🌓 **Light/dark mode** — respects `prefers-color-scheme`
- 📱 **Mobile-friendly** — responsive layout
- 📂 **Collapsible host sections** — clean overview for large networks
- 🔎 **Inline filter + search** — filter by IP, hostname, service, or risky-only toggle
- ↕️ **Sortable columns** — click any table header to sort
- ⚠️ **Risky port flags** — 18 common dangerous services highlighted automatically
- 🖥️ **OS detection** — optional with `--os` (requires root/sudo)
- 📄 **JSON export** — `--json` writes machine-readable output alongside the HTML
- 🔐 **CVE hints** — `--cve` fetches CVE summaries from NVD per service/version
- 🕒 **Timestamped filenames** — default output is `pawprint_2026-10-01_1430.html`
- 🛡️ **Safe XML parsing** — uses `defusedxml` when installed
- 📋 **Logging** — `--verbose` / `--quiet` flags

---

## Sample output

Want to see what a report looks like before running it?
👉 **[View sample report](https://htmlpreview.github.io/?https://github.com/Hackercat-git/Pawprint/blob/main/sample_report.html)** — generated from the included `sample_scan.xml`

---

## Installation

**Requirements:** Python 3.8+, and `nmap` installed for live scans.

```bash
git clone https://github.com/Hackercat-git/Pawprint.git
cd Pawprint
pip install -r requirements.txt
```

---

## Usage

```bash
# Live scan of a subnet
python pawprint.py 192.168.1.0/24

# Parse an existing nmap XML file
python pawprint.py --xml scan.xml

# Specify output file
python pawprint.py 192.168.1.0/24 -o my_report.html

# Scan specific ports with OS detection
python pawprint.py 192.168.1.0/24 --ports 1-1024 --os

# Export JSON alongside HTML
python pawprint.py 192.168.1.0/24 --json results.json

# Fetch CVE hints from NVD (requires internet + optional API key)
python pawprint.py --xml scan.xml --cve --nvd-key YOUR_KEY_HERE

# Verbose output
python pawprint.py 192.168.1.0/24 --verbose

# Allow public targets (only your own systems!)
python pawprint.py 1.2.3.4 --allow-public
```

### All flags

| Flag | Description |
|------|-------------|
| `target` | IP or CIDR to scan (e.g. `192.168.1.0/24`) |
| `--xml FILE` | Parse an existing `nmap -oX` file instead of scanning |
| `-o / --output FILE` | Output HTML filename (default: `pawprint_<timestamp>.html`) |
| `--json FILE` | Also write JSON output |
| `--ports RANGE` | Port range, e.g. `1-1024` or `22,80,443` |
| `--timing {0-5}` | nmap timing template (default: 4) |
| `--os` | Enable OS detection (requires root/sudo) |
| `--cve` | Fetch CVE hints from NVD per service/version |
| `--nvd-key KEY` | NVD API key to bypass rate limiting |
| `--allow-public` | Allow non-private targets |
| `--verbose` | Show debug output |
| `--quiet` | Suppress all output except errors |

---

## Running tests

```bash
pip install pytest
pytest test_pawprint.py -v
```

---

## Safety

- Public IP ranges are **refused by default** — use `--allow-public` only for systems you own
- XML is parsed with `defusedxml` when installed (protects against XML entity attacks)
- No data is sent anywhere unless you use `--cve` (NVD API)

---

## Legal disclaimer

> **Pawprint is provided for authorised use only.**
>
> You may only use this tool to scan networks and devices that you own or have **explicit written permission** to test. Scanning systems without authorisation may violate computer crime laws in your jurisdiction (including but not limited to the Dutch *Computer Crime Act*, the EU NIS2 Directive, and the US Computer Fraud and Abuse Act).
>
> The author(s) of Pawprint accept **no liability** for any damage, legal consequences, or misuse arising from the use of this tool. Use responsibly.


## License

MIT — see [LICENSE](LICENSE)
