# netscan-report

Turns an nmap scan of your own network into a clean, self-contained HTML report (light/dark, mobile friendly). Open ports on risky services are flagged for review.

## Usage

    python netscan_report.py 192.168.1.0/24 -o report.html
    python netscan_report.py --xml scan.xml -o report.html

Requires Python 3.8+ and (for live scans) nmap. No other dependencies.

## Safety

Only scan networks you own or are authorised to test. Public targets are refused unless `--allow-public` is passed.

## License

MIT
