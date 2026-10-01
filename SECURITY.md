# Security Policy

## Scope

Pawprint is a **read-only reporting tool** — it does not modify any systems. It runs nmap against networks you specify and generates an HTML/JSON report.

If you discover a vulnerability in Pawprint itself (e.g. code injection via crafted nmap XML, path traversal in output filename handling), please report it responsibly.

## Reporting a Vulnerability

Open a [GitHub issue](https://github.com/Hackercat-git/Pawprint/issues) marked **[SECURITY]** in the title, or contact via the email on the profile page.

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact

I aim to respond within 5 business days.

## Responsible Use

This tool is intended **only for scanning networks you own or have explicit written permission to test.** Misuse may violate computer crime laws in your jurisdiction. The `--allow-public` flag exists solely for authorised testing of your own infrastructure.
