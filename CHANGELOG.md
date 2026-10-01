# Changelog

All notable changes to Pawprint are documented here.

## [1.1.0] - 2026-10-01

### Added
- Collapsible host sections (`<details>/<summary>`) for large-network readability
- Inline JS filter: search by IP, hostname, service; risky-only toggle
- Sortable table columns (click any header)
- Timestamped default output filename (`pawprint_<date>_<time>.html`)
- `--os` flag for OS detection (requires root/sudo)
- `--ports` flag to specify port range(s)
- `--timing` flag for nmap timing template (0–5)
- `--json` flag to export machine-readable JSON output
- `--cve` flag for NVD CVE hint lookup per service/version
- `--nvd-key` flag for NVD API key (bypasses rate limiting)
- `--verbose` / `--quiet` logging flags (replaces bare `print` statements)
- `defusedxml` support for safe XML parsing (falls back to stdlib)
- `SECURITY.md`, `CHANGELOG.md`, `pyproject.toml`, `requirements.txt`
- `test_pawprint.py` — 15 pytest tests (parse, render, check_target, RISKY)
- Extended RISKY port dict (+SSH, SMTP, HTTP, HTTP-alt, port 8080)

### Changed
- Public IP validation now correctly parses full `ip_network` objects
- Host cards now show OS accuracy percentage when available
- Report title updated to "🐾 Pawprint — Network Report"

### Fixed
- README renamed from "netscan-report" to "Pawprint" throughout

## [1.0.0] - 2026-09-26

### Added
- Initial release: nmap XML → self-contained HTML report
- Light/dark mode, mobile-friendly layout
- Risky port flagging (14 services)
- `--xml` for parsing existing scan files
- `--allow-public` safety override
