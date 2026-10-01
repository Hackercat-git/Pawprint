"""Basic tests for Pawprint — run with: python -m pytest test_pawprint.py -v"""

import pathlib
import pytest
from pawprint import parse, render, check_target, RISKY

SAMPLE_XML = pathlib.Path(__file__).parent / "sample_scan.xml"


# ---------------------------------------------------------------------------
# parse()
# ---------------------------------------------------------------------------
def test_parse_returns_list():
    if not SAMPLE_XML.exists():
        pytest.skip("sample_scan.xml not found")
    hosts = parse(SAMPLE_XML.read_text(encoding="utf-8"))
    assert isinstance(hosts, list)


def test_parse_host_keys():
    if not SAMPLE_XML.exists():
        pytest.skip("sample_scan.xml not found")
    hosts = parse(SAMPLE_XML.read_text(encoding="utf-8"))
    if hosts:
        h = hosts[0]
        for key in ("ip", "name", "mac", "vendor", "os", "ports"):
            assert key in h, f"missing key '{key}' in host dict"


def test_parse_port_keys():
    if not SAMPLE_XML.exists():
        pytest.skip("sample_scan.xml not found")
    hosts = parse(SAMPLE_XML.read_text(encoding="utf-8"))
    for h in hosts:
        for p in h["ports"]:
            for key in ("port", "proto", "service", "version"):
                assert key in p


def test_parse_ports_sorted():
    if not SAMPLE_XML.exists():
        pytest.skip("sample_scan.xml not found")
    hosts = parse(SAMPLE_XML.read_text(encoding="utf-8"))
    for h in hosts:
        ports = [p["port"] for p in h["ports"]]
        assert ports == sorted(ports), "ports not sorted ascending"


def test_parse_invalid_xml_exits():
    import sys
    with pytest.raises(SystemExit):
        parse("this is not xml")


# ---------------------------------------------------------------------------
# render()
# ---------------------------------------------------------------------------
MINIMAL_HOST = [{
    "ip": "192.168.1.1", "name": "router", "mac": "AA:BB:CC:DD:EE:FF",
    "vendor": "Acme", "os": "Linux 5.x", "os_acc": "95",
    "ports": [
        {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 9.0"},
        {"port": 445, "proto": "tcp", "service": "microsoft-ds", "version": ""},
    ],
}]


def test_render_returns_html():
    html = render(MINIMAL_HOST, "192.168.1.0/24")
    assert html.startswith("<!doctype html")
    assert "</html>" in html


def test_render_contains_ip():
    html = render(MINIMAL_HOST, "192.168.1.0/24")
    assert "192.168.1.1" in html


def test_render_flags_risky_port():
    html = render(MINIMAL_HOST, "192.168.1.0/24")
    assert "⚠️" in html  # port 445 is in RISKY


def test_render_escapes_html():
    host = [{
        "ip": "10.0.0.1", "name": "<script>alert(1)</script>", "mac": "",
        "vendor": "", "os": "", "os_acc": "", "ports": [],
    }]
    html = render(host, "10.0.0.0/24")
    assert "<script>alert(1)</script>" not in html


def test_render_no_ports_message():
    host = [{
        "ip": "10.0.0.2", "name": "", "mac": "", "vendor": "",
        "os": "", "os_acc": "", "ports": [],
    }]
    html = render(host, "10.0.0.0/24")
    assert "No open ports found" in html


# ---------------------------------------------------------------------------
# check_target()
# ---------------------------------------------------------------------------
def test_check_target_private_ok():
    check_target("192.168.1.0/24", allow_public=False)  # should not raise


def test_check_target_loopback_ok():
    check_target("127.0.0.1", allow_public=False)


def test_check_target_public_blocked():
    with pytest.raises(SystemExit):
        check_target("8.8.8.8", allow_public=False)


def test_check_target_public_allowed():
    check_target("8.8.8.8", allow_public=True)  # should not raise


def test_check_target_invalid():
    with pytest.raises(SystemExit):
        check_target("not-an-ip", allow_public=False)


# ---------------------------------------------------------------------------
# RISKY dict sanity
# ---------------------------------------------------------------------------
def test_risky_values_are_strings():
    for port, msg in RISKY.items():
        assert isinstance(port, int)
        assert isinstance(msg, str) and len(msg) > 0
