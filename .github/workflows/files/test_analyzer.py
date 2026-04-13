"""
Unit tests for the Log File Analyzer.
Run: pytest test_analyzer.py -v
"""

import json
import pytest
import tempfile
import os
from analyzer import parse_log, analyze, PATTERNS


# ─── FIXTURES ─────────────────────────────────────────────────────────────────

SAMPLE_LOG = """\
Apr  1 10:00:01 server sshd[1]: Failed password for root from 192.168.1.100 port 22 ssh2
Apr  1 10:00:03 server sshd[1]: Failed password for root from 192.168.1.100 port 22 ssh2
Apr  1 10:00:05 server sshd[1]: Failed password for root from 192.168.1.100 port 22 ssh2
Apr  1 10:00:07 server sshd[1]: Failed password for admin from 192.168.1.100 port 22 ssh2
Apr  1 10:00:09 server sshd[1]: Failed password for admin from 192.168.1.100 port 22 ssh2
Apr  1 10:01:00 server sshd[1]: Invalid user oracle from 10.0.0.55
Apr  1 10:02:00 server sshd[1]: Accepted password for deploy from 203.0.113.42 port 51234 ssh2
Apr  1 10:03:00 server sudo[2]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Apr  1 10:04:00 server sshd[1]: Failed password for root from 45.33.32.156 port 22 ssh2
Apr  1 10:04:02 server sshd[1]: Failed password for root from 45.33.32.156 port 22 ssh2
"""

@pytest.fixture
def temp_log():
    """Write sample log to a temp file and return path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_LOG)
        path = f.name
    yield path
    os.unlink(path)


# ─── PARSE TESTS ──────────────────────────────────────────────────────────────

def test_parse_counts_lines(temp_log):
    events = parse_log(temp_log)
    assert events["raw_line_count"] == 10

def test_parse_detects_failed_logins(temp_log):
    events = parse_log(temp_log)
    assert len(events["failed_login"]) == 7  # 5 from .100, 2 from .156

def test_parse_detects_successful_login(temp_log):
    events = parse_log(temp_log)
    assert len(events["successful_login"]) >= 1

def test_parse_detects_privilege_escalation(temp_log):
    events = parse_log(temp_log)
    assert len(events["privilege_escalation"]) >= 1

def test_parse_detects_invalid_users(temp_log):
    events = parse_log(temp_log)
    assert len(events["invalid_user"]) >= 1

def test_parse_nonexistent_file():
    with pytest.raises(SystemExit):
        parse_log("/nonexistent/path/to/file.log")


# ─── ANALYZE TESTS ────────────────────────────────────────────────────────────

def test_brute_force_detection(temp_log):
    events = parse_log(temp_log)
    findings = analyze(events, threshold=5)
    brute_ips = [e["ip"] for e in findings["brute_force_ips"]]
    assert "192.168.1.100" in brute_ips

def test_below_threshold_not_brute_force(temp_log):
    events = parse_log(temp_log)
    findings = analyze(events, threshold=5)
    brute_ips = [e["ip"] for e in findings["brute_force_ips"]]
    assert "45.33.32.156" not in brute_ips  # only 2 attempts

def test_suspicious_ip_collected(temp_log):
    events = parse_log(temp_log)
    findings = analyze(events, threshold=5)
    suspicious_ips = [e["ip"] for e in findings["suspicious_ips"]]
    assert "45.33.32.156" in suspicious_ips

def test_privilege_escalation_in_findings(temp_log):
    events = parse_log(temp_log)
    findings = analyze(events, threshold=5)
    assert len(findings["privilege_escalations"]) >= 1

def test_stats_populated(temp_log):
    events = parse_log(temp_log)
    findings = analyze(events, threshold=5)
    stats = findings["stats"]
    assert stats["total_failed_logins"] > 0
    assert stats["brute_force_threshold"] == 5
    assert stats["total_lines_parsed"] == 10

def test_threshold_change_affects_findings(temp_log):
    events = parse_log(temp_log)
    findings_low = analyze(events, threshold=2)
    findings_high = analyze(events, threshold=10)
    # Lower threshold → more brute-force IPs flagged
    assert len(findings_low["brute_force_ips"]) >= len(findings_high["brute_force_ips"])

def test_targeted_users_listed(temp_log):
    events = parse_log(temp_log)
    findings = analyze(events, threshold=5)
    for entry in findings["brute_force_ips"]:
        if entry["ip"] == "192.168.1.100":
            assert "root" in entry["targeted_users"]
            assert "admin" in entry["targeted_users"]

def test_severity_critical_for_high_count():
    # Synthetic: 20 failed logins from one IP
    events = {
        "failed_logins": [{"ip": "1.2.3.4", "user": "root"} for _ in range(20)],
        "successful_logins": [],
        "privilege_escalations": [],
        "invalid_users": [],
        "port_scans": [],
        "raw_line_count": 20,
    }
    findings = analyze(events, threshold=5)
    brute = findings["brute_force_ips"]
    assert len(brute) == 1
    assert brute[0]["severity"] == "CRITICAL"
