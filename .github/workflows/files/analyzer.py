#!/usr/bin/env python3
"""
Log File Analyzer - SOC/VAPT Post-Exploitation Analysis Tool
Detects brute-force attempts, suspicious IPs, and privilege escalation events.
"""

import re
import sys
import json
import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ─── CONFIG ───────────────────────────────────────────────────────────────────

DEFAULT_BRUTE_FORCE_THRESHOLD = 5   # failed logins before flagging
DEFAULT_OUTPUT = "report.json"


# ─── PATTERNS ─────────────────────────────────────────────────────────────────

TS = r'(?P<timestamp>\w+ +\d+ \d+:\d+:\d+)'  # handles "Apr  1" (double space) and "Apr 10"

PATTERNS = {
    "failed_login": [
        # sshd / auth.log style
        re.compile(TS + r'.*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
        # sudo / pam style
        re.compile(TS + r'.*authentication failure.*user=(?P<user>\S+).*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)'),
        # generic
        re.compile(TS + r'.*FAILED LOGIN.*FROM (?P<ip>\d+\.\d+\.\d+\.\d+).*USER (?P<user>\S+)'),
    ],
    "successful_login": [
        re.compile(TS + r'.*Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
        re.compile(TS + r'.*session opened for user (?P<user>\S+).*by (?P<by>\S+)'),
    ],
    "privilege_escalation": [
        re.compile(TS + r'.*sudo\[\d+\]: (?P<user>\S+).*COMMAND=(?P<cmd>.+)'),
        re.compile(TS + r'.*su\[.*\].*Successful su for (?P<user>\S+) by (?P<by>\S+)'),
        re.compile(TS + r'.*(pkexec|doas).*root'),
    ],
    "invalid_user": [
        re.compile(TS + r'.*Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
    ],
    "port_scan": [
        re.compile(TS + r'.*(?:connection attempt|refused|REJECT).*from (?P<ip>\d+\.\d+\.\d+\.\d+).*port (?P<port>\d+)'),
    ],
}


# ─── PARSER ───────────────────────────────────────────────────────────────────

def parse_log(filepath: str) -> dict:
    """Parse a log file and return structured event data."""
    path = Path(filepath)
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    events = {
        "failed_login": [],
        "successful_login": [],
        "privilege_escalation": [],
        "invalid_user": [],
        "port_scan": [],
        "raw_line_count": 0,
    }

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            events["raw_line_count"] += 1
            line = line.strip()

            for event_type, pattern_list in PATTERNS.items():
                for pattern in pattern_list:
                    match = pattern.search(line)
                    if match:
                        record = match.groupdict()
                        record["raw"] = line
                        events[event_type].append(record)
                        break  # first matching pattern wins

    return events


# ─── ANALYSIS ─────────────────────────────────────────────────────────────────

def analyze(events: dict, threshold: int) -> dict:
    """Run analysis and produce findings."""
    findings = {
        "brute_force_ips": [],
        "suspicious_ips": [],
        "privilege_escalation": [],
        "invalid_user_attempts": [],
        "successful_login": [],
        "stats": {},
    }

    # --- Failed login counting per IP ---
    ip_fail_count = defaultdict(int)
    ip_fail_users = defaultdict(set)
    for event in events["failed_login"]:
        ip = event.get("ip", "unknown")
        user = event.get("user", "unknown")
        ip_fail_count[ip] += 1
        ip_fail_users[ip].add(user)

    for ip, count in ip_fail_count.items():
        entry = {
            "ip": ip,
            "failed_attempts": count,
            "targeted_users": list(ip_fail_users[ip]),
            "severity": "CRITICAL" if count >= threshold * 3 else "HIGH" if count >= threshold else "MEDIUM",
        }
        if count >= threshold:
            findings["brute_force_ips"].append(entry)
        else:
            findings["suspicious_ips"].append(entry)

    # Sort by count descending
    findings["brute_force_ips"].sort(key=lambda x: x["failed_attempts"], reverse=True)
    findings["suspicious_ips"].sort(key=lambda x: x["failed_attempts"], reverse=True)

    # --- Privilege escalation ---
    for event in events["privilege_escalation"]:
        findings["privilege_escalation"].append({
            "timestamp": event.get("timestamp", ""),
            "user": event.get("user") or event.get("by", "unknown"),
            "command": event.get("cmd", "unknown"),
            "raw": event.get("raw", ""),
            "severity": "HIGH",
        })

    # --- Invalid user attempts ---
    invalid_user_count = defaultdict(int)
    for event in events["invalid_user"]:
        key = f"{event.get('user','?')}@{event.get('ip','?')}"
        invalid_user_count[key] += 1

    for key, count in invalid_user_count.items():
        user, ip = key.split("@", 1)
        findings["invalid_user_attempts"].append({
            "user": user, "ip": ip, "count": count, "severity": "MEDIUM"
        })

    # --- Successful logins ---
    for event in events["successful_login"]:
        findings["successful_login"].append({
            "timestamp": event.get("timestamp", ""),
            "user": event.get("user", "unknown"),
            "ip": event.get("ip", "local"),
        })

    # --- Stats ---
    findings["stats"] = {
        "total_lines_parsed": events["raw_line_count"],
        "total_failed_logins": len(events["failed_login"]),
        "total_successful_logins": len(events["successful_login"]),
        "total_privilege_escalations": len(events["privilege_escalation"]),
        "total_invalid_user_attempts": len(events["invalid_user"]),
        "brute_force_threshold": threshold,
        "unique_attacker_ips": len(ip_fail_count),
        "brute_force_ips_count": len(findings["brute_force_ips"]),
    }

    return findings


# ─── REPORT ───────────────────────────────────────────────────────────────────

def print_report(findings: dict, source_file: str):
    """Print a human-readable report to stdout."""
    sep = "─" * 60
    stats = findings["stats"]

    print(f"\n{'═'*60}")
    print(f"  LOG FILE ANALYZER — VAPT/SOC REPORT")
    print(f"  Source : {source_file}")
    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*60}\n")

    print(f"[SUMMARY]")
    print(f"  Lines parsed              : {stats['total_lines_parsed']}")
    print(f"  Failed login events       : {stats['total_failed_logins']}")
    print(f"  Successful logins         : {stats['total_successful_logins']}")
    print(f"  Privilege escalations     : {stats['total_privilege_escalations']}")
    print(f"  Invalid user attempts     : {stats['total_invalid_user_attempts']}")
    print(f"  Unique attacker IPs       : {stats['unique_attacker_ips']}")
    print(f"  Brute-force threshold     : {stats['brute_force_threshold']} attempts")
    print()

    # Brute force
    if findings["brute_force_ips"]:
        print(f"{sep}")
        print(f"[!] BRUTE-FORCE DETECTED — {len(findings['brute_force_ips'])} IP(s)")
        print(f"{sep}")
        for entry in findings["brute_force_ips"]:
            print(f"  [{entry['severity']}] {entry['ip']}")
            print(f"         Attempts : {entry['failed_attempts']}")
            print(f"         Targets  : {', '.join(entry['targeted_users'])}")
        print()
    else:
        print("[✓] No brute-force IPs detected above threshold.\n")

    # Privilege escalation
    if findings["privilege_escalation"]:
        print(f"{sep}")
        print(f"[!] PRIVILEGE ESCALATION EVENTS — {len(findings['privilege_escalation'])}")
        print(f"{sep}")
        for e in findings["privilege_escalation"]:
            print(f"  [{e['severity']}] {e['timestamp']} — user: {e['user']}")
            if e['command'] != "unknown":
                print(f"         Command: {e['command']}")
        print()

    # Suspicious (below threshold)
    if findings["suspicious_ips"]:
        print(f"{sep}")
        print(f"[~] SUSPICIOUS IPs (below threshold) — {len(findings['suspicious_ips'])}")
        print(f"{sep}")
        for entry in findings["suspicious_ips"][:10]:  # top 10
            print(f"  [{entry['severity']}] {entry['ip']} — {entry['failed_attempts']} failed attempt(s)")
        print()

    print(f"{'═'*60}")
    print("  Report complete. JSON saved to report.json")
    print(f"{'═'*60}\n")


def save_json(findings: dict, output_path: str, source_file: str):
    """Save findings as structured JSON."""
    report = {
        "meta": {
            "tool": "Log File Analyzer",
            "version": "1.0.0",
            "source_file": source_file,
            "generated_at": datetime.now().isoformat(),
        },
        "findings": findings,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] JSON report saved → {output_path}")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log File Analyzer — SOC/VAPT Post-Exploitation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer.py /var/log/auth.log
  python analyzer.py sample_auth.log --threshold 3
  python analyzer.py sample_auth.log --output my_report.json
        """
    )
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--threshold", type=int, default=DEFAULT_BRUTE_FORCE_THRESHOLD,
                        help=f"Brute-force detection threshold (default: {DEFAULT_BRUTE_FORCE_THRESHOLD})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"Output JSON report path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--json-only", action="store_true",
                        help="Skip terminal report, only save JSON")

    args = parser.parse_args()

    print(f"[*] Parsing log file: {args.logfile}")
    events = parse_log(args.logfile)
    print(f"[*] Analyzing {events['raw_line_count']} lines...")
    findings = analyze(events, args.threshold)

    if not args.json_only:
        print_report(findings, args.logfile)

    save_json(findings, args.output, args.logfile)


if __name__ == "__main__":
    main()
