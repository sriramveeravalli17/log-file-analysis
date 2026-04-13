# 🔍 Log File Analyzer

> **SOC / VAPT Post-Exploitation Analysis Tool**  
> Detects brute-force attacks, suspicious IPs, and privilege escalation from system/auth logs.

[![CI](https://github.com/YOUR_USERNAME/log-file-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/log-file-analyzer/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 📌 Features

| Feature | Description |
|---|---|
| 🔴 Brute-Force Detection | Flags IPs exceeding a configurable failed-login threshold |
| 🟠 Privilege Escalation | Detects `sudo`, `su`, `pkexec` abuse |
| 🟡 Invalid User Enumeration | Tracks attempts on non-existent accounts |
| 🟢 Successful Login Tracking | Logs accepted authentications for correlation |
| 📄 JSON Report | Structured output for downstream VAPT documentation |
| ✅ CI/CD Pipeline | Auto-tests on every push via GitHub Actions |

---

## 📁 Project Structure

```
log-file-analyzer/
├── analyzer.py          # Main analysis script
├── test_analyzer.py     # Pytest unit tests
├── sample_auth.log      # Sample log for testing
├── requirements.txt     # Python dependencies
├── .github/
│   └── workflows/
│       └── ci.yml       # GitHub Actions CI pipeline
└── README.md
```

---

## 🚀 Usage

### Basic
```bash
python analyzer.py sample_auth.log
```

### Custom threshold
```bash
python analyzer.py /var/log/auth.log --threshold 3
```

### Save report to custom path
```bash
python analyzer.py /var/log/auth.log --output /tmp/vapt_report.json
```

### JSON only (no terminal output)
```bash
python analyzer.py sample_auth.log --json-only
```

### Help
```bash
python analyzer.py --help
```

---

## 🧪 Running Tests

```bash
pip install -r requirements.txt
pytest test_analyzer.py -v
```

---

## 📤 Deploy to GitHub — Step by Step

### Step 1 — Create a new GitHub repository

1. Go to [github.com/new](https://github.com/new)
2. Repository name: `log-file-analyzer`
3. Set to **Public** (so CI badge works)
4. Do **NOT** initialize with README (you already have one)
5. Click **Create repository**

---

### Step 2 — Set up Git locally

```bash
# Navigate to the project folder
cd log-file-analyzer

# Initialize git
git init

# Add all files
git add .

# First commit
git commit -m "feat: initial commit — log file analyzer with CI"
```

---

### Step 3 — Push to GitHub

```bash
# Add your GitHub repo as remote (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/log-file-analyzer.git

# Rename branch to main
git branch -M main

# Push
git push -u origin main
```

---

### Step 4 — Verify CI is running

1. Go to your repo on GitHub
2. Click the **Actions** tab
3. You should see **"Log Analyzer CI"** running automatically
4. It will test on Python 3.9, 3.10, and 3.11
5. On success → green ✅ badge

---

### Step 5 — Update the badge in README

Replace `YOUR_USERNAME` in the badge URL at the top of this README:

```md
[![CI](https://github.com/YOUR_USERNAME/log-file-analyzer/actions/workflows/ci.yml/badge.svg)](...)
```

Then push again:

```bash
git add README.md
git commit -m "docs: update badge URL"
git push
```

---

## 🛡️ Supported Log Formats

- `/var/log/auth.log` (Ubuntu/Debian)
- `/var/log/secure` (CentOS/RHEL)
- Custom logs matching sshd / sudo / PAM patterns

---

## 📊 Sample Output

```
════════════════════════════════════════════════════════════
  LOG FILE ANALYZER — VAPT/SOC REPORT
  Source : sample_auth.log
════════════════════════════════════════════════════════════

[SUMMARY]
  Lines parsed              : 28
  Failed login events       : 16
  Successful logins         : 3
  Privilege escalations     : 3
  Unique attacker IPs       : 3

────────────────────────────────────────────────────────────
[!] BRUTE-FORCE DETECTED — 2 IP(s)
────────────────────────────────────────────────────────────
  [CRITICAL] 192.168.1.100
         Attempts : 8
         Targets  : root, admin, ubuntu, pi
  [HIGH] 45.33.32.156
         Attempts : 6
         Targets  : root

[!] PRIVILEGE ESCALATION EVENTS — 3
  [HIGH] Apr  1 10:03:00 — user: deploy  Command: /bin/bash
  [HIGH] Apr  1 10:03:05 — user: deploy  Command: /usr/bin/cat /etc/shadow
  [HIGH] Apr  1 10:06:00 — user: www-data  Command: /bin/sh
```

---

## 🤝 Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m 'feat: add X'`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📜 License

MIT © 2024
