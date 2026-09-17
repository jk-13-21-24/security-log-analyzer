# 🔎 Security Log Analyzer

A Python-based authentication log analysis and detection
tool designed for SOC and cybersecurity learning.

The project parses Linux SSH authentication logs,
normalizes security events, detects suspicious
authentication behavior, maps detections to MITRE ATT&CK,
and generates SOC-style incident reports.

---

## 🎯 Project Goals

This project demonstrates practical security operations
concepts including:

- Security log analysis
- Authentication monitoring
- Brute-force detection
- Password-spraying detection
- Detection engineering
- MITRE ATT&CK mapping
- Incident reporting
- Python automation
- Automated testing

---

✨ Features
Authentication Log Parsing

The parser extracts:

  Timestamp
  Hostname
  Event type
  Username
  Source IP address
  Source port

Supported authentication events include:

  Failed login
  Successful login
  Invalid user

---

🔬 Example Investigation

When a detection is generated, the analyzer produces
a Markdown incident report containing:

  Incident ID
  Detection name
  Severity
  Source IP
  Target accounts
  Attempt count
  MITRE ATT&CK mapping
  Investigation recommendations
  Incident status

---

⚠️ Disclaimer

This project is intended for cybersecurity education,
authorized security testing, and defensive research.

Only analyze systems, networks, logs, and data that you
own or have explicit permission to examine.

---

👤 Author

JK

Cybersecurity-focused developer interested in:

SOC Operations
Detection Engineering
Digital Forensics
Incident Response
Security Automation
Threat Detection

---

⭐ If you find this project useful, consider giving
the repository a star.

---

## 🏗️ Architecture

```text
                    Authentication Logs
                            │
                            ▼
                    ┌───────────────┐
                    │     Parser    │
                    └───────┬───────┘
                            │
                            ▼
                    Normalized Events
                            │
                            ▼
                  ┌──────────────────┐
                  │ Detection Engine │
                  └────────┬─────────┘
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
         SSH Brute Force       Password Spraying
                │                     │
                ▼                     ▼
              T1110                T1110.003
                │                     │
                └──────────┬──────────┘
                           ▼
                    Security Alerts
                           │
                           ▼
                   Incident Reporter
                           │
                           ▼
                   Markdown Reports


