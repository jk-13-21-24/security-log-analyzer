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
