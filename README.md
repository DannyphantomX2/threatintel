# ThreatIntel

A command-line threat intelligence tool that queries VirusTotal to investigate IPs, domains, and file hashes, scores verdicts, and generates structured PDF reports.

[![asciicast](https://asciinema.org/a/qxdc9h44IEEyf3UP.svg)](https://asciinema.org/a/qxdc9h44IEEyf3UP)

---

## Features

- **IP Investigation** — query reputation, geolocation, ASN, and vendor verdicts for any IP address
- **Domain Investigation** — assess domains against 90+ security vendors via VirusTotal
- **File Hash Investigation** — look up MD5, SHA-1, or SHA-256 hashes for known malware
- **VirusTotal Integration** — uses the VirusTotal v3 API for all lookups
- **Verdict Scoring** — automatic Clean, Suspicious, or Malicious classification based on vendor detections
- **PDF Report Generation** — produces a structured, timestamped PDF report for each scan

---

## Requirements

- Python 3.8+
- [requests](https://pypi.org/project/requests/)
- [reportlab](https://pypi.org/project/reportlab/)
- A [VirusTotal API key](https://www.virustotal.com/gui/join-us) (free tier supported)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/youruser/threatintel.git
cd threatintel

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install requests reportlab

# Set your VirusTotal API key
export VT_API_KEY="your_api_key_here"
```

To persist the API key across sessions, add the export line to your `~/.bashrc` or `~/.zshrc`.

---

## Usage

```bash
# Investigate an IP address
python3 threatintel.py --ip 185.220.101.45

# Investigate a domain
python3 threatintel.py --domain google.com

# Investigate a file hash
python3 threatintel.py --hash <file_hash>

# Save the PDF report to a specific directory
python3 threatintel.py --ip 185.220.101.45 --output ./reports
```

### All Arguments

| Argument | Description | Default |
|---|---|---|
| `--ip` | IP address to investigate | |
| `--domain` | Domain to investigate | |
| `--hash` | MD5, SHA-1, or SHA-256 file hash to investigate | |
| `--output` | Directory to save the PDF report | `.` |

---

## Sample Output

```
Querying VirusTotal for IP: 185.220.101.45

  Target       : 185.220.101.45
  Type         : IP
  Country      : DE
  AS Owner     : Tor Exit Node Operator
  Network      : 185.220.101.0/24
  Reputation   : -82
  Malicious    : 16
  Suspicious   : 3
  Total Vendors: 93

VERDICT: MALICIOUS (16/93 vendors)

Report saved: threat_185_220_101_45_20250601_143022.pdf
```

---

## Verdict Scoring

Verdicts are calculated from the number of vendors that flag the target as malicious.

| Verdict | Malicious Detections | Action |
|---|---|---|
| **CLEAN** | 0 | No action required |
| **SUSPICIOUS** | 1 to 5 | Monitor and investigate further |
| **MALICIOUS** | 6 or more | Block immediately, initiate incident response |

---

## PDF Report

Each scan generates a timestamped PDF named `threat_[target]_[TIMESTAMP].pdf`. The report contains five sections.

**Section 1 — Header.** Target, target type, scan date, and tool version.

**Section 2 — Verdict Banner.** Color-coded verdict: green for Clean, amber for Suspicious, red for Malicious.

**Section 3 — Analysis Summary.** Table of malicious, suspicious, harmless, and undetected counts alongside total vendors queried.

**Section 4 — Raw Intelligence.** Key fields returned by VirusTotal: country, AS owner, network, reputation score for IPs and domains; file name, file type, and file size for hashes.

**Section 5 — Recommendations.** One paragraph of actionable guidance based on the verdict.

---

## Tech Stack

| Component | Library |
|---|---|
| CLI argument parsing | `argparse` (stdlib) |
| VirusTotal API queries | `requests` |
| PDF generation | `reportlab` |
| Verdict logic | Custom scoring in `threatintel.py` |

### File Structure

```
threatintel/
├── threatintel.py   # CLI entry point and verdict logic
├── virustotal.py    # VirusTotal API wrapper functions
├── report.py        # PDF report generator
└── README.md
```

---

## Disclaimer

ThreatIntel is intended for authorized security research, threat analysis, and defensive operations only. Do not use this tool against targets you do not have explicit permission to investigate. The authors accept no liability for misuse.
