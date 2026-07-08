# IOC Scanner & Threat Intelligence Checker

A Python-based cybersecurity automation tool that analyzes Indicators of Compromise (IOCs) such as IP addresses, URLs, domains, and file hashes.

The project integrates with VirusTotal API to perform threat intelligence lookups, classify security risks, and store scan results for investigation and reporting.

---

# Features

## IOC Threat Intelligence Integration

The scanner integrates with the VirusTotal API to:

- Analyze IP addresses
- Retrieve threat intelligence information
- Collect antivirus detection statistics
- Identify malicious and suspicious indicators

---

## Threat Classification

The scanner analyzes VirusTotal results and classifies IOCs as:

- Clean
- Suspicious
- Malicious


---

## Security Logging

The project includes automated logging functionality:

- Stores scan results in JSON format
- Records IOC details
- Saves threat classification results
- Includes scan timestamps for investigation tracking

Example log file:
logs/
└── scan_results.json