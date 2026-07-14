# IOC Scanner & Threat Intelligence Checker

A Python-based cybersecurity automation tool that analyzes Indicators of Compromise (IOCs) such as IP addresses, URLs, domains, and file hashes.
The project integrates with VirusTotal API to perform threat intelligence lookups, classify security risks, and store scan results for investigation and reporting.


# Features

## Multi-IOC Threat Intelligence Analysis
The scanner supports:
- IP address analysis
- URL analysis
- Domain analysis
- File hash analysis

Using VirusTotal API, it retrieves:
- Antivirus detection statistics
- Threat intelligence information
- Security reputation data

## IOC Classification
Each IOC is classified as:
- Clean
- Suspicious
- Malicious
based on VirusTotal detection results.

## IOC Normalization

The scanner automatically cleans IOC input by:

- Removing extra spaces
- Converting input to lowercase
- Cleaning URL formatting

## Batch IOC Scanning
The scanner can process multiple IOCs from a file: sample_IOCs.txt
This allows faster investigation of multiple indicators, similar to SOC analyst workflows.

## Risk Scoring
The scanner calculates IOC risk using VirusTotal detection results.
Risk levels:

- Low
- Medium
- High

Risk scores are stored in scan reports.


## Security Logging
Scan results are automatically stored in JSON format.
Logs include:
- IOC value
- Threat classification
- Malicious detections
- Suspicious detections
- Timestamp
Example log file:
logs/
└── scan_results.json


## Major Updates
API error handling
Supported IOC types
Validation
Report output
Risk scoring

# Usage

Add IOCs to sample_IOCs.txt

Run:
```bash
python scanner.py
```

Results are saved automatically:
```bash
logs/scan_results.json
```

# Technologies Used
- Python
- Requests
- VirusTotal API
- JSON Logging
- Regular Expressions
