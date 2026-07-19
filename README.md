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

## Command Line Input Support
The scanner supports custom IOC input files through command line arguments.

Example:
python scanner.py sample_IOCs.txt
or
python scanner.py custom_IOCs.txt

## Risk Scoring
The scanner calculates IOC risk using VirusTotal detection results.
Risk levels:

- Low
- Medium
- High
Risk scores are stored in scan reports.

Risk information includes:

- Risk score
- Risk level
- Detection counts

## IOC Analytics and Reporting
The scanner provides investigation summaries including:
### Scan summary
Example: 
===================================
Scan Summary
Total IOCs Scanned: 10
Clean: 6
Suspicious: 3
Malicious: 1

### IOC Type Distribution
Example:
IOC Type Distribution

IP Address: 4
Domain: 3
URL: 2
File Hash: 1
Unknown: 0
This provides visibility into the types of indicators being analyzed.

### Scan Performance Metrics
The scanner measures total scan execution time to provide performance visibility.

Example:
Scan completed in 4.27 seconds

## Error Handling

The scanner handles:

- Invalid IOCs
- VirusTotal API failures
- Network errors
- Unsupported IOC types
- Connection timeouts

The program continues scanning remaining indicators instead of stopping.

## Security Logging
Scan results are automatically stored in JSON format.
Logs include:
- IOC value
- IOC type
- Threat classification
- Risk score
- Risk level
- Malicious detections
- Suspicious detections
- Timestamp
Example log file:
logs/
└── scan_results.json

## CSV Report Export

The scanner can export results to CSV format for analysis in Excel or SIEM reporting workflows.

Generated report:
logs/
└── scan_results.csv

- CSV reports include:
- IOC value
- IOC type
- Status
- Risk score
- Risk level
- Detection counts
- Timestamp

## HTML Security Report

The scanner generates an HTML report for easy viewing in any web browser.

Generated file:
```
logs/
└── security_report.html
```

The report includes:
- Report generation timestamp
- Scan summary
- Total IOC count
- Clean, Suspicious, and Malicious totals
- IOC details table
- Risk scores
- Risk levels
- Detection statistics
- Improved HTML formatting for easier analysis

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
- IP Address Validation
- Base64 URL Encoding

# Current Capabilities

Multi-IOC scanning
IP, Domain, URL, and Hash detection
VirusTotal threat intelligence lookups
IOC normalization
IOC validation
Risk scoring
Batch scanning
JSON logging
CSV export
Command line input support
Scan performance metrics
IOC analytics and reporting
Error handling