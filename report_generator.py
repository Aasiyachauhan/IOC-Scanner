import csv
import json
from datetime import datetime


def export_to_csv():

    with open("logs/scan_results.json", "r") as file:
        data = json.load(file)

    if not data:
        print("No scan results available.")
        return

    fieldnames = [
        "ioc",
        "status",
        "risk_score",
        "risk_level",
        "malicious",
        "suspicious",
        "harmless",
        "timestamp"
    ]

    with open("logs/scan_results.csv", "w", newline="") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(data)

    print("CSV report generated successfully.")


def generate_html_report():

    with open("logs/scan_results.json", "r") as file:
        data = json.load(file)

    if not data:
        print("No scan results available.")
        return

    # Calculate summary statistics

    total = len(data)

    clean = 0
    suspicious = 0
    malicious = 0

    for result in data:

        if result.get("status") == "Clean":
            clean += 1

        elif result.get("status") == "Suspicious":
            suspicious += 1

        elif result.get("status") == "Malicious":
            malicious += 1

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""
    <html>
    <head>
        <title>IOC Scanner Security Report</title>

        <style>

        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f4f4f4;
        }}

        h1 {{
            color: #1f2937;
        }}

        .summary {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
            background: white;
        }}

        th, td {{
            border: 1px solid #d1d5db;
            padding: 10px;
            text-align: left;
        }}

        th {{
            background-color: #374151;
            color: white;
        }}

        .clean {{
            color: green;
            font-weight: bold;
        }}

        .suspicious {{
            color: orange;
            font-weight: bold;
        }}

        .malicious {{
            color: red;
            font-weight: bold;
        }}

        </style>
    </head>

    <body>

    <h1>IOC Scanner Security Report</h1>

    <p><strong>Generated:</strong> {generated}</p>

    <div class="summary">

    <h2>Summary</h2>

    <p><strong>Total Scanned:</strong> {total}</p>
    <p><strong>Clean:</strong> {clean}</p>
    <p><strong>Suspicious:</strong> {suspicious}</p>
    <p><strong>Malicious:</strong> {malicious}</p>

    </div>

    <h2>IOC Details</h2>

    <table>

    <tr>
        <th>IOC</th>
        <th>Status</th>
        <th>Risk Score</th>
        <th>Risk Level</th>
        <th>Malicious</th>
        <th>Suspicious</th>
        <th>Harmless</th>
        <th>Timestamp</th>
    </tr>
    """

    for result in data:

        status = result.get("status", "Unknown")

        if status == "Clean":
            status_class = "clean"

        elif status == "Suspicious":
            status_class = "suspicious"

        else:
            status_class = "malicious"

        html += f"""

        <tr>
            <td>{result.get("ioc", "N/A")}</td>
            <td class="{status_class}">{status}</td>
            <td>{result.get("risk_score", "N/A")}</td>
            <td>{result.get("risk_level", "N/A")}</td>
            <td>{result.get("malicious", 0)}</td>
            <td>{result.get("suspicious", 0)}</td>
            <td>{result.get("harmless", 0)}</td>
            <td>{result.get("timestamp", "N/A")}</td>
        </tr>

        """

    html += """

    </table>

    </body>
    </html>
    """

    with open("logs/security_report.html", "w") as file:
        file.write(html)

    print("HTML report generated successfully.")