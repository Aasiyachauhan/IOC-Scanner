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

    html = f"""
    <html>
    <head>
        <title>IOC Scanner Report</title>
    </head>

    <body>

    <h1>IOC Scanner Security Report</h1>

    <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

    <table border="1">
        <tr>
            <th>IOC</th>
            <th>Status</th>
            <th>Risk Score</th>
            <th>Risk Level</th>
            <th>Malicious</th>
            <th>Suspicious</th>
            <th>Harmless</th>
        </tr>
    """

    for result in data:

        html += f"""
        <tr>
            <td>{result['ioc']}</td>
            <td>{result['status']}</td>
            <td>{result.get('risk_score', 'N/A')}</td>
            <td>{result.get('risk_level', 'N/A')}</td>
            <td>{result['malicious']}</td>
            <td>{result['suspicious']}</td>
            <td>{result['harmless']}</td>
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

if __name__ == "__main__":
    generate_html_report()