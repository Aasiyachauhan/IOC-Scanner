import csv
import json


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