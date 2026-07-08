import json
import os
from datetime import datetime


def save_result(ioc, result):

    log_entry = {
        "ioc": ioc,
        "status": result["status"],
        "malicious": result["malicious"],
        "suspicious": result["suspicious"],
        "harmless": result["harmless"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    log_file = "logs/scan_results.json"

    if os.path.exists(log_file):

        with open(log_file, "r") as file:
            data = json.load(file)

    else:
        data = []

    data.append(log_entry)

    with open(log_file, "w") as file:
        json.dump(data, file, indent=4)