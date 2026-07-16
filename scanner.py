import sys
from threat_intel import analyze_result
from logger import save_result
from ioc_reader import read_iocs
from ioc_router import scan_ioc
from ioc_parser import identify_ioc_type
from datetime import datetime
from utils import normalize_ioc
from report_generator import export_to_csv

def main():

    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        
    else:
        input_file = "sample_IOCs.txt"
        
    iocs = read_iocs(input_file)

    clean_count = 0
    suspicious_count = 0
    malicious_count = 0

    ioc_stats = {
        "IP Address": 0,
        "Domain": 0,
        "URL": 0,
        "File Hash": 0,
        "Unknown": 0
    }


    for ioc in iocs:

        ioc = normalize_ioc(ioc)
        ioc_type = identify_ioc_type(ioc)
        ioc_stats[ioc_type] += 1

        result = scan_ioc(ioc)

        if "error" in result:

            print("\n=========================")
            print("IOC Scan Report")
            print("=========================")
            print("Indicator:")
            print(ioc)
            print("\nScan Error:")
            print(result["error"])
            print("=========================")

            continue

        if "data" not in result:

            print("\n=========================")
            print("IOC Scan Report")
            print("=========================")
            print("Indicator:")
            print(ioc)
            print("\nUnable to analyze IOC")
            print("=========================")

            continue

        analysis = analyze_result(result)

        if analysis["status"] == "Clean":
            clean_count += 1

        elif analysis["status"] == "Suspicious":
            suspicious_count += 1

        elif analysis["status"] == "Malicious":
            malicious_count += 1

        save_result(ioc, analysis)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("\n=========================")
        print("IOC Scan Report")
        print("=========================")

        print("\nIndicator:")
        print(ioc)

        print("\nType:")
        print(ioc_type)

        print("\nRisk:")
        print(analysis["status"])

        print("\nRisk Score:")
        print(analysis["risk_score"])

        print("\nRisk Level:")
        print(analysis["risk_level"])

        print("\nMalicious:")
        print(analysis["malicious"])

        print("\nSuspicious:")
        print(analysis["suspicious"])

        print("\nHarmless:")
        print(analysis["harmless"])

        print("\nTimestamp:")
        print(timestamp)

        print("=========================")

    # Summary Section

    total_scanned = (
        clean_count +
        suspicious_count +
        malicious_count
    )

    print("\n===================================")
    print("Scan Summary")
    print("===================================")

    print("Total IOCs Scanned:", total_scanned)
    print("Clean:", clean_count)
    print("Suspicious:", suspicious_count)
    print("Malicious:", malicious_count)

    print("===================================")

    print("\nIOC Type Distribution")
    print("======================")

    for ioc_type, count in ioc_stats.items():
        print(f"{ioc_type}: {count}")

        print("===================================")
        export_to_csv()

if __name__ == "__main__":
    main()