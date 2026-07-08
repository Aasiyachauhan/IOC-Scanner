from threat_intel import check_ip, analyze_result
from logger import save_result


def main():

    ip = input("Enter IP address: ")

    print("\nScanning IOC...")

    # Step 1: Get threat intelligence data from VirusTotal
    result = check_ip(ip)

    # Step 2: Analyze VirusTotal response
    analysis = analyze_result(result)

    # Step 3: Save scan result into JSON log file
    save_result(ip, analysis)


    print("\n===== IOC Scan Report =====")

    print("IOC:", ip)
    print("Status:", analysis["status"])
    print("Malicious detections:", analysis["malicious"])
    print("Suspicious detections:", analysis["suspicious"])
    print("Clean engines:", analysis["harmless"])

    print("\nScan result saved successfully!")


if __name__ == "__main__":
    main()