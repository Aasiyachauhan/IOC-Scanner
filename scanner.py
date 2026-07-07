from threat_intel import check_ip, analyze_result


def main():

    ip = input("Enter IP address: ")

    print("\nScanning IOC...")
    
    result = check_ip(ip)

    analysis = analyze_result(result)


    print("\n===== IOC Scan Report =====")

    print("IOC:", ip)
    print("Status:", analysis["status"])
    print("Malicious detections:", analysis["malicious"])
    print("Suspicious detections:", analysis["suspicious"])
    print("Clean engines:", analysis["harmless"])



if __name__ == "__main__":
    main()