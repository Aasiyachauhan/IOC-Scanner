from threat_intel import check_ip, analyze_result
from logger import save_result
from ioc_reader import read_iocs


def main():

    iocs = read_iocs("sample_IOCs.txt")


    for ioc in iocs:

        print("\nScanning:", ioc)


        result = check_ip(ioc)

        analysis = analyze_result(result)


        save_result(ioc, analysis)


        print("--------------------")
        print("IOC:", ioc)
        print("Status:", analysis["status"])
        print("Malicious:", analysis["malicious"])
        print("Suspicious:", analysis["suspicious"])
        print("--------------------")



if __name__ == "__main__":
    main()