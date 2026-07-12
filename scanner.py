from threat_intel import analyze_result
from logger import save_result
from ioc_reader import read_iocs
from ioc_router import scan_ioc


def main():

    iocs = read_iocs("sample_IOCs.txt")


    for ioc in iocs:

        print("\nScanning:", ioc)

        result = scan_ioc(ioc)


        if "data" not in result:
            print("Unable to analyze:", ioc)
            continue


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