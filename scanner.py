from threat_intel import analyze_result
from logger import save_result
from ioc_reader import read_iocs
from ioc_router import scan_ioc
from ioc_parser import identify_ioc_type


def main():

    iocs = read_iocs("sample_IOCs.txt")


    for ioc in iocs:

        print("\nScanning:", ioc)

        ioc_type = identify_ioc_type(ioc)

        print("IOC Type:", ioc_type)


        result = scan_ioc(ioc)


        if "error" in result:

            print("Scan Error:", result["error"])
            continue


        if "data" not in result:

            print("Unable to analyze:", ioc)
            continue


        analysis = analyze_result(result)


        save_result(ioc, analysis)


        print("--------------------")
        print("IOC:", ioc)
        print("Type:", ioc_type)
        print("Status:", analysis["status"])
        print("Malicious:", analysis["malicious"])
        print("Suspicious:", analysis["suspicious"])
        print("Harmless:", analysis["harmless"])
        print("--------------------")



if __name__ == "__main__":
    main()