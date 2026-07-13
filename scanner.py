from threat_intel import analyze_result
from logger import save_result
from ioc_reader import read_iocs
from ioc_router import scan_ioc
from ioc_parser import identify_ioc_type
from datetime import datetime
from utils import normalize_ioc

def main():

    iocs = read_iocs("sample_IOCs.txt")


    for ioc in iocs:
        ioc = normalize_ioc(ioc)
        ioc_type = identify_ioc_type(ioc)


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


        print("\nMalicious:")
        print(analysis["malicious"])


        print("\nSuspicious:")
        print(analysis["suspicious"])


        print("\nHarmless:")
        print(analysis["harmless"])


        print("\nTimestamp:")
        print(timestamp)


        print("=========================")



if __name__ == "__main__":
    main()