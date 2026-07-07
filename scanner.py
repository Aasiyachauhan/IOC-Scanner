from ioc_parser import identify_ioc_type


def main():

    test_iocs = [
        "8.8.8.8",
        "google.com",
        "https://example.com",
        "44d88612fea8a8f36de82e1278abb02f"
    ]


    for ioc in test_iocs:

        result = identify_ioc_type(ioc)

        print(f"{ioc} --> {result}")



if __name__ == "__main__":
    main()