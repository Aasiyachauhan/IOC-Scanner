from ioc_parser import identify_ioc_type


def main():

    print("======================")
    print(" IOC Scanner tool")
    print("======================")

    ioc = input("Enter IOC: ")

    result = identify_ioc_type(ioc)

    print("\nResults")
    print("----------------")
    print("IOC:", ioc)
    print("Type:", result)


if __name__ == "__main__":
    main()