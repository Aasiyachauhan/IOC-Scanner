def read_iocs(file_path):

    with open(file_path, "r") as file:

        iocs = file.readlines()


    cleaned_iocs = []

    for ioc in iocs:

        ioc = ioc.strip()

        if ioc:
            cleaned_iocs.append(ioc)


    return cleaned_iocs