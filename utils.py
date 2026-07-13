# Helper functions will be added here.

def normalize_ioc(ioc):
    """
    Clean IOC input before scanning.
    """

    ioc = ioc.strip()

    ioc = ioc.lower()


    # Remove trailing slash from URLs

    if ioc.endswith("/"):
        ioc = ioc[:-1]


    return ioc