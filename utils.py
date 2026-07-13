# Helper functions will be added here.

def normalize_ioc(ioc):
    """
    Clean IOC input before scanning.
    """

    # Remove spaces
    ioc = ioc.strip()

    # Convert uppercase letters to lowercase
    ioc = ioc.lower()

    return ioc