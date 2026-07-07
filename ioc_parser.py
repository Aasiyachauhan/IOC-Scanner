import re


def identify_ioc_type(ioc):
    """
    Identify the type of IOC.
    """

    if validate_ip(ioc):
        return "IP Address"

    elif validate_hash(ioc):
        return "File Hash"

    elif validate_url(ioc):
        return "URL"

    elif validate_domain(ioc):
        return "Domain"

    else:
        return "Unknown"



def validate_ip(ioc):
    """
    Validate IPv4 addresses.
    """

    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    return bool(re.match(pattern, ioc))



def validate_hash(ioc):
    """
    Validate MD5, SHA1, SHA256 hashes.
    """

    pattern = r"^[a-fA-F0-9]{32,64}$"

    return bool(re.match(pattern, ioc))



def validate_url(ioc):
    """
    Validate URLs.
    """

    pattern = r"^https?://"

    return bool(re.match(pattern, ioc))



def validate_domain(ioc):
    """
    Validate domain names.
    """

    pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    return bool(re.match(pattern, ioc))