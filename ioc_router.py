from ioc_parser import identify_ioc_type
from threat_intel import (
    check_ip,
    check_url,
    check_domain,
    check_hash
)

def scan_ioc(ioc):

    ioc_type = identify_ioc_type(ioc)

    if ioc_type == "IP Address":

        return check_ip(ioc)

    elif ioc_type == "URL":

        return check_url(ioc)

    elif ioc_type == "Domain":

        return check_domain(ioc)

    elif ioc_type == "File Hash":

        return check_hash(ioc)

    else:

        return {
            "error": "Unsupported IOC"
        }
    