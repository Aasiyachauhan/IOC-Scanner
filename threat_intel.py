import requests
from config import VT_API_KEY


BASE_URL = "https://www.virustotal.com/api/v3"


def check_ip(ip):

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(
        f"{BASE_URL}/ip_addresses/{ip}",
        headers=headers
    )

    return response.json()



def check_url(url):

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(
        f"{BASE_URL}/urls/{url}",
        headers=headers
    )

    return response.json()



def analyze_result(data):

    stats = data["data"]["attributes"]["last_analysis_stats"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]


    if malicious > 5:
        status = "Malicious"

    elif malicious > 0 or suspicious > 0:
        status = "Suspicious"

    else:
        status = "Clean"


    return {
        "status": status,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless
    }