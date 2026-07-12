import requests
import base64
from config import VT_API_KEY


BASE_URL = "https://www.virustotal.com/api/v3"


headers = {
    "x-apikey": VT_API_KEY
}



def check_ip(ip):

    response = requests.get(
        f"{BASE_URL}/ip_addresses/{ip}",
        headers=headers
    )

    return response.json()



def check_domain(domain):

    response = requests.get(
        f"{BASE_URL}/domains/{domain}",
        headers=headers
    )

    return response.json()



def check_hash(file_hash):

    response = requests.get(
        f"{BASE_URL}/files/{file_hash}",
        headers=headers
    )

    return response.json()



def check_url(url):

    # VirusTotal requires URL encoding

    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")


    response = requests.get(
        f"{BASE_URL}/urls/{url_id}",
        headers=headers
    )


    return response.json()



def analyze_result(data):

    if "data" not in data:
        return {
            "status": "Unknown",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0
        }


    stats = data["data"]["attributes"]["last_analysis_stats"]


    malicious = stats.get("malicious",0)
    suspicious = stats.get("suspicious",0)
    harmless = stats.get("harmless",0)



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