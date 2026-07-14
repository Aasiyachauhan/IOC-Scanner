import requests
import base64
from config import VT_API_KEY

BASE_URL = "https://www.virustotal.com/api/v3"

headers = {
    "x-apikey": VT_API_KEY
}

def make_request(endpoint):

    try:
        response = requests.get(
            f"{BASE_URL}/{endpoint}",
            headers=headers,
            timeout=10
        )
        return response.json()

    except requests.exceptions.RequestException as e:

        return {
            "error": str(e)
        }

def check_ip(ip):

    return make_request(
        f"ip_addresses/{ip}"
    )

def check_domain(domain):

    return make_request(
        f"domains/{domain}"
    )

def check_hash(file_hash):

    return make_request(
        f"files/{file_hash}"
    )

def check_url(url):

    # VirusTotal requires URL encoding

    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    return make_request(
        f"urls/{url_id}"
    )


def analyze_result(data):

    # Handle API errors or invalid responses

    if "data" not in data:

        return {
            "status": "Unknown",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0
        }


    stats = data["data"]["attributes"]["last_analysis_stats"]


    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)



    if malicious > 5:
        status = "Malicious"

    elif malicious > 0 or suspicious > 0:
        status = "Suspicious"

    else:
        status = "Clean"

    risk_score = calculate_risk(malicious, suspicious)
    risk_level = get_risk_level(risk_score)



    return {

        "status": status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless

    }

def calculate_risk(malicious, suspicious):
    """
    Calculate IOC risk score.
    Malicious detections have higher weight
    than suspicious detections.
    """

    score = (malicious * 10) + (suspicious * 5)


    # Maximum score is 100

    if score > 100:
        score = 100


    return score

def get_risk_level(score):
    if score >= 70:
        return "High"
    
    elif score >= 30:
        return "Medium"

    else:
        return "Low"