import requests
import time
import base64

import os

API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    raise ValueError("VirusTotal API key not found in .env file")


def check_url_virustotal(url):
    headers = {
        "x-apikey": API_KEY
    }

    # Submit URL
    scan_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(scan_url, headers=headers, data={"url": url})

    if response.status_code != 200:
        return {"error": "Failed to submit URL"}

    # Encode URL for lookup
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # Wait for analysis
    time.sleep(10)

    # Fetch result
    analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    result = requests.get(analysis_url, headers=headers)

    if result.status_code != 200:
        return {"error": "Failed to fetch analysis"}

    stats = result.json()["data"]["attributes"]["last_analysis_stats"]

    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"]
    }


def vt_verdict(stats):
    if stats["malicious"] > 0:
        return "MALICIOUS"
    elif stats["suspicious"] > 0:
        return "SUSPICIOUS"
    else:
        return "LEGIT"



