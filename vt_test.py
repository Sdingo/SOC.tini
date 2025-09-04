# vt_test.py — Minimal working VirusTotal v3 test script

import requests

# 🔑 Replace with your actual VirusTotal v3 API key (for local testing only)
VT_API_KEY = "YOUR_API_KEY"
VT_URL = "https://www.virustotal.com/api/v3"

headers = {"x-apikey": VT_API_KEY}

def check_ip(ip):
    url = f"{VT_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        malicious = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
        print(f"IP: {ip} → Malicious count: {malicious}")
    else:
        print(f"Error checking IP {ip}: {response.status_code} - {response.text}")

def check_domain(domain):
    url = f"{VT_URL}/domains/{domain}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        malicious = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
        print(f"Domain: {domain} → Malicious count: {malicious}")
    else:
        print(f"Error checking domain {domain}: {response.status_code} - {response.text}")

def check_hash(file_hash):
    url = f"{VT_URL}/files/{file_hash}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        malicious = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
        print(f"Hash: {file_hash} → Malicious count: {malicious}")
    else:
        print(f"Error checking hash {file_hash}: {response.status_code} - {response.text}")

if __name__ == "__main__":
    # ✅ Test values
    test_ip = "8.8.8.8"
    test_domain = "example.com"
    test_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test file hash

    check_ip(test_ip)
    check_domain(test_domain)
    check_hash(test_hash)
