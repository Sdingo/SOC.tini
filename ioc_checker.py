# ioc_checker.py — SOC-ready IOC checker with CSV output and .env support

import requests
import sys
import csv
import os
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3"

if not VT_API_KEY:
    print("Error: VirusTotal API key not found. Please set VT_API_KEY in your .env file.")
    sys.exit(1)

headers = {"x-apikey": VT_API_KEY}

# ==========================
# Functions to query VirusTotal
# ==========================
def check_ip(ip):
    url = f"{VT_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        return malicious
    else:
        print(f"Error checking IP {ip}: {response.status_code} - {response.text}")
        return None

def check_domain(domain):
    url = f"{VT_URL}/domains/{domain}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        return malicious
    else:
        print(f"Error checking domain {domain}: {response.status_code} - {response.text}")
        return None

def check_hash(file_hash):
    url = f"{VT_URL}/files/{file_hash}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        return malicious
    else:
        print(f"Error checking hash {file_hash}: {response.status_code} - {response.text}")
        return None

# ==========================
# Determine IOC type
# ==========================
def detect_ioc_type(ioc):
    # Simple detection logic
    if "." in ioc and not ioc.replace(".", "").isdigit():
        return "Domain"
    elif ioc.replace(".", "").isdigit():
        return "IP"
    else:
        return "Hash"

# ==========================
# Main function
# ==========================
def main():
    if len(sys.argv) < 2:
        print("Usage: python ioc_checker.py <IOC or file.txt>")
        sys.exit(1)

    target = sys.argv[1]

    # Prepare CSV output
    csv_file = "ioc_results.csv"
    with open(csv_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IOC", "Type", "Malicious Count"])

        # Single IOC input
        if not target.endswith(".txt"):
            iocs = [target.strip()]
        else:
            # Read IOCs from file
            try:
                with open(target, "r") as f:
                    iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except FileNotFoundError:
                print(f"Error: File not found - {target}")
                sys.exit(1)

        # Process each IOC
        for ioc in iocs:
            print(f"Querying VirusTotal for: '{ioc}'")
            ioc_type = detect_ioc_type(ioc)

            if ioc_type == "IP":
                malicious_count = check_ip(ioc)
            elif ioc_type == "Domain":
                malicious_count = check_domain(ioc)
            else:
                malicious_count = check_hash(ioc)

            if malicious_count is not None:
                print(f"{ioc_type}: {ioc} → Malicious count: {malicious_count}")
                writer.writerow([ioc, ioc_type, malicious_count])
            else:
                writer.writerow([ioc, ioc_type, "Error"])

    print(f"\n✅ Results saved to {csv_file}")

# ==========================
# Entry point
# ==========================
if __name__ == "__main__":
    main()
