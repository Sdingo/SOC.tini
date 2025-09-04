# IOC Checker — SOC Tool for Threat Intelligence

## Introduction
In modern Security Operations Centers (SOC), analysts are constantly faced with large volumes of potential Indicators of Compromise (IOCs) — including IP addresses, domains, and file hashes — that need to be quickly assessed for malicious activity. Manual investigation is time-consuming and prone to human error. To enhance efficiency, SOC teams often integrate external threat intelligence tools such as VirusTotal to automate IOC verification.

This project demonstrates an **introduction to integrating external tools to solve SOC problems**, specifically by using VirusTotal to automatically check IOCs and generate actionable intelligence.

---

## Problem Statement
SOC analysts frequently encounter situations where they need to:

- Quickly verify if an IP, domain, or file hash is malicious.
- Handle large lists of IOCs efficiently without manually checking each one.
- Maintain accurate records of threat analysis for reporting and further investigation.

Manually performing these tasks is **inefficient, error-prone, and delays incident response**, especially under high-volume attack scenarios.

---

## Solution
To address these challenges, I developed a **Python-based IOC Checker** that:

1. Accepts multiple IOCs from a file or a single IOC as input.
2. Integrates with the VirusTotal v3 API to query each IOC.
3. Automatically determines the type of IOC (IP, domain, or hash) and retrieves the latest threat analysis.
4. Outputs results both to the console and saves them to a CSV file for record-keeping.

This solution **automates IOC verification**, allowing analysts to focus on higher-level incident response tasks, reduces human error, and provides a structured output that can be incorporated into broader SOC workflows.

---

## Challenges Faced
During development, several challenges were encountered:

1. **API Key Security:** Initial attempts hard-coded the VirusTotal API key, which is unsafe for version control. Solution: moved the key to a `.env` file and loaded it securely using `python-dotenv`.

2. **File Parsing Issues:** Extra spaces, newline characters, or comments in IOC files caused VirusTotal to return errors. Solution: implemented line stripping, comment skipping, and input cleaning.

3. **API Response Handling:** Free-tier VirusTotal API limits and inconsistent responses (e.g., 401 or 404) required robust error handling to prevent the script from crashing.

4. **IOC Type Detection:** Automatically distinguishing between IPs, domains, and hashes was necessary to query VirusTotal correctly. Implemented a simple detection logic based on string patterns.

---

## Architecture
The architecture of the IOC Checker is **modular and SOC-ready**:

+-------------------+
| Input (.txt / IOC)|
+-------------------+
|
v
+-------------------+
| IOC Parsing & |
| Cleaning Module |
+-------------------+
|
v
+-------------------+
| IOC Type Detector |
+-------------------+
|
v
+-------------------+
| VirusTotal API |
| Integration |
+-------------------+
|
v
+-------------------+
| Output Module |
| - Console |
| - CSV File |
+-------------------+


- **IOC Parsing & Cleaning:** Strips whitespace, ignores comments, and ensures valid input.  
- **IOC Type Detector:** Determines whether the IOC is an IP, domain, or hash.  
- **VirusTotal API Integration:** Queries each IOC, handles responses, and extracts malicious counts.  
- **Output Module:** Displays results in the console and writes structured CSV for records.

---

## Conclusion
This project demonstrates **practical integration of external tools (VirusTotal) into a SOC workflow**. By automating IOC verification, it solves a critical problem of efficiency and accuracy in threat analysis. The modular design ensures that this tool can be expanded further, such as adding alert notifications, dashboards, or integrating other threat intelligence platforms.

This IOC Checker represents a **foundational step for developing SOC automation tools** and provides a tangible example of how Python and external APIs can enhance security operations.
