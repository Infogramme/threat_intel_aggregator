# threat_intel_aggregator
This tool is a lightweight Python-based utility that fetches and aggregates threat intelligence data from public feeds. It collects Indicators of Compromise (IOCs) such as malicious IPs and domains, helping analysts quickly spot trends and generate actionable threat summaries.

##  Features

-  Pulls data from multiple threat intelligence sources
-  Normalizes and deduplicates indicators
-  Highlights the most frequently reported IOCs
-  Exports results to JSON and CSV formats
-  Easy to use and extend

---

##  Supported Feeds

- AbuseIPDB (`ipsum` list)
- Malc0de IP Blacklist
- OpenPhish Phishing URLs

You can add more by editing the `FEEDS` dictionary in the script.

---

##  Installation

No external dependencies are required (uses built-in libraries).  
Tested with Python 3.7+

```bash
git clone https://github.com/infogramme/threat-intel-aggregator.git
cd threat-intel-aggregator
python threat_intel_aggregator.py

---

## Output

After execution, you’ll get:

threats_report.json: All IOCs grouped by indicator and source

threats_report.csv: Flat table of indicator/source pairs

Summary of top IOCs printed to console


Example:
Top 10 Indicators:
 - 45.83.64.1 (2 sources)
 - malicious-domain.com (2 sources)

[+] Exported indicators to threats_report.json
[+] Exported indicators to threats_report.csv

## Example Use Cases

Building IP blocklists

Detecting emerging threats

Enriching SIEM data

Feeding into automated firewall or alerting systems

## Disclaimer
Use responsibly. Always verify indicators before acting upon them in production environments.
