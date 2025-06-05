#!/usr/bin/env python3

"""
Threat Intelligence Feed Aggregator
-----------------------------------
Fetches IOCs (IPs, domains) from public feeds and aggregates them into a report.
"""

import requests
import csv
import json
from collections import Counter
from datetime import datetime

# Sample threat intelligence feeds
FEEDS = {
    "AbuseIPDB": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "Malc0de": "http://malc0de.com/bl/IP_Blacklist.txt",
    "OpenPhish": "https://openphish.com/feed.txt",
}

def fetch_feed(name, url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.text.splitlines()
        print(f"[+] Fetched {len(data)} entries from {name}")
        return name, data
    except Exception as e:
        print(f"[-] Failed to fetch {name}: {e}")
        return name, []

def normalize_indicators(name, lines):
    indicators = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "://" in line:
            line = line.split("://")[-1].split("/")[0]
        indicators.append((line, name))
    return indicators

def aggregate_iocs(feeds):
    all_indicators = []
    for name, url in feeds.items():
        source_name, raw_lines = fetch_feed(name, url)
        indicators = normalize_indicators(source_name, raw_lines)
        all_indicators.extend(indicators)
    return all_indicators

def summarize(indicators):
    ioc_counter = Counter([ioc for ioc, _ in indicators])
    top_iocs = ioc_counter.most_common(10)
    return top_iocs

def export_to_json(indicators, filename="threats_report.json"):
    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "indicators": [{"indicator": ioc, "sources": [s for i, s in indicators if i == ioc]} for ioc in set(i for i, _ in indicators)]
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Exported indicators to {filename}")

def export_to_csv(indicators, filename="threats_report.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Indicator", "Source"])
        for ioc, source in indicators:
            writer.writerow([ioc, source])
    print(f"[+] Exported indicators to {filename}")

if __name__ == "__main__":
    print("[*] Starting Threat Intelligence Feed Aggregator...")
    indicators = aggregate_iocs(FEEDS)
    summary = summarize(indicators)

    print("\nTop 10 Indicators:")
    for ioc, count in summary:
        print(f" - {ioc} ({count} sources)")

    export_to_json(indicators)
    export_to_csv(indicators)