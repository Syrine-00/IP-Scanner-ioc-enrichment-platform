import argparse
import ipaddress
from unittest import result
import dotenv
import os
import requests
import time
import base64
from flask import Flask, render_template, request

dotenv.load_dotenv()
'''
This script scans IP addresses, IP ranges, files containing IPs, 
or URLs using the VirusTotal API.
It checks if the provided IPs or URLs are malicious based on the analysis 
results from VirusTotal.
'''


VT_BASE_URL = "https://www.virustotal.com/api/v3"
DETECTION_THRESHOLD = 3  # detection percentage above which a result is flagged MALICIOUS


def build_result(identifier, stats, owner=None, threshold=DETECTION_THRESHOLD):
    """
    Computes the verdict from VirusTotal stats and returns a dictionary.
    This dictionary is the "neutral" form of the result: the CLI prints it,
    the web page renders it as HTML. Neither display mode is hardcoded here.
    """
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    percent_malicious = (malicious + suspicious) / total * 100 if total > 0 else 0
    is_malicious = percent_malicious > threshold

    return {
        "identifier": str(identifier),
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "percent_malicious": round(percent_malicious, 1),
        "is_malicious": is_malicious,
        "stats": stats,
        "owner": owner,
    }


def display_result(result):
    verdict = "MALICIOUS" if result["is_malicious"] else "NOT MALICIOUS"

    print(f"{result['identifier']} is {verdict} ({result['percent_malicious']}% detection rate)")
    print(f"Malicious: {result['malicious']}, Suspicious: {result['suspicious']}")
    print("Detailed Analysis:")
    print(result["stats"])

    if result["owner"] is not None:
        print("OWNER: ", result["owner"])



def scan_ip(ip):
    try:
        ip=ipaddress.ip_address(ip)
        print("IP is VALID")
    except ValueError:
        print("IP is INVALID")
        return

    url= f"{VT_BASE_URL}/ip_addresses/{ip}"

    headers={"x-apikey": os.getenv("VT_API_KEY")}
    response=requests.get(url, headers=headers)

    print("STATUS CODE:", response.status_code)

    data=response.json()
    stats=data["data"]["attributes"]["last_analysis_stats"]
    owner = data["data"]["attributes"]["as_owner"]

    display_result(ip, stats, owner)

    


def scan_range_ip(rangeip):
    try:
        network=ipaddress.ip_network(rangeip, strict=False)
        print(f"IP Range {network}: VALID")
    except ValueError:
        print(f"IP Range {rangeip}: INVALID")
        return

    for ip in network.hosts():
        if ip.is_private:
            print(f"IP {ip} is PRIVATE, skipping scan.")
            continue
        scan_ip(str(ip))
        time.sleep(15)



def scan_file(file_path):
    try:
        with open(file_path, 'r') as file:
            for  line in file:
                ip=line.split("->")[0].strip().replace("[.]", ".").strip()
                try:
                    ip=ipaddress.ip_address(ip)
                    print(f"IP: {ip}")
                    if ip.is_private:
                        print(f"IP {ip} is PRIVATE, skipping scan.")
                        continue
                    scan_ip(ip)
                    time.sleep(15)
                except ValueError:
                    if ip=="":
                        continue
                    else:
                        print("IP is INVALID")

    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return



def scan_url(url):
    if url.startswith(("http://", "https://")) is False:
        url="https://" + url
    print(f"Scanning URL: {url}")

    url_id=base64.b64encode(url.encode()).decode()
    if url_id.endswith("="):
        url_id=url_id.rstrip("=")

    id= f"{VT_BASE_URL}/urls/{url_id}"

    headers={"x-apikey": os.getenv("VT_API_KEY")}
    response=requests.get(id, headers=headers)

    code=response.status_code
    print("STATUS CODE:", code)

    if code==200:
        data=response.json()
        stats=data["data"]["attributes"]["last_analysis_stats"]
        result = build_result(url, stats)
        display_result(result)
        return result

    elif code==404:
        print(f"{url} not found in VirusTotal database, submitting for analysis...")

        submit_url= f"{VT_BASE_URL}/urls"
        submit_response=requests.post(submit_url, headers=headers, data={"url": url})

        if submit_response.status_code!=200:
            print(f"Error submitting URL: {submit_response.status_code}")
            return
        
        id=submit_response.json()["data"]["id"]

        analysis_url= f"{VT_BASE_URL}/analyses/{id}"
        print("Waiting for analysis to complete...",end="", flush=True)
        for _ in range(5): #5 attempts, 15 seconds apart
            time.sleep(15)
            print(".", end="", flush=True)

            retry_response=requests.get(analysis_url ,headers=headers)

            if retry_response.status_code!=200:
                continue

            data=retry_response.json()
            if "data" not in data:
                continue
            status = data["data"]["attributes"]["status"]
            if status != "completed":
                print(".")
                continue
            
            stats=data["data"]["attributes"]["stats"]
            result = build_result(url, stats)
            display_result(result)
            return result

        print("\nTimeout: Analysis not completed within the expected time frame.")

    else:
        print(f"Error fetching URL analysis: {code}")


# Web interface (Flask)

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    scan_type = request.form.get("scan_type", "ip")
    scan_value = ""

    if request.method == "POST":
        scan_type = request.form.get("scan_type")
        scan_value = request.form.get("scan_value", "").strip()

        if not scan_value:
            error = "Please enter a value to scan."
        elif scan_type == "ip":
            result = scan_ip(scan_value)
        elif scan_type == "url":
            result = scan_url(scan_value)
        else:
            error = "Unknown scan type."

        if result is None and error is None:
            error = "No usable result (invalid input or API error)."

    return render_template(
        "index.html",
        result=result,
        error=error,
        scan_type=scan_type,
        scan_value=scan_value,
    )


def run_web():
    print("Starting web interface on http://127.0.0.1:5000")
    app.run(debug=True)


def main():
    parser=argparse.ArgumentParser(description='IP Scanner')
    parser.add_argument('--ip', type=str, help="IP address to scan")
    parser.add_argument('--rangeip', type=str, help="IP address range to scan")
    parser.add_argument('--file', type=str, help="File containing IP addresses to scan")
    parser.add_argument('--url', type=str, help="URL to scan")
    parser.add_argument("--web", action="store_true", help="Launch the web interface")

    args=parser.parse_args()
    if args.web:
        run_web()
    elif args.ip:
        scan_ip(args.ip)
    elif args.rangeip:
        scan_range_ip(args.rangeip)
    elif args.file:
        scan_file(args.file)
    elif args.url:
        scan_url(args.url)
    else:
        print("No valid input provided. Please use --ip, --rangeip, --file, or --url.")



if __name__ == "__main__":
    main()