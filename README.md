# sqli-beast
SQLi-Beast — Powerful, multi-threaded SQL injection testing and discovery tool for pentesters.

SQLi-Beast is a brutally honest, flexible, and advanced tool for automated SQL injection vulnerability testing, written in Python.
It supports error-based, time-based, wordlist brute-force on tables and columns, multi-threading, proxy rotation, and multiple report formats.
Features:
DB auto‑detection (MySQL, MSSQL, PostgreSQL, Oracle)
Error‑based and time‑based heuristics
Wordlist brute‑force for tables and columns
Multi‑threaded scanning
Proxy rotation (--proxy-file)
Logs in CSV, JSON, and HTML
Highlights vulnerable inputs in the HTML report
User‑friendly CLI

Requirements
Python >= 3.8

requests
beautifulsoup4
Install dependencies:
pip install -r requirements.txt

-------------------------------------------------------------------------------------------------------
Usage Examples:

Basic:
python sqli_beast.py -u http://example.com/login.php

-------------------------------------------------------------------------------------------------------
With proxy file and all report formats:
python sqli_beast.py -u http://example.com/login.php -pfp proxies.txt --output-format all

-------------------------------------------------------------------------------------------------------
Bruteforce tables and columns:
python sqli_beast.py -u http://example.com/login.php --db-detect -tw wordlists/tables.txt -cw wordlists/columns.txt

-------------------------------------------------------------------------------------------------------
| Flag              | Description                         |
| ----------------- | ----------------------------------- |
| `-u`              | Target URL                          |
| `-pf`             | Payload file                        |
| `-pfp`            | Proxy file                          |
| `-tw`             | Tables wordlist                     |
| `-cw`             | Columns wordlist                    |
| `--db-detect`     | Database auto‑detection             |
| `--output-format` | `csv`, `json`, `html`, `all`        |
| `--log-all`       | Log everything, not just vulnerable |
| `-t`              | Number of threads                   |
| `-st`             | Sleep threshold                     |
| `-cd`             | Content diff threshold              |

For full list of options:
python sqli_beast.py -h


Disclaimer

SQLi‑Beast is intended solely for educational, research, and authorized penetration testing purposes.
You must obtain explicit written permission from the owner of the target system before using this tool on any infrastructure.

The author(s) of SQLi‑Beast shall not be held liable for any direct, indirect, incidental, or consequential damages arising from the use or misuse of this software.
Any illegal use is strictly prohibited and is entirely the responsibility of the user.

By using SQLi‑Beast, you agree to comply with all applicable local, state, and international laws and regulations regarding cybersecurity and data privacy.











