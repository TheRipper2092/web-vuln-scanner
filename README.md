# web-vuln-scanner
A Python-based tool to detect common web vulnerabilities like XSS, SQL Injection, and CSRF. Built with Flask, requests, and BeautifulSoup, aligned with OWASP Top 10.
## Features
- Crawls URLs for forms and input fields.
- Tests for XSS, SQLi, and CSRF vulnerabilities.
- Responsive Flask UI with Tailwind CSS.
- Saves results to `scan_results.json` and logs to `scan_results.log`.

## Installation
```bash
pip3 install requests beautifulsoup4 flask

Usage

    Run the scanner:
    bash

    python3 scanner.py
    Navigate to http://127.0.0.1:5000 in a browser.
    Enter a target URL and click "Start Scan".

Warning: Only scan websites you have explicit permission to test.
Dependencies

    Python 3
    requests
    beautifulsoup4
    flask

undefined

Save and exit (Ctrl+O, Enter, Ctrl+X).

Commit and push:
bash
git add README.md
git commit -m "Add README.md"
git push origin main
