# web-vuln-scanner
A Python-based tool to detect common web vulnerabilities like XSS, SQL Injection, and CSRF. Built with Flask, requests, and BeautifulSoup, aligned with OWASP Top 10.
## Features
- Crawls URLs for forms and input fields.
- Tests for XSS, SQLi, and CSRF vulnerabilities.
- Responsive Flask UI with Tailwind CSS.
- Saves results to `scan_results.json` and logs to `scan_results.log`.

## Prerequisites
- Python 3.6 or higher
- Kali Linux or any Linux distribution with Python
- Internet connection for dependency installation
- A browser (e.g., Firefox) to access the web interface
  
## Usage
Run the Scanner: Start the Flask server to launch the web interface:
bash
python3 scanner.py
The server will start, and you'll see output like:
text
Server running at http://127.0.0.1:5000
 * Serving Flask app 'scanner'
 * Debug mode: on
 * Running on http://0.0.0.0:5000 (Press CTRL+C to quit)
Access the Web Interface:

    Open a browser and navigate to http://127.0.0.1:5000.
    You’ll see a form to enter a target URL and a warning about ethical use.

Perform a Scan:

    Enter a target URL (e.g., http://localhost/dvwa for a local test environment).
    Warning: Only scan websites you have explicit permission to test to avoid legal issues (e.g., CFAA violations).
    Click "Start Scan" to begin.
    Results will display in a table, showing vulnerability type, payload, evidence, severity, and timestamp.

View Results:

    Results are saved to scan_results.json in the project directory.
    Logs are saved to scan_results.log with timestamps and details.
    Example scan_results.json:
    json

    [
        {
            "type": "XSS",
            "payload": "<script>alert('XSS')</script>",
            "evidence": "Reflected payload: <script>alert('XSS')</script>",
            "severity": "High",
            "timestamp": "2025-06-23 16:44:00"
        }
    ]

Stop the Scanner:

    Press Ctrl+C in the terminal to stop the Flask server.
    
## Troubleshoot
Setting Up a Test Environment

To safely test the scanner, set up DVWA (Damn Vulnerable Web Application):
bash
sudo apt install apache2 mysql-server php php-mysql php-gd -y
git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa
sudo chmod -R 777 /var/www/html/dvwa
sudo systemctl start apache2 mysql

## Installation
```bash
pip3 install requests beautifulsoup4 flask
**Clone the Repository**:
   ```bash
   git clone https://github.com/TheRipper2092/web-vuln-scanner.git
   cd web-vuln-scanner




