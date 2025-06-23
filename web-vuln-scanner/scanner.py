import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
from flask import Flask, request, render_template, jsonify
import json
import logging
from datetime import datetime
import os

# Configure logging
logging.basicConfig(filename='scan_results.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Sample payloads for testing
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "\"'><script>alert('XSS')</script>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users --",
    "' UNION SELECT NULL, username, password FROM users --"
]

# Vulnerability detection patterns
SQLI_ERROR_PATTERNS = [
    r"sql syntax.*mysql",
    r"warning.*mysql.*",
    r"unclosed quotation mark",
    r"quoted string not properly terminated"
]

# Severity levels (aligned with OWASP Top 10)
SEVERITY = {
    "XSS": "High",
    "SQLi": "Critical",
    "CSRF": "Medium"
}

# Store scan results
results = []

def crawl_url(url):
    """Crawl the URL to find forms and input fields."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        inputs = []
        for form in forms:
            form_inputs = form.find_all('input')
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs.append({'action': action, 'method': method, 'inputs': form_inputs})
        return forms, inputs
    except Exception as e:
        logging.error(f"Error crawling {url}: {str(e)}")
        return [], []

def test_xss(url, form_data, form_action, method):
    """Test for XSS vulnerabilities."""
    vulnerabilities = []
    try:
        for payload in XSS_PAYLOADS:
            test_data = form_data.copy()
            for key in test_data:
                test_data[key] = payload
            if method == 'get':
                response = requests.get(form_action, params=test_data, timeout=5)
            else:
                response = requests.post(form_action, data=test_data, timeout=5)
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'payload': payload,
                    'evidence': f"Reflected payload: {payload}",
                    'severity': SEVERITY['XSS'],
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                logging.info(f"XSS detected at {form_action} with payload: {payload}")
    except Exception as e:
        logging.error(f"Error testing XSS on {form_action}: {str(e)}")
    return vulnerabilities

def test_sqli(url, form_data, form_action, method):
    """Test for SQL Injection vulnerabilities."""
    vulnerabilities = []
    try:
        for payload in SQLI_PAYLOADS:
            test_data = form_data.copy()
            for key in test_data:
                test_data[key] = payload
            if method == 'get':
                response = requests.get(form_action, params=test_data, timeout=5)
            else:
                response = requests.post(form_action, data=test_data, timeout=5)
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'SQLi',
                        'payload': payload,
                        'evidence': f"SQL error pattern matched: {pattern}",
                        'severity': SEVERITY['SQLi'],
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    logging.info(f"SQLi detected at {form_action} with payload: {payload}")
                    break
    except Exception as e:
        logging.error(f"Error testing SQLi on {form_action}: {str(e)}")
    return vulnerabilities

def check_csrf(form):
    """Check for missing CSRF tokens in forms."""
    if form.get('method', 'get').lower() == 'get':
        return []  # GET forms typically don't need CSRF tokens
    csrf_token = form.find('input', {'name': re.compile(r'csrf|token', re.I)})
    if not csrf_token:
        return [{
            'type': 'CSRF',
            'payload': None,
            'evidence': 'Missing CSRF token in POST form',
            'severity': SEVERITY['CSRF'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }]
    return []

def scan_url(target_url):
    """Main scanning function."""
    global results
    results = []
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    try:
        forms, inputs = crawl_url(target_url)
    except Exception as e:
        logging.error(f"Failed to crawl {target_url}: {str(e)}")
        return [{"error": f"Failed to crawl URL: {str(e)}"}]
    
    # Test for XSS, SQLi, and CSRF
    for form_info in inputs:
        form_action = urllib.parse.urljoin(target_url, form_info['action'])
        method = form_info['method']
        form_data = {inp.get('name'): 'test' for inp in form_info['inputs'] if inp.get('name')}
        
        # Test XSS
        xss_vulns = test_xss(target_url, form_data, form_action, method)
        results.extend(xss_vulns)
        
        # Test SQLi
        sqli_vulns = test_sqli(target_url, form_data, form_action, method)
        results.extend(sqli_vulns)
        
        # Check CSRF
        if form_info['inputs']:
            csrf_vulns = check_csrf(form_info['inputs'][0].parent)
            results.extend(csrf_vulns)
    
    # Save results to JSON
    with open('scan_results.json', 'w') as f:
        json.dump(results, f, indent=4)
    
    return results

# Create templates directory if it doesn't exist
if not os.path.exists('templates'):
    os.makedirs('templates')

# Write HTML templates with Tailwind CSS
with open('templates/index.html', 'w') as f:
    f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Vulnerability Scanner</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
    <div class="container mx-auto px-4 py-8 max-w-3xl">
        <h1 class="text-3xl font-bold text-gray-800 mb-6 text-center">Web Application Vulnerability Scanner</h1>
        <div class="bg-yellow-100 border-l-4 border-yellow-500 p-4 mb-6 rounded">
            <p class="text-yellow-700"><strong>Warning:</strong> Only scan websites you have explicit permission to test.</p>
        </div>
        <form action="/scan" method="post" class="bg-white p-6 rounded-lg shadow-md">
            <label for="url" class="block text-gray-700 font-medium mb-2">Target URL</label>
            <input type="text" id="url" name="url" placeholder="http://example.com" required
                   class="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
            <button type="submit"
                    class="mt-4 w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition">
                Start Scan
            </button>
        </form>
    </div>
</body>
</html>
    ''')

with open('templates/results.html', 'w') as f:
    f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Results</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8 max-w-5xl">
        <h1 class="text-3xl font-bold text-gray-800 mb-6 text-center">Scan Results for {{ url }}</h1>
        {% if results and not results[0].error %}
        <div class="overflow-x-auto bg-white rounded-lg shadow-md">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Payload</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Evidence</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    {% for result in results %}
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ result.type }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ result.payload or 'N/A' }}</td>
                        <td class="px-6 py-4 text-sm text-gray-900">{{ result.evidence }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ result.severity }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ result.timestamp }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% elif results and results[0].error %}
        <div class="bg-red-100 border-l-4 border-red-500 p-4 mb-6 rounded">
            <p class="text-red-700">{{ results[0].error }}</p>
        </div>
        {% else %}
        <div class="bg-green-100 border-l-4 border-green-500 p-4 mb-6 rounded">
            <p class="text-green-700">No vulnerabilities found.</p>
        </div>
        {% endif %}
        <a href="/" class="inline-block mt-6 bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition">Back to Scanner</a>
    </div>
</body>
</html>
    ''')

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('url')
    if not target_url:
        return render_template('results.html', results=[{"error": "No URL provided"}], url="N/A")
    
    try:
        scan_results = scan_url(target_url)
        return render_template('results.html', results=scan_results, url=target_url)
    except Exception as e:
        logging.error(f"Scan failed for {target_url}: {str(e)}")
        return render_template('results.html', results=[{"error": f"Scan failed: {str(e)}"}], url=target_url)

if __name__ == '__main__':
    print("Server running at http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
