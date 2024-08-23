import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import concurrent.futures
import ast
import csv
import time

class HybridXSSDetectionTool:
    def __init__(self, mode, target_url=None, code_directory=None):
        self.mode = mode
        self.target_url = target_url
        self.code_directory = code_directory
        self.vulnerabilities = []
        self.crawled_urls = []

    def dast_init(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        self.driver = webdriver.Chrome(options=chrome_options)
        self.xss_payloads = {
            'html': ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"],
            'attribute': ['" onmouseover="alert(1)"'],
            'js': ["');alert(1);//", "');alert(1)//"],
            # Add more payloads if necessary
        }

    def run(self):
        if self.mode == 'sast' or self.mode == 'hybrid':
            self.run_sast()
        
        if self.mode == 'dast' or self.mode == 'hybrid':
            if self.target_url:
                self.dast_init()
                self.run_dast()
                self.driver.quit()

        # Save reports with distinct filenames based on mode
        if self.mode == 'sast':
            self.generate_report("sast_results.csv")
        elif self.mode == 'dast':
            self.generate_report("dast_results.csv")
        elif self.mode == 'hybrid':
            self.generate_report("hybrid_results.csv")

    def run_sast(self):
        print("Running SAST...")
        results = self.scan_directory(self.code_directory)
        if results:
            print(f"Found {len(results)} SAST vulnerabilities.")
        else:
            print("No SAST vulnerabilities found.")
        
        for result in results:
            for vuln in result['vulnerabilities']:
                if len(vuln) >= 3:
                    mitigation = self.get_sast_mitigation(vuln[2])
                    self.vulnerabilities.append({
                        'file': result['file'],
                        'context': 'SAST',
                        'line_number': vuln[0],
                        'description': vuln[2],
                        'mitigation': mitigation,
                        'payload': None,
                        'response': None
                    })

    def scan_python_file(self, filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            source = file.read()

        try:
            tree = ast.parse(source)
        except SyntaxError:
            print(f"Syntax error in file {filepath}, skipping...")
            return []

        detector = PythonWebAppXSSDetector()
        detector.visit(tree)
        
        return detector.vulnerabilities

    def scan_directory(self, directory):
        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    print(f"Checking file: {filepath}")
                    vulnerabilities = self.scan_python_file(filepath)
                    if vulnerabilities:
                        results.append({
                            'file': filepath,
                            'vulnerabilities': vulnerabilities
                        })
        return results

    def run_dast(self):
        print("Running DAST...")
        self.visited_urls = set()
        self.crawl(self.target_url)

    def crawl(self, url):
        if url in self.visited_urls or not url.startswith(self.target_url):
            return
        print(f"Crawling {url}")
        self.visited_urls.add(url)
        self.crawled_urls.append(url)
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        self.process_forms(soup, url)
        self.follow_links(soup, url)

    def follow_links(self, soup, base_url):
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            url = urljoin(base_url, href)
            self.crawl(url)

    def process_forms(self, soup, url):
        forms = soup.find_all('form')
        print(f"Found {len(forms)} form(s) on {url}")
        for form in forms:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [
                    executor.submit(self.inject_payload, form, payload, url, context)
                    for context, payloads in self.xss_payloads.items()
                    for payload in payloads
                ]
                for future in concurrent.futures.as_completed(futures):
                    response = future.result()
                    if response:
                        self.analyze_response(response, url)

    def inject_payload(self, form, payload, url, context):
        action = form.attrs.get('action', url)
        method = form.attrs.get('method', 'get').lower()
        form_url = urljoin(url, action)

        data = {}
        for input_tag in form.find_all('input'):
            input_name = input_tag.attrs.get('name')
            if input_name:
                data[input_name] = payload

        try:
            if method == 'post':
                response = requests.post(form_url, data=data)
            else:
                response = requests.get(form_url, params=data)
            return response
        except requests.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def analyze_response(self, response, url):
        for context, payloads in self.xss_payloads.items():
            for payload in payloads:
                if payload in response.text:
                    print(f"XSS vulnerability detected with payload: {payload}")
                    mitigation = self.get_dast_mitigation(context)
                    self.vulnerabilities.append({
                        'url': url,
                        'context': context,
                        'line_number': None,
                        'payload': payload,
                        'description': 'XSS vulnerability detected',
                        'mitigation': mitigation,
                        'response': response.text
                    })

        try:
            self.driver.get(url)
            for context, payloads in self.xss_payloads.items():
                for payload in payloads:
                    if payload in self.driver.page_source:
                        print(f"DOM-based XSS vulnerability detected with payload: {payload}")
                        mitigation = self.get_dast_mitigation(context)
                        self.vulnerabilities.append({
                            'url': url,
                            'context': context,
                            'line_number': None,
                            'payload': payload,
                            'description': 'DOM-based XSS vulnerability detected',
                            'mitigation': mitigation,
                            'response': self.driver.page_source
                        })
        except WebDriverException as e:
            print(f"Selenium failed to load the page: {e}")

    def get_sast_mitigation(self, description):
        """Provide mitigation advice for SAST vulnerabilities."""
        owasp_link = "For more information, visit: https://owasp.org/www-community/attacks/xss/"
        if 'Unsafe use of \'safe\' filter' in description:
            return f'Avoid using the `safe` filter. Instead, properly escape output to prevent XSS. {owasp_link}'
        if 'Use of potentially unsafe function' in description:
            return f'Avoid using unsafe functions like `eval` or `exec`. Consider using safer alternatives. {owasp_link}'
        if 'Potentially unsafe use of request data' in description:
            return f'Sanitize and validate all user inputs before processing them. {owasp_link}'
        if 'User input assigned' in description:
            return f'Sanitize all user inputs before assigning them to variables. {owasp_link}'
        if 'Function might return unsanitized user input' in description:
            return f'Ensure that all data returned by functions is properly sanitized. {owasp_link}'
        return f'Review code for potential security risks. {owasp_link}'

    def get_dast_mitigation(self, context):
        """Provide mitigation advice for DAST vulnerabilities."""
        owasp_link = "For more information, visit: https://owasp.org/www-community/attacks/xss/"
        if context == 'html':
            return f'Ensure all user inputs are properly escaped before rendering in HTML. {owasp_link}'
        if context == 'attribute':
            return f'Properly encode attributes to prevent injection of malicious scripts. {owasp_link}'
        if context == 'js':
            return f'Avoid inserting untrusted data directly into JavaScript. Use safe APIs instead. {owasp_link}'
        return f'Review and sanitize all user inputs. {owasp_link}'

    def generate_report(self, filename):
        output_dir = os.getcwd()
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = os.path.join(output_dir, f"{filename}_{timestamp}.csv")

        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['File/URL', 'Context', 'Line Number', 'Payload', 'Vulnerability Description', 'Mitigation', 'Response Snippet']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for vuln in self.vulnerabilities:
                    writer.writerow({
                        'File/URL': vuln.get('file', vuln.get('url')),
                        'Context': vuln['context'],
                        'Line Number': vuln.get('line_number', 'N/A'),
                        'Payload': vuln.get('payload', 'N/A'),
                        'Vulnerability Description': vuln['description'],
                        'Mitigation': vuln['mitigation'],
                        'Response Snippet': vuln.get('response', '')[:100] if vuln.get('response') else ''
                    })

            # Save the list of crawled URLs if DAST or Hybrid was run
            if self.mode in ['dast', 'hybrid']:
                crawled_urls_filename = os.path.join(output_dir, f"crawled_urls_{timestamp}.csv")
                with open(crawled_urls_filename, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['Crawled URL'])
                    for url in self.crawled_urls:
                        writer.writerow([url])

            print(f"Report saved as {filename}")

        except PermissionError as e:
            print(f"Failed to save the report: {e}")

class PythonWebAppXSSDetector(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['render_template', 'render']:
                for keyword in node.keywords:
                    if isinstance(keyword.value, ast.Str):
                        if 'safe' in keyword.value.s or '{{' in keyword.value.s:
                            self.vulnerabilities.append(
                                (node.lineno, node.col_offset, f"Unsafe use of 'safe' filter or raw HTML in template rendering: {keyword.value.s}")
                            )
        
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.vulnerabilities.append(
                    (node.lineno, node.col_offset, f"Use of potentially unsafe function: {node.func.id}")
                )
        
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['format', 'join']:
                for arg in node.args:
                    if isinstance(arg, ast.Call):
                        if isinstance(arg.func, ast.Name) and arg.func.id in ['request', 'get']:
                            self.vulnerabilities.append(
                                (node.lineno, node.col_offset, f"Potentially unsafe use of request data in {node.func.attr}: {arg.func.id}")
                            )
        
        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id in ['request', 'get']:
                if isinstance(node.targets[0], ast.Name):
                    self.vulnerabilities.append(
                        (node.lineno, node.col_offset, f"User input assigned to {node.targets[0].id} without sanitization.")
                    )
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for n in node.body:
            if isinstance(n, ast.Return):
                if isinstance(n.value, ast.Call):
                    if isinstance(n.value.func, ast.Name) and n.value.func.id in ['request', 'get']:
                        self.vulnerabilities.append(
                            (node.lineno, node.col_offset, f"Function {node.name} might return unsanitized user input.")
                        )
        self.generic_visit(node)

if __name__ == "__main__":
    mode = input("Select mode (sast, dast, hybrid): ").lower()
    target_url = None
    code_directory = None

    if mode == 'sast' or mode == 'hybrid':
        code_directory = input("Enter the directory to scan: ")

    if mode == 'dast' or mode == 'hybrid':
        target_url = input("Enter the URL to scan: ")

    hybrid_tool = HybridXSSDetectionTool(mode, target_url=target_url, code_directory=code_directory)
    hybrid_tool.run()
