import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import concurrent.futures
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
import csv
import time

class AdvancedXSSDAST:
    def __init__(self, target_url):
        self.target_url = target_url
        self.visited_urls = set()
        self.crawled_urls = []  # List to store crawled URLs
        self.vulnerabilities = []
        self.init_browser()
        self.xss_payloads = {
            'html': ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"],
            'attribute': ['" onmouseover="alert(1)"'],
            'js': ["');alert(1);//", "');alert(1)//"],
            # Add more payloads if necessary
        }

    def init_browser(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        self.driver = webdriver.Chrome(options=chrome_options)

    def run(self):
        self.crawl(self.target_url)
        self.generate_report("dast_results.csv")
        self.driver.quit()

    def crawl(self, url):
        if url in self.visited_urls or not url.startswith(self.target_url):
            return
        print(f"Crawling {url}")
        self.visited_urls.add(url)
        self.crawled_urls.append(url)  # Store the URL in the list
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        self.process_forms(soup, url)
        self.process_url_parameters(url)  # New method to inject payloads into URL parameters
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

    def process_url_parameters(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param in query_params:
            for payload in self.xss_payloads['html']:  # Use your payloads here
                modified_params = query_params.copy()
                modified_params[param] = payload
                new_query = urlencode(modified_params, doseq=True)
                modified_url = parsed_url._replace(query=new_query).geturl()
                print(f"Testing URL with payload: {modified_url}")
                try:
                    response = requests.get(modified_url)
                    self.analyze_response(response, modified_url)
                except requests.RequestException as e:
                    print(f"Request failed: {e}")

    def analyze_response(self, response, url):
        for context, payloads in self.xss_payloads.items():
            for payload in payloads:
                if payload in response.text:
                    print(f"XSS vulnerability detected with payload: {payload}")
                    mitigation = self.get_dast_mitigation(context)
                    self.vulnerabilities.append({
                        'url': url,
                        'context': context,
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
                            'payload': payload,
                            'description': 'DOM-based XSS vulnerability detected',
                            'mitigation': mitigation,
                            'response': self.driver.page_source
                        })
        except WebDriverException as e:
            print(f"Selenium failed to load the page: {e}")

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

        # Define the timestamp once at the start of the function
        timestamp = time.strftime("%Y%m%d-%H%M%S")

        filename = os.path.join(output_dir, f"{filename}_{timestamp}.csv")

        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['URL', 'Context', 'Payload', 'Vulnerability Description', 'Mitigation', 'Response Snippet']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for vuln in self.vulnerabilities:
                    writer.writerow({
                        'URL': vuln['url'],
                        'Context': vuln['context'],
                        'Payload': vuln['payload'],
                        'Vulnerability Description': vuln['description'],
                        'Mitigation': vuln['mitigation'],
                        'Response Snippet': vuln['response'][:100]  # Snippet of the response
                    })

            # Also save the list of crawled URLs
            crawled_urls_filename = os.path.join(output_dir, f"crawled_urls_{timestamp}.csv")
            with open(crawled_urls_filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Crawled URL'])
                for url in self.crawled_urls:
                    writer.writerow([url])

            print(f"DAST report saved as {filename}")
            print(f"Crawled URLs saved as {crawled_urls_filename}")

        except PermissionError as e:
            print(f"Failed to save the report: {e}")

if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    dast = AdvancedXSSDAST(target_url)
    dast.run()
