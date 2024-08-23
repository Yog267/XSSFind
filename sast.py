import os
import re
import csv

# Define patterns for various XSS vulnerabilities
patterns = {
    "Unsanitized User Input": r"request\.(GET|POST)\[.*\]",
    "Direct Output of User Input": r"{{.*request\.(GET|POST)\[.*\].*}}",
    "Use of Unsafe Functions": r"\b(eval|setTimeout|setInterval|innerHTML|outerHTML|document\.write)\b",
    "Missing Output Encoding": r"response\.write\(.*request\.(GET|POST)\[.*\]\)",
    "DOM Manipulation Issues": r"document\.getElementById\(\w+\)\.(innerHTML|outerHTML|value) =.*request\.(GET|POST)\[.*\]",
    "Lack of Content Security Policy (CSP)": r"Content-Security-Policy",
    "Insecure Event Handlers": r"on(click|mouseover|mouseout|keydown|keyup|focus|blur) *= *['\"].*request\.(GET|POST)\[.*\].*['\"]",
    "Reflected User Input": r"response\.write\(.*request\.(GET|POST)\[.*\]\)",
    "Stored User Input": r"db\.insert\(.+request\.(GET|POST)\[.*\]",
    "Misuse of JavaScript Libraries": r"\b(eval|Function)\(.*\)",
    "Vulnerable Third-Party Components": r"script src=.*\b(known_vuln_lib)\b",
    "Insecure Data Handling in Cookies": r"document\.cookie *= *request\.(GET|POST)\[.*\]",
    "Improper URL Construction": r"(href|src) *= *['\"].*request\.(GET|POST)\[.*\].*['\"]",
    "Insecure Handling of File Uploads": r"request\.FILES\['.*'\]",
    "JSONP Callback Issues": r"\bcallback *= *request\.(GET|POST)\[.*\]"
}

def scan_file_for_xss(file_path):
    """Scan a file for potential XSS vulnerabilities based on predefined patterns."""
    vulnerabilities = []
    
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            for vuln_type, pattern in patterns.items():
                if re.search(pattern, line):
                    vulnerabilities.append((i + 1, line.strip(), vuln_type))
    
    return vulnerabilities

def scan_directory_for_xss(directory):
    """Scan all Python files in a directory for potential XSS vulnerabilities."""
    xss_issues = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                print(f"Checking file: {file_path}")
                vulnerabilities = scan_file_for_xss(file_path)
                if vulnerabilities:
                    xss_issues.append({
                        'file': file_path,
                        'vulnerabilities': vulnerabilities
                    })
    
    return xss_issues

def generate_sast_report(results):
    with open('sast_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['File', 'Line Number', 'Vulnerability Type', 'Vulnerability Description', 'Mitigation']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            for vuln in result['vulnerabilities']:
                mitigation = get_sast_mitigation(vuln[2])
                writer.writerow({
                    'File': result['file'],
                    'Line Number': vuln[0],
                    'Vulnerability Type': vuln[2],
                    'Vulnerability Description': vuln[1],
                    'Mitigation': mitigation
                })

    print("SAST report saved as sast_results.csv")

def get_sast_mitigation(vuln_type):
    """Provide mitigation advice for SAST vulnerabilities."""
    owasp_link = "For more information, visit: https://owasp.org/www-community/attacks/xss/"
    if vuln_type == 'Unsanitized User Input':
        return f'Sanitize and validate all user inputs before processing them. {owasp_link}'
    if vuln_type == 'Direct Output of User Input':
        return f'Avoid directly outputting user inputs. Properly escape or encode the output. {owasp_link}'
    if vuln_type == 'Use of Unsafe Functions':
        return f'Avoid using unsafe functions like `eval`, `setTimeout`, or `innerHTML`. Use safer alternatives. {owasp_link}'
    if vuln_type == 'Missing Output Encoding':
        return f'Ensure that all output is properly encoded before rendering it to the user. {owasp_link}'
    if vuln_type == 'DOM Manipulation Issues':
        return f'Avoid manipulating the DOM with untrusted data. Use safe methods to update the DOM. {owasp_link}'
    if vuln_type == 'Lack of Content Security Policy (CSP)':
        return f'Implement a strong Content Security Policy (CSP) to mitigate XSS attacks. {owasp_link}'
    if vuln_type == 'Insecure Event Handlers':
        return f'Avoid directly using user input in event handlers. Validate and sanitize the input. {owasp_link}'
    if vuln_type == 'Reflected User Input':
        return f'Properly sanitize and encode user inputs before reflecting them in the response. {owasp_link}'
    if vuln_type == 'Stored User Input':
        return f'Sanitize and validate inputs before storing them in the database. {owasp_link}'
    if vuln_type == 'Misuse of JavaScript Libraries':
        return f'Avoid using functions like `eval` or `Function` to execute code. Use safer alternatives. {owasp_link}'
    if vuln_type == 'Vulnerable Third-Party Components':
        return f'Ensure that third-party libraries are secure and up-to-date. {owasp_link}'
    if vuln_type == 'Insecure Data Handling in Cookies':
        return f'Securely handle data in cookies and avoid exposing sensitive information. {owasp_link}'
    if vuln_type == 'Improper URL Construction':
        return f'Sanitize and validate user inputs before using them to construct URLs. {owasp_link}'
    if vuln_type == 'Insecure Handling of File Uploads':
        return f'Properly validate and sanitize file uploads to avoid malicious content. {owasp_link}'
    if vuln_type == 'JSONP Callback Issues':
        return f'Avoid using JSONP and switch to safer alternatives like CORS. {owasp_link}'
    return f'Review code for potential security risks. {owasp_link}'

if __name__ == "__main__":
    directory_to_scan = input("Enter the directory to scan: ")
    report = scan_directory_for_xss(directory_to_scan)
    if report:
        generate_sast_report(report)
    else:
        print("No potential SAST vulnerabilities found.")
