# DevTools Code Documentation

DevTools is a multifunctional tool designed for basic security testing on web applications and servers. The tool allows users to execute various testing functions for reconnaissance and vulnerability assessment, including:

1. **Subdomain Discovery**: Searches for subdomains associated with a given domain using the `crt.sh` database.
2. **GET Request Flooding**: Sends multiple repeated GET requests to a specified URL for testing request handling and rate-limiting detection.
3. **Comprehensive Port Scanning**: Scans all ports (1-65535) on a target server to identify open ports.
4. **Directory and Sensitive File Bruteforcing**: Attempts to access common directories and sensitive files on the target URL.
5. **SQL Injection Testing**: Checks for SQL Injection vulnerabilities by injecting various SQL payloads into the URL parameters.
6. **Cross-Site Scripting (XSS) Testing**: Tests for XSS vulnerabilities by injecting potential malicious scripts into URL parameters.
7. **HTTP Header and SSL/TLS Inspection**: Inspects HTTP headers and SSL/TLS certificates for security insights.
8. **CSRF Testing**: Attempts to detect CSRF vulnerabilities by simulating form submissions with common CSRF payloads.

## Features

- **Subdomain Discovery**: Retrieves subdomains for a specified domain from the `crt.sh` database to aid in reconnaissance. This feature is valuable for gathering information about additional services or assets that may be accessible through subdomains.
  
- **Spam GET Requests**: Sends configurable batches of GET requests to the target URL to test server rate-limiting and request-handling capabilities. This can reveal potential throttling or abuse protections on the target server, indicating whether the server can handle high traffic volumes without performance degradation.
  
- **Full Port Scanning**: Scans all ports from 1 to 65535 on the target server to identify open ports, which can indicate services running and potentially vulnerable configurations. An open port may expose network services (e.g., SSH, FTP, HTTP) that can be probed for further vulnerabilities, making this scan essential for a comprehensive security assessment.
  
- **Directory and Sensitive File Bruteforcing**: Attempts to access commonly known directories (e.g., `/admin`, `/config`) and sensitive files (e.g., `.env`, `config.json`) to identify unprotected endpoints. Finding unprotected directories or files can expose valuable information, such as server configurations, environment variables, or potentially sensitive data.

- **SQL Injection Testing**: Injects various SQL payloads into URL parameters to test for potential SQL Injection vulnerabilities, which can lead to unauthorized access or data leaks if exploited. Detecting SQL injection vulnerabilities is crucial, as they allow attackers to manipulate backend database queries.

- **XSS Testing**: Injects JavaScript payloads into URL parameters to test for potential Cross-Site Scripting (XSS) vulnerabilities, which can enable client-side code execution if unprotected. XSS vulnerabilities pose a risk for user session hijacking, phishing, and spreading malware.

- **HTTP Header and SSL/TLS Inspection**: Collects and displays HTTP headers from the server and inspects SSL/TLS certificate details, providing security insights into server configurations. This feature helps identify misconfigurations in SSL certificates, potential downgrade attacks, and insecure HTTP headers.

- **CSRF Testing**: Attempts to detect Cross-Site Request Forgery (CSRF) vulnerabilities by simulating form submissions with common CSRF payloads. Detecting CSRF vulnerabilities can prevent unauthorized actions being performed on behalf of authenticated users, a common risk in web applications without anti-CSRF protections.


## Requirements
This tool requires Python 3.7 or higher and the `aiohttp` library. Make sure Python and required packages are installed on your system.


## Requirements
This tool requires Python and the `aiohttp` library. Make sure Python 3.7 or higher is installed on your system.

### Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/kdandy/devtools.git
   cd devtools
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt

## Usage
1. **Run the program**:
   ```bash
   python3 devtools.py

## LICENSE

This tool was developed by [kdandy](https://github.com/kdandy/devtools/blob/main/LICENSE) and is available on GitHub. Please use it responsibly and only for purposes that comply with service policies.