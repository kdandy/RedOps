# RedOps Code Documentation

RedOps is a multifunctional tool designed for basic security testing on web applications and servers. The tool allows users to execute various testing functions for reconnaissance and vulnerability assessment, including:

1. **Subdomain Discovery**: Searches for subdomains associated with a given domain using the `crt.sh` database.
2. **GET Request Flooding**: Sends multiple repeated GET requests to a specified URL for testing request handling and rate-limiting detection.
3. **Comprehensive Port Scanning**: Scans all ports (1-65535) on a target server to identify open ports.
4. **Directory and Sensitive File Bruteforcing**: Attempts to access common directories and sensitive files on the target URL.
5. **SQL Injection Testing**: Checks for SQL Injection vulnerabilities by injecting various SQL payloads into the URL parameters.
6. **Cross-Site Scripting (XSS) Testing**: Tests for XSS vulnerabilities by injecting potential malicious scripts into URL parameters.
7. **HTTP Header and SSL/TLS Inspection**: Inspects HTTP headers and SSL/TLS certificates for security insights.
8. **CSRF Testing**: Attempts to detect CSRF vulnerabilities by simulating form submissions with common CSRF payloads.
9. **Reverse DNS Lookup**: Performs reverse DNS lookup on a specified IP address to retrieve associated hostnames.
10. **DNS Zone Transfer Testing**: Attempts to perform a DNS zone transfer on a target domain to discover hidden subdomains and DNS records.
11. **Open Redirect Testing**: Tests for open redirect vulnerabilities by appending various payloads to URL parameters.
12. **Command Injection Testing**: Injects command injection payloads into URL parameters to check for command execution vulnerabilities.
13. **CVE Exploit Checker**: Checks the target server for known vulnerabilities (e.g., Log4Shell, Spring4Shell) based on a predefined list of CVEs.

## Features

### **Subdomain Discovery**
Retrieves subdomains for a specified domain using the `crt.sh` database, which aggregates publicly available SSL/TLS certificates. This feature helps uncover additional assets and services linked to the target domain that may otherwise remain hidden. Subdomain discovery is a crucial step in expanding the attack surface during reconnaissance.

### **Spam GET Requests**
Sends configurable batches of GET requests to a specified URL, helping to test server performance under load and identify rate-limiting mechanisms. This feature can:
- Detect potential DoS vulnerabilities.
- Reveal if the server implements throttling to mitigate abuse.
- Simulate high-traffic scenarios to evaluate server resilience.

### **Full Port Scanning**
Performs a comprehensive scan of all 65,535 ports on the target server to identify open ports. Open ports can indicate running services such as:
- **SSH** (22)
- **FTP** (21)
- **HTTP/HTTPS** (80/443)
- **Database Services** (MySQL, PostgreSQL, etc.)
This feature helps in identifying misconfigured services or unauthorized services running on the server.

### **Directory and Sensitive File Bruteforcing**
Attempts to access commonly known directories and sensitive files by brute-forcing predictable paths. Examples include:
- **Directories**: `/admin`, `/config`, `/backup`
- **Files**: `.env`, `wp-config.php`, `database.sql`
These paths can reveal critical information like environment variables, database credentials, or even backup files that should not be publicly accessible.

### **SQL Injection Testing**
Injects various SQL payloads into URL parameters to check for SQL Injection vulnerabilities. SQL Injection allows attackers to manipulate database queries, potentially leading to:
- Unauthorized data access.
- Database schema disclosure.
- Data modification or deletion.
The tool tests for both error-based and time-based SQL Injection techniques.

### **XSS Testing**
Tests for Cross-Site Scripting (XSS) vulnerabilities by injecting malicious JavaScript payloads into URL parameters. If a web application fails to properly sanitize user input, this can lead to:
- **Session hijacking**.
- **Phishing attacks**.
- **Defacement or malware distribution**.
The tool covers a range of XSS vectors, including stored, reflected, and DOM-based XSS.

### **HTTP Header and SSL/TLS Inspection**
Analyzes HTTP headers and SSL/TLS certificates to evaluate server security configurations. This feature helps in:
- Detecting insecure HTTP headers such as `X-Frame-Options`, `Content-Security-Policy`, and `Strict-Transport-Security`.
- Verifying SSL/TLS certificate validity, issuer, and expiration.
- Identifying potential misconfigurations that could lead to man-in-the-middle (MITM) attacks or downgrade vulnerabilities.

### **CSRF Testing**
Simulates form submissions with common Cross-Site Request Forgery (CSRF) payloads to test for vulnerabilities. CSRF attacks trick authenticated users into executing unwanted actions, such as:
- Changing account settings.
- Transferring funds.
- Deleting data.
This feature helps identify web applications that lack anti-CSRF protections, such as CSRF tokens.

### **Reverse DNS Lookup**
Performs a reverse DNS lookup on a specified IP address to find associated hostnames. This feature helps:
- Identify multiple services hosted on the same IP.
- Expand the attack surface by discovering additional domains pointing to the same server.

### **DNS Zone Transfer Testing**
Attempts to perform a DNS zone transfer, which can reveal detailed DNS records if misconfigured. This includes:
- **Subdomains**.
- **Mail servers**.
- **TXT records** (e.g., SPF, DKIM configurations).
Zone transfer is typically restricted to authorized hosts, but if left open, it can expose valuable information for further exploitation.

### **Open Redirect Testing**
Checks for open redirect vulnerabilities by appending payloads to URL parameters. Open redirect vulnerabilities can be exploited to:
- Redirect users to malicious websites.
- Facilitate phishing attacks.
- Bypass URL filters.
The tool tests various endpoints and parameters to identify unvalidated redirects.

### **Command Injection Testing**
Injects command injection payloads into URL parameters to test for arbitrary command execution. If a web application improperly handles user input in system commands, it can lead to:
- Unauthorized command execution.
- File system manipulation.
- Server compromise.
This feature tests common payloads to identify such vulnerabilities in web applications or APIs.

### **CVE Exploit Checker**
Checks the target server for known vulnerabilities based on a list of Common Vulnerabilities and Exposures (CVE). This feature allows you to quickly assess whether the server is vulnerable to widely known exploits, such as:
- **Log4Shell (CVE-2021-44228)**: A critical vulnerability in the Log4j library.
- **Spring4Shell (CVE-2022-22965)**: A vulnerability in the Spring framework.
- **BlueKeep (CVE-2019-0708)**: A critical vulnerability in Microsoft Remote Desktop Services.
Regularly updating the CVE list ensures the tool covers the latest threats.

## Requirements
This tool requires Python 3.7 or higher and the `aiohttp` library. Make sure Python and required packages are installed on your system.

### Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/kdandy/redops.git
   cd RedOps
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt

### Installation python3-venv
1. **Install python3-venv (if not installed)**:
   ```bash
   sudo apt install python3-venv
   python3 -m venv myenv
   source myenv/bin/activate
   pip install -r requirements.txt
2. **Once done, you can deactivate the environment by**:
   ```bash
   deactivate

## Usage
1. **Run the program**:
   ```bash
   python3 redops.py

## LICENSE

This tool was developed by [kdandy](https://github.com/kdandy/devtools/blob/main/LICENSE) and is available on GitHub. Please use it responsibly and only for purposes that comply with service policies.
