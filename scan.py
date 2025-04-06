import requests
import argparse
import os
import json

# Load payloads from file
def load_payloads(filepath):
    if not os.path.exists(filepath):
        print(f"[-] Payload file not found: {filepath}")
        return []
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

# LFI scan logic
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
        except Exception as e:
            continue
    return results

# RFI scan logic
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

# Save output to JSON
def save_results(results, filename):
    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", filename), 'w') as f:
        json.dump(results, f, indent=4)

# Main logic
def main():
    parser = argparse.ArgumentParser(description="LFI & RFI Scanner")
    parser.add_argument("-u", "--url", help="Target URL (e.g. http://target.com/index.php?page=)", required=True)
    parser.add_argument("--lfi", action="store_true", help="Scan for Local File Inclusion")
    parser.add_argument("--rfi", action="store_true", help="Scan for Remote File Inclusion")
    parser.add_argument("--lfi-payloads", default="payloads/lfi.txt", help="LFI payloads file")
    parser.add_argument("--rfi-payloads", default="payloads/rfi.txt", help="RFI payloads file")

    args = parser.parse_args()

    if not args.lfi and not args.rfi:
        print("[-] You must choose at least --lfi or --rfi")
        return

    if args.lfi:
        lfi_payloads = load_payloads(args.lfi_payloads)
        lfi_results = scan_lfi(args.url, lfi_payloads)
        save_results(lfi_results, "lfi_results.json")

    if args.rfi:
        rfi_payloads = load_payloads(args.rfi_payloads)
        rfi_results = scan_rfi(args.url, rfi_payloads)
        save_results(rfi_results, "rfi_results.json")

    print("[+] Scanning complete.")

if __name__ == "__main__":
    main()
