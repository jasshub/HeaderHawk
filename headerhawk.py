import requests
from colorama import Fore, Style, init
from urllib.parse import urlparse
import socket
import ipaddress

init(autoreset=True)

SECURITY_HEADERS = {
    # (same as before, unchanged)
    # You already have these configured correctly
}

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        scheme = parsed.scheme

        if scheme not in ["http", "https"]:
            return False

        # Resolve domain to IP
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        # Block private, loopback, link-local, and reserved addresses
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return False

        return True
    except Exception as e:
        return False

def check_security_headers(url):
    try:
        if not url.startswith("http"):
            url = "https://" + url

        if not is_safe_url(url):
            print(f"{Fore.RED}❌ Blocked potentially unsafe or internal URL: {url}")
            return

        response = requests.get(url, timeout=10)
        headers = response.headers

        print(f"\n{Fore.CYAN}🔍 Security Headers Audit for: {url}\n{'-'*70}")

        total_score = 0
        max_score = len(SECURITY_HEADERS) * 10

        for header, details in SECURITY_HEADERS.items():
            if header in headers:
                value = headers[header]
                if details["check"](value):
                    print(f"{Fore.GREEN}[✅] {header}: {value} (✔ Score: 10/10)")
                    total_score += 10
                else:
                    print(f"{Fore.YELLOW}[⚠️] {header} exists but is misconfigured! (Score: 5/10)")
                    print(f"{Fore.YELLOW}    🔹 Current: {value}")
                    print(f"{Fore.BLUE}    🔹 Recommended: {details['recommended']}")
                    print(f"{Fore.BLUE}    🔹 Reason: {details['reason']}")
                    total_score += 5
            else:
                print(f"{Fore.RED}[❌] {header} is missing! (Score: 0/10)")
                print(f"{Fore.BLUE}    🔹 Recommended: {details['recommended']}")
                print(f"{Fore.BLUE}    🔹 Reason: {details['reason']}")

        percentage_score = (total_score / max_score) * 100
        print(f"\n📊 {Style.BRIGHT}Final Security Score: {total_score}/{max_score} ({percentage_score:.2f}%)")

        if percentage_score >= 90:
            level = Fore.GREEN + "🟢 Excellent (Minimal Risk)"
        elif percentage_score >= 70:
            level = Fore.YELLOW + "🟡 Good (Some Improvements Needed)"
        elif percentage_score >= 50:
            level = Fore.MAGENTA + "🟠 Fair (Moderate Risk - Action Needed)"
        else:
            level = Fore.RED + "🔴 Poor (High Risk - Immediate Action Needed)"

        print(f"{Style.BRIGHT}🚨 Attention Level: {level}\n")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}❌ Error fetching {url}: {e}")

if __name__ == "__main__":
    url = input("🌐 Enter the website URL (e.g., example.com or https://example.com): ").strip()
    check_security_headers(url)
