import requests
from colorama import Fore, Style, init
from urllib.parse import urlparse
import socket
import ipaddress
from pyfiglet import figlet_format

init(autoreset=True)

# ------------------- Security Headers Definition -------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "check": lambda v: "max-age" in v and "includeSubDomains" in v,
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "reason": "Enforces HTTPS, prevents downgrade attacks",
    },
    "Content-Security-Policy": {
        "check": lambda v: "default-src" in v and "'unsafe-inline'" not in v,
        "recommended": "default-src 'self'; script-src 'self' 'nonce-randomvalue'",
        "reason": "Prevents XSS, clickjacking, and injection attacks",
    },
    "X-Frame-Options": {
        "check": lambda v: v in ["DENY", "SAMEORIGIN"],
        "recommended": "DENY or SAMEORIGIN",
        "reason": "Prevents clickjacking attacks",
    },
    "X-Content-Type-Options": {
        "check": lambda v: v.lower() == "nosniff",
        "recommended": "nosniff",
        "reason": "Prevents MIME-type sniffing",
    },
    "X-XSS-Protection": {
        "check": lambda v: "1; mode=block" in v,
        "recommended": "1; mode=block (CSP is preferred instead)",
        "reason": "Mitigates XSS attacks (legacy header, CSP is better)",
    },
    "Referrer-Policy": {
        "check": lambda v: v in ["no-referrer", "strict-origin-when-cross-origin"],
        "recommended": "no-referrer or strict-origin-when-cross-origin",
        "reason": "Restricts referrer information for privacy",
    },
    "Permissions-Policy": {
        "check": lambda v: "geolocation" in v or "camera" in v,
        "recommended": "geolocation=(), microphone=(), camera=(), fullscreen=self",
        "reason": "Controls browser API permissions",
    },
    "Cache-Control": {
        "check": lambda v: "no-store" in v or "no-cache" in v,
        "recommended": "no-store, no-cache, must-revalidate",
        "reason": "Prevents sensitive data caching",
    },
    "Access-Control-Allow-Origin": {
        "check": lambda v: v != "*",
        "recommended": "Specify a trusted origin, avoid '*'",
        "reason": "Prevents unauthorized cross-origin access (CORS)",
    },
}

# ------------------- Banner -------------------
def print_banner():
    print(Fore.CYAN + Style.BRIGHT + figlet_format("HeaderHawk"))
    print(f"{Style.BRIGHT}{Fore.BLUE}HeaderHawk – Security Headers Audit Tool (v1.0)")
    print(f"{Fore.MAGENTA}https://github.com/jasshub/HeaderHawk\n{Style.RESET_ALL}")

# ------------------- Internet Check -------------------
def is_internet_available():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

# ------------------- Domain Resolver & Filter -------------------
def is_url_safe_and_resolved(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False

        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return False

        return True
    except Exception:
        return False

# ------------------- Main Scanner -------------------
def check_security_headers():
    url_input = input("🌐 Enter the website URL (e.g., example.com or https://example.com): ").strip()

    if not url_input.startswith("http"):
        url_input = "https://" + url_input

    if is_url_safe_and_resolved(url_input):
        try:
            headers = {"User-Agent": "Mozilla/5.0 (HeaderHawk Scanner)"}
            response = requests.get(url_input, headers=headers, timeout=10)
            header_data = response.headers

            print(f"\n{Fore.CYAN}🔍 Security Headers Audit for: {url_input}\n{'-'*70}")

            total_score = 0
            max_score = len(SECURITY_HEADERS) * 10

            for header, details in SECURITY_HEADERS.items():
                if header in header_data:
                    value = header_data[header]
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
            print(f"{Fore.RED}❌ Error fetching {url_input}: {e}")
    else:
        print(f"{Fore.RED}❌ Unsafe or disallowed URL: {url_input}")

# ------------------- Entry Point -------------------
if __name__ == "__main__":
    print_banner()

    if not is_internet_available():
        print(f"{Fore.RED}❌ Internet connection is not working. Please check and try again.\n")
    else:
        check_security_headers()
