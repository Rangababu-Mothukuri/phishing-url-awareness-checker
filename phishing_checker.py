
import ipaddress
import re
from urllib.parse import urlparse, unquote


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "ow.ly",
    "shorturl.at",
    "rebrand.ly",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "secure",
    "update",
    "billing",
    "confirm",
    "wallet",
    "webscr",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "work",
    "zip",
    "country",
    "gq",
    "tk",
}


def is_ip_address(hostname):
    """Return True if hostname is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def inspect_url(url):
    warnings = []
    score = 0

    def add_warning(message, points):
        nonlocal score
        warnings.append(message)
        score += points

    url = url.strip()

    if not url:
        return {
            "score": 0,
            "risk": "INVALID",
            "warnings": ["Please enter a URL."],
        }

    # Add a scheme for parsing if the user did not provide one.
    # This does not visit the URL.
    if "://" not in url:
        parsed = urlparse("https://" + url)
    else:
        parsed = urlparse(url)

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    if not hostname:
        return {
            "score": 0,
            "risk": "INVALID",
            "warnings": ["Could not identify a hostname. Check the URL format."],
        }

    # 1. @ symbol
    if "@" in url:
        add_warning(
            "URL contains an @ symbol, which can hide the actual hostname.",
            25,
        )

    # 2. Long URL
    if len(url) > 100:
        add_warning(
            "URL is unusually long.",
            5,
        )

    # 3. IP address as hostname
    if is_ip_address(hostname):
        add_warning(
            "Hostname is an IP address instead of a domain name.",
            25,
        )

    # 4. Too many hostname labels
    labels = hostname.split(".")
    if len(labels) >= 5:
        add_warning(
            "Hostname contains five or more parts.",
            8,
        )

    # 5. Punycode
    if "xn--" in hostname:
        add_warning(
            "Hostname contains punycode, which may represent unusual characters.",
            20,
        )

    # 6. HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        add_warning(
            "URL uses HTTP instead of HTTPS.",
            8,
        )

    # 7. Suspicious keywords
    found_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in hostname or keyword in parsed.path.lower()
    ]

    if found_keywords:
        add_warning(
            "URL contains suspicious keyword(s): "
            + ", ".join(sorted(found_keywords)),
            6,
        )

    # 8. URL shortener
    if hostname in SHORTENERS:
        add_warning(
            "URL uses a known URL-shortening service.",
            15,
        )

    # 9. Suspicious top-level domain
    tld = hostname.split(".")[-1]

    if tld in SUSPICIOUS_TLDS:
        add_warning(
            f"Hostname uses the potentially suspicious .{tld} domain ending.",
            10,
        )

    # 10. Percent-encoded characters
    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))

    if encoded_count >= 3:
        add_warning(
            "URL contains multiple percent-encoded characters.",
            8,
        )

    # 11. Encoded URL or another URL inside the query
    decoded_url = unquote(url)

    if re.search(r"https?://", decoded_url.split("://", 1)[-1]):
        add_warning(
            "URL may contain another embedded URL.",
            15,
        )

    # 12. Unusual port
    try:
        port = parsed.port

        if port is not None and port not in {80, 443}:
            add_warning(
                f"URL uses a non-standard port: {port}.",
                8,
            )

    except ValueError:
        add_warning(
            "URL contains an invalid port number.",
            10,
        )

    # 13. Deep path
    path_parts = [part for part in parsed.path.split("/") if part]

    if len(path_parts) >= 6:
        add_warning(
            "URL contains a very deep path.",
            5,
        )

    # Keep the score between 0 and 100.
    score = min(score, 100)

    if score >= 50:
        risk = "HIGH RISK"
    elif score >= 20:
        risk = "MEDIUM RISK"
    else:
        risk = "LOW RISK"

    if not warnings:
        warnings.append("No obvious warning indicators detected.")

    return {
        "score": score,
        "risk": risk,
        "warnings": warnings,
    }


def main():
    print("=" * 45)
    print("       PHISHING URL AWARENESS CHECKER")
    print("=" * 45)
    print("This tool analyzes URL text only.")
    print("It does not visit URLs or contact external services.")
    print()

    while True:
        url = input("Enter a URL (or type 'quit' to exit): ").strip()

        if url.lower() == "quit":
            print("Goodbye!")
            break

        result = inspect_url(url)

        print("\n" + "-" * 45)
        print(f"Risk Score: {result['score']}/100")
        print(f"Classification: {result['risk']}")
        print("\nFindings:")

        for warning in result["warnings"]:
            print(f"- {warning}")

        print("\nNote:")
        print("A low score does not guarantee that a URL is safe.")
        print("-" * 45)
        print()


if __name__ == "__main__":
    main()
