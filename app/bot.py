import os
import pickle
import socket
import atexit

# Known bot suffixes used for reverse DNS validation
KNOWN_BOTS = {
    "Googlebot": [".googlebot.com"],
    "Bingbot": [".search.msn.com"],
    "AhrefsBot": [".ahrefs.com", ".ahrefs.net"],
    "YandexBot": [".yandex.ru", ".yandex.com", ".yandex.net"],
    "SemrushBot": [".semrush.com"],
    "DuckDuckBot": [".duckduckgo.com"],
    "MJ12bot": [".majestic12.co.uk"],
    "Slurp": [".crawl.yahoo.net"],
    "Applebot": [".apple.com"]
}

# Cache file paths for verified and spoofed bot IPs
VERIFIED_IP_FILE = "verified_bots.pkl"
SPOOFED_IP_FILE = "spoofed_bots.pkl"

def pickle_load(path):
    """
    Load a set object from a pickle file.

    If the file does not exist or is invalid/corrupted, returns an empty set.

    Args:
        path (str): Path to the pickle file.

    Returns:
        set: The loaded set from the pickle file, or an empty set on error.
    """
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except Exception:
        return set()

# Load IP caches early to avoid NameError during runtime
verified_bot_ips = pickle_load(VERIFIED_IP_FILE)
spoofed_bot_ips = pickle_load(SPOOFED_IP_FILE)

def save_ip_caches():
    """
    Persist IP address caches for verified and spoofed bots.

    This function is registered with `atexit` and ensures that any updates
    to `verified_bot_ips` and `spoofed_bot_ips` are saved to disk when the program exits.
    This reduces redundant DNS lookups across executions.
    """
    with open(VERIFIED_IP_FILE, "wb") as f:
        pickle.dump(verified_bot_ips, f)
    with open(SPOOFED_IP_FILE, "wb") as f:
        pickle.dump(spoofed_bot_ips, f)

atexit.register(save_ip_caches)

def reverse_dns(ip):
    """
    Perform a reverse DNS lookup for the given IP address.

    Args:
        ip (str): The IP address to resolve.

    Returns:
        str or None: The resolved hostname, or None if the lookup fails.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def forward_dns(hostname):
    """
    Resolve a hostname to its corresponding IP address using forward DNS.

    Args:
        hostname (str): The hostname to resolve.

    Returns:
        str or None: The resolved IP address, or None if resolution fails.
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def is_valid_bot(ip, ua):
    """
    Validate whether the request came from a legitimate known bot.

    First this function check whether the IP is already cached as verified or spoofed.
    Then, it checks:
      1. If the user-agent string matches a known bot.
      2. If reverse DNS of the IP ends with an expected domain suffix.
      3. If forward DNS of the resolved hostname points back to the same IP.

    If all checks pass, the IP is marked as verified. Otherwise, it's marked as spoofed.

    Args:
        ip (str): The IP address of the requester.
        ua (str): The User-Agent string from the request.

    Returns:
        bool: True if the request is from a valid bot, False otherwise.
    """
    if ip in verified_bot_ips:
        return True
    if ip in spoofed_bot_ips:
        return False

    for bot, suffixes in KNOWN_BOTS.items():
        if bot.lower() in ua.lower():
            rdns = reverse_dns(ip)
            if not rdns or not any(rdns.endswith(sfx) for sfx in suffixes):
                spoofed_bot_ips.add(ip)
                return False
            if forward_dns(rdns) != ip:
                spoofed_bot_ips.add(ip)
                return False
            verified_bot_ips.add(ip)
            return True

    return False  # Not a known bot
