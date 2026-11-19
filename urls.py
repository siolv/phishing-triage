"""URL parsing and lookalike checks.

The goal is a short list of evidence a human can verify, not a black box.
Nothing here visits the suspicious link.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from models import Signal, URLReport

# Multi-part public suffixes used by the audience this tool targets.
SUFFIXES = {
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "co.uk", "org.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "com.sg", "com.my", "co.id",
    "com.br", "com.mx",
}

# Brand name -> official registered domain. Keep this short and high-signal.
BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "netflix": "netflix.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "bpi": "bpi.com.ph",
    "gcash": "gcash.com",
    "maya": "maya.ph",
    "landbank": "landbank.com",
    "metrobank": "metrobank.com.ph",
    "unionbank": "unionbankph.com",
    "steam": "steampowered.com",
    "roblox": "roblox.com",
    "discord": "discord.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "github": "github.com",
    "linkedin": "linkedin.com",
    "docusign": "docusign.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "t.ly",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "live", "shop", "support",
    "rest", "icu", "cam", "buzz", "monster", "cfd", "sbs", "quest", "lol",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".apk",
    ".zip", ".rar", ".iso", ".lnk", ".hta",
}

HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
})

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    lowered = raw.lower()
    if lowered.startswith(("javascript:", "data:")):
        return raw
    if lowered.startswith("www."):
        return "http://" + raw
    if "://" not in raw:
        return "http://" + raw
    return raw


def registered_domain(host: str) -> str:
    """Approximate the registrable domain, including common two-part suffixes."""
    host = host.lower().strip(".")
    if not host or _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:]) if len(labels) >= 3 else ""
    if last_three and ".".join(labels[-2:]) in SUFFIXES:
        return last_three
    if last_two in SUFFIXES:
        return host
    return last_two


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalize_brand(text: str) -> str:
    lowered = text.lower().translate(HOMOGLYPHS)
    return lowered.replace("rn", "m").replace("vv", "w")


def _distance(left: str, right: str, limit: int = 3) -> int:
    """Small Levenshtein distance with an early exit."""
    if left == right:
        return 0
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, 1):
        current = [i]
        for j, char_right in enumerate(right, 1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (char_left != char_right)
            current.append(min(insert, delete, replace))
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def brand_signals(host: str) -> list[Signal]:
    """Flag lookalike brands and brand names used on the wrong domain."""
    host = host.lower().strip(".")
    if not host or _is_ip(host) or "." not in host:
        return []
    registered = registered_domain(host)
    sld = registered.split(".")[0]
    normalized = _normalize_brand(sld)
    signals: list[Signal] = []
    seen: set[str] = set()

    def add(code: str, title: str, severity: str, weight: int, evidence: str):
        if code not in seen:
            seen.add(code)
            signals.append(
                Signal(code, title, severity, weight, evidence, "url")
            )

    for brand, official in BRANDS.items():
        if sld == brand:
            if registered != official:
                add(
                    f"brand_wrong_domain_{brand}",
                    "Brand name on an unofficial domain",
                    "critical", 40,
                    f"'{brand}' is used in {registered}, but the official domain is {official}.",
                )
            continue

        length = len(brand)
        limit = 1 if length >= 5 else 0
        if length >= 10:
            limit = 2
        if normalized == brand:
            add(
                f"lookalike_{brand}",
                "Lookalike domain",
                "critical", 40,
                f"{sld} imitates {brand} with swapped characters.",
            )
            continue
        distance = _distance(normalized, brand, limit)
        if distance <= limit and distance > 0:
            add(
                f"lookalike_{brand}",
                "Lookalike domain",
                "critical", 40,
                f"{sld} is {distance} character(s) away from {brand}.",
            )

        if "-" in sld and brand in [
            _normalize_brand(part) for part in sld.split("-")
        ]:
            add(
                f"brand_hyphen_{brand}",
                "Brand plus extra words in the domain",
                "high", 40,
                f"{sld} adds words to the brand '{brand}'.",
            )

    # A brand inside a subdomain, while the registered domain belongs to someone else.
    labels = host.split(".")
    registered_labels = registered.split(".")
    subdomain = labels[: -len(registered_labels)] if registered_labels else []
    normalized_subdomain = [_normalize_brand(label) for label in subdomain]
    for brand, official in BRANDS.items():
        if any(brand in label for label in normalized_subdomain) and registered != official:
            add(
                f"brand_subdomain_{brand}",
                "Brand hidden in a subdomain",
                "critical", 40,
                f"{host} puts '{brand}' in a subdomain, but the real domain is {registered}.",
            )
            break

    return signals


def safe_display(url: str) -> str:
    """Show the URL without printing passwords or long query values."""
    try:
        parts = urlsplit(normalize_url(url))
    except ValueError:
        return url
    netloc = parts.netloc
    if parts.password:
        netloc = netloc.replace(f":{parts.password}@", ":***@")
    query = [
        (key, "***" if len(value) > 4 else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit(
        (parts.scheme, netloc, parts.path, urlencode(query, safe="*"), parts.fragment)
    )


def extract_urls(text: str, limit: int = 8) -> list[str]:
    found: list[str] = []
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(").,;]}>'\"")
        if url not in found:
            found.append(url)
        if len(found) >= limit:
            break
    return found


def analyze_url(raw: str) -> URLReport:
    normalized = normalize_url(raw)
    try:
        parts = urlsplit(normalized)
    except ValueError:
        return URLReport(
            raw=raw,
            display=raw,
            host="",
            registered="",
            scheme="",
            notes=["The URL could not be parsed."],
        )

    host = (parts.hostname or "").lower().strip(".")
    registered = registered_domain(host) if host else ""
    is_ip = _is_ip(host)
    report = URLReport(
        raw=raw,
        display=safe_display(raw),
        host=host,
        registered=registered,
        scheme=parts.scheme.lower(),
        is_ip=is_ip,
    )

    def add(code, title, severity, weight, evidence):
        if not any(signal.code == code for signal in report.signals):
            report.signals.append(
                Signal(code, title, severity, weight, evidence, "url")
            )

    if not host:
        if parts.scheme.lower() in ("javascript", "data"):
            add(
                "dangerous_scheme", "Dangerous link type", "high", 30,
                f"The link uses the {parts.scheme} scheme.",
            )
        else:
            add(
                "invalid_url", "Unparseable URL", "medium", 10,
                "No hostname could be read from the link.",
            )
        return report

    for signal in brand_signals(host):
        if not any(existing.code == signal.code for existing in report.signals):
            report.signals.append(signal)

    if is_ip:
        add(
            "ip_host", "IP address instead of a domain", "high", 30,
            f"The link points straight to {host}, which hides the real domain.",
        )

    if "xn--" in host:
        add(
            "punycode", "Punycode domain", "high", 30,
            "The domain uses international characters that can imitate Latin letters.",
        )

    if registered in SHORTENERS or host in SHORTENERS:
        add(
            "shortener", "Link shortener", "medium", 10,
            f"{host} hides the final destination.",
        )

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        add(
            "suspicious_tld", "Unusual top-level domain", "low", 8,
            f".{tld} is common in short-lived phishing domains.",
        )

    if parts.username or parts.password or "@" in parts.netloc:
        add(
            "userinfo", "Credentials or '@' before the host", "high", 25,
            "Text before '@' can disguise the real domain.",
        )
        username = (parts.username or "").lower()
        for brand in BRANDS:
            if brand in username:
                add(
                    f"brand_userinfo_{brand}",
                    "Brand name in the login part of the link",
                    "high", 25,
                    f"The text before '@' mentions '{brand}', but the real host is {host}.",
                )
                break

    try:
        port = parts.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        add(
            "nonstandard_port", "Non-standard port", "low", 8,
            f"The link uses port {port}.",
        )

    subdomain_count = max(0, len(host.split(".")) - len(registered.split(".")))
    if subdomain_count >= 3:
        add(
            "many_subdomains", "Deep subdomain chain", "low", 8,
            f"{subdomain_count} subdomains appear before {registered}.",
        )

    if len(normalized) > 120:
        add(
            "long_url", "Very long URL", "low", 5,
            f"The link is {len(normalized)} characters long.",
        )

    suffix = "." + parts.path.rsplit(".", 1)[-1].lower() if "." in parts.path else ""
    if suffix in DANGEROUS_EXTENSIONS:
        add(
            "dangerous_extension", "Executable or archive in the link", "high", 20,
            f"The path ends in {suffix}.",
        )

    if parts.scheme.lower() == "http":
        add(
            "insecure_http", "No HTTPS", "low", 5,
            "The link uses http:// instead of https://.",
        )

    if len(re.findall(r"%[0-9a-fA-F]{2}", normalized)) >= 4:
        add(
            "heavy_encoding", "Heavily encoded URL", "low", 5,
            "The link hides characters with percent-encoding.",
        )

    return report
