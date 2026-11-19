"""Domain age and DNS checks using public, keyless services.

RDAP gives registration dates. DNS-over-HTTPS reads SPF, DMARC, and A records
without needing a local resolver library. If either service is unavailable, the
report says so instead of guessing.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache

from models import DomainReport, Signal

USER_AGENT = "phishing-triage/1.0 (local inbox triage)"
RDAP_URL = "https://rdap.org/domain/{domain}"
DOH_URL = "https://cloudflare-dns.com/dns-query"


def _get_json(url: str, timeout: int = 8):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/dns-json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def parse_rdap(payload: dict, domain: str, now: datetime | None = None) -> DomainReport:
    report = DomainReport(domain=domain)
    if not isinstance(payload, dict):
        report.notes.append("RDAP returned no usable data.")
        return report

    events = payload.get("events") or []
    created = None
    for event in events:
        action = str(event.get("eventAction", "")).lower()
        if action == "registration":
            raw = event.get("eventDate", "")
            try:
                created = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                created = None
            break

    if created is None:
        report.notes.append("Registration date was not available.")
        return report

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    age = max(0, (now - created).days)
    report.age_days = age
    report.created = created.date().isoformat()

    for entity in payload.get("entities") or []:
        if "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray") or []
        if len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "fn" and len(item) > 3:
                    report.registrar = str(item[3])
                    break

    if age < 30:
        report.signals.append(
            Signal(
                "domain_new_30", "Domain registered in the last 30 days",
                "critical", 30,
                f"{domain} was registered {age} day(s) ago ({report.created}).",
                "domain",
            )
        )
    elif age < 90:
        report.signals.append(
            Signal(
                "domain_new_90", "Domain registered in the last 90 days",
                "high", 20,
                f"{domain} was registered {age} day(s) ago ({report.created}).",
                "domain",
            )
        )
    elif age < 365:
        report.signals.append(
            Signal(
                "domain_new_year", "Domain less than a year old",
                "medium", 10,
                f"{domain} was registered {age} day(s) ago ({report.created}).",
                "domain",
            )
        )

    return report


@lru_cache(maxsize=64)
def lookup_rdap(domain: str) -> DomainReport:
    payload = _get_json(RDAP_URL.format(domain=urllib.parse.quote(domain)))
    if payload is None:
        report = DomainReport(domain=domain)
        report.notes.append("RDAP lookup failed or timed out.")
        return report
    return parse_rdap(payload, domain)


@lru_cache(maxsize=128)
def txt_records(name: str) -> list[str] | None:
    url = DOH_URL + "?" + urllib.parse.urlencode({"name": name, "type": "TXT"})
    payload = _get_json(url)
    if payload is None:
        return None
    records = []
    for answer in payload.get("Answer") or []:
        if answer.get("type") != 16:
            continue
        value = str(answer.get("data", "")).strip('"')
        if value:
            records.append(value)
    return records


def parse_dmarc(records: list[str] | None) -> str | None:
    if not records:
        return None
    for record in records:
        record = record.strip().strip('"')
        if record.lower().startswith("v=dmarc1"):
            for part in record.split(";"):
                piece = part.strip()
                if piece.lower().startswith("p="):
                    return piece.split("=", 1)[1].strip().lower()
            return "none"
    return None


def parse_spf(records: list[str] | None) -> str | None:
    if not records:
        return None
    for record in records:
        record = record.strip().strip('"')
        if record.lower().startswith("v=spf1"):
            return record
    return None


def _resolves(domain: str) -> bool | None:
    url = DOH_URL + "?" + urllib.parse.urlencode({"name": domain, "type": "A"})
    payload = _get_json(url)
    if payload is None:
        return None
    return bool(payload.get("Answer"))


def enrich_domain(domain: str, lookup: bool = True) -> DomainReport:
    if not domain:
        return DomainReport(domain="", notes=["No domain to look up."])
    if not lookup:
        return DomainReport(domain=domain, notes=["Network lookups were disabled."])

    report = lookup_rdap(domain)
    policy = parse_dmarc(txt_records(f"_dmarc.{domain}"))
    spf = parse_spf(txt_records(domain))
    resolved = _resolves(domain)

    if policy == "none":
        report.signals.append(
            Signal(
                "dmarc_policy_none", "DMARC policy is only monitoring",
                "low", 5,
                f"{domain} publishes DMARC with p=none, so failures are not blocked.",
                "domain",
            )
        )
    elif policy in ("quarantine", "reject"):
        report.notes.append(f"DMARC policy for {domain}: p={policy}.")
    else:
        report.notes.append(f"No DMARC policy was found for {domain}.")

    if not spf:
        report.notes.append(f"No SPF record was found for {domain}.")
    if resolved is False:
        report.signals.append(
            Signal(
                "domain_no_dns", "Domain does not resolve",
                "medium", 10,
                f"{domain} has no A record; the link or sender may be dead.",
                "domain",
            )
        )
    elif resolved is None:
        report.notes.append("DNS lookup failed or timed out.")

    return report
