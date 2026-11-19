"""Read raw email headers and turn authentication results into plain signals."""

from __future__ import annotations

import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr

from models import HeaderReport, Signal
from urls import BRANDS, brand_signals, extract_urls

AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")
DKIM_DOMAIN_RE = re.compile(r"\bd\s*=\s*([^;\s]+)", re.I)
DKIM_SELECTOR_RE = re.compile(r"\bs\s*=\s*([^;\s]+)", re.I)
SPF_HEADER_RE = re.compile(r"^\s*([a-zA-Z]+)", re.M)

URGENCY_WORDS = (
    "urgent", "verify", "suspend", "locked", "invoice", "payment",
    "password", "gift", "winner", "refund", "delivery", "failed",
    "action required", "final notice", "account closure",
)


def address_domain(value: str) -> str:
    _, address = parseaddr(value or "")
    if "@" in address:
        return address.rsplit("@", 1)[1].lower().strip(".")
    return ""


def _auth_results(message) -> dict[str, str]:
    combined = "\n".join(message.get_all("Authentication-Results") or [])
    results: dict[str, str] = {}
    for match in AUTH_RE.finditer(combined):
        results[match.group(1).lower()] = match.group(2).lower()
    return results


def _body_urls(message) -> list[str]:
    texts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        texts.append(payload.decode("utf-8", "ignore"))
                except (LookupError, ValueError):
                    continue
    else:
        try:
            payload = message.get_payload(decode=True)
            if payload:
                texts.append(payload.decode("utf-8", "ignore"))
        except (LookupError, ValueError):
            pass
    urls: list[str] = []
    for text in texts:
        for url in extract_urls(text):
            if url not in urls:
                urls.append(url)
    return urls[:8]


def _add(report: HeaderReport, code, title, severity, weight, evidence):
    if not any(signal.code == code for signal in report.signals):
        report.signals.append(
            Signal(code, title, severity, weight, evidence, "email")
        )


def analyze_headers(raw: str) -> HeaderReport:
    message = Parser(policy=policy.default).parsestr(raw)
    report = HeaderReport()

    from_header = message.get("From", "")
    report.from_name, report.from_address = parseaddr(str(from_header))
    report.from_domain = address_domain(str(from_header))
    report.reply_to = str(message.get("Reply-To", "") or "")
    report.return_path = str(message.get("Return-Path", "") or "")
    report.subject = str(message.get("Subject", "") or "")

    auth = _auth_results(message)
    received_spf = str(message.get("Received-SPF", "") or "")
    spf_header = SPF_HEADER_RE.search(received_spf)

    report.spf = auth.get("spf") or (
        spf_header.group(1).lower() if spf_header else "not reported"
    )
    report.dkim = auth.get("dkim", "not reported")
    report.dmarc = auth.get("dmarc", "not reported")

    dkim_signature = "\n".join(message.get_all("DKIM-Signature") or [])
    domain_match = DKIM_DOMAIN_RE.search(dkim_signature)
    selector_match = DKIM_SELECTOR_RE.search(dkim_signature)
    report.dkim_domain = domain_match.group(1).lower() if domain_match else ""
    if report.dkim == "not reported" and dkim_signature:
        report.dkim = "signed, result not reported"
    report.urls = _body_urls(message)

    if report.spf == "fail":
        _add(report, "spf_fail", "SPF failed", "high", 20,
             "The sending server is not allowed to send mail for that domain.")
    elif report.spf == "softfail":
        _add(report, "spf_softfail", "SPF soft-failed", "medium", 10,
             "The sending server is probably not authorised for that domain.")
    elif report.spf in ("none", "not reported"):
        _add(report, "spf_missing", "No SPF result", "low", 5,
             "SPF was not reported in the headers.")

    if report.dkim == "fail":
        _add(report, "dkim_fail", "DKIM failed", "high", 20,
             "The message signature did not match the sending domain.")
    elif report.dkim == "not reported":
        _add(report, "dkim_missing", "No DKIM result", "low", 3,
             "DKIM was not reported in the headers.")
    elif report.dkim.startswith("signed"):
        _add(report, "dkim_unverified", "DKIM signed, result unknown", "low", 3,
             "A DKIM signature exists, but the headers do not report a pass or fail.")

    if report.dmarc == "fail":
        _add(report, "dmarc_fail", "DMARC failed", "critical", 25,
             "The message failed the domain owner's DMARC policy.")
    elif report.dmarc == "none":
        _add(report, "dmarc_missing", "No DMARC result", "low", 5,
             "DMARC was not reported in the headers.")

    reply_domain = address_domain(report.reply_to)
    if reply_domain and reply_domain != report.from_domain:
        _add(report, "reply_to_mismatch", "Reply-To goes to another domain",
             "medium", 12,
             f"From is {report.from_domain or 'unknown'}; Reply-To is {reply_domain}.")

    return_domain = address_domain(report.return_path)
    if return_domain and return_domain != report.from_domain:
        _add(report, "return_path_mismatch", "Return-Path goes to another domain",
             "medium", 10,
             f"From is {report.from_domain or 'unknown'}; Return-Path is {return_domain}.")

    if report.from_domain:
        for signal in brand_signals(report.from_domain):
            _add(
                report,
                "sender_" + signal.code,
                "Sender domain imitates a brand",
                signal.severity,
                signal.weight,
                signal.evidence,
            )

    if report.from_domain:
        lowered_name = report.from_name.lower()
        for brand, official in BRANDS.items():
            if brand not in lowered_name:
                continue
            if report.from_domain == official or report.from_domain.endswith("." + official):
                continue
            _add(
                report,
                f"display_name_{brand}",
                "Display name claims a brand",
                "high", 20,
                f"The sender name says '{report.from_name}', but the address is @{report.from_domain}.",
            )
            break

    lowered_subject = report.subject.lower()
    hits = [word for word in URGENCY_WORDS if word in lowered_subject]
    if hits:
        _add(
            report, "urgent_language", "Urgent or account-themed subject",
            "low", 5,
            "Subject contains: " + ", ".join(hits[:4]) + ".",
        )

    # A reply-to domain can also be a lookalike.
    if reply_domain:
        for signal in brand_signals(reply_domain):
            _add(
                report,
                "reply_" + signal.code,
                "Reply-To domain imitates a brand",
                signal.severity,
                signal.weight,
                signal.evidence,
            )

    if not report.from_address:
        report.notes.append("No From address was found in the headers.")
    if not report.from_domain:
        report.notes.append("The sender domain could not be read.")
    if report.dmarc == "not reported":
        report.notes.append(
            "DMARC was not reported. A missing result is not the same as a pass."
        )
    if report.dkim_domain and report.from_domain and report.dkim_domain != report.from_domain:
        report.notes.append(
            f"DKIM was signed by {report.dkim_domain}, not {report.from_domain}."
        )
    if report.urls:
        count = len(report.urls)
        report.notes.append(
            f"{count} {'link' if count == 1 else 'links'} "
            f"{'was' if count == 1 else 'were'} found in the message body."
        )

    return report
