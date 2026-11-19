#!/usr/bin/env python3
"""Local phishing and suspicious-link triage.

Paste a URL, or point it at a saved email/header file. It checks the link
shape, SPF/DKIM/DMARC results, domain age, and lookalike patterns, then asks a
local Ollama model to draft a plain-English note and escalation message.

Nothing is uploaded. Links are not opened. No cloud model is used.

Usage:
    python triage.py --url "https://example.com/login"
    python triage.py --headers samples/phishing.eml
    python triage.py --headers samples/phishing.eml --no-ai
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from assistant import DEFAULT_MODEL, DEFAULT_URL, draft_note
from headers import address_domain, analyze_headers
from intel import enrich_domain
from models import Assessment, HeaderReport, Signal, URLReport
from report import render
from urls import analyze_url, safe_display

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def verdict_for(score: int) -> str:
    if score >= 70:
        return "LIKELY PHISHING"
    if score >= 40:
        return "SUSPICIOUS"
    if score >= 20:
        return "LOW CONFIDENCE - REVIEW"
    return "NO STRONG PHISHING SIGNALS"


def dedupe(signals: list[Signal]) -> list[Signal]:
    seen = set()
    result = []
    for signal in signals:
        # Same evidence means the same finding, even if one module named it
        # "sender domain" and another named it "url".
        key = signal.evidence.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(signal)
    return result


def build_evidence(
    header: HeaderReport | None,
    urls: list[URLReport],
    domains,
) -> tuple[list[Signal], int, str]:
    signals: list[Signal] = []
    if header:
        signals += header.signals
    for url in urls:
        signals += url.signals
    for domain in domains:
        signals += domain.signals
    signals = dedupe(signals)
    score = min(100, sum(signal.weight for signal in signals))
    return signals, score, verdict_for(score)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Triage a URL or raw email headers locally."
    )
    parser.add_argument("--url", action="append", default=[], help="link to check (repeatable)")
    parser.add_argument("--headers", help="file with raw headers or a saved .eml")
    parser.add_argument("--out", default="report.md", help="Markdown report path")
    parser.add_argument("--json", help="optional JSON output path")
    parser.add_argument("--no-ai", action="store_true", help="skip the local model note")
    parser.add_argument("--no-lookup", action="store_true", help="skip RDAP and DNS lookups")
    parser.add_argument("--max-links", type=int, default=5, help="links to analyse")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--ollama-url", default=DEFAULT_URL)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--no-fail", action="store_true", help="always exit 0")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if not args.url and not args.headers:
        print("Give me a link with --url, or a header file with --headers.")
        return 1

    started = time.time()
    header: HeaderReport | None = None
    header_label = ""

    if args.headers:
        path = Path(args.headers).expanduser()
        if not path.is_file():
            print(f"Header file not found: {path}")
            return 1
        raw = path.read_text(encoding="utf-8", errors="replace")
        header = analyze_headers(raw)
        header_label = path.name
        if not header.from_address:
            print("[warn] No From address was found; this may not be a full header file.")

    raw_urls = list(args.url)
    if header:
        raw_urls += header.urls
    unique_urls = []
    for raw in raw_urls:
        if raw not in unique_urls:
            unique_urls.append(raw)
    unique_urls = unique_urls[: args.max_links]

    url_reports = [analyze_url(raw) for raw in unique_urls]

    domain_names: list[str] = []
    for report in url_reports:
        if report.registered and not report.is_ip:
            domain_names.append(report.registered)
    if header:
        for value in (
            header.from_domain,
            address_domain(header.reply_to),
            address_domain(header.return_path),
            header.dkim_domain,
        ):
            if value and value not in domain_names:
                domain_names.append(value)
    domain_names = domain_names[:5]

    domains = [
        enrich_domain(domain, lookup=not args.no_lookup)
        for domain in domain_names
    ]

    signals, score, verdict = build_evidence(header, url_reports, domains)

    if args.headers and unique_urls:
        link_word = "link" if len(unique_urls) == 1 else "links"
        label = f"{header_label} + {len(unique_urls)} {link_word}"
    elif args.headers:
        label = header_label
    else:
        label = safe_display(unique_urls[0])

    assessment = Assessment(
        input_label=label,
        score=score,
        verdict=verdict,
        signals=signals,
        urls=url_reports,
        header=header,
        domains=domains,
    )

    ai = None
    ai_error = None
    if args.no_ai:
        ai_error = "Skipped with --no-ai."
    elif score < 20 and not header:
        ai_error = "No note requested for a clean link check."
    else:
        print(f"[*] Asking {args.model} for the triage note (local)...")
        ai, ai_error = draft_note(
            assessment, args.model, args.ollama_url, args.timeout
        )
        if ai_error:
            print(f"[!] {ai_error}")
            print("[*] Continuing with the rule-based report only.")

    meta = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "elapsed_seconds": round(time.time() - started, 1),
    }
    report_path = Path(args.out)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        render(assessment, ai, ai_error, meta), encoding="utf-8", newline="\n"
    )

    if args.json:
        payload = {
            "generated_at": meta["generated_at"],
            "input": label,
            "verdict": verdict,
            "score": score,
            "signals": [
                {
                    "code": signal.code,
                    "title": signal.title,
                    "severity": signal.severity,
                    "weight": signal.weight,
                    "evidence": signal.evidence,
                    "category": signal.category,
                }
                for signal in signals
            ],
            "urls": [
                {
                    "display": url.display,
                    "host": url.host,
                    "registered_domain": url.registered,
                    "signals": [signal.code for signal in url.signals],
                }
                for url in url_reports
            ],
            "email": (
                {
                    "from_name": header.from_name,
                    "from_address": header.from_address,
                    "from_domain": header.from_domain,
                    "reply_to": header.reply_to,
                    "return_path": header.return_path,
                    "subject": header.subject,
                    "spf": header.spf,
                    "dkim": header.dkim,
                    "dmarc": header.dmarc,
                    "notes": header.notes,
                }
                if header
                else None
            ),
            "domains": [
                {
                    "domain": domain.domain,
                    "age_days": domain.age_days,
                    "created": domain.created,
                    "registrar": domain.registrar,
                    "notes": domain.notes,
                }
                for domain in domains
            ],
            "ai": {"used": ai is not None, "error": ai_error},
        }
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    print(f"[*] {verdict} - {score}/100 - {len(signals)} signal(s)")
    for signal in sorted(signals, key=lambda item: -item.weight)[:4]:
        print(f"    {signal.severity.upper():<8} {signal.title}")
    print(f"[+] Report: {report_path}")
    if args.json:
        print(f"[+] JSON: {args.json}")

    if score >= 70 and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
