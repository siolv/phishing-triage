"""Render the triage report as Markdown."""

from __future__ import annotations

from models import Assessment

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _text(value) -> str:
    """Escape angle brackets so an email address does not vanish as HTML."""
    return (
        _cell(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _age(domain) -> str:
    if domain.age_days is None:
        return "unknown"
    return f"{domain.age_days} days"


def _verdict_advice(score: int) -> list[str]:
    if score >= 70:
        return [
            "Do not click any link or open any attachment in this message.",
            "Report it to your IT or security contact and keep the original message "
            "for investigation.",
            "Delete it only after IT confirms they have what they need.",
            "If you already clicked or entered credentials, change that password now, "
            "turn on MFA, and tell IT what you entered.",
        ]
    if score >= 40:
        return [
            "Do not use the link or reply to the message.",
            "Verify the request through a phone number or app you already trust, not "
            "through the contact details in the email.",
            "If the sender is genuine, ask them to confirm from their normal account.",
            "Report it if the request involves money, passwords, or account access.",
        ]
    if score >= 20:
        return [
            "Treat the message with caution and do not open the link yet.",
            "Check the sender through a known channel before acting.",
            "Report it if you were not expecting the message.",
        ]
    return [
        "No strong phishing signals were found, but this is not a guarantee.",
        "If the message was unexpected, verify the sender through a known channel.",
        "Do not enter credentials from a link you did not expect.",
    ]


def render(
    assessment: Assessment,
    ai: dict | None,
    ai_error: str | None,
    meta: dict,
) -> str:
    lines = [
        "# Phishing Triage Report",
        "",
        f"**Generated:** {meta['generated_at']}  ",
        f"**Input:** {_cell(assessment.input_label)}  ",
        f"**Verdict:** **{assessment.verdict}**  ",
        f"**Risk score:** {assessment.score}/100",
        "",
        "> This is inbox triage, not a guarantee. A low score does not prove an email "
        "is safe, and a high score does not prove it is malicious.",
        "",
        "## What to do now",
        "",
    ]
    lines += [f"- [ ] {item}" for item in _verdict_advice(assessment.score)]
    lines.append("")

    if assessment.signals:
        lines += [
            "## Signals",
            "",
            "| Severity | Signal | Evidence |",
            "|---|---|---|",
        ]
        for signal in sorted(
            assessment.signals,
            key=lambda item: (-item.weight, SEVERITY_ORDER.get(item.severity, 9)),
        ):
            lines.append(
                f"| {signal.severity.upper()} | {_cell(signal.title)} | "
                f"{_cell(signal.evidence)} |"
            )
        lines.append("")
    else:
        lines += [
            "## Signals",
            "",
            "No rules fired. That only means the checks below found nothing obvious.",
            "",
        ]

    if assessment.header:
        header = assessment.header
        lines += [
            "## Email check",
            "",
            f"**From:** {_text(header.from_name)} &lt;{_text(header.from_address)}&gt;  ",
            f"**Reply-To:** {_text(header.reply_to) or 'not set'}  ",
            f"**Return-Path:** {_text(header.return_path) or 'not set'}  ",
            f"**Subject:** {_text(header.subject) or 'not set'}",
            "",
            "| Check | Result |",
            "|---|---|",
            f"| SPF | {header.spf} |",
            f"| DKIM | {header.dkim} |",
            f"| DMARC | {header.dmarc} |",
        ]
        if header.dkim_domain:
            lines.append(f"| DKIM signing domain | {header.dkim_domain} |")
        lines.append("")
        if header.notes:
            lines += ["**Notes:**", ""]
            lines += [f"- {note}" for note in header.notes]
            lines.append("")

    if assessment.urls:
        lines += ["## Links checked", ""]
        for url in assessment.urls:
            lines += [
                f"### `{url.display}`",
                "",
                f"- Host: `{url.host or 'unknown'}`",
                f"- Registered domain: `{url.registered or 'unknown'}`",
            ]
            if url.signals:
                lines.append(
                    "- Signals: " + ", ".join(signal.title for signal in url.signals)
                )
            if url.notes:
                lines += [f"- Note: {note}" for note in url.notes]
            lines.append("")

    if assessment.domains:
        lines += [
            "## Domain check",
            "",
            "| Domain | Age | Created | Registrar |",
            "|---|---|---|---|",
        ]
        for domain in assessment.domains:
            lines.append(
                f"| `{domain.domain}` | {_age(domain)} | "
                f"{domain.created or 'unknown'} | {_text(domain.registrar or 'unknown')} |"
            )
        notes = list(
            dict.fromkeys(
                note for domain in assessment.domains for note in domain.notes
            )
        )
        if notes:
            lines += ["", "**Notes:**", ""]
            lines += [f"- {note}" for note in notes]
        lines.append("")

    lines += ["## Local model triage note", ""]
    if ai:
        if ai.get("summary"):
            lines += [ai["summary"], ""]
        if ai.get("escalation_note"):
            lines += [
                "### Escalation draft",
                "",
                *[f"> {line}" for line in ai["escalation_note"].splitlines()],
                "",
            ]
        if ai.get("questions"):
            lines += ["### Verify through another channel", ""]
            lines += [f"- {question}" for question in ai["questions"]]
            lines.append("")
    else:
        lines += [
            f"> Local model note unavailable: {ai_error or 'not requested'}",
            ">",
            "> The rule-based findings above are complete and unaffected.",
            "",
        ]

    lines += [
        "## What this check cannot see",
        "",
        "- Links are not opened or detonated, so a page can change after the check.",
        "- Attachments are not opened or analysed.",
        "- SPF, DKIM, and DMARC results come from the headers; full DKIM "
        "cryptographic verification is not performed.",
        "- Domain age comes from public RDAP data and can be unavailable for some "
        "domains.",
        "- Headers can be forged, and the local model can be wrong.",
        "",
        "---",
        "",
        "*Generated locally. No link was visited, no email was uploaded, and no cloud "
        "model was called.*",
        "",
    ]
    return "\n".join(lines)
