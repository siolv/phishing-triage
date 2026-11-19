"""Draft the human explanation and escalation note with a local Ollama model."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from models import Assessment

DEFAULT_MODEL = "qwen3.5:9b"
DEFAULT_URL = "http://localhost:11434/api/generate"

PROMPT = """You are an inbox triage analyst. Write for a busy, non-technical employee.

You receive evidence from a deterministic scanner. Do not invent facts, domains,
people, or outcomes. If the evidence does not settle something, say so.

Return ONE JSON object, no code fences, with exactly these keys:
{
  "summary": "2-3 plain-English sentences: what this is and how worried to be.",
  "escalation_note": "4-6 sentences ready to send to a manager or IT helpdesk. Say what arrived, the strongest evidence, what the person should do, and what to preserve.",
  "questions": ["3 short questions the recipient can use to verify through another channel"]
}

STYLE
- Short sentences. No jargon unless you explain it in the same sentence.
- Do not tell the person to click or open the link.
- Never claim an email is safe. Use "no strong signals" instead.
- Say "likely phishing" or "suspicious". Never say "confirmed", "definitely", or "proven".
- Say "failed authentication" rather than "forged"; headers can fail for several reasons.
- Tell the person to report it to their IT/helpdesk and keep the original message for investigation. Never tell them to delete it before reporting, and never tell them to forward it to anyone except IT.
- The final verdict is set by the scanner; do not change it.

EVIDENCE
"""


def build_evidence(assessment: Assessment) -> dict:
    payload = {
        "verdict": assessment.verdict,
        "score": assessment.score,
        "input": assessment.input_label,
        "signals": [
            {
                "title": signal.title,
                "severity": signal.severity,
                "evidence": signal.evidence,
            }
            for signal in assessment.signals
        ],
        "urls": [
            {
                "display": url.display,
                "host": url.host,
                "registered_domain": url.registered,
                "signals": [signal.title for signal in url.signals],
            }
            for url in assessment.urls
        ],
        "domains": [
            {
                "domain": domain.domain,
                "age_days": domain.age_days,
                "created": domain.created,
                "registrar": domain.registrar,
                "notes": domain.notes,
            }
            for domain in assessment.domains
        ],
    }
    if assessment.header:
        header = assessment.header
        payload["email"] = {
            "from_name": header.from_name,
            "from_address": header.from_address,
            "from_domain": header.from_domain,
            "reply_to": header.reply_to,
            "return_path": header.return_path,
            "subject": header.subject,
            "spf": header.spf,
            "dkim": header.dkim,
            "dmarc": header.dmarc,
            "dkim_domain": header.dkim_domain,
            "notes": header.notes,
        }
    return payload


def _clean(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\s*\n", "", text)
    text = re.sub(r"\n```$", "", text)
    return text.strip()


def ask_ollama(prompt: str, model: str, url: str, timeout: int) -> str:
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "format": "json",
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
                "num_ctx": 4096,
                "num_predict": 800,
            },
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"Ollama HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(
            f"Cannot reach Ollama at {url} ({error.reason}). Is 'ollama serve' running?"
        ) from error
    except (TimeoutError, OSError) as error:
        raise RuntimeError(f"Ollama call timed out after {timeout}s: {error}") from error
    return _clean(payload.get("response", ""))


DEFAULT_QUESTIONS = [
    "Did you expect this message, or did it arrive without warning?",
    "Can you confirm the request through a phone number or app you already trust?",
    "Have you clicked a link, opened an attachment, or entered any information?",
]


def draft_note(
    assessment: Assessment,
    model: str = DEFAULT_MODEL,
    url: str = DEFAULT_URL,
    timeout: int = 600,
) -> tuple[dict | None, str | None]:
    prompt = PROMPT + json.dumps(build_evidence(assessment), indent=2)
    try:
        raw = ask_ollama(prompt, model, url, timeout)
        data = json.loads(raw)
    except (RuntimeError, json.JSONDecodeError) as error:
        return None, str(error)

    summary = str(data.get("summary", "")).strip()
    escalation = str(data.get("escalation_note", "")).strip()
    questions = data.get("questions", [])
    if isinstance(questions, str):
        questions = [questions]
    questions = [str(item).strip() for item in questions if str(item).strip()]
    for fallback in DEFAULT_QUESTIONS:
        if len(questions) >= 3:
            break
        if fallback not in questions:
            questions.append(fallback)
    if not summary and not escalation:
        return None, "The model returned an empty note."
    return {
        "summary": summary,
        "escalation_note": escalation,
        "questions": questions[:3],
    }, None
