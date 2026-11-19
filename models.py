"""Shared data structures for the triage report."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Signal:
    code: str
    title: str
    severity: str          # critical / high / medium / low / info
    weight: int
    evidence: str
    category: str = "url"  # url / email / domain


@dataclass
class URLReport:
    raw: str
    display: str
    host: str
    registered: str
    scheme: str
    is_ip: bool = False
    signals: list[Signal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class HeaderReport:
    from_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    spf: str = "not reported"
    dkim: str = "not reported"
    dmarc: str = "not reported"
    dkim_domain: str = ""
    signals: list[Signal] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class DomainReport:
    domain: str
    age_days: int | None = None
    created: str = ""
    registrar: str = ""
    signals: list[Signal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Assessment:
    input_label: str
    score: int
    verdict: str
    signals: list[Signal]
    urls: list[URLReport]
    header: HeaderReport | None = None
    domains: list[DomainReport] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for signal in self.signals:
            counts[signal.severity] = counts.get(signal.severity, 0) + 1
        return counts
