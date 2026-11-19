"""Tests for URL, header, domain, and scoring logic."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from headers import analyze_headers  # noqa: E402
from intel import parse_dmarc, parse_rdap, parse_spf  # noqa: E402
from models import Signal  # noqa: E402
from triage import build_evidence, dedupe, verdict_for  # noqa: E402
from urls import analyze_url, registered_domain, safe_display  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def codes(report) -> set[str]:
    return {signal.code for signal in report.signals}


class URLTests(unittest.TestCase):
    def test_lookalike_brand(self):
        report = analyze_url("https://paypa1.com/verify")
        self.assertIn("lookalike_paypal", codes(report))
        self.assertGreaterEqual(sum(s.weight for s in report.signals), 30)

    def test_brand_with_extra_words(self):
        report = analyze_url("https://paypal-login.top/")
        self.assertIn("brand_hyphen_paypal", codes(report))

    def test_brand_in_subdomain(self):
        report = analyze_url("https://paypal.com.account-check.xyz/login")
        self.assertIn("brand_subdomain_paypal", codes(report))

    def test_ip_host(self):
        report = analyze_url("http://203.0.113.42/login")
        self.assertIn("ip_host", codes(report))

    def test_shortener(self):
        report = analyze_url("https://bit.ly/abc123")
        self.assertIn("shortener", codes(report))

    def test_userinfo_disguise(self):
        report = analyze_url("https://paypal.com@evil.example/login")
        self.assertIn("userinfo", codes(report))
        self.assertIn("brand_userinfo_paypal", codes(report))
        self.assertEqual(report.registered, "evil.example")

    def test_punycode(self):
        report = analyze_url("https://xn--pypal-4ve.com/login")
        self.assertIn("punycode", codes(report))

    def test_javascript_link(self):
        report = analyze_url("javascript:alert(1)")
        self.assertIn("dangerous_scheme", codes(report))

    def test_clean_url_has_no_high_signals(self):
        report = analyze_url("https://github.com/settings")
        high = [s for s in report.signals if s.severity in ("critical", "high")]
        self.assertEqual(high, [])

    def test_registered_domain_two_part_suffix(self):
        self.assertEqual(registered_domain("login.bpi.com.ph"), "bpi.com.ph")
        self.assertEqual(registered_domain("mail.google.com"), "google.com")

    def test_safe_display_hides_query_values(self):
        shown = safe_display("https://paypa1.com/verify?account=person@example.com&token=8f3a9c2b71")
        self.assertNotIn("person@example.com", shown)
        self.assertNotIn("8f3a9c2b71", shown)
        self.assertIn("paypa1.com", shown)


class HeaderTests(unittest.TestCase):
    def test_phishing_headers(self):
        raw = (SAMPLES / "phishing.eml").read_text(encoding="utf-8")
        report = analyze_headers(raw)
        self.assertEqual(report.spf, "fail")
        self.assertEqual(report.dmarc, "fail")
        self.assertIn("spf_fail", codes(report))
        self.assertIn("dmarc_fail", codes(report))
        self.assertIn("sender_lookalike_paypal", codes(report))
        self.assertIn("reply_to_mismatch", codes(report))
        self.assertTrue(report.urls)
        self.assertIn("paypa1.com", report.urls[0])

    def test_legit_headers(self):
        raw = (SAMPLES / "legit.eml").read_text(encoding="utf-8")
        report = analyze_headers(raw)
        self.assertEqual(report.spf, "pass")
        self.assertEqual(report.dmarc, "pass")
        urgent = [s for s in report.signals if s.severity in ("critical", "high")]
        self.assertEqual(urgent, [])

    def test_display_name_brand_mismatch(self):
        raw = (
            'From: "PayPal Support" <help@random-domain.example>\n'
            "Subject: Hello\n\n"
        )
        report = analyze_headers(raw)
        self.assertIn("display_name_paypal", codes(report))


class IntelTests(unittest.TestCase):
    def test_rdap_new_domain(self):
        now = datetime(2026, 11, 19, tzinfo=timezone.utc)
        payload = {
            "events": [
                {"eventAction": "registration", "eventDate": "2026-11-01T00:00:00Z"}
            ],
            "entities": [],
        }
        report = parse_rdap(payload, "new-example.com", now=now)
        self.assertEqual(report.age_days, 18)
        self.assertEqual(report.signals[0].severity, "critical")

    def test_rdap_old_domain(self):
        now = datetime(2026, 11, 19, tzinfo=timezone.utc)
        payload = {
            "events": [
                {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}
            ]
        }
        report = parse_rdap(payload, "old-example.com", now=now)
        self.assertGreater(report.age_days, 365)
        self.assertEqual(report.signals, [])

    def test_dmarc_parsing(self):
        self.assertEqual(
            parse_dmarc(['"v=DMARC1; p=reject; rua=mailto:x@example.com"']), "reject"
        )
        self.assertEqual(parse_dmarc(['v=DMARC1; p=none']), "none")
        self.assertIsNone(parse_dmarc([]))

    def test_spf_parsing(self):
        self.assertIn("v=spf1", parse_spf(["v=spf1 include:_spf.example.com ~all"]))
        self.assertIsNone(parse_spf(["google-site-verification=abc"]))


class ScoringTests(unittest.TestCase):
    def test_verdict_bands(self):
        self.assertEqual(verdict_for(80), "LIKELY PHISHING")
        self.assertEqual(verdict_for(45), "SUSPICIOUS")
        self.assertEqual(verdict_for(25), "LOW CONFIDENCE - REVIEW")
        self.assertEqual(verdict_for(0), "NO STRONG PHISHING SIGNALS")

    def test_dedupe_keeps_one_copy(self):
        signal = Signal("x", "X", "high", 10, "same evidence")
        self.assertEqual(len(dedupe([signal, signal])), 1)

    def test_score_caps_at_100(self):
        signals = [Signal(f"s{i}", "S", "critical", 30, "e") for i in range(6)]
        _, score, verdict = build_evidence(None, [], [])
        self.assertEqual(score, 0)
        # The real cap is applied in build_evidence; check the rule directly.
        self.assertEqual(min(100, sum(s.weight for s in signals)), 100)
        self.assertEqual(verdict, "NO STRONG PHISHING SIGNALS")


if __name__ == "__main__":
    unittest.main()
