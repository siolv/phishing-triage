# Phishing Triage Report

**Generated:** 2026-11-19T20:29:29+08:00  
**Input:** phishing.eml + 1 link  
**Verdict:** **LIKELY PHISHING**  
**Risk score:** 100/100

> This is inbox triage, not a guarantee. A low score does not prove an email is safe, and a high score does not prove it is malicious.

## What to do now

- [ ] Do not click any link or open any attachment in this message.
- [ ] Report it to your IT or security contact and keep the original message for investigation.
- [ ] Delete it only after IT confirms they have what they need.
- [ ] If you already clicked or entered credentials, change that password now, turn on MFA, and tell IT what you entered.

## Signals

| Severity | Signal | Evidence |
|---|---|---|
| CRITICAL | Sender domain imitates a brand | paypa1 imitates paypal with swapped characters. |
| HIGH | Reply-To domain imitates a brand | paypal-help adds words to the brand 'paypal'. |
| CRITICAL | DMARC failed | The message failed the domain owner's DMARC policy. |
| HIGH | SPF failed | The sending server is not allowed to send mail for that domain. |
| HIGH | Display name claims a brand | The sender name says 'PayPal Security', but the address is @paypa1.com. |
| MEDIUM | Reply-To goes to another domain | From is paypa1.com; Reply-To is paypal-help.top. |
| MEDIUM | Return-Path goes to another domain | From is paypa1.com; Return-Path is paypal-help.top. |
| MEDIUM | Domain does not resolve | paypal-help.top has no A record; the link or sender may be dead. |
| LOW | Urgent or account-themed subject | Subject contains: urgent, locked. |

## Email check

**From:** PayPal Security &lt;security@paypa1.com&gt;  
**Reply-To:** PayPal Help &lt;recover@paypal-help.top&gt;  
**Return-Path:** &lt;bounce@paypal-help.top&gt;  
**Subject:** Urgent: your account has been locked

| Check | Result |
|---|---|
| SPF | fail |
| DKIM | none |
| DMARC | fail |

**Notes:**

- 1 link was found in the message body.

## Links checked

### `https://paypa1.com/verify?account=***&token=***`

- Host: `paypa1.com`
- Registered domain: `paypa1.com`
- Signals: Lookalike domain

## Domain check

| Domain | Age | Created | Registrar |
|---|---|---|---|
| `paypa1.com` | 9525 days | 2000-10-20 | MarkMonitor Inc. |
| `paypal-help.top` | 371 days | 2025-11-12 | NameSilo,LLC |

**Notes:**

- DMARC policy for paypa1.com: p=reject.
- No DMARC policy was found for paypal-help.top.
- No SPF record was found for paypal-help.top.

## Local model triage note

This is a high-confidence phishing attempt impersonating PayPal using a fake website and email addresses. The scanner detected critical failures in security checks, meaning this message is not safe to interact with.

### Escalation draft

> A deterministic scanner has flagged an incoming email as likely phishing with a score of 100. The strongest evidence shows the sender domain uses swapped characters to imitate PayPal and fails strict authentication policies. You should not click any links or reply to this message. Please report this immediately to your IT helpdesk and keep the original message intact for their investigation.

### Verify through another channel

- Does the email address in the 'From' field look slightly different from the official company domain?
- Is there a sense of urgency or fear in the subject line asking you to act quickly?
- Can you verify if the sender's domain name is registered by a known security registrar?

## What this check cannot see

- Links are not opened or detonated, so a page can change after the check.
- Attachments are not opened or analysed.
- SPF, DKIM, and DMARC results come from the headers; full DKIM cryptographic verification is not performed.
- Domain age comes from public RDAP data and can be unavailable for some domains.
- Headers can be forged, and the local model can be wrong.

---

*Generated locally. No link was visited, no email was uploaded, and no cloud model was called.*
