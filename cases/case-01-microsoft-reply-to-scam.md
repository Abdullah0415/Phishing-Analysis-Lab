# Case 1: Microsoft "Unusual Sign-in Activity" Reply-To Scam

| | |
|---|---|
| **Verdict** | 🔴 **Malicious**: phishing for information, Microsoft brand impersonation |
| **MITRE ATT&CK** | T1598 Phishing for Information |
| **Source** | phishing_pot `sample-2.eml` (same campaign: `sample-15`, `sample-26`, and 10+ more with the same subject) |
| **Email date** | 8 Sep 2023, 05:47:04 UTC |
| **Analysed** | 23 Nov 2026 |
| **Screenshots** | [PH-03](../screenshots/PH-03-case1-key-fields.png), [PH-04](../screenshots/PH-04-case1-authentication.png) |

## Summary

The email claims to come from the "Microsoft account team" and warns of unusual sign-in activity. It is sent from an unrelated domain, uses a free Gmail address as Reply-To, and fails every authentication check. It contains **no web links at all**: every button is a `mailto:` link to the attacker's Gmail. The goal is to make the victim reply, which confirms a live mailbox for a follow-up scam.

## Header analysis

| Field | Value | Finding |
|---|---|---|
| From | "Microsoft account team" `no-reply@access-accsecurity[.]com` | 🚩 Microsoft display name, non-Microsoft domain |
| Reply-To | `sotrecognizd@gmail[.]com` | 🚩 Free mailbox: replies go to the attacker |
| Return-Path | `bounce@thcultarfdes[.]co[.]uk` | 🚩 A third, unrelated domain |
| Message-ID | *(empty)* | 🚩 Real Microsoft mail always has one |
| To | `phishing@pot` | Honeypot placeholder |

**Three different domains in one email** (From, Reply-To, Return-Path). A real sender does not do this.

## Authentication

| Check | Result |
|---|---|
| SPF | `none`: `thcultarfdes[.]co[.]uk` has no SPF record; sender IP `89.144.44[.]2` |
| DKIM | `none`: message not signed |
| DMARC | `permerror` for `access-accsecurity[.]com` |

Nothing passed. A genuine Microsoft email would show `dkim=pass header.d=microsoft.com` and `dmarc=pass`.

## Received chain (read bottom to top)

| Hop | From → By | Note |
|---|---|---|
| 1 (origin) | `thcultarfdes[.]co[.]uk` (**89.144.44[.]2**) → `mail.protection.outlook.com` | Real origin, 05:47:04 UTC |
| 2–4 | Microsoft 365 internal hops | **Receiving** side (honeypot mailbox), not the sender |

Delivered in 2 seconds. The many `outlook.com` lines are a trap for new analysts: they belong to the recipient, not the sender.

## Sender IP and domains

- **89.144.44[.]2**: MSCode.pl, Poland, *Data Center / Web Hosting* (a rented VPS, not Microsoft infrastructure)
- AbuseIPDB (23 Nov 2026): 1 report, **0 % confidence**. Scores decay over time and this sample is from 2023, so reputation here is weak evidence, not a verdict.
- `access-accsecurity[.]com`: whois returns **No match** on 23 Nov 2026 (domain no longer registered).

## Body

`emlAnalyzer -u` found only `mailto:` links:

| Button | What the victim expects | What happens |
|---|---|---|
| "Report The User" | Report to Microsoft | Opens a new email to `sotrecognizd@gmail[.]com` |
| "Unsubscribe me" | Stop the emails | Confirms to the attacker that the inbox is live |

With no URLs, link-scanning filters have nothing to inspect.

## IOCs

| Type | Value |
|---|---|
| domain | `access-accsecurity[.]com` |
| domain | `thcultarfdes[.]co[.]uk` |
| email | `sotrecognizd[@]gmail[.]com` |
| ip | `89.144.44[.]2` |

## Recommended actions (if this reached a real user)

- Block sender domains and the Reply-To address at the mail gateway
- Search mailboxes for the subject "Microsoft account unusual signin activity" and for messages to/from the Gmail address; purge
- Ask whether anyone replied; if so, treat follow-up contact as hostile
