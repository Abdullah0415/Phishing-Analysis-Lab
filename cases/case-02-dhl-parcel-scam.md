# Case 2: DHL "We Could Not Find Your Address" Parcel Scam

| | |
|---|---|
| **Verdict** | 🔴 **Malicious**: DHL brand impersonation with a phishing link |
| **MITRE ATT&CK** | T1566.002 Spearphishing Link, T1656 Impersonation |
| **Source** | phishing_pot `sample-409.eml` (similar: `sample-713`) |
| **Email date** | 30 Sep 2026, 21:00:37 UTC |
| **Analysed** | 23 Nov 2026 |
| **Screenshots** | [PH-05](../screenshots/PH-05-case2-key-fields.png), [PH-05b](../screenshots/PH-05b-case2-authentication.png), [PH-06](../screenshots/PH-06-case2-mxtoolbox-chain.png) |

## Summary

A Dutch-language parcel notice "from DHL" that at first glance has a clean header: From and Return-Path match and there is no Reply-To. But every part of the header tells a different story: a Microsoft 365 tenant address in From, a Gmail Message-ID, a Google sending IP, and a DKIM signature from a fourth domain. All authentication fails. The links point to a domain registered about 70 days before the email.

## Header analysis

| Field | Value | Finding |
|---|---|---|
| From | "DHL Logistiek Centre" `blake.garcia@organprotech88.onmicrosoft[.]com` | 🚩 DHL name, free Microsoft 365 tenant address (not `dhl.com` / `dhl.nl`) |
| Subject | "(Actie vereist) We konden uw adres niet vinden" | 🚩 "(Action required) We could not find your address": classic parcel lure |
| Return-Path | same as From | No mismatch, which makes the header look "clean" |
| Message-ID | `…@mail.gmail[.]com` | 🚩 Gmail ID on a "Microsoft" email |

## Authentication

| Check | Result |
|---|---|
| SPF | `fail`: sender IP `74.125.228[.]169` (Google) is not allowed for `organprotech88.onmicrosoft[.]com` |
| DKIM | `fail`: signature from `send.workwithshadow[.]com` did not verify |
| DMARC | `none` |
| compauth | `fail` (Microsoft's own composite verdict) |

**Four different stories:** From (Microsoft tenant), Message-ID (Gmail), sending IP (Google), DKIM (workwithshadow). A genuine email tells one story.

## Received chain (MXToolbox, 6 seconds total)

| Hop | Detail | Note |
|---|---|---|
| 1 | `unknown 10.6.254.211`, Klaviyo worker hostname, no timestamp | Below the first trusted server: likely copied from a real marketing email, cannot be trusted |
| 2–3 | `gmailapi.google.com` with HTTPREST | Sent by a script through the **Gmail API** |
| 4–5 | `mail-ej2-f41.google.com` (**74.125.228[.]169**) → `mail.protection.outlook.com` | Real handover, 21:00:39 UTC |
| 6–8 | Microsoft 365 | Receiving side |

MXToolbox blacklist marks on shared Google/Microsoft IPs are weak evidence: thousands of senders share them.

## Domains

| Domain | Finding |
|---|---|
| `workwithshadow[.]com` (DKIM `d=`) | Created 2024-10-09 (101domain). Likely a legitimate sender whose email was reused as a template; DKIM broke because the body was changed. **Not called malicious.** |
| `vigit99[.]com` | 🚩 Created **2026-07-22** (GoDaddy), ~70 days before the email. 5 of 6 links go here; none go to `dhl.com` |
| `i.imgur[.]com` | 1 link: image hosting for the logo |

## IOCs

| Type | Value | Note |
|---|---|---|
| domain | `vigit99[.]com` | Phishing landing domain |
| email | `blake.garcia[@]organprotech88.onmicrosoft[.]com` | Spoofed sender |
| ip | `74.125.228[.]169` | Google shared: context only, **do not block** |

## Recommended actions

- Block `vigit99[.]com` on web proxy / DNS
- Search for "DHL" display names on `*.onmicrosoft.com` senders; purge
- Lesson for users: check the domain, not just whether the header "looks consistent"
