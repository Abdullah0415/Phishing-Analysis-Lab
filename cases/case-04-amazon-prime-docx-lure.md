# Case 4: Amazon Prime "Card No Longer Valid" .docx Lure

| | |
|---|---|
| **Verdict** | 🔴 **Malicious**: phishing attachment carrying a link, Amazon impersonation, likely card-detail theft |
| **MITRE ATT&CK** | T1566.001 Spearphishing Attachment, T1204.002 User Execution: Malicious File |
| **Source** | phishing_pot `sample-1725.eml` |
| **Email date** | 23 Aug 2023, 17:58:23 UTC |
| **Analysed** | 23 Nov 2026 |
| **Screenshots** | [PH-09](../screenshots/PH-09-case4-file-hash.png), [PH-10](../screenshots/PH-10-case4-olevba-rels.png), [PH-10b](../screenshots/PH-10b-case4-urlscan-qrco.png) |

## Summary

An "Invalid Billing Payment" email with a Word attachment. The email body has **no links**, and the attachment has **no macros, no exploit and no malware**. Antivirus engines score it 0/64. The document is a "link carrier": a convincing Amazon Prime notice asking the reader to update their card through a short link. The danger is the link, not the file.

## Header analysis

| Field | Value | Finding |
|---|---|---|
| From | "Membership Service" `dono-treply-a7ibk9slwvqlkuyhe5t1@thanhnienviet[.]net` | 🚩 Fake "do-not-reply" + random string, Vietnamese domain |
| Subject | "Remainder : Invalid Billing Payment #4808-11142-22251 On August 23 2023" | 🚩 Typo ("Remainder"), random invoice number |
| Return-Path | same as From | |

## Authentication: pass for the sender's own domain

| Check | Result |
|---|---|
| SPF | ✅ pass, IP `209.85.218[.]42` (Google) |
| DKIM | ✅ pass, `d=thanhnienviet-net.20221208.gappssmtp[.]com` (Google Workspace default signature: the domain has no DKIM of its own) |
| DMARC | `bestguesspass` (no DMARC record; Google's guess) |

Sent from a Google Workspace account on `thanhnienviet[.]net` (compromised or attacker-owned). Nothing passed for `amazon.com`.

## Body

`emlAnalyzer`: **no URLs, no tracking pixels.** The only purpose of the email is to get the attachment opened, which evades link-scanning filters.

## Attachment (static analysis only, never opened)

| Check | Result |
|---|---|
| Name | `AMGV2UG-K6EYVM.docx` (random), 30,883 bytes |
| `file` | Microsoft Word 2007+ (real .docx, extension not spoofed) |
| **SHA-256** | `60b31cf185f9dc99d768d4068844fc8e239ce8c32cb056d6b1b94c5a2147fe35` |
| `olevba` | No VBA or XLM macros (a .docx cannot run macros) |
| `.rels` | 8 internal targets, **0** `TargetMode="External"`: no remote template |
| ZIP contents | 21 files, all dated `2012-07-02 09:52`: generated from a template or script |
| `media/image1.png` | 471 × 94 PNG banner (likely the Prime logo); `zbarimg` found no QR code |

**Document text** (from `word/document.xml`): *"Dear Prime Member, your Amazon Prime Membership is set to renew on August 22, 2023 … the card associated with your Prime membership is no longer valid … please use this link … your Amazon Prime benefits will be suspended."* It also contains a copied Amazon footer and address.

**The links:** two `HYPERLINK` **field codes** inside `document.xml`, both to `hxxps://qrco[.]de/beGfog`. The text "https://amazon.com" appears only as plain text, to build trust.

> **Lesson:** checking `.rels` alone reported "0 external" and missed the link. Field-code hyperlinks live in `document.xml`. Always read the document text too.

## Reputation

- **VirusTotal (hash search, never uploaded):** 0/64 vendors, but **community score −7** and 2 community comments; tags `docx`, `calls-wmi` (weak).
- **Why 0/64:** the file contains no code for antivirus to detect.
- **URLScan private scan** of `hxxps://qrco[.]de/beGfog` (23 Nov 2026): the QR Code Generator page *"Uh-oh! Someone pulled the plug. This QR Code is unavailable … account deactivated or blocked."* The service blocked the attacker's account. The final phishing page could not be observed.
- `qrco[.]de` is a legitimate QR Code Generator short-link service (8 years old, AWS `3.174.46[.]87`) abused as a redirector.

## IOCs

| Type | Value | Note |
|---|---|---|
| sha256 | `60b31cf185f9dc99d768d4068844fc8e239ce8c32cb056d6b1b94c5a2147fe35` | Attachment |
| url | `hxxps://qrco[.]de/beGfog` | Redirector link in the document |
| email | `dono-treply-a7ibk9slwvqlkuyhe5t1[@]thanhnienviet[.]net` | Sender |
| domain | `thanhnienviet[.]net` | Sending domain |
| ip | `209.85.218[.]42` | Google shared: context only, **do not block** |

## Recommended actions

- Block the SHA-256 at the mail gateway / EDR and the specific `qrco[.]de` path
- Search for the attachment hash and the subject pattern "Invalid Billing Payment"; purge
- Ask whether anyone opened the document and entered card details; if so, the card must be blocked
