# Case 5: H&M "Order Delivered" Notice (Legitimate Control)

| | |
|---|---|
| **Verdict** | 🟢 **Legitimate**: no action needed |
| **Source** | Analyst's own inbox (recipient replaced with `analyst@example.com`; order number and personal details left out) |
| **Email date** | 21 Nov 2026, 12:13:07 UTC |
| **Analysed** | 23 Nov 2026 |
| **Screenshots** | [PH-11](../screenshots/PH-11-case5-auth-pass.png) |

## Why this case is here

A SOC analyst must also be able to say **"this is not phishing"** with evidence. Most user-reported emails are legitimate, and closing them correctly matters as much as catching the bad ones.

## Header: every field tells the same story

| Field | Value | Consistent? |
|---|---|---|
| From | H&M `gr@delivery.hm.com` | ✅ |
| Return-Path | `…@parcel-mail.delivery.hm.com` | ✅ H&M subdomain |
| Reply-To | H&M `noreply0.cs.gr@hm.com` | ✅ |
| Message-ID | `…@eu-west-1.amazonses.com` | ✅ H&M's sending service (Amazon SES), normal for large brands |
| Subject | `=?UTF-8?B?…?=` | Base64 only because the subject is in Greek ("Your order has been delivered"). Encoding alone is not a red flag. |

Gmail also showed a verified (blue tick, BIMI) sender badge.

## Authentication: pass for the brand's own domain

| Check | Result |
|---|---|
| SPF | ✅ pass: `54.240.90[.]129` permitted for `parcel-mail.delivery.hm.com` |
| DKIM | ✅ pass `d=delivery.hm.com` (brand) + ✅ pass `d=amazonses.com` (service) |
| DMARC | ✅ pass, **`p=REJECT sp=REJECT`** for `delivery.hm.com` |

- `p=REJECT`: mail claiming to be from this domain that fails the checks is rejected outright. Attackers therefore have to use look-alike domains.
- DKIM also covers the **body hash**, so every link in the body was written and signed by H&M and not changed in transit.

## Links (by domain)

| Domain | Count | Finding |
|---|---|---|
| `parcel-api.delivery.hm.com`, `parcel-cdn.delivery.hm.com`, `www2.hm.com`, `fabric.hmgroup.com` | 51 | H&M / H&M Group |
| `schema.org`, `w3.org`, `fonts.googleapis.com`, `youtube.com`, `tiktok.com` | 11 | Standard / social |
| `hm.delivery-status[.]com` | 2 | **Not `hm.com`** (same shape as a subdomain trick), so verified |

`delivery-status[.]com`: created 2016, Amazon Registrar, whois privacy proxy, **VirusTotal 0/92, top-100K**, web infrastructure. It sits inside a DKIM- and DMARC-aligned H&M email, so H&M placed it there itself, most likely a parcel-tracking vendor. **Benign.**

## Why legitimate

- The brand domain authenticates with SPF, DKIM and DMARC (strict REJECT policy), aligned with From
- No urgency, no threat, no request for credentials or payment
- No attachments
- Matches a real order the mailbox owner placed

## Compared with Case 3

Both `one-lnk[.]com` (Case 3) and `delivery-status[.]com` (Case 5) scored **0/92** on VirusTotal. Reputation did not separate them. **Authentication alignment, content and context did.**
