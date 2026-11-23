# Case 3: MetaMask "Your Wallet Has Been Blocked" Seed-Phrase Phishing

| | |
|---|---|
| **Verdict** | 🔴 **Malicious**: credential (seed phrase) phishing via link, MetaMask impersonation |
| **MITRE ATT&CK** | T1566.002 Spearphishing Link, T1598.003 Spearphishing Link (for information) |
| **Source** | phishing_pot `sample-181.eml` (similar: `sample-403`) |
| **Email date** | 26 Jul 2023, 23:17:35 UTC |
| **Analysed** | 23 Nov 2026 |
| **Screenshots** | [PH-07](../screenshots/PH-07-case3-urls.png), [PH-08](../screenshots/PH-08-case3-urlscan.png) |

## Summary

A crypto-wallet scare email using the MetaMask name. **SPF and DKIM both pass**, but for an email-marketing platform's domain, not for MetaMask. The most likely explanation is an abused or compromised newsletter account on that platform. The single phishing link is wrapped in the platform's own click-tracking redirector, which has a clean reputation. The case shows that "pass" and "clean on VirusTotal" do not mean safe.

## Header analysis

| Field | Value | Finding |
|---|---|---|
| From | "MetaMask" `info@kommunal[.]se` | 🚩 Swedish trade-union domain, not `metamask.io` |
| Reply-To | `info@kommunal[.]se` | |
| Return-Path | *(empty)* | |
| Subject | "[IMPORTANT] Your wallet has been Blocked" | 🚩 Fear + urgency |

## Authentication: pass, but for the wrong domain

| Check | Result | For which domain? |
|---|---|---|
| SPF | ✅ pass, IP `91.227.208[.]158` | `innfactorholdningkommunal.anpdm[.]com` |
| DKIM | ✅ pass | `anpdm[.]com` |
| DMARC | none | `kommunal[.]se` |

`anpdm[.]com` is, as far as known, the sending domain of **APSIS**, a Swedish email-marketing platform. The mail genuinely came from APSIS, so authentication passed; **nothing passed for metamask.io**.

## Body

- **Plain-text part:** only the standard APSIS footer in Swedish ("view the HTML version", "unsubscribe"), which confirms an APSIS template.
- **HTML part (rendered text):** *"Important Notice! Dear, your cryptocurrency wallet is at significant risk … manually update your wallet before July 29th … failure may result in permanent loss of all your cryptocurrency holdings."* Button: **"Press here to Upgrade"**.

| Red flag | In this email |
|---|---|
| Deadline | "before July 29th", 2 days after sending |
| Fear | "permanent loss of all your holdings" |
| Generic greeting | "Dear" |
| Fake pretext | "Ethereum network surge", "manual update" |
| Single call to action | "Press here to Upgrade" |

Likely goal: a fake MetaMask page that asks for the wallet's **seed phrase**. MetaMask never asks for it by email.

## Links (defanged)

| Link | Finding |
|---|---|
| `fonts.googleapis[.]com` ×4, `www.w3[.]org` | Benign (fonts, XHTML namespace) |
| `www.anpdm[.]com/newsletterweb/…`, `www.anpdm[.]com/oa/…` | APSIS "view online" and "unsubscribe" |
| **`hxxps://one-lnk[.]com/x1exEpKh4Q1i491f…`** (long token) | 🚩 The "Upgrade" button |

- `one-lnk[.]com`: likely APSIS One's click-tracking redirector. **VirusTotal 0/92**, top-1M, created 8 years ago (Amazon Registrar). The reputation belongs to the platform, not the attacker.
- **URLScan private scan** (23 Nov 2026): `net::ERR_NAME_NOT_RESOLVED`. The final landing page could not be observed (link dead). VirusTotal had last analysed the domain 7 days earlier, so the two results disagree; both are recorded.

## IOCs

| Type | Value | Note |
|---|---|---|
| url | `hxxps://one-lnk[.]com/x1exEpKh4Q1i491fEvFn7cpmv…` | Full token kept in the private sample only |
| sender | `info[@]kommunal[.]se` via APSIS account `innfactorholdningkommunal` | |
| ip | `91.227.208[.]158` | APSIS sending IP: context only, **do not block** |

## Recommended actions

- Block the specific tracking URL (not the whole `one-lnk` / `anpdm` domain, which would break legitimate newsletters)
- Report the abused account to the platform
- User awareness: no wallet provider asks for a "manual upgrade" by email
