# Phishing Triage Playbook

A checklist for a SOC Level 1 analyst handling a **user-reported suspicious email**. Built from the five cases in this repo.

## 0. Safety first

- [ ] Work only inside an isolated analysis VM, never on your own workstation
- [ ] Never click a link or open an attachment from the email
- [ ] Never upload an attachment to VirusTotal: search by **SHA-256** only
- [ ] URL scans in URLScan are **Private** (or Unlisted), never Public
- [ ] Defang every IOC you write down: `hxxps://evil[.]com`, `1.2.3[.]4`, `user[@]domain[.]com`

## 1. Get the original

- [ ] Ask for the email as an attachment (`.eml`), or export it with "Show original / Download original"
- [ ] Record: reporter, time reported, subject, how many users received it

## 2. Header: who really sent it?

```bash
grep -iE "^(from|to|subject|date|return-path|reply-to|message-id):" mail.eml
grep -iE "spf=|dkim=|dmarc=|compauth=" mail.eml
grep -iE "^received:" -A2 mail.eml
```

- [ ] **From vs Return-Path vs Reply-To:** different domains? Reply-To on a free mailbox? (Case 1)
- [ ] **Display name vs domain:** brand name on an unrelated domain? (Cases 1–4)
- [ ] **Authentication:** did SPF/DKIM/DMARC pass, and **for which domain**? A pass for the attacker's or a platform's domain proves nothing about the brand. (Cases 3, 4)
- [ ] **One story?** Do Message-ID, sending IP, DKIM `d=` and From all point to the same organisation? (Case 2: four different stories. Case 5: one story.)
- [ ] **Received chain:** read bottom to top; the first trusted server is the real origin. Lines below it can be forged. The recipient's own servers (e.g. `outlook.com`) are not the sender. (Cases 1, 2)
- [ ] Sending IP: `whois`, AbuseIPDB. Data-center IPs for a "big brand" are suspicious. Low scores on old samples decay.
- [ ] Domain age: `whois <domain> | grep -i creation`. Registered days or weeks before the email = strong signal (Case 2).

## 3. Body and links

```bash
emlAnalyzer -i mail.eml --text
emlAnalyzer -i mail.eml -u | grep -oE 'https?://[^/ "]+' | sort | uniq -c | sort -rn
```

- [ ] Lure: urgency, deadline, fear of loss, generic greeting, single call to action (Case 3)
- [ ] Where do links really go? Any domain that is not the brand's? (Cases 2, 5)
- [ ] `mailto:` buttons instead of links = reply-to scam (Case 1)
- [ ] Redirectors / trackers / short links (`one-lnk`, `qrco.de`): reputation belongs to the platform, not the attacker (Cases 3, 4)
- [ ] URLScan (Private): what does the link lead to? Dead link ≠ safe: record "not observable"
- [ ] No links at all + attachment = the attachment is the payload (Case 4)

## 4. Attachments (static only)

```bash
emlAnalyzer -i mail.eml --extract-all -o ./attachments/
file <attachment>
sha256sum <attachment>
olevba <attachment>                       # Office macros
unzip -l <file.docx>                      # OOXML is a ZIP
unzip -p <file.docx> '*.rels' | grep -c 'TargetMode="External"'
unzip -p <file.docx> word/document.xml | sed -e 's/<\/w:p>/\n/g' -e 's/<[^>]*>//g'
pdfid <file.pdf>                          # /JavaScript, /OpenAction, /Launch
```

- [ ] Real type matches the extension?
- [ ] Hash on VirusTotal: detections **and** community score
- [ ] Macros? External relationships / remote template?
- [ ] **Read the document text**: field-code `HYPERLINK`s are not in `.rels` (Case 4)
- [ ] 0 detections ≠ safe: a "link carrier" has no code to detect (Case 4)

## 5. Verdict

| Verdict | When |
|---|---|
| **Malicious** | Impersonation + failed or misaligned authentication, malicious link/attachment, or credential/payment lure |
| **Suspicious** | Red flags without proof; escalate to Tier 2 |
| **Legitimate** | Brand domain authenticates and aligns (SPF + DKIM + DMARC), content matches a real interaction, no lure (Case 5) |

Map to MITRE ATT&CK: T1566.001 (attachment), T1566.002 (link), T1598 (phishing for information), T1656 (impersonation), T1204 (user execution).

## 6. Respond (if malicious)

- [ ] Block sender address/domain, malicious domains, URLs (specific path for shared platforms) and hashes
- [ ] **Do not block** shared provider IPs (Google, Microsoft, Amazon SES, marketing platforms): record them as context only
- [ ] Search all mailboxes for the same subject / sender / URL / hash; purge
- [ ] Ask: did anyone click, reply, open the attachment, or enter credentials/card details? If yes → password reset, MFA review, card block, incident ticket
- [ ] Report abuse to the platform that was misused (shortener, newsletter service, registrar)
- [ ] Reply to the reporter: thank them and tell them the outcome

## 7. Document

- [ ] Case report: header, authentication, chain, links, attachments, verdict, IOCs (see [`cases/`](cases/))
- [ ] Add IOCs to [`iocs/iocs.csv`](iocs/iocs.csv), defanged
- [ ] Times in **UTC**; note *when* each reputation check was done
