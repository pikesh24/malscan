# MALSCAN detection testing

How we check that MALSCAN catches what it claims to catch, and leaves alone what it should.

This document is the **checklist**. Every code path that can add points to a scan's score
gets a row. Each row needs two test cases: something malicious that *should* trigger it,
and something harmless that looks similar enough to trigger it by mistake. The second half
is what stops false positives from reaching users.

---

## The rules

**1. Test priority never changes scoring weights.**
The P0/P1/P2 column below decides which test cases get written first. It has no effect on
any point value in `attribution_module/scoring.py`. Prioritising a threat class means
testing it sooner and more thoroughly — not scoring it harder. Points move only when the
scorecard shows evidence, and only in the direction the evidence points.

**2. No false-positive fix ships without a malware case proving detection still works.**
Turning detection down is the easy way to make a false alarm disappear, and it is the worst
possible outcome. The scorecard reports catch-rate and false-alarm-rate side by side, per
class, so a change that improves one while damaging the other is visible in the same run.

**3. Every detection class keeps at least one malicious test case, whatever its priority.**
Including every YARA rule and every file-type analyser. Otherwise a future tuning change
could gut PE or ransomware detection and no test would notice.

**4. Reproduce before fixing.**
A bug becomes a failing test case first, then gets fixed. That way the fix is proven rather
than assumed, and the bug can't quietly return later.

---

## How to run it

```powershell
cd backend

pytest                                   # everything offline — unit + corpus. Must stay green.
python -m tests.corpus_report            # the scorecard: catch rate, false alarms, per-signal blame
python -m tests.corpus_report --explain <case-id>    # full score breakdown for one case
pytest -m live                           # real samples over the network. Opt-in, needs API keys.
```

`pytest -m live` is excluded from the default run. It hits free-tier APIs (VirusTotal,
URLScan, MalwareBazaar) and will eat the quota the live app depends on if run casually.

---

## Priority

Priority reflects **how threats actually reach our users** — overwhelmingly through
messaging and email rather than deliberate downloads.

- **P0** — arrives via WhatsApp, Telegram, Gmail, SMS, social media. Links and documents
  sent to ordinary people. This is the product's real threat model.
- **P1** — everything else that can add points. Fully covered, just written second.
- **P2** — known gaps. Listed so they are visible, not silently absent.

---

## P0 — social-engineering delivery

The artifact types that actually show up in scam messages.

| # | Threat | Malicious case | Harmless lookalike | Signal | Status |
|---|---|---|---|---|---|
| A1 | Bank/UPI phishing link | `hdfcbank-secure.tk` | `netbanking.hdfcbank.com` | typosquat, `url_processor.py:80` | ✅ |
| A2 | Lookalike characters | `paypa1.com`, `g00gle.com` | `1password.com` | homoglyph, `url_processor.py:182` | ✅ |
| A3 | Shortened scam link | `bit.ly` → phishing | `youtu.be` video link | shortener, `url_processor.py:39` | ✅ |
| A4 | Fake gov/tax portal | `incometax-refund.xyz` | `eportal.incometax.gov.in` | typosquat + TLD | ✅ |
| A5 | Courier/parcel scam | `indiapost-tracking.top` | `indiapost.gov.in` | typosquat + TLD | ⬜ |
| A6 | Malware-hosting URL | URLhaus-listed URL | ordinary CDN download | `_check_urlhaus` | ✅ |
| A7 | Raw-IP payload link | `http://45.x.x.x/app.apk` | — | raw IP + dangerous ext | ✅ |
| A8 | Fake invoice/GST PDF | JS wired to auto-open | tax form PDF with form JS | `_check_document_threats` | ✅ |
| A9 | PDF that launches a program | `/Launch` action | PDF with page-navigation action | `_check_document_threats` | ✅ |
| A10 | Resume/CV macro doc | `AutoOpen` VBA | macro-free `.docx` | `Office_AutoOpen_Macro` | ✅ |
| A11 | Wedding-invite / KYC APK | SMS read+send combo | messaging app with SMS perms | `_check_apk_permissions` | ✅ |
| A12 | Loan/spy APK | `BIND_DEVICE_ADMIN` | MDM/enterprise app | `_check_apk_permissions` | ✅ |
| A13 | Banking-overlay APK | `Drinik`, `FakeCalls` | legitimate banking app | YARA banking rules | ✅ |
| A14 | Disguised extension | `invoice.pdf.exe` | `.docx` (really a ZIP) | `type_mismatch` | ⬜ benign twin missing |

Note on A14: OOXML files genuinely *are* ZIP archives, so a naive type-mismatch check
false-positives on every Office document. Needs a benign case.

---

## P1 — every remaining scoring path

Grouped by where the points come from. All of these get cases.

### URL flags — `analysis_engine/url_processor.py`
Each flag is +20, capped at 60 by `_check_url_flags`. **35 points is already "Suspicious",
so any two flags together flag an artifact.** These combinations are the main
false-positive risk and the baseline run should be read with that in mind.

Weights now live in `url_processor.FLAG_WEIGHTS` — reasoned from how often each flag fires
on harmless sites, and **provisional until the phase-B base-rate run measures it**.

| Signal | Weight | Malicious case | Harmless lookalike | Status |
|---|---|---|---|---|
| Typosquat / homoglyph | 35 | `hdfcbank-secure.tk`, `g00gle.com` | any brand subdomain, `1password.com` | ✅ |
| Raw IP host | 20 | `http://1.2.3.4/x` | — | ✅ |
| Dangerous extension | 15 | `/update.exe` | `/app.js` (ordinary web asset) | ✅ |
| Executable over http | 15 | `http://host/update.exe` | same file over https | ✅ |
| Malware keyword in host | 15 | `free-crack-download.tk` | `download.mozilla.org` | ⬜ keyword list mixes strong and weak terms |
| Deep subdomain | 10 | `a.b.c.d.e.f.evil.tk` | legit multi-level CDN host | ⬜ |
| Long domain | 10 | generated DGA name | long but real domain | ⬜ |
| Shortener | 10 | `bit.ly` → confirmed payload | `youtu.be` link | ✅ |
| Abused TLD | 5 | `login.paypa1.tk` | `.shop` `.store` `.online` `.biz` `.live` | ✅ |
| Not HTTPS | 5 | plain-http C2 | http-only legacy gov site | ✅ |
| Keyword in path | 5 | `/payload.exe` | `/downloads/report.pdf`, `/base64-encoder` | ⬜ |
| Heavy URL encoding | 5 | obfuscated redirect | long signed S3/CDN URL | ⬜ |

### Threat-intel checks — `attribution_module/scoring.py`

| Signal | Function | Max | Harmless lookalike | Status |
|---|---|---|---|---|
| Known-hash blocklist | `_check_known_hashes` | 100 | — | ✅ covered |
| MalwareBazaar hash | `_check_malwarebazaar` | 100 | — | ✅ covered |
| ThreatFox IOC | `_check_threatfox` | 70 | low-confidence junk entry | ✅ patched |
| URLhaus | `_check_urlhaus` | 60 | — | ⬜ |
| AbuseIPDB | `_check_abuseipdb` | 40 | shared CDN/NAT IP with history | ⬜ |
| VirusTotal consensus | `_check_virustotal` | 100 | 1–2 vendor false flags | ✅ patched |
| URLScan verdict | `_check_urlscan` | 40 | non-zero score on a safe site | ⬜ |

### Heuristics — `attribution_module/scoring.py`

| Signal | Function | Max | Harmless lookalike | Status |
|---|---|---|---|---|
| File entropy | `_check_enhanced_static` | 15 | video, JPEG, PNG, installers | ✅ patched |
| Type mismatch | `_check_enhanced_static` | 30 | `.docx` is a ZIP | ⬜ |
| Suspicious strings | `_check_enhanced_static` | 40 | sysadmin/PowerShell tooling | ⬜ |
| PE section entropy | `_check_pe_sections` | 30 | packed but legitimate installer | ⬜ |
| Domain age | `_check_domain_age` | 40 | newly launched real business | ❌ finding 6 |
| Registrar | `_check_registrar` | 15 | Namecheap hosts millions of legit sites | ❌ finding 6 |
| Country | `_check_geoip` | 20 | any real `.ru` / `.cn` business | ❌ finding 5 |
| ASN / hosting | `_check_geoip` | 20 | OVH and LeaseWeb are mainstream | ❌ finding 5 |
| IOC volume | `_check_ioc_volume` | 18 | any large, link-rich page | ⬜ |
| Document threats | `_check_document_threats` | 90 | interactive form PDFs | ✅ patched |
| APK permissions | `_check_apk_permissions` | 60 | WhatsApp, Truecaller, any real messenger | ✅ scored by rarity, not volume |

### Verdict-shaping logic

These are correctness features, not noise. They need cases so nobody "improves" the
false-alarm rate by removing them.

| Behaviour | Where | Status |
|---|---|---|
| Benign-VT-consensus halving | `scoring.py:639` | ✅ covered |
| Artifact-evidence requirement for Malicious | `scoring.py` (`artifact_total`) | ✅ covered |
| `partial` flag surfaced | `scoring.py:716` | ✅ covered |
| Clear → Inconclusive on incomplete intel | `scoring.py:716` | ✅ covered |
| Safe-domain intel suppression | `main.py:628` | ⬜ |
| Safe indicators stripped from IOCs | `main.py:149` | ✅ layer 2 |
| Submitted domain survives its own report | `main.py:149` | ✅ layer 2 — was broken |
| Per-flag URL weights reach the scorer | `main.py:682` | ✅ layer 2 |

### YARA rules — `analysis_engine/yara_rules/common_threats.yar`

One malicious case each. 21 rules:

`EICAR_Test_File` · `PowerShell_EncodedCommand` · `PowerShell_DownloadCradle` ·
`PowerShell_AMSI_Bypass` · `PE_In_Document` · `Base64_Encoded_PE` ·
`PDF_JavaScript_Exploit` · `PDF_AutoAction` · `Office_AutoOpen_Macro` ·
`Office_DDE_Exploit` · `Hardcoded_TOR_Onion` · `Suspicious_IP_C2` ·
`Generic_RAT_Strings` · `Njrat_Indicators` · `AsyncRAT_Indicators` ·
`Drinik_Banking_Trojan` · `FakeCalls_Banking_App` · `Generic_Banking_Overlay` ·
`Generic_Ransomware_Note` · `File_Encryption_API` · `Suspicious_Section_Names`

Known false-positive risks: `PDF_AutoAction` fires on ordinary "open at page 1" PDFs,
`Suspicious_IP_C2` on any embedded IP, `File_Encryption_API` on legitimate crypto software.

### Attacks against MALSCAN itself

Hostile input aimed at the scanner rather than the user.

| Attack | Guard | Status |
|---|---|---|
| Zip slip | `commonpath` + `realpath` | ✅ escape, absolute path, sibling-prefix |
| Zip bomb | budget caps in three analysers | ✅ file count, size budget, lying header |
| Deeply nested archives | depth budget | ✅ |
| XXE | `defusedxml` + DTD guard | ⬜ |
| Malformed PE header | — | ⬜ |
| Oversized upload | `MAX_UPLOAD_BYTES` | ✅ covered |
| SSRF via `/proxy/image` | host allowlist | ⬜ — redirects still followed (AUDIT S3) |

---

## P2 — known gaps

Not currently detectable. Listed so they are visible rather than silently missing. These
are **new detection capability**, out of scope for the testing work itself.

| Gap | Why | Verified against |
|---|---|---|
| **QR codes in PDFs/images** (quishing) | no image decoding or QR parsing anywhere | — |
| **Password-protected archives** | `zipfile` opens the container, can't read encrypted entries | `document_analyzer.py:169` |
| `.lnk` shortcut files | not in magic signatures | `static_analyzer.py:19-37` |
| OneNote `.one` attachments | not handled | `document_analyzer.py:276-315` |
| HTML smuggling attachments | not handled | `document_analyzer.py:276-315` |
| ISO / IMG containers | not in magic signatures | `static_analyzer.py:19-37` |

QR-in-PDF is the highest-value gap given the P0 threat model — scam PDFs increasingly put
the phishing link in a QR code specifically to defeat URL extraction.

---

## Baseline results

_Filled in by `python -m tests.corpus_report` once the corpus is seeded._

<!-- BASELINE:START -->
First measured run, 27 cases, before any fixes:

| class | n | caught | missed | wrongly flagged | correct | catch rate | false alarm rate |
|---|---|---|---|---|---|---|---|
| abused-tld | 2 | 1 | 0 | 1 | 0 | 100.0% | 100.0% |
| apk | 4 | 2 | 0 | 1 | 1 | 100.0% | 50.0% |
| document | 4 | 2 | 0 | 0 | 2 | 100.0% | 0.0% |
| file-static | 3 | 1 | 0 | 0 | 2 | 100.0% | 0.0% |
| infrastructure | 3 | 1 | 0 | 1 | 1 | 100.0% | 50.0% |
| phishing-url | 7 | 2 | 1 | 1 | 3 | 66.7% | 25.0% |
| threat-intel | 2 | 1 | 0 | 0 | 1 | 100.0% | 0.0% |
| url-shortener | 2 | 1 | 0 | 1 | 0 | 100.0% | 100.0% |
| **TOTAL** | 27 | 11 | 1 | 5 | 10 | 91.7% | 33.3% |

**One in three harmless artifacts is flagged.** What the run surfaced, worst first:

1. **`_parse_age_days` never parses any date** (`scoring.py:92`). `ds[:len(fmt)]` slices the
   date by the length of the *format string* — `"%Y-%m-%d"` is 8 characters but produces a
   10-character date, so `"2026-07-20"` is truncated to `"2026-07-"`. Every format falls
   through to a year-only fallback that measures age from 1 January. A domain registered 5
   days ago is reported as 205 days old and scores 0 instead of 40.
   **Domain-age risk is dead from roughly April onward every year** — and "registered days
   ago" is the strongest single phishing signal in the P0 threat model. False negative.

2. **Brand subdomains reported as impersonating their own brand** (`url_processor.py:105`).
   `netbanking.hdfcbank.com`, `mail.google.com`, `eportal.incometax.gov.in`. Over plain
   http — how links arrive by SMS — this reaches Suspicious on a genuine bank login page.

3. **`youtu.be` flagged as impersonating `youtube.com`** (`url_processor.py:101`, Levenshtein
   distance 2). Combined with the deliberate shortener flag, every YouTube link shared over
   WhatsApp scores 40 = Suspicious.

4. **Permissions cannot separate an SMS stealer from Google Messages.** `apk/benign-sms-app`
   and `apk/malicious-sms-stealer` carry an identical permission set. Only the YARA family
   match distinguishes them; permissions alone put both at 50 = Suspicious.

5. **Mainstream hosting is on the suspicious-ASN list.** OVH (AS16276) and LeaseWeb
   (AS60781) are among Europe's largest providers. Country + ASN = 40, so a legitimate site
   is Suspicious on geography alone.

6. **Mainstream commercial TLDs are treated as abused.** `.shop`, `.store`, `.online`,
   `.biz`, `.live` are sold by every registrar. On plain http a small business hits 40.

7. **One URL flag can never reach Suspicious.** A lone lookalike domain scores +20 against a
   35-point threshold, so `paypa1.com` over HTTPS reads Clear. False negative.

Findings 1 and 7 are false negatives and 2–6 are false positives, which is the reason the
scorecard reports both columns: fixing only one side would have looked like progress.

### After fixing findings 1, 2 and 3

| class | n | caught | missed | wrongly flagged | correct | catch rate | false alarm rate |
|---|---|---|---|---|---|---|---|
| abused-tld | 2 | 1 | 0 | 1 | 0 | 100.0% | 100.0% |
| apk | 4 | 2 | 0 | 1 | 1 | 100.0% | 50.0% |
| document | 4 | 2 | 0 | 0 | 2 | 100.0% | 0.0% |
| file-static | 3 | 1 | 0 | 0 | 2 | 100.0% | 0.0% |
| infrastructure | 3 | 1 | 0 | 2 | 0 | 100.0% | 100.0% |
| phishing-url | 7 | 2 | 1 | 0 | 4 | 66.7% | 0.0% |
| threat-intel | 2 | 1 | 0 | 0 | 1 | 100.0% | 0.0% |
| url-shortener | 2 | 1 | 0 | 0 | 1 | 100.0% | 0.0% |
| **TOTAL** | 27 | 11 | 1 | 4 | 11 | 91.7% | 26.7% |

What changed:

- `phishing-url` false alarms **25% → 0%**. Real bank and government login pages no longer
  read as impersonating themselves.
- `url-shortener` false alarms **100% → 0%**. Shared YouTube links are Clear again.
- Catch rate held at **91.7%** — no true positive was traded away for either fix.
- `infrastructure` false alarms **50% → 100%**, and that is the fixes working correctly.
  Repairing the date parser brought domain-age scoring back to life, which immediately
  exposed `benign-new-startup-domain` (finding 6) — a false positive the broken parser had
  been hiding. A one-sided scorecard would have recorded this as a regression.

Still open, in rough priority order: finding 4 (APK permissions cannot separate a legitimate
SMS app from an SMS stealer), 6 (new legitimate domains start at 55), 5 (mainstream ASNs),
7 (a single URL flag cannot reach Suspicious), and mainstream commercial TLDs. Each is
reproduced by a case marked `known_bug`, so `pytest` stays green while the scorecard keeps
reporting the truth.

### After phase A — structural fixes

| class | n | caught | missed | wrongly flagged | correct | catch rate | false alarm rate |
|---|---|---|---|---|---|---|---|
| abused-tld | 2 | 1 | 0 | 0 | 1 | 100.0% | 0.0% |
| apk | 4 | 2 | 0 | 0 | 2 | 100.0% | 0.0% |
| document | 4 | 2 | 0 | 0 | 2 | 100.0% | 0.0% |
| file-static | 3 | 1 | 0 | 0 | 2 | 100.0% | 0.0% |
| infrastructure | 3 | 1 | 0 | 2 | 0 | 100.0% | 100.0% |
| phishing-url | 7 | 3 | 0 | 0 | 4 | 100.0% | 0.0% |
| threat-intel | 2 | 1 | 0 | 0 | 1 | 100.0% | 0.0% |
| url-shortener | 3 | 1 | 0 | 0 | 2 | 100.0% | 0.0% |
| **TOTAL** | 28 | 12 | 0 | 2 | 14 | **100.0%** | **12.5%** |

Catch rate **91.7% → 100%** and false alarms **33.3% → 12.5%**. Nothing is missed.

What changed:

- **Per-flag URL weights.** A flat +20 per flag was wrong in both directions. Plain http (now
  +5) and an abused TLD (now +5) are near-universal among harmless sites and used to add to
  40 in pairs; a brand lookalike (now +35) is rare and specific and could not reach the
  35-point threshold alone. Closes finding 7 and the mainstream-TLD row together.
- **A new combination signal**, `http_executable` (+15): an executable over https from a
  known vendor is ordinary, but the same file over plain http can be swapped in transit.
  The danger is the pair, so it is scored as its own signal rather than by inflating either
  half. Added because `test_submit_url_flow` — a requirement that predates this work —
  caught the gap.
- **APK permissions scored by rarity, not volume.** `count >= 5 → +35` measured app
  complexity; the SMS stealer and the legitimate SMS app have byte-identical permission
  sets. Volume now scores nothing while the report still lists what was requested. Rare
  capabilities carry the weight: `BIND_DEVICE_ADMIN`, `BIND_ACCESSIBILITY_SERVICE`,
  `INSTALL_PACKAGES` (+35 each); `SYSTEM_ALERT_WINDOW` and `REQUEST_INSTALL_PACKAGES` (+15,
  since Truecaller-style caller ID and chat bubbles legitimately need overlays); overlay +
  accessibility together (+25) is the banking-trojan capture pattern. Closes finding 4.
- **Artifact-evidence requirement** (generalises the old weak-IOC cap). "Malicious" is a
  claim about the artifact, so it now requires evidence about the artifact — its hash, its
  bytes, its structure, or a scanner's verdict on it. Registrar, ASN, country, domain age
  and intel on merely-referenced indicators can raise suspicion but cannot alone confirm
  malware. This caps findings 5 and 6 structurally while they wait for measurement.

Two corpus expectations were wrong and were corrected rather than worked around:

- `url-shortener/malicious-bitly-http` labelled a bare shortened link malicious on no
  evidence. Deleted, and replaced by a shortener whose destination URLhaus confirms, plus a
  benign bare-shortener case asserting we must **not** flag without evidence.
- `infrastructure/malicious-bulletproof-host` expected Malicious from infrastructure alone.
  It is the same shape as the two benign cases in its class, differing only in which ASN —
  which is precisely why it must not reach "confirmed malicious".

**Deliberately not fixed:** `apk/malicious-sms-stealer` now reaches Suspicious (55) rather
than Malicious, because one critical YARA match is worth 40. The tempting fix — raising APK
permission weights — would recreate the false positive just removed. The real finding is
that a YARA rule *naming a family* (Drinik, njRAT, AsyncRAT, FakeCalls) is artifact-identity
evidence as strong as a hash match, yet scores the same as a generic behaviour rule. Fixing
that means separating the two kinds of rule, and the generic ones (`PDF_AutoAction`,
`Generic_Ransomware_Note`, `Suspicious_IP_C2`) are FP-prone, so it needs benign YARA cases
first. Logged, not patched.

**Infrastructure stays at 100% false alarms on purpose.** Findings 5 and 6 need the benign
base-rate measurement, not another guess at the numbers.

### Layer 2 — the pipeline seam

The corpus calls `calculate_score()` directly and never touches `main.py`, so a change to
how `main.py` assembles `analysis_data` could undo a scoring fix with every corpus case
still green. Five tests in `backend/tests/test_api.py` now cover that seam, and the first
run found a bug no corpus case could reach:

**A submitted allow-listed URL was stripped from its own report.** `_strip_safe_indicators`
kept the literal submitted string (`https://github.com/`) but `main.py` derives `github.com`
into `iocs["domains"]`, and that derived host was not in the keep-set, so it was removed as
allow-listed. WHOIS, DNS and GeoIP all read `domains[0]` *after* the strip — so submitting
any allow-listed URL produced a report with no registrar, no DNS records, no geolocation and
no domain node in the graph. The comment at `main.py:629` asserted the opposite ("so the
report can still geolocate it, graph it"). Fixed by keeping the submitted URL's host
alongside the URL itself.

The other four tests pin: per-flag weights surviving into the scorer, real bank subdomains
staying free of "impersonate" wording end-to-end, the artifact-evidence rule holding through
the pipeline, and namespace boilerplate being stripped without taking genuine indicators
with it.

Suite: **92 passed, 2 xfailed** (the two xfails are findings 5 and 6, awaiting phase B).

### Indicator policy — found by manual scanning, not by the corpus

Scanning a text file containing only `https://mail.google.com` produced a report reading
**"no network indicators extracted"**, which was untrue. Investigating it exposed a false
negative far worse than the empty panel:

`SAFE_DOMAIN_PATTERNS` **deleted** matching indicators, and the list had grown to include
platforms that host arbitrary user content. So every one of these vanished from the report
— unscored, undisplayed, and never sent to URLhaus or ThreatFox:

```
https://raw.githubusercontent.com/attacker/repo/main/payload.ps1
https://github.com/badactor/malware/releases/download/v1/loader.exe
https://storage.googleapis.com/attacker-bucket/stage2.bin
https://drive.google.com/uc?export=download&id=EVIL
```

GitHub, Google Drive and Google Cloud Storage are among the most abused malware-staging
platforms. The list was effectively a published set of 25 domains an attacker could host on
to become invisible to MALSCAN.

The root mistake: **reputation was treated as covering everything hosted on a domain.**
`github.com` being trustworthy says nothing about `github.com/<stranger>/<file>`.
Reputation belongs to whoever controls the domain, never to an arbitrary path on it.

It also explained why the same URL behaved differently in the two entry paths. A submitted
URL is preserved via `keep`; an extracted one is not. The rule assumed *extracted =
boilerplate*, but a link deliberately placed in a scanned file is the subject of the scan.

Fixed by splitting one list into two with opposite treatment (`app/main.py`):

| | contents | treatment |
|---|---|---|
| `NAMESPACE_IDENTIFIERS` | `w3.org`, `schemas.microsoft.com`, RFC 2606 names, loopback | deleted — nothing is hosted there |
| `REPUTABLE_HOSTS` | `github.com`, `google.com`, `apple.com`, … | kept and shown; a **bare** reference does not attract intel lookups or scoring, but a **path-bearing** URL is scored and scanned normally |

`_is_suppressible_indicator` is the single decision point, and `_pick_best_url` now selects
path-bearing reputable URLs as external-scan targets instead of skipping them. Intel
suppression narrowed to bare references, so a confirmed URLhaus detection is no longer
discarded because of where the payload happened to be hosted.

11 tests in `backend/tests/test_indicator_policy.py`, written failing first. Suite:
**101 passed, 2 xfailed**; catch rate and false-alarm rate unchanged at 100% / 12.5%.

### Risk-ranked selection — spelling no longer decides what gets analysed

Only one URL per document gets heuristic analysis, VirusTotal and URLScan, and only one
domain gets WHOIS/DNS/GeoIP. Both took the first entry, and IOC lists are sorted
alphabetically for reproducibility — so **which link a scan examined came down to spelling**.
A document containing `aaa-harmless.example/page` and `zzz-evil.tk/payload.exe` analysed the
harmless one and never looked at the payload.

Seen live: a file citing `mail.google.com` and `netbanking.hdfcbank.com` enriched Google,
because "m" sorts before "n". The `Registrar Reputation +15` finding on the bank's actual
registrar simply never appeared — the score changed based on alphabetical order.

`_rank_urls_by_risk` now orders candidates by their summed flag weights, ties broken
alphabetically so repeat scans still agree. `analyze_url` does no I/O, so scoring every
extracted URL is free; only the external lookups stay budgeted to one.

```
risk  10  http://aaa-harmless.example/page
risk   0  https://mail.google.com          (bare reputable — skipped)
risk   5  http://www.w3.org/2001/XMLSchema (boilerplate — skipped)
risk  45  http://zzz-evil.tk/payload.exe   <- analysed and scanned
```

Enrichment follows the same choice, so WHOIS/DNS/GeoIP describe the host actually worth
looking at. Report reasons now name the host a flag came from (`URL anomaly on evil.tk: …`)
— with several links in a file, "not using HTTPS" alone left the reader guessing which.

Suite: **105 passed, 2 xfailed**; catch rate and false alarms unchanged at 100% / 12.5%.

### Phase B — infrastructure weights, measured

`tests/live/base_rates.py` enriched a pinned 300-domain sample of the Tranco top 10,000
(seed 20260725, list downloaded 2026-07-25) and ran the real scoring checks against the
results. Findings 5 and 6 had been left open specifically so these numbers, not intuition,
would set the weights.

Full sample, 300 domains (WHOIS resolved for 249, GeoIP for 237):

| check | fires on benign top-10k | was | now |
|---|---|---|---|
| Country Risk | **6.7%** — Alibaba Cloud, Selectel, NGENIX | 20 | 5 |
| Registrar Reputation | **6.3%** — every hit Namecheap | 15 | **0** (reported, not scored) |
| ASN — mainstream budget | **1.0%** — all three OVH | 20 | 5 |
| ASN — bulletproof | 0% here; genuinely discriminative | 20 | 20 |
| Domain Age (≤90d) | 0.3% — **unmeasurable, see below** | 40 | 30 |

Weights were set from a partial run (192 domains) and the complete run confirmed every one:
country 8.3% → 6.7%, registrar 6.8% → 6.3%, ASN 0.5% → 1.0%. No decision changed.

Three things the measurement showed that reasoning had not:

- **39 of 141 domains geolocated to Canada.** They are not in Canada — those are Cloudflare
  anycast edges. For anything behind a CDN, which is most of the modern web, the country
  field describes an edge node rather than the host. The signal is both common among benign
  sites *and* frequently measuring the wrong thing.
- **The registrar list tracks nothing real.** Namecheap appears 11 times in the sample and
  is flagged; GoDaddy appears 16 times and is not, though it is larger and at least as
  abused. Flagging one and not the other is arbitrary, so the check now reports the
  registrar as context and scores zero.
- **The ASN list was two lists.** Bulletproof providers exist to ignore abuse reports and
  keep full weight. OVH and LeaseWeb are among Europe's largest hosts, abused precisely
  because they are cheap and popular.

**What the data could not say.** Of 266 domains with a usable creation date: none under 30
days, exactly one under 90 (`videystream.vip`, 81d), six under a year, median age 17.7
years. A week-old legitimate business is by definition not among the world's most popular
sites, so one data point is not a base rate — domain age is unmeasurable this way. The drop
from 40 to 30 is therefore a *structural* argument, not an empirical one: no single fact
about a domain's paperwork should clear the 35-point threshold unaided. Measuring it
properly needs newly-registered-domain feeds with known-good labels.

**A flaw in the harness itself, worth recording.** The report counted a signal only when it
*scored*. Zeroing the registrar weight therefore made it vanish from the table entirely —
the tool stopped measuring the check that had just been changed, and a future re-weight
would have looked like the problem disappearing. It now counts whether a check matched,
independent of points. Anything that measures a system it is part of needs this care.

**Sample bias, stated deliberately.** Popular sites sit behind Cloudflare and Akamai, not
budget hosts; small businesses live in the long tail. So 8.3% and 6.8% are *lower bounds* on
how often these fire on harmless sites — which argues for smaller weights, not larger.

Result: **109 passed, 0 xfailed. Catch rate 100%, false alarms 0% across all eight classes.**

That means the corpus has run out of things to say, not that the problem is solved — 28
cases is a small sample and every one of them was written by someone who already knew what
they were looking for. The manual scans found three bugs the corpus could not.

### YARA — the engine was dead, and switching it on would have been worse

`yara-python` was an optional extra that was never installed, so the rule file was never
compiled. **It did not compile.** Two independent authoring errors, each of which takes the
entire file down, because `yara.compile()` loads it as a unit:

- `FakeCalls_Banking_App` declared `$icici` and never referenced it — an unreferenced string
  is a compile *error* in YARA.
- `Suspicious_IP_C2` used a non-capturing group `(?:…)`, which YARA's regex engine does not
  support.

Both surfaced as `yara_available: False` — identical to the dependency being absent. A dead
detection engine was indistinguishable from a disabled one, in development and in
production. All 21 rules had never run.

Fixing the compile errors alone would have shipped something far worse. Measured against 370
known-benign files (`tests/live/yara_false_positives.py` — Windows System32 binaries, npm
JavaScript, Python packages, local PDFs):

| | before | after |
|---|---|---|
| Windows System32 binaries scoring points | **100%** | 0% |
| python packages | 3.3% | 0% |
| documents | 20% | 0% |

Four separate defects, each confirmed by inspecting the matched bytes rather than guessed:

- **`PE_In_Document` had its logic inverted.** `($mz at 0)` means the file *starts* with MZ —
  a plain executable, not a document hiding one. It matched all 120 sampled System32
  binaries. Now requires a PDF or OLE container with the PE inside it.
- **`Base64_Encoded_PE` used `nocase` on base64**, which is case-sensitive, and a
  three-character string `"TVo"`. It matched `tVo` in ordinary binary data.
- **`Drinik_Banking_Trojan` — critical, +40 — matched Microsoft's `ShellAppRuntime.exe`**
  on `"iAssist"`, which occurs inside `UIAssistant`. A 7-character nocase substring is not
  an identification. Same class of bug as the typosquat matching.
- **`File_Encryption_API` matched `wlidsvc.dll`**, the Windows credential service, on
  `CryptEncrypt` + `DeleteFile`. Capability is not intent — it now also requires directory
  enumeration, and reports rather than scores.
- **`PDF_AutoAction` downgraded to `medium`.** `_check_document_threats` already scores
  `/OpenAction` at a calibrated +10; the rule double-counted it at +25 *and*, because YARA
  scores into `intel_total`, switched off the benign-VirusTotal-consensus dampener that
  exists to stop exactly this false positive.

14 tests in `backend/tests/test_yara_rules.py`, including a compile guard — the thing whose
absence let this persist — and a true-positive case for every loosened rule, since tuning a
rule until benign files stop matching is worthless if the malicious shape stops matching
too. They scan **in memory**: EICAR and a PowerShell download cradle written to disk lose a
race with the developer's antivirus, which quarantines them before YARA can open the file.

`yara-python` is now a declared dependency, so a broken rule file fails the build rather
than silently disabling itself.

### The analysers, run on real files

`tests/corpus/` feeds `calculate_score()` dictionaries describing what an analyser *would
have produced*. That only tests the scorer's reaction to inputs the fixture author invented
— it cannot tell you the analyser emits them. `backend/tests/test_analyzers_real_files.py`
builds files with real structure and runs the real analysers. Two more dead paths:

**APK permission analysis never worked on a real APK.** `_parse_manifest_xml` read only
plain-text `AndroidManifest.xml`, and every APK built by the Android toolchain ships binary
AXML — so permission extraction returned an empty list for every real APK, and a sideloaded
banking trojan looked like an app requesting nothing. This is the #1 P0 threat and its main
heuristic, reweighted earlier in this same document, was reading nothing.

Fixed by recovering permission names from the AXML string pool, where they survive as
readable text (UTF-16LE on older builds, UTF-8 on newer). Not a full AXML parse — it cannot
distinguish a `<uses-permission>` from a string referenced elsewhere — but a permission name
is in the pool because the manifest names it, and the alternative was detecting nothing.

**Ordinary form PDFs were classified as drive-by documents.** `has_js_auto_combo` matched
`/(OpenAction|AA)` followed by JavaScript. `/AA` is "additional actions" and the sub-key
decides everything: on a form field (`/Fo` focus, `/K` keystroke, `/V` validate, `/C`
calculate) the script runs when a user interacts with the field, which is what every
interactive form does. Only a page-open action (`/O`) fires by itself. So a tax form scored
45 instead of 15 — and the corpus could not see it, because the fixture asserting
`has_js_auto_combo: false` supplied that value by hand rather than deriving it from the
analyser.

16 tests, including a parametrised case per form-field action and a page-open case proving
the genuine drive-by shape is still caught.

### Hostile archives

`backend/tests/test_archive_attacks.py` — 9 tests through the real API, since the guards
live inline in `process_scan_job` and a unit test of the helpers would not reach them.
`generate_test_files.py` had built samples like these but no test ever ran them.

**The guards held.** Zip slip (traversal, absolute member path, and the sibling-prefix case
`commonpath` exists to catch), file-count and decompressed-size budgets, a hand-built member
declaring 1 byte while containing 8 MB, and six levels of nesting — all handled, with
ordinary archives still having their contents extracted and their IOCs surfaced.

Worth recording for the method rather than the result: at real limits these took **96
seconds**, in a suite that otherwise runs in nine. A budget check can only be proven at scale
by producing that scale. Since the limits are module globals read at call time, lowering them
exercises the identical branch — **96s → 4s**. The full-scale bomb survives as an opt-in test
(`MALSCAN_SLOW_ARCHIVE_TESTS=1`, ~60s) because real memory behaviour is the one property the
down-scaled version cannot show. A suite people stop running protects nothing.

### A real APK broke the "0% false positives" result immediately

The YARA measurement above reported 0% after its fixes. Then a genuine APK was scanned —
**F-Droid, an open-source app store — and it scored 75/Malicious.**

The benign corpus held Windows binaries, npm JavaScript, Python packages and PDFs. **No
APKs.** An APK is a large ZIP full of translations, resource strings and repo metadata, a
string profile nothing else in the corpus resembles — and it is the P0 artifact type. The
blind spot was in the measurement, not the rules.

| rule | matched | reality |
|---|---|---|
| `Generic_Ransomware_Note` **critical, +40** | `"bitcoin"` + `"how to restore"` | a donation method and a backup feature |
| `Hardcoded_TOR_Onion` **high, +25** | F-Droid's own `.onion` mirror | Tor is a privacy feature |
| `Suspicious_IP_C2` | `127.0.0.1` | **localhost**, described as "C2 infrastructure" |

All three share the earlier authoring error: generic strings treated as specific evidence.
`2 of them` over a list containing "bitcoin" and "ransom" means any app that mentions
cryptocurrency and has a restore feature is critical ransomware. The weak keywords were
removed rather than outvoted — a word describes a topic, not an act. Tor and IP-literal
observations dropped to `medium`, so they still appear as report context at zero points, and
`Suspicious_IP_C2` no longer claims localhost is C2 infrastructure (report text is part of
the product; routability is already decided properly by `is_reportable_ip` in Python).

F-Droid now scores **15/Clear** — the +15 being `REQUEST_INSTALL_PACKAGES`, which is exactly
right for an app store, and still visible in the report.

Also validated here: the APK binary-AXML fix works against a **genuine** manifest (47 KB,
magic `03000800`), extracting 29 permissions. The synthetic AXML in the unit tests is a
simplification of the format, so that could not be assumed.

`yara_false_positives.py` now collects an `android-apks` bucket (`MALSCAN_APK_DIR`, plus
`~/Downloads`) so this artifact type is measured rather than assumed. Five regression tests
cover the three rules, each paired with a true-positive case.

### Still open, in priority order

1. **Corpus breadth.** 28 scoring cases, and the tables above still have ⬜ rows — several
   URL flags, most YARA rules. Every "0%" so far has meant the corpus ran out of things to
   say: a single real APK falsified the last one within minutes.
2. Critical YARA family-naming rules score the same as generic behaviour rules.
3. GeoIP reports the anycast edge for CDN-fronted hosts — now confirmed at scale (39/141 of
   the sample "in Canada"). The country signal is weak partly *because* of this.
4. Only one URL gets *external* scanning (VirusTotal/URLScan). Now the riskiest rather than
   an arbitrary one, but a document with two genuinely dangerous links only gets one
   checked. Widening it spends free-tier quota, so it needs a deliberate budget.
5. Phase C — reputation as a prior, with the vendored Public Suffix List.
<!-- BASELINE:END -->
