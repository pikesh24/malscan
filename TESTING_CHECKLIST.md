# Malscan manual testing checklist

Hands-on testing, done through the real UI against the real backend. This is
deliberately **not** the automated suite — `docs/TESTING.md` covers that, and the
whole point here is that manual results keep diverging from what the tests say.
Where they disagree, the manual result is the true one.

Work top to bottom. Sections 1–4 are the foundation; if those are wrong, nothing
below them means much.

---

## How to use this

**Record three things per test:** the verdict banner, the score, and the top line
of Score Composition. A test "passes" if the verdict is in the expected band *and*
the reason given is the right reason. A right answer for a wrong reason is a
failure worth writing down — it means the next similar file will be wrong.

**Verdict bands.** Malicious ≥ 70, Suspicious ≥ 35, Clear < 35, plus Inconclusive,
which replaces a would-be Clear when something could not be checked. Inconclusive
is never a downgrade of a real detection.

**Expected values below are the local heuristic floor.** VirusTotal, URLScan and
abuse.ch run on top and can only push the score *up*. So "expect ≥ 35" means 35
from Malscan's own logic; a real run may land higher. If a run lands *lower*,
that's a finding.

**Two things will bite you, so front-load them:**

- **Your antivirus will eat some samples.** Anything shaped like a real dropper —
  EICAR, a shortcut with an encoded PowerShell command, a VBS download cradle —
  may be quarantined between upload and scan. That is not a Malscan bug. Malscan
  should then report **Inconclusive**, never Clear. That behaviour is itself
  test 16.1. If you want the sample to survive, add a Bitdefender exclusion for
  your test folder *and* the backend's vault directory.
- **VirusTotal free tier is 4 requests/minute, 500/day.** A rapid run through this
  list will hit that. Scans slow down or come back Inconclusive with a rate-limit
  reason. Pace yourself, or expect it and note it.

**Rescanning the same file is not a cache hit.** There is a 5-second debounce for
double-clicks; past that the pipeline genuinely re-runs. A rescan being much
faster is normal — the first scan uploads an unknown file to VirusTotal and waits;
the second finds the hash already there.

---

## 0. Before you start

- [ ] Backend running (`uvicorn app.main:app --port 8001`), `/docs` returns 200
- [ ] Frontend running (`npm run dev`), loads at `http://localhost:3000`
- [ ] `backend/.env` has `VT_API_KEY` and `URLSCAN_API_KEY` — without them the intel
      sections stay empty and half this list tests nothing
- [ ] Check remaining VirusTotal quota before a long session
- [ ] Decide your AV stance: exclusions on, or accept quarantine and test for it

---

## 1. Foundation — does the basic loop work at all

- [ ] **Submit nothing** — click scan with no file and no URL → clean error, no crash
- [ ] **Empty file** (0 bytes) → completes, does not crash, verdict Clear or Inconclusive
- [ ] **1-byte file** → completes
- [ ] **Plain .txt with no links, no keywords** → **Clear**, score 0, no findings.
      This is the most important negative case in the whole document. If an
      ordinary text file scores anything, every threshold below is unreliable.
- [ ] **Same file twice, back to back (<5s)** → second is debounced, result identical
- [ ] **Same file twice, 30s apart** → genuinely rescans, verdict stable
- [ ] **Same file, different filename** → same verdict and score. Filename must not
      change the answer.
- [ ] **Report loads** for every completed scan, with no blank panels
- [ ] **PDF export** works from a completed report
- [ ] **50 MB+ file** → rejected with a clear size error, not a hang

---

## 2. Text files and links

The foundation for URL extraction. All of these are `.txt` unless stated.

### 2a. Link counting and extraction

- [ ] No links → no indicators section, Clear
- [ ] One safe link (`https://example.com/pricing`) → link extracted and listed, Clear
- [ ] One known-bad link (see Appendix for sources) → extracted, score rises
- [ ] Two safe links → both listed
- [ ] Ten safe links → all listed (or capped with an honest "showing N of M")
- [ ] 100 links → does not hang, list is bounded, no giant unreadable report
- [ ] Mixed: 3 safe + 2 bad → **the bad ones drive the verdict**, and the report names
      *which* link was the problem, not just a total
- [ ] Duplicate link repeated 20 times → counted once, does not multiply the score
- [ ] Link with no scheme (`example.com/path`) → still extracted
- [ ] Link inside a sentence with punctuation (`visit https://x.example/a.` ) → trailing
      full stop not included in the URL
- [ ] Link in the middle of a word / no whitespace → sensible behaviour, no crash

### 2b. Link shapes worth their own test

- [ ] `http://` (not https) download of an `.exe` → flagged as an insecure executable fetch
- [ ] Raw public IP URL (`http://198.51.100.23/panel`) → extracted, treated as an indicator
- [ ] Private IP (`http://192.168.1.10/admin`) → **not** reported as a threat indicator
- [ ] Loopback (`http://127.0.0.1:8080`) → not reported
- [ ] `x.x.x.0` and broadcast addresses → not reported
- [ ] URL shortener (`bit.ly`, `t.me`) → flagged as a shortener
- [ ] Punycode / IDN host (`xn--…`) → flagged
- [ ] Lookalike domain (`paypa1-secure.example`) → typosquatting flag
- [ ] Real brand domain (`https://www.google.com`) → **not** flagged as impersonation
- [ ] Suspicious TLD (`.tk`, `.xyz`, `.top`) → flagged, but weakly
- [ ] Very long URL (500+ chars) → handled, truncated sensibly in the report
- [ ] URL with credentials (`http://user:pass@host.example/`) → flagged
- [ ] Deeply nested subdomains (`a.b.c.d.e.example.com`) → handled

### 2c. Same content, other containers

- [ ] Links inside a `.csv` → extracted
- [ ] Links inside a `.json` → extracted
- [ ] Links inside a `.md` → extracted
- [ ] Links inside a `.log` → extracted
- [ ] Links inside a file with **no extension** → extracted
- [ ] Text file renamed `.exe` → **not** treated as a PE; type mismatch noted
- [ ] Unicode filename (`ré­sumé­中.txt`) → no encoding crash
- [ ] Very long filename (200 chars) → handled
- [ ] File with Windows-1252 / UTF-16 encoding → links still found

---

## 3. URL submission (the other entry point)

- [ ] **Known-good site** (`https://www.wikipedia.org`) → Clear, screenshot renders
- [ ] **Known-bad URL** from URLhaus → Malicious, and the report says which source flagged it
- [ ] **AMTSO phishing test page** (Appendix) → flagged
- [ ] **Google Safe Browsing test page** (Appendix) → flagged
- [ ] URL with no scheme typed in → accepted or clearly rejected, not silently mangled
- [ ] URL that 404s → completes with an honest "page not found", not Clear-by-accident
- [ ] URL that times out / dead domain → Inconclusive or an explicit error, **not Clear**
- [ ] Site behind Cloudflare → hosting section does not claim the CDN's country as the host's
- [ ] Site with many third-party resources (a news site) → third-party panel lists them,
      score stays Clear. **Ordinary sites must not be flagged for having a CDN.**
- [ ] Site loading from object storage (S3/R2) → host listed as observed-but-unchecked,
      not scored on that alone
- [ ] Screenshot renders in the report and in the exported PDF
- [ ] Same URL twice → same vantage point, same language rendering (country pinning)
- [ ] A `.ru`/`.de`/`.jp` site → screenshot is the **US** rendering, not localised
- [ ] Very long URL with query string → handled
- [ ] URL to a direct file download (`https://…/setup.exe`) → note what happens; Malscan
      scores the *page*, not the file behind it (known limitation)

---

## 4. Documents

- [ ] Clean PDF → Clear
- [ ] PDF with embedded JavaScript → flagged
- [ ] PDF with `/OpenAction` auto-run → flagged
- [ ] PDF with an embedded file → flagged
- [ ] PDF with a normal interactive form → **Clear**. Forms use JavaScript legitimately;
      if this flags, the PDF check is too aggressive
- [ ] Large real-world PDF (a bank statement, a manual) → Clear
- [ ] Clean `.docx` → Clear
- [ ] `.docm` with a macro → flagged
- [ ] `.xlsm` with a macro → flagged
- [ ] Macro doc **renamed to `.zip`** → still flagged (regression, see 20)
- [ ] Macro doc **renamed to `.dat`** / no extension → still flagged
- [ ] Legacy `.doc` (OLE) with a macro → flagged
- [ ] Legacy `.doc` renamed → still detected via magic bytes
- [ ] Office doc containing a malicious URL → URL extracted as an indicator
- [ ] Office doc with DDE fields → flagged
- [ ] A real, ordinary `.docx` you actually use → **Clear**. Best false-positive test here.
- [ ] RTF file → handled without crashing
- [ ] Password-protected Office document → honest about not reading it

---

## 5. Executables

- [ ] Clean signed Windows binary (e.g. from `C:\Windows\System32`) → **Clear**.
      A signed Microsoft binary scoring anything is a serious false positive.
- [ ] Small unsigned self-built exe → low score, no invented findings
- [ ] Packed/high-entropy binary → entropy noted, but not decisive alone
- [ ] `.exe` renamed `.jpg` → type mismatch flagged
- [ ] `.exe` renamed `.pdf` → type mismatch flagged
- [ ] `.dll` → recognised as PE
- [ ] ELF binary → recognised as ELF, not misread as Windows
- [ ] EICAR test file (Appendix) → detected, **or** quarantined by your AV and reported
      Inconclusive (see 11.1)
- [ ] A real sample hash from MalwareBazaar, submitted **as a hash lookup if supported** →
      MalwareBazaar/VirusTotal sections populate
- [ ] Binary with an embedded URL → URL extracted
- [ ] Binary with embedded suspicious strings (`VirtualAlloc`, `IsDebuggerPresent`) → noted
- [ ] Very small file claiming to be a PE (`MZ` + 10 bytes) → no crash

---

## 6. Archives

- [ ] Plain zip, two harmless text files → Clear, both members listed
- [ ] Zip containing an exe → member listed, PE noted
- [ ] Zip containing a macro document → document analysis runs on the member
- [ ] **Nested zip, 2 deep** → inner members still analysed
- [ ] **Nested zip, 4 deep** → stops at the depth limit and **says so** in the report
- [ ] Zip with 600+ files → file-count limit hit, report says only part was examined
- [ ] Zip bomb (small file, huge expansion) → blocked, report says why, no disk fill
- [ ] **Zip Slip** (member path `../../escaped.txt`) → blocked, nothing written outside
- [ ] **Password-protected zip** → **Inconclusive**, names the members it could not read,
      and explicitly does *not* say Clear
- [ ] Partially encrypted zip (one member locked, one readable) → readable member still
      analysed, locked one still reported
- [ ] Encrypted zip containing a *known-bad* member → still Malicious if anything else
      detects it; Inconclusive must never bury a real detection
- [ ] `.7z` file → **Inconclusive**, "cannot open this format", not Clear
- [ ] `.cab` file → same
- [ ] `.gz` / `.tar` file → same
- [ ] `.iso` file → identified as an ISO and reported unexaminable (not "Unknown")
- [ ] `.rar` file → extracted if a backend is installed; if not, says so explicitly
- [ ] Truncated / corrupt zip → handled, no crash
- [ ] Zip with a unicode member name → handled
- [ ] Empty zip → Clear, no crash

---

## 7. Android APKs

- [ ] Ordinary app (INTERNET only) → **Clear**. Most apps on the store look like this.
- [ ] A real APK you trust (from your phone) → **Clear**. The single best mobile
      false-positive test.
- [ ] Overlay + accessibility permissions → **Malicious/Suspicious**, and the report calls
      out the *combination*, not two separate lines
- [ ] Accessibility alone → flagged but lower
- [ ] Overlay alone → flagged but lower
- [ ] `REQUEST_INSTALL_PACKAGES` (dropper) → flagged
- [ ] `BIND_DEVICE_ADMIN` → flagged
- [ ] SMS permissions (`READ_SMS` + `SEND_SMS`) → flagged as SMS-stealer pattern
- [ ] **NFC alone** → **not scored** (transit and payment apps use it), but still listed
- [ ] **NFC + accessibility** → scored as the contactless-relay pattern
- [ ] APK **renamed to `.zip`** → still fully analysed (regression, see 20)
- [ ] APK **inside a zip** → still analysed, report names the member it came from
- [ ] APK containing a second APK → the *submitted* app's manifest drives the verdict
- [ ] APK with a binary (AXML) manifest → permissions still recovered
- [ ] APK with a huge/lying manifest size → refused, no memory blowup
- [ ] APK with URLs in its DEX strings → extracted as indicators

---

## 8. Scripts and shortcuts

### 8a. Scripts

- [ ] Ordinary `.js` (a few lines of page script) → **Clear**
- [ ] **Minified library** (`jquery.min.js`, real one) → **Clear**. Minified code looks
      obfuscated by every structural measure; this must not flag.
- [ ] `.vbs` download-and-run dropper → flagged, dropper chain named
- [ ] `.js` using `WScript.Shell` → flagged (browser JS cannot do this)
- [ ] `.js` using `ADODB.Stream` → flagged
- [ ] Obfuscated `.js` building object names from character codes → still flagged
- [ ] Script with obfuscation but **no** dangerous API → low/no score
- [ ] `.ps1` with an encoded command → flagged
- [ ] `.bat` with `certutil -urlcache` → flagged
- [ ] Script writing a `Run` registry key → persistence flagged
- [ ] Script inside a zip → still analysed
- [ ] Script's second-stage URL → extracted as an indicator
- [ ] A real, ordinary build script from this repo → **Clear**

### 8b. Windows shortcuts (.lnk)

- [ ] Ordinary shortcut to Notepad → **Clear**
- [ ] Shortcut to a document → **Clear**
- [ ] Shortcut running `powershell -enc <base64>` → flagged, command line shown
- [ ] Shortcut with a download cradle → flagged
- [ ] Shortcut with 80 spaces padding the command → padding trick flagged
- [ ] Shortcut set to run hidden → flagged
- [ ] Shortcut with a document icon but an interpreter target → disguise flagged
- [ ] Shortcut inside a zip → still analysed
- [ ] Truncated / malformed `.lnk` → no crash
- [ ] A real shortcut from your Start Menu → **Clear**

---

## 9. HTML attachments

- [ ] Ordinary saved web page → **Clear**
- [ ] Newsletter HTML with an inline base64 logo → **Clear** (images are the legitimate
      reason for a big base64 blob)
- [ ] HTML smuggling page (Blob + createObjectURL + download) → flagged
- [ ] Smuggling page with an **obfuscated loader** → still flagged (the payload decodes
      to `MZ` regardless of how the loader is written)
- [ ] Fake CAPTCHA / ClickFix page that writes to the clipboard → flagged
- [ ] Page with a normal download button → **Clear** (download buttons are everywhere)
- [ ] `.hta` file → analysed
- [ ] `.svg` with embedded script → analysed
- [ ] HTML inside a zip → still analysed
- [ ] Very large HTML file (10 MB) → bounded, no hang

---

## 10. Browser extensions

- [ ] Narrow extension (storage + one site) → **Clear**
- [ ] A real extension you use (e.g. uBlock) → note the result. Ad blockers legitimately
      request very broad access; if this screams, the weighting is wrong.
- [ ] `<all_urls>` + `cookies` → flagged as a session harvester
- [ ] `nativeMessaging` → flagged
- [ ] Extension loading remote code via CSP → flagged
- [ ] Manifest V2 extension (host patterns in `permissions`) → still parsed
- [ ] `.crx` with the CRX3 signed header → manifest still read
- [ ] Extension inside a zip → still analysed
- [ ] Corrupt `manifest.json` → no crash

---

## 11. Threat-intelligence sources

Each is a separate scoring line that can carry a verdict alone. Test them
individually — when one silently stops working, the score just looks low.

- [ ] **VirusTotal — known-bad file.** EICAR or a MalwareBazaar sample → "VirusTotal
      Consensus" appears with a real vendor count and named detections
- [ ] **VirusTotal — 1 vendor only** → scores **nothing**. One vendor is deliberately
      treated as noise; if it scores, expect false positives everywhere
- [ ] **VirusTotal — unknown file** (something you just made) → reported as *unknown*,
      never as clean
- [ ] **VirusTotal — named vendors** shown, not just totals
- [ ] **MalwareBazaar — hash hit** → family and first-seen date populate
- [ ] **MalwareBazaar — archive member hit.** Known sample inside a zip → hit promoted to
      the artifact and **names the member it came from**
- [ ] **MalwareBazaar — double-zipped** known sample → still matched
- [ ] **ThreatFox — IOC match.** File containing a current ThreatFox IOC → malware name
      and confidence shown
- [ ] **URLhaus — URL match.** File containing a current URLhaus URL → flagged
- [ ] **AbuseIPDB — flagged IP** → "AbuseIPDB Abuse Confidence" appears (needs
      `ABUSEIPDB_API_KEY`)
- [ ] **AbuseIPDB — clean IP** (8.8.8.8) → no score
- [ ] **Known-hash blocklist** — EICAR by hash → "Known Malicious Hash Match", 100
- [ ] **Several sources hit at once** → scores combine sensibly, nothing double-counted

### Safe-domain suppression (fixed a real false positive)

- [ ] File containing a **bare** `google.com` reference → any ThreatFox/URLhaus hit on
      that bare domain is **suppressed**. Malware configs reference google.com for
      connectivity checks, and this once scored google.com itself as Malicious
- [ ] File containing a **path-bearing** URL on a reputable host
      (`github.com/x/releases/download/loader.exe`) → the hit is **kept**. Suppression
      must drop bare references only, never a real report about a specific hosted file

---

## 12. Domain, hosting and infrastructure

Only fires when a domain or IP is in play — submit URLs, or files containing them.

- [ ] **Brand-new domain** (registered days ago) → "Domain Age Risk" scores high
- [ ] **A few months old** → scores moderately
- [ ] **Decades-old domain** (`ibm.com`) → scores **nothing**
- [ ] **No WHOIS date available** → no score, no invented age
- [ ] WHOIS returning a year only → age not wildly overstated
- [ ] **Registrar** shown as context and scores **0** — reported, not judged
- [ ] **Bulletproof-host ASN** → "Hosting / ASN Risk" scores
- [ ] **Budget host** (OVH, Contabo) → scores weakly, never decisively
- [ ] **Mainstream cloud** (AWS, Google) → no meaningful score
- [ ] **Anycast CDN.** Scan an Indian or Brazilian site behind Cloudflare → the report does
      **not** claim the CDN edge's country as the site's location
- [ ] **High-risk country** hosting → weak signal only
- [ ] **DNS records** (A, MX, TXT) populate for a real domain
- [ ] **GeoIP map / coordinates** render for a real IP
- [ ] Domain that does not resolve → honest empty enrichment, no crash
- [ ] IP-only submission → GeoIP and AbuseIPDB still run

---

## 13. YARA rules

21 rules exist. Each is a claim that can silently stop matching.

- [ ] EICAR → `EICAR_Test_File`
- [ ] PowerShell encoded command → `PowerShell_EncodedCommand`
- [ ] `Net.WebClient` + `DownloadString` + `IEX` → `PowerShell_DownloadCradle`
- [ ] AMSI bypass string → `PowerShell_AMSI_Bypass`
- [ ] PE embedded in a document → `PE_In_Document`
- [ ] Base64-encoded PE in a text file → `Base64_Encoded_PE`
- [ ] PDF with JavaScript → `PDF_JavaScript_Exploit`
- [ ] PDF auto-action → `PDF_AutoAction`
- [ ] Office auto-open macro → `Office_AutoOpen_Macro`
- [ ] Office DDE → `Office_DDE_Exploit`
- [ ] `.onion` address → `Hardcoded_TOR_Onion`
- [ ] Ransomware note text → `Generic_Ransomware_Note`
- [ ] Encryption API strings → `File_Encryption_API`
- [ ] Suspicious PE section names → `Suspicious_Section_Names`
- [ ] RAT indicator strings → `Generic_RAT_Strings` / `Njrat` / `AsyncRAT`
- [ ] Banking-overlay strings → `Generic_Banking_Overlay`
- [ ] **Fires on an archive member** → report names which file it fired on
- [ ] **Same payload repeated 20x in one archive** → score does not multiply
- [ ] An ordinary document → **no** YARA hits

---

## 14. Scoring behaviour and verdict shaping

Logic that changes the answer without appearing as its own finding. Easy to break,
hard to notice.

- [ ] **Benign-consensus dampening.** A file with mild heuristic signals that 40+
      VirusTotal engines all call clean → heuristic score **halved**, and a
      "Benign VirusTotal Consensus (reduction)" line appears. An ordinary PDF with
      forms and JavaScript is the easiest way to trigger it
- [ ] Dampening does **not** apply when VirusTotal did not return (partial scan)
- [ ] Dampening does **not** apply when any engine flagged the file
- [ ] **Weak-IOC corroboration cap** — many weak indicators, no corroboration → capped,
      and the cap is visible in Score Composition
- [ ] The cap does **not** apply to a directly submitted URL
- [ ] **Riskiest URL wins.** A file containing both `mail.google.com` and a phishing
      domain → the **phishing** domain gets WHOIS/GeoIP/URLScan. Spelling must not decide
      which link gets analysed
- [ ] **Artifact vs indicator.** A URL submitted directly can carry a verdict; the same
      URL merely mentioned inside a file should weigh less
- [ ] **Score caps** — a file tripping many checks tops out at 100, no overflow
- [ ] **Score Composition sums** to the displayed total, including reductions
- [ ] **Attribution / family** populates on a known sample, and says
      "Unknown / Unattributed" otherwise rather than guessing
- [ ] **Verdict boundaries** — find files landing near 34/35 and 69/70 and confirm the
      band flips where it should

---

## 15. Clustering and scan history

Needs several scans in sequence, so do this section as a block.

- [ ] Two different files sharing an IP or domain → linked as related
- [ ] The related panel names the shared indicator
- [ ] Two unrelated files → **not** linked
- [ ] Cluster count and risk signals populate
- [ ] The same file scanned twice → no confusing self-cluster
- [ ] After 10+ scans the panel is still readable and bounded
- [ ] Scans do not get noticeably slower as history grows
- [ ] If the UI offers clearing history → scans still work afterwards

---

## 16. Failure and degradation — where a wrong answer is dangerous

The theme: **"we could not check" must never render as "nothing is wrong."**

- [ ] **16.1 — AV quarantines the sample mid-scan** → **Inconclusive**, reason mentions
      antivirus. Reproduce by scanning EICAR with real-time protection on. A Clear here
      is the worst bug the product can have
- [ ] Unreadable / permission-denied file → Inconclusive
- [ ] VirusTotal rate limit hit (scan rapidly) → Inconclusive with a rate-limit reason,
      **not** Clear and not a silent zero
- [ ] VirusTotal key removed from `.env` → intel section honestly empty, scan completes
- [ ] URLScan key removed → sandbox section absent, no crash
- [ ] AbuseIPDB key removed → section absent, no crash
- [ ] Backend restarted mid-scan → job does not sit "Processing" forever
- [ ] Network disconnected mid-scan → honest failure, not Clear
- [ ] Unknown-to-VirusTotal file → reported as *unknown*, not clean
- [ ] A Failed job → the report page renders something sensible, not a blank crash
- [ ] Malformed/garbage file of every type above → no 500s

---

## 17. Security of Malscan itself

The scanner is a target. Everything here is attacker-controlled input rendered back
to a user.

- [ ] **XSS via filename** — upload `<script>alert(1)</script>.txt` → escaped in the
      report, nothing executes
- [ ] **XSS via page title** — scan a URL whose `<title>` contains HTML → escaped
- [ ] **XSS via indicators** — a file containing `"><img src=x onerror=alert(1)>` as a
      fake URL → escaped everywhere it is rendered
- [ ] **XSS in the PDF export** — same inputs, check the rendered PDF
- [ ] **Path traversal via filename** — `../../evil.txt` → sanitised, nothing written
      outside the vault
- [ ] **Zip Slip** — archive member `../../escaped.txt` → blocked
- [ ] **SSRF via `/proxy/image`** — try `http://169.254.169.254/latest/meta-data/`, then
      `http://localhost:8001/`, then any non-allowlisted host → all refused
- [ ] **`/proxy/image` redirect** — allowed host redirecting elsewhere → not followed
- [ ] **`/proxy/image` content type** — non-image response → not served as HTML
- [ ] **Job ID access** — fetch `/status/<another job id>` → note whether any
      authorisation exists. If any report is readable by anyone holding the ID, that
      should be a decision rather than a surprise
- [ ] **Oversized upload** → rejected at the limit, no memory blowup
- [ ] **Decompression bomb** → blocked by the budget
- [ ] **Deeply nested archive** → depth limit holds
- [ ] **XXE** — an Office/APK manifest declaring a DTD or entities → refused
- [ ] **Long-running scan** → does not block other scans

---

## 18. Report and UX

- [ ] Verdict banner colour matches the verdict (green/amber/red/slate)
- [ ] Inconclusive renders **slate**, never green
- [ ] Score Composition adds up to the total, including reductions
- [ ] Every Score Composition bar also appears on the risk radar, and vice versa
- [ ] Reasons read for a non-expert — consequence, not API name
- [ ] Third-party resource chips distinguish flagged / checked / unchecked
- [ ] Archive panel appears even when nothing could be extracted
- [ ] Indicators are deduplicated
- [ ] Infrastructure graph renders, nodes clickable
- [ ] PDF export matches the on-screen report (fonts, colours, nothing clipped)
- [ ] PDF export of a report containing a screenshot → image embeds
- [ ] PDF export with `BROWSERLESS_WS_URL` unset → clean 501, not a crash
- [ ] Report renders at phone width
- [ ] Long filenames and long URLs do not break the layout
- [ ] Scan duration shown is real, not the debounced copy's
- [ ] A report with no findings still looks intentional, not broken

---

## 19. Other endpoints and pages

- [ ] `/report/{id}/json` returns valid JSON matching the on-screen report
- [ ] `/report/{id}` HTML view renders standalone
- [ ] `/report/{id}` for a non-existent ID → clean 404
- [ ] `/status/{id}` for a non-existent ID → clean 404
- [ ] **`/analysis` page** loads and does what it claims
- [ ] **`/settings` page** loads; a changed setting persists and takes effect
- [ ] Home page with no scans yet → sensible empty state
- [ ] Browser back/forward between pages → no stale state
- [ ] Refresh mid-scan → progress still tracked

---

## 20. Regression — bugs fixed on `coverage-gaps`

Each was a real, exploitable false-clean. Re-run after any refactor.

- [ ] APK renamed to `.zip` → still analysed
- [ ] APK inside a zip → still analysed
- [ ] Macro document renamed to `.zip` → macros still found
- [ ] APK / extension / plain zip → **not** reported as an Office document
- [ ] `.7z`, `.cab`, `.gz`, ISO → Inconclusive, not Clear
- [ ] Password-protected zip → Inconclusive, members named
- [ ] Quarantined/unreadable artifact → Inconclusive, antivirus mentioned
- [ ] Rate-limited VirusTotal → distinct from "still analysing"
- [ ] `.lnk` → parsed, not scanned as an opaque blob
- [ ] HTML smuggling → payload identified by decoded magic bytes
- [ ] `.crx` → manifest read, not just walked as a zip
- [ ] NFC alone → not scored; NFC + accessibility → scored
- [ ] Same URL scanned twice → same country vantage point
- [ ] A known-bad member inside an encrypted archive → still Malicious, not Inconclusive

---

## 21. Limits and performance

- [ ] Time a clean text file → seconds
- [ ] Time a URL scan → 15–45s expected (URLScan sandbox dominates)
- [ ] Time an unknown binary → slow first scan (VirusTotal upload + wait), fast after
- [ ] Two scans at once → both complete
- [ ] Five scans at once → all complete, no deadlock
- [ ] Track VirusTotal quota across a session — note what one scan really costs
- [ ] A 45 MB file → completes or fails cleanly at the limit
- [ ] An archive with 500 members → completes within the file-count budget
- [ ] Memory during a large archive scan → no runaway growth

---

## Appendix — where to get safe test material

**Never download real malware to a working machine.** Everything below is either an
industry-standard harmless test file or a reference list you read without visiting.

| Source | Use | Link |
|---|---|---|
| EICAR test file | The standard harmless "detect me" file. Your AV *will* grab it. | https://www.eicar.org/download-anti-malware-testfile/ |
| EICAR direct | Plain-text form, easiest to paste into other files | https://secure.eicar.org/eicar.com.txt |
| AMTSO malware download check | Verifies download-blocking behaviour | https://www.amtso.org/feature-settings-check-download-of-malware/ |
| AMTSO phishing page | Harmless page flagged industry-wide as phishing | https://www.amtso.org/feature-settings-check-phishing-page/ |
| AMTSO drive-by check | Drive-by download behaviour | https://www.amtso.org/feature-settings-check-drive-by-download/ |
| AMTSO index | The rest of the feature checks | https://www.amtso.org/security-features-check/ |
| Google Safe Browsing test pages | Known-flagged malware and phishing URLs | https://testsafebrowsing.appspot.com/ |
| URLhaus | Live malicious URL list — **copy the URL, do not visit** | https://urlhaus.abuse.ch/browse/ |
| MalwareBazaar | Real samples (zipped, password `infected`) — only in a VM | https://bazaar.abuse.ch/browse/ |

**Files you can make yourself in seconds**, and should, because they cover most of
this list: a `.txt` with links in it; a `.docm` with an empty macro; any `.exe`
renamed to `.jpg`; a zip of two text files; a zip inside a zip; a password-protected
zip (7-Zip → Add → set a password); a `.lnk` (right-click → New → Shortcut → target
`powershell -w hidden -c echo hi`); an APK pulled off your own phone; a `.crx`
exported from your own Chrome profile.

**Safe placeholder domains.** Use `.example`, `example.com`, `example.org` — RFC 2606
reserves them, so they can never resolve to anything real. Good for "bad link" tests
where you only care that the URL was *extracted*, not that it was rated.

---

## Recording what you find

For anything that fails, capture: the file or URL, the verdict + score you got, the
verdict you expected, and the top Score Composition line. The last one matters most —
it tells you whether the pipeline reached the right answer for the right reason.

Worth flagging separately, because they point at different problems:

- **False clean** — the dangerous one. Anything Clear that should not be.
- **False positive** — an ordinary file scoring. Erodes trust fastest.
- **Right verdict, wrong reason** — will break on the next similar file.
- **Crash or hang** — should be zero.
