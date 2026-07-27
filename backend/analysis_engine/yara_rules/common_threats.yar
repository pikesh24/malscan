/*
  MalScan YARA Ruleset — common_threats.yar
  Covers: EICAR, PowerShell obfuscation, document exploits,
          PE packers, RATs, banking trojans, Indian threat context.

  FILE-TYPE GATING
  ----------------
  Every rule below states which container it applies to. Without that, rules
  written for one format match another's ordinary contents: scanning Paytm's
  APK fired PDF_JavaScript_Exploit (the app bundles WebViews, so "/JavaScript"
  and "unescape" appear) and PowerShell_DownloadCradle (nocase matches on
  "downloadFile", "WebClient", "iEX(" — routine Java method and class names).
  Two critical rules, +40 each, on a payments app used by hundreds of millions.

  A rule that does not say what it applies to will eventually match everything.
*/

private rule IsPDF  { condition: uint32be(0) == 0x25504446 }               // %PDF
private rule IsZIP  { condition: uint32be(0) == 0x504B0304 }               // PK\x03\x04 — APK/JAR/OOXML
private rule IsPE   { condition: uint16(0)   == 0x5A4D }                   // MZ
private rule IsOLE  { condition: uint32be(0) == 0xD0CF11E0 }               // legacy .doc/.xls

// Scripts and plain text: anything that is not one of the binary containers
// above. PowerShell, batch and JavaScript droppers live here.
private rule IsScriptOrText { condition: not IsPDF and not IsZIP and not IsPE and not IsOLE }

// ── EICAR Test File ───────────────────────────────────────────────────────────

rule EICAR_Test_File {
    meta:
        description = "EICAR standard antivirus test file"
        severity    = "informational"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

// ── PowerShell Obfuscation ────────────────────────────────────────────────────

rule PowerShell_EncodedCommand {
    meta:
        description = "PowerShell -EncodedCommand or -enc flag — commonly used to hide malicious scripts"
        severity    = "high"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = " -enc " nocase
        $enc3 = " -e " nocase
        $b64  = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        IsScriptOrText and (($enc1 or $enc2 or $enc3) and $b64)
}

rule PowerShell_DownloadCradle {
    meta:
        description = "PowerShell download-and-execute cradle — malware delivery technique"
        severity    = "critical"
    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "WebClient" nocase
        $dl4 = "Invoke-Expression" nocase
        $dl5 = "IEX(" nocase
        $dl6 = "Net.WebClient" nocase
    condition:
        IsScriptOrText and (2 of ($dl*))
}

rule PowerShell_AMSI_Bypass {
    meta:
        description = "Attempt to disable AMSI (Windows antimalware interface)"
        severity    = "critical"
    strings:
        $amsi1 = "amsiInitFailed" nocase
        $amsi2 = "AmsiScanBuffer" nocase
        $amsi3 = "[Ref].Assembly.GetType" nocase
        $amsi4 = "System.Management.Automation.AmsiUtils" nocase
    condition:
        IsScriptOrText and (any of ($amsi*))
}

// ── Executable in Document ────────────────────────────────────────────────────

rule PE_In_Document {
    meta:
        description = "Windows executable (MZ/PE header) embedded inside a document or archive"
        severity    = "high"
    strings:
        $mz   = { 4D 5A }
        $pe   = { 50 45 00 00 }
        $pdf  = "%PDF"
        $ole  = { D0 CF 11 E0 }
    condition:
        // Was: ($mz at 0) and $pe and not ($pdf at 0) and not ($zip at 0).
        // "$mz at 0" means the file STARTS with MZ — that is a plain executable,
        // not a document with one hidden inside, so this matched every .exe and
        // .dll on the system. Measured at 123/370 benign files, including all
        // 120 sampled Windows System32 binaries.
        //
        // The container must be the document, and the PE must be inside it.
        // ZIP is deliberately excluded: an archive containing an .exe is how
        // ordinary software ships, and archive contents are extracted and
        // scanned separately anyway.
        (($pdf at 0) or ($ole at 0)) and $mz and $pe
}

rule Base64_Encoded_PE {
    meta:
        description = "Base64-encoded Windows executable — common obfuscation for malware dropper"
        severity    = "high"
    strings:
        // Base64 is case-SENSITIVE, so `nocase` was wrong: it let "tVo" match,
        // and a three-character string occurs constantly in ordinary binary
        // data. Measured on 11/370 benign files, all Microsoft-signed.
        // Only the long, specific PE-header encodings are kept.
        $b64_mz1 = "TVqQAAMAAAA"
        $b64_mz2 = "TVpAAAMAAAA"
        $b64_mz3 = "TVoAAAAAAAA"
    condition:
        any of ($b64_mz*)
}

// ── Document Exploits ─────────────────────────────────────────────────────────

rule PDF_JavaScript_Exploit {
    meta:
        description = "PDF with JavaScript that uses known exploit patterns"
        severity    = "critical"
    strings:
        $js1 = "/JavaScript"
        $js2 = "/JS "
        $ev1 = "eval("   nocase
        $ev2 = "unescape" nocase
        $ev3 = "String.fromCharCode" nocase
    condition:
        IsPDF and (($js1 or $js2) and any of ($ev*))
}

rule PDF_AutoAction {
    meta:
        description = "PDF with automatic action that triggers without user interaction"
        // Downgraded from "high": /OpenAction is present in a large share of
        // ordinary PDFs (usually just "open at page 1"), and this matched a
        // normal specification document in the benign sample.
        //
        // _check_document_threats already scores this properly — +10 alone, +45
        // only when JavaScript is wired to the auto-trigger. At "high" the rule
        // both double-counted it at +25 and, because YARA scores into
        // intel_total, switched off the benign-VirusTotal-consensus dampener
        // that exists to stop exactly this false positive. Reports, not scores.
        severity    = "medium"
    strings:
        $aa1 = "/OpenAction"
        $aa2 = "/AA "
        $aa3 = "/Launch"
    condition:
        IsPDF and (any of ($aa*))
}

rule Office_AutoOpen_Macro {
    meta:
        description = "Office document with auto-executing macro (AutoOpen/Document_Open)"
        severity    = "critical"
    strings:
        $auto1 = "AutoOpen"        nocase
        $auto2 = "Document_Open"   nocase
        $auto3 = "Workbook_Open"   nocase
        $auto4 = "Auto_Open"       nocase
        $shell = "Shell("          nocase
        $wscr  = "WScript"         nocase
        $cobj  = "CreateObject"    nocase
    condition:
        (IsZIP or IsOLE) and (any of ($auto*) and any of ($shell, $wscr, $cobj))
}

rule Office_DDE_Exploit {
    meta:
        description = "Office DDE field injection — executes commands without macros"
        severity    = "critical"
    strings:
        $dde1 = "DDEAUTO" nocase
        $dde2 = "DDE("    nocase
        $cmd  = "cmd"     nocase
        $ps   = "powershell" nocase
    condition:
        (IsZIP or IsOLE) and (($dde1 or $dde2) and ($cmd or $ps))
}

// ── Suspicious Network Activity ───────────────────────────────────────────────

rule Hardcoded_TOR_Onion {
    meta:
        description = "Contains a .onion address — Tor hidden service reference"
        // Downgraded from "high": using Tor is a privacy feature, not an act of
        // malice. This matched F-Droid's own official .onion repository mirror,
        // and the same is true of Tor Browser, OnionShare, SecureDrop and
        // Brave. Worth showing an analyst, not worth points on its own — the
        // original description asserted "C2 communication", which the presence
        // of an address does not establish.
        severity    = "medium"
    strings:
        $onion = /[a-z2-7]{16,56}\.onion/ nocase
    condition:
        $onion
}

rule Suspicious_IP_C2 {
    meta:
        description = "Many hardcoded IP-address literals"
        // Renamed from "potential C2 infrastructure". The regex matches any
        // dotted quad, including 127.0.0.1, 10.x and 0.0.0.0 — it fired on
        // F-Droid because the app contains localhost. Calling localhost "C2
        // infrastructure" in a user-facing report is simply wrong, and the
        // report text is part of the product.
        //
        // Routability is already decided properly in Python by
        // is_reportable_ip(), which rejects private, loopback, reserved and
        // multicast ranges. YARA's regex engine has no lookahead, so expressing
        // the same exclusion here is not worth the complexity; this stays a
        // report-only observation at "medium" (zero points).
        severity    = "medium"
    strings:
        // YARA's regex engine has no non-capturing groups — "(?:" is a syntax
        // error, and a syntax error anywhere takes the whole rule file down
        // with it. A plain capturing group behaves identically here.
        $ip = /\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/
    condition:
        #ip > 10
}

// ── RAT / Remote Access Trojans ───────────────────────────────────────────────

rule Generic_RAT_Strings {
    meta:
        description = "Generic remote access trojan capability strings"
        severity    = "high"
    strings:
        $screen  = "screenshot"      nocase
        $keylog  = "keylogger"       nocase
        $webcam  = "webcam"          nocase
        $rdp     = "RemoteDesktop"   nocase
        $upload  = "upload_file"     nocase
        $dload   = "download_file"   nocase
        $reverse = "reverse_shell"   nocase
        $cmd     = "execute_command" nocase
    condition:
        (IsPE or IsScriptOrText) and (3 of them)
}

rule Njrat_Indicators {
    meta:
        description = "njRAT / Bladabindi — common in targeted attacks against Indian organisations"
        severity    = "critical"
    strings:
        $str1 = "njrat"        nocase
        $str2 = "Bladabindi"   nocase
        $str3 = "HvncPlugin"   nocase
        $str4 = "Microsoft\\Windows NT\\CurrentVersion\\Run" nocase
        $reg  = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        (IsPE or IsScriptOrText) and (any of ($str*) or ($reg and 1 of ($str*)))
}

rule AsyncRAT_Indicators {
    meta:
        description = "AsyncRAT — remote access trojan delivered via phishing documents"
        severity    = "critical"
    strings:
        $s1 = "AsyncRAT"      nocase
        $s2 = "HRZN"          nocase
        $s3 = "AES_decrypt"   nocase
        $s4 = "GetInstallPath" nocase
    condition:
        (IsPE or IsScriptOrText) and (2 of them)
}

// ── Banking Trojans (India-specific context) ──────────────────────────────────

rule Drinik_Banking_Trojan {
    meta:
        description = "Drinik Android banking trojan — targets Indian bank customers"
        severity    = "critical"
    strings:
        $str1 = "iAssist"          nocase
        $str2 = "drinikapk"        nocase
        $str3 = "incometax.gov"    nocase
    condition:
        // "iAssist" alone matched Microsoft's ShellAppRuntime.exe — it occurs
        // inside ordinary identifiers such as "UIAssistant". A 7-character
        // nocase substring is not an identification, so it now needs the
        // accessibility-service indicator alongside it. "drinikapk" is specific
        // enough to stand on its own.
        // Fired on Paytm via ($str3 and $acc): the app pays income tax, so it
        // contains "incometax.gov", and "AccessibilityService" is a standard
        // Android API name present in essentially every large app — an SDK
        // reference, not an intent. $sbi is three characters and matches inside
        // arbitrary words. None of those identify a family.
        //
        // What is left actually names Drinik: its package string, or its app
        // name together with the tax portal it impersonates.
        IsZIP and ($str2 or ($str1 and $str3))
}

rule FakeCalls_Banking_App {
    meta:
        description = "FakeCalls Android malware — impersonates bank customer care in India"
        severity    = "critical"
    strings:
        $hana  = "hanaBankServiceCode" nocase
        $call  = "FakeCall"            nocase
        $bank  = "bankCallService"     nocase
    condition:
        // $icici was declared and never referenced, which YARA treats as a
        // compile ERROR — it took the whole rule file down with it, so all 21
        // rules silently failed to load and no YARA scan ever ran.
        // Referencing two different banks is the signal: an app naming several
        // banks is impersonating customer care, whereas an app naming one is
        // usually that bank's own app.
        // The bank-name branch is gone. Paytm matched all three — "hdfcbank",
        // "icicibank", "axisbank" — because a payments app lists every bank it
        // supports for account linking. So does every UPI app, and so does each
        // bank's own app. A list of bank names is what legitimate financial
        // software looks like; it says nothing about impersonation.
        //
        // (This branch was mine: fixing an unreferenced-string compile error I
        // widened "$hdfc and $axis" to "2 of three". The original would have
        // flagged Paytm too — I made a bad condition slightly worse.)
        //
        // The FakeCalls-specific service strings remain, and those do identify
        // the family.
        IsZIP and ($hana or $call or $bank)
}

rule Generic_Banking_Overlay {
    meta:
        description = "Generic banking overlay trojan indicators"
        severity    = "high"
    strings:
        $overlay1 = "android.permission.BIND_ACCESSIBILITY_SERVICE" nocase
        $overlay2 = "android.permission.SYSTEM_ALERT_WINDOW" nocase
        $overlay3 = "TYPE_ACCESSIBILITY_OVERLAY" nocase
        $bank1    = "netbanking"  nocase
        $bank2    = "mobilebank"  nocase
        $bank3    = "UPI"
        $bank4    = "BHIM"
    condition:
        IsZIP and (($overlay1 and $overlay3) or ($overlay2 and ($bank1 or $bank2 or $bank3 or $bank4)))
}

// ── Ransomware Indicators ─────────────────────────────────────────────────────

rule Generic_Ransomware_Note {
    meta:
        description = "Ransomware payment note string patterns"
        severity    = "critical"
    strings:
        // Phrases that essentially never occur outside a ransom note.
        $note1 = "your files have been encrypted" nocase
        $note2 = "pay to recover"                  nocase
        $note4 = "decrypt your files"              nocase
        $note8 = "all your files have been"        nocase
        $note9 = "to restore your files"           nocase
    condition:
        // Was `2 of them` over a list that also held "bitcoin", "ransom",
        // "HOW TO RESTORE" and "ALL YOUR FILES". F-Droid — an open-source app
        // store — matched "bitcoin" (apps list it as a donation method) and
        // "how to restore" (a backup feature) and was scored CRITICAL, worth
        // +40, on that basis alone.
        //
        // A word like "bitcoin" or "ransom" describes a topic, not an act: it
        // appears in wallets, news readers and security tools. Only the full
        // extortion phrasing is evidence, so the weak keywords are gone rather
        // than merely outvoted.
        any of them
}

rule File_Encryption_API {
    meta:
        description = "Crypto APIs combined with mass file enumeration — ransomware shape"
        // Downgraded from "high": encrypting and deleting files is what backup
        // tools, password managers and installers do. Matched Microsoft's
        // wlidsvc.dll (the Windows credential service) on CryptEncrypt +
        // DeleteFile. Capability is not intent, so this reports rather than
        // scores, and only fires when file ENUMERATION is present too — walking
        // every directory to encrypt what it finds is the ransomware-specific
        // part, not the crypto call.
        severity    = "medium"
    strings:
        $enc1 = "CryptEncrypt"     nocase
        $enc2 = "BCryptEncrypt"    nocase
        $enc3 = "AES_set_encrypt_key" nocase
        $del1 = "DeleteFile"       nocase
        $del2 = "SHFileOperation"  nocase
        $walk1 = "FindFirstFile"   nocase
        $walk2 = "FindNextFile"    nocase
    condition:
        IsPE and (any of ($enc*) and any of ($del*) and all of ($walk*))
}

// ── Packer / Obfuscation Indicators ──────────────────────────────────────────

rule Suspicious_Section_Names {
    meta:
        description = "PE with known packer or protector section names"
        severity    = "medium"
    strings:
        $upx0  = "UPX0"
        $upx1  = "UPX1"
        $mpress = ".MPRESS"
        $aspack = "ASPACK"
        $petite = ".petite"
        $fsg    = ".FSG"
    condition:
        IsPE and (any of them)
}
