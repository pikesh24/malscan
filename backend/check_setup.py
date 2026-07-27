"""
backend/check_setup.py

Preflight check. Run it after cloning or pulling and it tells you exactly what
is missing, instead of leaving you to work it out from a stack trace.

    python check_setup.py

Written because most of what MALSCAN does degrades *silently* when a dependency
or data file is absent: YARA scanning, RAR extraction and PDF export all fall
back quietly by design, so a half-installed environment looks like a working one
that simply never detects anything. This makes that visible.

Nothing here touches the network except the optional API-key checks, and those
only read whether a key is present — never what it is.
"""

import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

OK, WARN, FAIL = "  [ok]  ", "  [warn]", "  [FAIL]"
_problems, _warnings = [], []


def _report(status, label, detail=""):
    print(f"{status} {label}" + (f" — {detail}" if detail else ""))
    if status == FAIL:
        _problems.append(label)
    elif status == WARN:
        _warnings.append(label)


def check_python():
    v = sys.version_info
    if v < (3, 9):
        _report(FAIL, f"Python {v.major}.{v.minor}", "3.9+ required")
    else:
        _report(OK, f"Python {v.major}.{v.minor}.{v.micro}")


REQUIRED = [
    ("fastapi", "API framework"),
    ("uvicorn", "ASGI server"),
    ("sqlalchemy", "database"),
    ("requests", "HTTP client"),
    ("jinja2", "report templating"),
    ("markupsafe", "report escaping"),
    ("dotenv", "reads backend/.env"),
    ("whois", "WHOIS enrichment"),
    ("dns", "DNS enrichment"),
    ("defusedxml", "hardens APK manifest parsing"),
    ("pefile", "PE analysis"),
    ("multipart", "file uploads"),
]

OPTIONAL = [
    ("yara", "YARA scanning — 21 rules. WITHOUT IT ALL YARA DETECTION IS OFF",
     "pip install yara-python"),
    ("rarfile", "scanning inside .rar archives", "pip install rarfile"),
    ("playwright", "PDF export of reports", "pip install playwright && playwright install chromium"),
    ("pytest", "running the test suite", "pip install -r requirements-dev.txt"),
]


def check_imports():
    print("\nRequired packages")
    for mod, why in REQUIRED:
        try:
            importlib.import_module(mod)
            _report(OK, mod, why)
        except ImportError:
            _report(FAIL, mod, f"{why} — pip install -r requirements.txt")

    print("\nOptional packages (features degrade silently without these)")
    for mod, why, how in OPTIONAL:
        try:
            importlib.import_module(mod)
            _report(OK, mod, why)
        except ImportError:
            _report(WARN, mod, f"{why} — {how}")


def check_data_files():
    """Committed data the engine reads at runtime."""
    print("\nData files")
    for rel, why in [
        ("analysis_engine/yara_rules/common_threats.yar", "YARA rules"),
        ("analysis_engine/data/public_suffix_list.dat", "registrable-domain (eTLD+1) computation"),
        ("analysis_engine/data/reputable_domains.txt", "reputation prior — suppresses typosquat false positives"),
    ]:
        path = os.path.join(HERE, rel)
        if os.path.exists(path):
            kb = os.path.getsize(path) / 1024
            _report(OK, rel, f"{why} ({kb:.0f} KB)")
        else:
            _report(FAIL, rel, f"missing — {why}")


def check_yara_rules():
    """A rule file that does not compile disables every rule, and used to be
    indistinguishable from yara-python simply not being installed."""
    print("\nYARA ruleset")
    try:
        import yara  # noqa: F401
    except ImportError:
        _report(WARN, "rules not verified", "yara-python not installed, so no rule ever runs")
        return
    sys.path.insert(0, HERE)
    from analysis_engine.yara_scanner import scan_file

    result = scan_file(__file__)
    if result.get("yara_available"):
        import yara as _y
        compiled = _y.compile(filepath=os.path.join(
            HERE, "analysis_engine", "yara_rules", "common_threats.yar"))
        # IsPDF/IsZIP/... are private file-type gates, not detections.
        n = sum(1 for r in compiled if not getattr(r, "is_private", False))
        _report(OK, "rules compile and load", f"{n} detection rules active")
    else:
        _report(FAIL, "rules failed to load", str(result.get("yara_error"))[:120])


ENV_KEYS = [
    ("VT_API_KEY", "VirusTotal — the heaviest signal (up to +100) and the benign-consensus dampener"),
    ("URLSCAN_API_KEY", "URLScan sandbox verdict + screenshot"),
    ("ABUSECH_AUTH_KEY", "URLhaus / ThreatFox / MalwareBazaar — abuse.ch now REQUIRES this"),
    ("ABUSEIPDB_API_KEY", "IP abuse history (optional)"),
]


def check_env():
    print("\nEnvironment (backend/.env)")
    env_path = os.path.join(HERE, ".env")
    if not os.path.exists(env_path):
        _report(WARN, ".env missing",
                "get it from the team — scans still run, but with no threat intel")
    else:
        _report(OK, ".env present")

    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
    except ImportError:
        return

    for key, why in ENV_KEYS:
        if os.environ.get(key, "").strip():
            _report(OK, key, why)
        else:
            _report(WARN, f"{key} not set", why)


def check_writable():
    print("\nWritable paths")
    for rel in ("vault", "reports"):
        path = os.path.join(HERE, rel)
        try:
            os.makedirs(path, exist_ok=True)
            probe = os.path.join(path, ".write-probe")
            with open(probe, "w") as fh:
                fh.write("x")
            os.unlink(probe)
            _report(OK, f"{rel}/", "writable")
        except OSError as exc:
            _report(FAIL, f"{rel}/", f"not writable — {exc}")


def main():
    print("MALSCAN preflight\n" + "=" * 60)
    check_python()
    check_imports()
    check_data_files()
    check_yara_rules()
    check_env()
    check_writable()

    print("\n" + "=" * 60)
    if _problems:
        print(f"{len(_problems)} problem(s) must be fixed before the backend will work correctly:")
        for p in _problems:
            print(f"   - {p}")
    if _warnings:
        print(f"\n{len(_warnings)} warning(s) — the app runs, but these features are OFF:")
        for w in _warnings:
            print(f"   - {w}")
    if not _problems and not _warnings:
        print("Everything is set up correctly.")
    elif not _problems:
        print("\nNo blocking problems.")
    return 1 if _problems else 0


if __name__ == "__main__":
    sys.exit(main())
