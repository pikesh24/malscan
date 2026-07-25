"""
tests/live/yara_false_positives.py

Measures which YARA rules fire on files that are definitely not malware.

Why this exists
---------------
The 21 rules in yara_rules/common_threats.yar have never executed in a test.
`yara-python` is optional and was uninstalled, so the whole subsystem was
dormant — in development and, since render.yaml installs only the requirements
files, in production too. That hides a rule like

    rule PDF_AutoAction { strings: $aa1 = "/OpenAction" ... severity = "high" }

which matches a large share of perfectly ordinary PDFs. A "high" match is worth
+25 and lands in `intel_total`, and the benign-VirusTotal-consensus dampener
only applies when `intel_total == 0` — so a weak YARA hit silently switches off
the protection added specifically to stop ordinary form PDFs being flagged.

The same reasoning as tests/live/base_rates.py: a rule that fires on files
nobody would call malicious cannot carry the weight its severity claims.

    python -m tests.live.yara_false_positives
    python -m tests.live.yara_false_positives --limit 200

Benign corpus, gathered from the machine rather than committed (these are large
and OS-specific):
  - Windows\\System32 binaries — Microsoft-signed, the closest thing to hand to
    a NIST NSRL "known good" set
  - the repo's own node_modules JavaScript
  - installed Python packages
  - PDFs found under the user profile, if any

Deliberately outside `pytest`: it reads thousands of files off disk.
"""

import argparse
import glob
import os
import random
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from analysis_engine.yara_scanner import scan_file  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Severity -> what _check_yara pays for it, so the report can show the cost of
# each false positive rather than just its name.
SEVERITY_POINTS = {"critical": 40, "high": 25, "medium": 0, "informational": 0}


def collect_benign(limit_per_source=120):
    """Files no reasonable person would call malware."""
    buckets = {}

    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    sys32 = os.path.join(sysroot, "System32")
    if os.path.isdir(sys32):
        pe = glob.glob(os.path.join(sys32, "*.dll")) + glob.glob(os.path.join(sys32, "*.exe"))
        buckets["windows-system-binaries"] = pe

    node_modules = os.path.join(REPO, "frontend", "node_modules")
    if os.path.isdir(node_modules):
        js = []
        for root, dirs, files in os.walk(node_modules):
            dirs[:] = dirs[:6]          # keep the walk bounded
            js += [os.path.join(root, f) for f in files if f.endswith(".js")]
            if len(js) > 4000:
                break
        buckets["npm-javascript"] = js

    try:
        import site
        pkgs = []
        for d in site.getsitepackages():
            if os.path.isdir(d):
                for root, dirs, files in os.walk(d):
                    dirs[:] = dirs[:6]
                    pkgs += [os.path.join(root, f) for f in files if f.endswith((".py", ".pyd"))]
                    if len(pkgs) > 4000:
                        break
        buckets["python-packages"] = pkgs
    except Exception:
        pass

    # Android packages. Their absence was a blind spot with real consequences:
    # the first measurement covered Windows binaries, npm JavaScript, Python
    # packages and PDFs, reported 0% after the rule fixes, and a legitimate
    # open-source app store then scored 75/Malicious. An APK is a large ZIP full
    # of translations, resource strings and repo metadata — a string profile
    # nothing else in the corpus resembles — and it is the P0 artifact type.
    # Point MALSCAN_APK_DIR at a folder of legitimate APKs to include them.
    apks = []
    apk_dir = os.environ.get("MALSCAN_APK_DIR")
    for base in filter(None, [apk_dir, os.path.expanduser("~/Downloads")]):
        if os.path.isdir(base):
            apks += glob.glob(os.path.join(base, "*.apk"))
    if apks:
        buckets["android-apks"] = apks

    docs = []
    for base in (os.path.expanduser("~/Documents"), os.path.expanduser("~/Downloads"), REPO):
        if os.path.isdir(base):
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs[:8] if d != "node_modules"]
                docs += [os.path.join(root, f) for f in files if f.lower().endswith((".pdf", ".docx", ".xlsx"))]
                if len(docs) > 400:
                    break
    if docs:
        buckets["documents"] = docs

    rng = random.Random(20260725)   # pinned so re-runs scan the same files
    return {
        name: rng.sample(paths, min(limit_per_source, len(paths)))
        for name, paths in buckets.items() if paths
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="YARA false-positive measurement")
    ap.add_argument("--limit", type=int, default=120, help="files per source (default 120)")
    args = ap.parse_args(argv)

    probe = scan_file(__file__)
    if not probe.get("yara_available"):
        print("yara-python is not installed — nothing to measure.")
        print("  pip install yara-python")
        return 1

    buckets = collect_benign(args.limit)
    if not buckets:
        print("found no benign files to scan")
        return 1

    fired = defaultdict(Counter)      # rule -> Counter(source)
    severity_of = {}
    examples = defaultdict(list)
    scanned = Counter()
    scored_files = Counter()

    for source, paths in buckets.items():
        print(f"scanning {len(paths):>4} files from {source} ...")
        for path in paths:
            try:
                if os.path.getsize(path) > 40 * 1024 * 1024:
                    continue
            except OSError:
                continue
            res = scan_file(path)
            scanned[source] += 1
            cost = 0
            for m in res.get("yara_matches") or []:
                rule = m["rule"]
                fired[rule][source] += 1
                severity_of[rule] = m.get("severity", "medium")
                if len(examples[rule]) < 3:
                    examples[rule].append(os.path.basename(path))
                cost += SEVERITY_POINTS.get(m.get("severity", "medium"), 0)
            if cost:
                scored_files[source] += 1

    total = sum(scanned.values())
    print()
    print(f"YARA false positives — {total} known-benign files")
    for source, n in scanned.items():
        hit = scored_files[source]
        print(f"   {source:<26} {n:>4} scanned, {hit:>4} would gain points ({100.0*hit/n:.1f}%)")

    print()
    print(f"{'rule':<28} {'severity':<14} {'pts':>4} {'files':>6}  examples")
    print("-" * 96)
    if not fired:
        print("(no rule matched any benign file)")
    for rule, counts in sorted(fired.items(), key=lambda kv: -sum(kv[1].values())):
        sev = severity_of.get(rule, "medium")
        pts = SEVERITY_POINTS.get(sev, 0)
        n = sum(counts.values())
        flag = "  <-- SCORES" if pts else ""
        print(f"{rule:<28} {sev:<14} {pts:>4} {n:>6}  {', '.join(examples[rule])}{flag}")

    print("-" * 96)
    print("A rule matching files like these cannot carry the weight its severity claims.")
    print("Rules marked SCORES add points today; 'medium' and 'informational' do not.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
