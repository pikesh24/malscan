"""
tests/live/apk_base_rates.py

Measures how often each APK permission signal fires on apps that are
definitely not malicious.

Why this exists
---------------
The companion script `base_rates.py` measures this for infrastructure signals.
Every APK weight in `_check_apk_permissions` was set by judgement instead —
+35 for a critical permission, +15 for an elevated one, +15 for READ_SMS with
SEND_SMS, +25 for overlay with accessibility. None has been measured against
ordinary apps, so none is known to separate malware from anything.

The useful measure is discriminative power, roughly
`P(signal | malicious) / P(signal | benign)`. This measures the denominator.
A permission held by a large share of ordinary apps carries little information
however alarming it sounds, and a combination almost no ordinary app requests
is worth far more than its current weight suggests.

The immediate question it exists to answer: READ_SMS + SEND_SMS together
scores +15, which lands an SMS stealer at Clear. Google Play has restricted SMS
permissions to default handlers since 2019, so the pair should be rare — but
"should be" is exactly the reasoning this script replaces.

    python -m tests.live.apk_base_rates              # measure (downloads ~57MB)
    python -m tests.live.apk_base_rates --report     # re-print from cache
    python -m tests.live.apk_base_rates --limit 500  # short run

Deliberately NOT part of `pytest`: it makes a large network fetch. The
extracted permissions are cached so a re-run costs nothing.

Known bias, and it matters
--------------------------
F-Droid ships only free and open-source apps, which skew privacy-respecting
and permission-light compared with the commercial Play catalogue. So these
rates are an UNDERCOUNT of how common a permission is in the wild. That makes
them conservative in a useful direction: a signal firing often even here is
certainly too common to be worth much. A signal that is rare here is not
thereby proven rare on Play, and should not be weighted up on this evidence
alone.
"""

import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from attribution_module.scoring import (  # noqa: E402
    _CRITICAL_PERMISSIONS,
    _ELEVATED_PERMISSIONS,
    _check_apk_permissions,
)

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(HERE, "apk_base_rates_cache.json")
INDEX_URL = "https://f-droid.org/repo/index-v1.json"


def _load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def measure(limit=None):
    """Download the F-Droid index and cache each app's declared permissions.

    Only the permission list is kept — the index is ~57MB and everything else
    in it is irrelevant here.
    """
    print(f"fetching {INDEX_URL} (~57MB, one request)")
    request = urllib.request.Request(INDEX_URL, headers={"User-Agent": "malscan-base-rates"})
    with urllib.request.urlopen(request, timeout=180) as response:
        index = json.loads(response.read())

    packages = index.get("packages") or {}
    cache = {}
    for name, versions in packages.items():
        if not versions:
            continue
        # versions[0] is the current release; older ones would double-count an
        # app and let a long history outvote a short one.
        entry = versions[0]
        perms = [p[0] for p in (entry.get("uses-permission") or []) if p and p[0]]
        cache[name] = sorted(set(perms))
        if limit and len(cache) >= limit:
            break

    with open(CACHE_FILE, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=0, sort_keys=True)
    print(f"cached {len(cache)} apps -> {os.path.basename(CACHE_FILE)}")
    return cache


def report(cache=None, limit=None):
    cache = cache or _load_cache()
    if not cache:
        print("no measurements cached — run without --report first")
        return
    apps = sorted(cache)[:limit] if limit else sorted(cache)
    total = len(apps)

    perm_hits = {}      # permission -> count
    reason_hits = {}    # scoring reason -> count
    score_hist = {}     # score -> count
    scored_apps = []

    for name in apps:
        perms = cache[name]
        for p in perms:
            if p in _CRITICAL_PERMISSIONS or p in _ELEVATED_PERMISSIONS:
                perm_hits[p] = perm_hits.get(p, 0) + 1
        score, reasons = _check_apk_permissions({"is_apk": True, "dangerous_permissions": perms})
        score_hist[score] = score_hist.get(score, 0) + 1
        for r in reasons:
            reason_hits[r.split(" — ")[0]] = reason_hits.get(r.split(" — ")[0], 0) + 1
        if score:
            scored_apps.append((score, name))

    def pct(n):
        return f"{100.0 * n / total:5.2f}%"

    print(f"\n{total} benign apps (F-Droid current releases)\n")

    print("Permissions Malscan scores, by share of benign apps holding them:")
    for perm, n in sorted(perm_hits.items(), key=lambda kv: -kv[1]):
        tier = "critical +35" if perm in _CRITICAL_PERMISSIONS else "elevated +15"
        print(f"  {pct(n)} {n:5}  {perm.rsplit('.', 1)[-1]:28} {tier}")
    if not perm_hits:
        print("  (none)")

    print("\nScoring reasons fired, by share of benign apps:")
    for reason, n in sorted(reason_hits.items(), key=lambda kv: -kv[1]):
        print(f"  {pct(n)} {n:5}  {reason[:74]}")
    if not reason_hits:
        print("  (none)")

    print("\nWhat Malscan would score these benign apps:")
    for score in sorted(score_hist):
        band = "Malicious" if score >= 70 else "Suspicious" if score >= 35 else "Clear"
        print(f"  {pct(score_hist[score])} {score_hist[score]:5}  {score:3} points  ({band})")

    flagged = [(s, n) for s, n in scored_apps if s >= 35]
    print(f"\n{len(flagged)} benign apps ({pct(len(flagged)).strip()}) would be Suspicious or worse:")
    for score, name in sorted(flagged, reverse=True)[:15]:
        print(f"  {score:3}  {name}")

    # The question this script was written for.
    both = [n for n in apps
            if "android.permission.READ_SMS" in cache[n]
            and "android.permission.SEND_SMS" in cache[n]]
    read_only = [n for n in apps if "android.permission.READ_SMS" in cache[n]]
    print(f"\nREAD_SMS + SEND_SMS together: {pct(len(both)).strip()} ({len(both)}/{total})")
    print(f"READ_SMS at all:              {pct(len(read_only)).strip()} ({len(read_only)}/{total})")
    print("Currently scored +15, which leaves an SMS stealer at Clear.")
    for n in both[:10]:
        print(f"  {n}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="re-print from cache, no network")
    parser.add_argument("--limit", type=int, help="only consider the first N apps")
    args = parser.parse_args()
    report(limit=args.limit) if args.report else report(measure(args.limit), limit=args.limit)
