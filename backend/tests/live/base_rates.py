"""
tests/live/base_rates.py

Measures how often each infrastructure signal fires on domains that are
definitely not malicious.

Why this exists
---------------
`calculate_score` weights signals by how alarming they sound rather than by how
well they separate malicious from harmless. Namecheap registers millions of
legitimate domains and scores +15. OVH hosts a large share of Europe's web and
scores +20. Every legitimate business is under a week old on its first day and
scores +40. The corpus proved these produce false positives; it cannot tell us
what the weights should be instead.

The useful measure is discriminative power — roughly
`P(signal | malicious) / P(signal | benign)`. This script measures the
denominator. A signal firing on a large share of the Tranco top 10,000 carries
little information no matter how sinister it sounds.

    python -m tests.live.base_rates              # measure (slow, hits network)
    python -m tests.live.base_rates --report     # re-print from cache
    python -m tests.live.base_rates --limit 50   # short run

Deliberately NOT part of `pytest`. It makes hundreds of live WHOIS and GeoIP
calls, and ip-api.com's free tier allows 45 requests/minute — results are cached
to JSON so a re-run costs nothing.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from analysis_engine.osint_enricher import get_geoip, get_whois  # noqa: E402
from attribution_module.scoring import (  # noqa: E402
    _check_domain_age,
    _check_geoip,
    _check_registrar,
    _parse_age_days,
)

HERE = os.path.dirname(os.path.abspath(__file__))
DOMAINS_FILE = os.path.join(HERE, "benign_domains.txt")
CACHE_FILE = os.path.join(HERE, "base_rates_cache.json")

# ip-api.com free tier: 45 requests/minute. Stay under it or lookups start
# failing silently and the measurement quietly becomes wrong.
GEOIP_INTERVAL = 60.0 / 40


def load_domains(limit=None):
    domains = []
    with open(DOMAINS_FILE, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rank, _, domain = line.partition(",")
            domains.append((int(rank), domain))
    return domains[:limit] if limit else domains


def _load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def measure(limit=None):
    """Enrich each domain and record which scoring checks fire. Resumable."""
    cache = _load_cache()
    domains = load_domains(limit)
    todo = [(r, d) for r, d in domains if d not in cache]
    print(f"{len(domains)} domains, {len(cache)} already cached, {len(todo)} to fetch")

    last_geoip = 0.0
    for i, (rank, domain) in enumerate(todo, 1):
        entry = {"rank": rank}
        try:
            whois = get_whois(domain) or {}
            entry["registrar"] = whois.get("registrar")
            entry["age_days"] = _parse_age_days(whois.get("creation_date"))
        except Exception as exc:
            entry["whois_error"] = str(exc)[:120]

        try:
            import socket
            ip = socket.gethostbyname(domain)
            entry["ip"] = ip
            wait = GEOIP_INTERVAL - (time.time() - last_geoip)
            if wait > 0:
                time.sleep(wait)
            geo = get_geoip(ip) or {}
            last_geoip = time.time()
            entry["country"] = geo.get("countryCode")
            entry["asn"] = geo.get("asn")
            entry["isp"] = geo.get("isp")
        except Exception as exc:
            entry["geoip_error"] = str(exc)[:120]

        cache[domain] = entry
        if i % 10 == 0 or i == len(todo):
            with open(CACHE_FILE, "w", encoding="utf-8") as fh:
                json.dump(cache, fh, indent=1, sort_keys=True)
            print(f"  {i}/{len(todo)}  {domain}")

    with open(CACHE_FILE, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=1, sort_keys=True)
    return cache


def report(cache=None, limit=None):
    cache = cache or _load_cache()
    domains = [d for _, d in load_domains(limit) if d in cache]
    if not domains:
        print("no measurements cached — run without --report first")
        return

    tally = {}          # signal -> [count, points, [examples]]
    scored = 0
    have_whois = have_geoip = 0

    def hit(name, points, example):
        slot = tally.setdefault(name, [0, 0, []])
        slot[0] += 1
        slot[1] += points
        if len(slot[2]) < 4:
            slot[2].append(example)

    for domain in domains:
        e = cache[domain]
        whois = {"registrar": e.get("registrar"), "creation_date": None}
        geoip = {"countryCode": e.get("country"), "asn": e.get("asn"), "isp": e.get("isp")}

        # Count whether a check MATCHED, not whether it scored. Keying off points
        # meant that zeroing a weight made the signal vanish from this table —
        # the harness stopped measuring the very check that had just been changed,
        # and a future re-weight would have looked like the problem disappearing.
        total = 0
        if e.get("registrar"):
            have_whois += 1
            s, reasons = _check_registrar(whois)
            if reasons:
                hit("Registrar Reputation", s, f"{domain} ({e['registrar'][:34]})")
            total += s
        if e.get("age_days") is not None:
            s, reasons, _ = _check_domain_age({"creation_date": None})
            if e["age_days"] <= 90:
                hit("Domain Age Risk", 0, f"{domain} ({e['age_days']}d)")

        if e.get("country") or e.get("asn"):
            have_geoip += 1
            s, reasons = _check_geoip(geoip)
            for r in reasons:
                label = "Country Risk" if "country" in r else "ASN / Hosting Risk"
                hit(label, 0, f"{domain} ({e.get('asn') or e.get('country')})")
            total += s
        if total:
            scored += 1

    n = len(domains)
    print()
    print(f"Benign base rates — {n} domains from the Tranco top 10,000")
    print(f"  WHOIS resolved for {have_whois}/{n}, GeoIP for {have_geoip}/{n}")
    print()
    print(f"{'signal':<24} {'fires on':>9} {'rate':>8}   examples")
    print("-" * 92)
    for name, (count, _pts, examples) in sorted(tally.items(), key=lambda kv: -kv[1][0]):
        print(f"{name:<24} {count:>4}/{n:<4} {100.0*count/n:>7.1f}%   {', '.join(examples)}")

    print("-" * 92)
    print(f"{'ANY signal fires':<24} {scored:>4}/{n:<4} {100.0*scored/n:>7.1f}%")
    print()
    print("Read this as: a signal firing on a large share of these domains cannot")
    print("distinguish malicious from harmless, whatever its current weight.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="benign base-rate measurement")
    ap.add_argument("--report", action="store_true", help="print from cache without fetching")
    ap.add_argument("--limit", type=int, help="only the first N domains")
    args = ap.parse_args(argv)

    cache = None if args.report else measure(args.limit)
    report(cache, args.limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
