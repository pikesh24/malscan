"""
analysis_engine/public_suffix.py

Works out the registrable domain (eTLD+1) — the part of a hostname someone
actually had to register and therefore controls.

Why this is not "the last two labels"
-------------------------------------
`github.io`, `web.app`, `pages.dev`, `workers.dev`, `blogspot.com` and hundreds
more are *public suffixes*: anyone can take a subdomain under them. Treating
`evil.github.io` as "github.io" would hand an attacker the reputation of GitHub
by uploading a page, and phishing on `*.web.app` and `*.pages.dev` is routine.

So reputation, allow-listing and brand comparison all have to be anchored on the
registrable domain computed from the real Public Suffix List:

    evil.github.io     -> evil.github.io      (github.io is a public suffix)
    mail.google.com    -> google.com
    google.com.evil.tk -> evil.tk
    www.bbc.co.uk      -> bbc.co.uk           (co.uk is a public suffix)

The list is vendored at data/public_suffix_list.dat rather than fetched, so
analysis stays offline and deterministic and this package keeps its "no external
dependencies" property. No stdlib module does this.
"""

import os
from functools import lru_cache

_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "public_suffix_list.dat")

# Populated on first use: (normal rules, wildcard rules, exception rules).
_rules = None


def _load():
    """Parse the PSL into three sets. Cheap enough to do once per process."""
    global _rules
    if _rules is not None:
        return _rules

    normal, wildcard, exception = set(), set(), set()
    try:
        with open(_DATA, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                if line.startswith("!"):
                    exception.add(line[1:].lower())
                elif line.startswith("*."):
                    wildcard.add(line[2:].lower())
                else:
                    normal.add(line.lower())
    except OSError:
        # Missing list must not take the scanner down. Callers still get a
        # sensible answer from the two-label fallback in registrable_domain.
        pass

    _rules = (normal, wildcard, exception)
    return _rules


@lru_cache(maxsize=4096)
def public_suffix(host: str) -> str:
    """The public-suffix part of a hostname ("co.uk", "github.io", "com")."""
    normal, wildcard, exception = _load()
    host = (host or "").lower().strip(".")
    if not host:
        return ""

    labels = host.split(".")
    # Exceptions win outright: "!city.kawasaki.jp" means kawasaki.jp is the
    # suffix there, not city.kawasaki.jp.
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exception:
            return ".".join(labels[i + 1:])

    # Longest match wins, so walk from the most specific candidate.
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in normal:
            return candidate
        parent = ".".join(labels[i + 1:])
        if parent and parent in wildcard:
            # "*.ck" makes any single label under .ck a suffix.
            return candidate

    # Unknown TLD (an internal name, a typo, a brand-new gTLD): the PSL's own
    # default rule is "*", i.e. treat the last label as the suffix.
    return labels[-1]


@lru_cache(maxsize=4096)
def registrable_domain(host: str) -> str:
    """The suffix plus one label — what somebody registered and controls.

    Returns "" for an empty host, and the host itself when it *is* a public
    suffix with nothing registered under it (bare "github.io", bare "co.uk").
    """
    host = (host or "").lower().strip(".").split(":")[0]
    if not host:
        return ""

    # An IP address has no registrable domain; return it unchanged so callers
    # can compare it as-is rather than getting a meaningless "1.2".
    if host.replace(".", "").isdigit() or ":" in host:
        return host

    suffix = public_suffix(host)
    if not suffix or host == suffix:
        return host

    remainder = host[: -(len(suffix) + 1)]
    if not remainder:
        return host
    return remainder.split(".")[-1] + "." + suffix


_REPUTABLE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "reputable_domains.txt"
)
_reputable = None


def _load_reputable():
    global _reputable
    if _reputable is not None:
        return _reputable
    entries = set()
    try:
        with open(_REPUTABLE_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    entries.add(line)
    except OSError:
        pass
    _reputable = entries
    return _reputable


@lru_cache(maxsize=4096)
def is_established_domain(host: str) -> bool:
    """True when the host's registrable domain is in the Tranco top 10,000.

    Used for exactly one thing: a site millions of people visit is not a
    lookalike of something else. `telegraph.co.uk` is one edit from
    telegram.org, `wetter.com` two from twitter.com, `google-analytics.com`
    contains "google" as a token — all flagged as impersonation, and no
    string-distance rule can tell them from `paypa1.com`, because the difference
    is not in the spelling.

    Deliberately narrow. This says nothing about whether an artifact is safe: a
    popular site can be compromised, and that is what threat intel is for.
    Reputation may only ever dampen weak heuristics.

    Anchored on the registrable domain, and shared hosting was excluded when the
    list was built, so no page on github.io or workers.dev inherits anything.
    """
    reg = registrable_domain(host)
    return bool(reg) and reg in _load_reputable()


def same_registrable_domain(a: str, b: str) -> bool:
    """True when two hostnames are controlled by the same registrant.

    The comparison every allow-list and brand check should use: it treats
    mail.google.com and google.com as one party, while keeping
    evil.github.io and github.io apart.
    """
    ra, rb = registrable_domain(a), registrable_domain(b)
    return bool(ra) and ra == rb
