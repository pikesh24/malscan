"""
analysis_engine/resource_chain.py
The third parties a page actually loads, and what can be said about them.

Why this exists
---------------
Reputation services rate the domain you ask about. A page is not its domain: it
is that domain plus every host it pulls active content from, and on a monetised
or compromised page the dangerous part is almost never the domain itself.

deutschland.com is the worked example. VirusTotal saw 1 vendor out of 92 flag
it — below the noise floor by design — and URLScan's own engines called it
benign. Malscan scored it 0/100. The page loads a script from an S3 bucket that
92 vendors had 9 detections on, and a desktop AV blocked on contact. That bucket
was already in the report, rendered as a grey chip, read by nothing.

What this module is careful NOT to do
-------------------------------------
The obvious fix — "flag pages that load from S3" — is the trap. Object storage,
free app hosting and CDN tunnels host an enormous amount of the ordinary web,
and per tests/live/base_rates.py a signal that fires on a large share of the
Tranco top 10,000 carries little information no matter how sinister it sounds.
Blocklist reputation has the opposite failure: it is silent on infrastructure
that is new, single-use, or simply unknown, which is most of what matters.

So the two are kept apart on purpose:

  * Reputation (VirusTotal, URLhaus, ThreatFox) is what SCORES. It is specific
    evidence about a named host.
  * Structure (who the host is, where it sits, how it relates to the page) is
    what DESCRIBES. On its own it is mostly reported, not scored, because on its
    own it does not separate malicious from ordinary.

Structure earns points only where a conjunction is genuinely rare on legitimate
pages — a bare IP serving script, an executable pulled from anonymous hosting —
and it decides the ORDER in which hosts spend the small VirusTotal budget, which
is where it pays for itself regardless of weighting.
"""

import ipaddress
import logging
from urllib.parse import urlparse

from analysis_engine.public_suffix import (
    is_established_domain,
    registrable_domain,
    same_registrable_domain,
)
from analysis_engine.url_processor import SUSPICIOUS_TLDS, URL_SHORTENERS

logger = logging.getLogger(__name__)


# Providers that let anyone publish content under a hostname they do not own.
# Membership is NOT a risk claim: these host a large share of the legitimate web.
# It means "the hostname tells you nothing about who is behind the content",
# which is what makes an unrelated one worth a reputation lookup ahead of a
# named corporate CDN.
ANONYMOUS_HOSTING_SUFFIXES = {
    # Object storage
    "s3.amazonaws.com", "s3.us-east-1.amazonaws.com", "blob.core.windows.net",
    "storage.googleapis.com", "firebasestorage.googleapis.com",
    "digitaloceanspaces.com", "backblazeb2.com", "r2.dev", "wasabisys.com",
    "oss-cn-hangzhou.aliyuncs.com", "cos.ap-guangzhou.myqcloud.com",
    # Free app / page hosting
    "pages.dev", "workers.dev", "netlify.app", "vercel.app", "github.io",
    "gitlab.io", "glitch.me", "repl.co", "replit.dev", "surge.sh",
    "herokuapp.com", "azurewebsites.net", "web.app", "firebaseapp.com",
    "onrender.com", "fly.dev", "koyeb.app", "railway.app",
    # Tunnels / ephemeral endpoints
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "loca.lt", "serveo.net",
    # Consumer file sharing and paste sites
    "dropbox.com", "dl.dropboxusercontent.com", "mega.nz", "mediafire.com",
    "anonfiles.com", "gofile.io", "pastebin.com", "paste.ee", "ghostbin.com",
    "cdn.discordapp.com", "media.discordapp.net", "t.me", "telegra.ph",
    # Free site builders
    "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com",
    "000webhostapp.com", "neocities.org",
}

# Payloads a PAGE has no ordinary reason to fetch on its own.
#
# Note what is absent: .js. Every page on the web loads JavaScript, so treating
# it as a payload ranked Google Analytics above the malicious S3 bucket on the
# very first run of this module — with a budget of three lookups it would have
# spent them on Google and missed the threat entirely. The same reasoning keeps
# out .bin and .wasm (ordinary web app assets). This list is about file types a
# browser fetch is genuinely odd for, not file types that are executable in the
# abstract.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".jse", ".jar", ".hta", ".apk", ".dmg", ".pkg", ".deb", ".rpm",
    ".sh", ".pif", ".cpl", ".lnk",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".cab", ".iso", ".img"}

# Facet weights. Deliberately small and, unlike the registrar/hosting weights,
# NOT measured — no base-rate run exists for resource chains, so these are set
# to inform rather than to convict. A conjunction is what carries signal, so the
# scoring check rewards combinations rather than summing these naively.
FACET_LABELS = {
    "anonymous_hosting": "content served from anonymous/shared hosting",
    "raw_ip": "content served from a bare IP address with no domain",
    "punycode": "internationalised (punycode) hostname",
    "suspicious_tld": "hostname on a TLD common in abuse",
    "url_shortener": "hostname is a link shortener",
    "executable_payload": "executable or script payload fetched",
    "archive_payload": "archive payload fetched",
    "unestablished": "hostname is not a widely-visited domain",
}


def _hostname(value: str) -> str:
    """Accepts a bare host or a full URL and returns a lowercase hostname."""
    value = (value or "").strip().lower()
    if not value:
        return ""
    if "://" in value:
        try:
            return (urlparse(value).hostname or "").lower()
        except ValueError:
            return ""
    return value.split("/")[0].split(":")[0]


def _is_raw_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _matches_suffix(host: str, suffixes: set) -> str | None:
    """Longest matching suffix, so s3.amazonaws.com wins over amazonaws.com."""
    best = None
    for suffix in suffixes:
        if host == suffix or host.endswith("." + suffix):
            if best is None or len(suffix) > len(best):
                best = suffix
    return best


def classify_host(host: str, target_url: str = "", paths: list | None = None) -> dict:
    """
    Describes one third-party host. Pure string work — no network, no blocklist.

    `paths` are URLs observed being fetched from this host, used only to notice
    an executable or archive payload.
    """
    host = _hostname(host)
    if not host:
        return {}

    facets = []
    if _is_raw_ip(host):
        facets.append("raw_ip")
    else:
        provider = _matches_suffix(host, ANONYMOUS_HOSTING_SUFFIXES)
        if provider:
            facets.append("anonymous_hosting")
        if host.startswith("xn--") or ".xn--" in host:
            facets.append("punycode")
        reg = registrable_domain(host)
        if reg:
            tld = "." + reg.split(".")[-1]
            if tld in SUSPICIOUS_TLDS:
                facets.append("suspicious_tld")
            if reg in URL_SHORTENERS:
                facets.append("url_shortener")
        if not is_established_domain(host):
            facets.append("unestablished")

    for raw in paths or []:
        try:
            path = (urlparse(raw).path or "").lower()
        except ValueError:
            continue
        dot = path.rfind(".")
        if dot == -1:
            continue
        ext = path[dot:]
        if ext in EXECUTABLE_EXTENSIONS and "executable_payload" not in facets:
            facets.append("executable_payload")
        elif ext in ARCHIVE_EXTENSIONS and "archive_payload" not in facets:
            facets.append("archive_payload")

    return {
        "host": host,
        "registrable_domain": registrable_domain(host),
        "facets": facets,
        "first_party": bool(target_url) and same_registrable_domain(host, _hostname(target_url)),
    }


# How interesting a facet makes a host, used ONLY to order the reputation budget.
# Ranking is cheap and cannot produce a false positive, so it can be more
# opinionated than the scoring is.
_PRIORITY = {
    "executable_payload": 6,
    "raw_ip": 5,
    "archive_payload": 4,
    "punycode": 4,
    "anonymous_hosting": 3,
    "url_shortener": 3,
    "suspicious_tld": 2,
    "unestablished": 1,
}


def priority(entry: dict) -> int:
    return sum(_PRIORITY.get(f, 0) for f in entry.get("facets", []))


def analyze(urlscan_data: dict, target_url: str = "") -> dict:
    """
    Turns a URLScan result into the page's third-party resource chain.

    Returns {"hosts": [classified...], "third_party_domains": N, "skipped": bool}.
    First-party hosts are dropped: a site loading its own assets is not a chain.
    Everything else is kept and classified, including hosts with no facets at
    all, because "we saw this and know nothing about it" is the honest state and
    the report should be able to say so.
    """
    if not urlscan_data or urlscan_data.get("error") or urlscan_data.get("status") == "pending":
        return {"hosts": [], "third_party_domains": 0, "skipped": True}

    observed = {}
    # Request URLs first: they cover every host the domain list does and carry
    # the path, which is what reveals a payload. The domain list is a fallback
    # for results (and reused older scans) that lack the URL list.
    for raw in urlscan_data.get("resource_urls") or []:
        host = _hostname(raw)
        if host:
            observed.setdefault(host, []).append(raw)
    for raw in urlscan_data.get("outgoing_domains") or []:
        host = _hostname(raw)
        if host:
            observed.setdefault(host, [])

    hosts = []
    for host, paths in observed.items():
        entry = classify_host(host, target_url, paths)
        if not entry or entry["first_party"]:
            continue
        hosts.append(entry)

    hosts.sort(key=lambda e: (-priority(e), e["host"]))
    distinct = {e["registrable_domain"] for e in hosts if e["registrable_domain"]}
    return {
        "hosts": hosts,
        "third_party_domains": len(distinct),
        "skipped": False,
    }


# A host must be more interesting than "not in the Tranco top 10,000" to be
# worth a lookup — that alone describes most of the web, including
# fonts.googleapis.com, which the reputable list does not contain. Set just
# above the weight of `unestablished` so that facet can never buy a lookup by
# itself.
MIN_PRIORITY_FOR_LOOKUP = 2


def select_for_reputation(chain: dict, budget: int) -> list:
    """
    The hosts worth spending a rate-limited reputation lookup on.

    VirusTotal's free tier allows 4 requests/minute and the pipeline already
    spends some of that, so this is a hard budget, not a soft preference. One
    lookup per registrable domain — checking six buckets on one provider tells
    you about the provider, not the page. Returns fewer than `budget`, or
    nothing at all, when no host clears the bar; an unspent lookup is better
    than one spent on a font CDN.
    """
    if budget <= 0 or chain.get("skipped"):
        return []
    picked, seen = [], set()
    for entry in chain.get("hosts") or []:
        if priority(entry) < MIN_PRIORITY_FOR_LOOKUP:
            continue
        reg = entry.get("registrable_domain") or entry["host"]
        if reg in seen:
            continue
        seen.add(reg)
        picked.append(entry["host"])
        if len(picked) >= budget:
            break
    return picked
