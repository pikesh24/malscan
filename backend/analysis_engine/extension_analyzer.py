"""
analysis_engine/extension_analyzer.py
Browser extension (CRX / unpacked) analysis.

Why this exists
---------------
A browser extension runs inside the browser with whatever access its manifest
asks for. An extension holding `<all_urls>` plus `cookies` can read every
session token the user has — including ones protected by MFA, because a stolen
live session skips the login entirely. That is why malicious extensions are a
standing route to account takeover rather than a curiosity.

A .crx is a ZIP, so the archive walk already extracted and hashed its members
and found nothing interesting: the manifest is a small JSON file and the
payload is ordinary JavaScript. The permission model — the part that actually
says what the extension can do — was never read, exactly as the APK manifest
was not read before that path was fixed.

This is deliberately the same shape as apk_analyzer: read the manifest, report
the permissions, and let scoring weight the combinations. The parallel is not
accidental — the question is identical ("what did this thing ask to be allowed
to do"), only the platform differs.
"""

import json
import logging
import zipfile

logger = logging.getLogger(__name__)

# CRX3 puts a signed header in front of the ZIP. zipfile usually still opens
# such a file because it locates the central directory from the end, but the
# magic is what identifies the format.
CRX_MAGIC = b"Cr24"

MAX_MANIFEST_BYTES = 1 * 1024 * 1024

# Permissions that grant broad reach. The description says what an attacker gets,
# not what the API is called — a permission list is only useful if the reader
# understands the consequence.
NOTABLE_PERMISSIONS = {
    "debugger":
        "attach the browser debugger — complete control over every page",
    "nativeMessaging":
        "talk to a program installed on the machine, bridging the browser sandbox",
    "cookies":
        "read cookies, including live session tokens that bypass multi-factor login",
    "webRequest":
        "observe every network request the browser makes",
    "webRequestBlocking":
        "modify or block network requests in flight",
    "declarativeNetRequest":
        "rewrite or block requests by rule",
    "proxy":
        "route the user's traffic through a server of its choosing",
    "management":
        "disable or uninstall other extensions, including security ones",
    "tabs":
        "see the URL and title of every open tab",
    "clipboardRead":
        "read whatever the user copies",
    "downloads":
        "download files to the machine",
    "history":
        "read full browsing history",
    "scripting":
        "inject scripts into pages",
    "privacy":
        "change privacy and security settings",
    "contentSettings":
        "change per-site security settings",
}

# Host patterns meaning "every site".
_ALL_SITES = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/")


def _read_manifest(path: str) -> dict | None:
    try:
        if not zipfile.is_zipfile(path):
            return None
        with zipfile.ZipFile(path, "r") as zf:
            if "manifest.json" not in zf.namelist():
                return None
            info = zf.getinfo("manifest.json")
            if info.file_size > MAX_MANIFEST_BYTES:
                logger.warning("Extension manifest is implausibly large — skipping")
                return None
            raw = zf.read("manifest.json")
        # Extension manifests are frequently UTF-8 with a BOM.
        return json.loads(raw.decode("utf-8-sig", errors="replace"))
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, KeyError) as e:
        logger.info(f"Extension manifest unreadable for {path}: {e}")
        return None
    except Exception as e:
        logger.warning(f"Extension manifest parse failed for {path}: {e}")
        return None


def _host_patterns(manifest: dict) -> list:
    hosts = list(manifest.get("host_permissions") or [])
    for script in manifest.get("content_scripts") or []:
        if isinstance(script, dict):
            hosts.extend(script.get("matches") or [])
    # Manifest V2 mixes host patterns into the permissions array.
    for perm in manifest.get("permissions") or []:
        if isinstance(perm, str) and ("://" in perm or perm == "<all_urls>"):
            hosts.append(perm)
    return hosts


def analyze_extension(file_path: str, data: bytes = None) -> dict:
    """
    Reads a browser extension's manifest and reports what it can reach.

    Returns is_extension False for anything that is not one, so callers can hand
    it any file.
    """
    result = {
        "is_extension": False,
        "name": None,
        "version": None,
        "manifest_version": None,
        "permissions": [],
        "notable_permissions": [],
        "host_permissions": [],
        "all_sites_access": False,
        "remote_code": False,
        "findings": [],
        "codes": [],
    }

    manifest = _read_manifest(file_path)
    if not manifest or "manifest_version" not in manifest:
        return result

    result["is_extension"] = True
    result["name"] = manifest.get("name")
    result["version"] = manifest.get("version")
    result["manifest_version"] = manifest.get("manifest_version")

    permissions = [p for p in (manifest.get("permissions") or []) if isinstance(p, str)]
    permissions += [p for p in (manifest.get("optional_permissions") or []) if isinstance(p, str)]
    result["permissions"] = permissions

    hosts = _host_patterns(manifest)
    result["host_permissions"] = hosts
    result["all_sites_access"] = any(h in _ALL_SITES for h in hosts)

    findings, codes = [], []

    def record(code, description):
        if code not in codes:
            codes.append(code)
            findings.append(description)

    for perm in permissions:
        if perm in NOTABLE_PERMISSIONS:
            result["notable_permissions"].append(perm)
            record(f"perm_{perm}", f"Can {NOTABLE_PERMISSIONS[perm]} ({perm})")

    if result["all_sites_access"]:
        record("all_sites", "Requests access to every site the user visits")

    # A manifest pointing at a remote script means the code that will run is not
    # the code that was reviewed — the extension can change after installation.
    blob = json.dumps(manifest)
    if "http://" in blob or "https://" in blob:
        for key in ("content_security_policy", "background", "sandbox", "web_accessible_resources"):
            if "http" in json.dumps(manifest.get(key) or ""):
                result["remote_code"] = True
                record("remote_code",
                       f"Loads code from a remote URL via '{key}' — what runs can change after install")
                break

    if "unsafe-eval" in blob or "unsafe-inline" in blob:
        record("unsafe_csp",
               "Relaxes the content security policy to allow eval or inline script")

    result["findings"], result["codes"] = findings, codes
    return result
