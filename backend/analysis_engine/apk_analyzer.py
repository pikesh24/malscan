"""
analysis_engine/apk_analyzer.py
Parses Android APK files to extract security-relevant metadata:
  - Package name, app label
  - Requested permissions (flagging dangerous ones)
  - Embedded URLs/IPs inside DEX bytecode
"""

import zipfile
import re
import logging

# Prefer defusedxml to neutralise XML entity-expansion ("billion laughs") and
# external-entity attacks in an attacker-supplied AndroidManifest.xml. Fall back
# to stdlib ElementTree with a manual DTD/entity guard if defusedxml isn't
# installed, so a missing optional dependency never silently disables parsing.
try:
    from defusedxml.ElementTree import fromstring as _xml_fromstring
    _DEFUSED_XML = True
except ImportError:  # pragma: no cover - defusedxml is a declared dependency
    from xml.etree.ElementTree import fromstring as _xml_fromstring
    _DEFUSED_XML = False

logger = logging.getLogger(__name__)

# Permissions that indicate potentially malicious behaviour
DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_PHONE_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    # Contactless relay is a 2026 banking-malware technique: the app reads a
    # card and relays it to an attacker terminal. Listed so it is reported;
    # scoring deliberately gives it nothing on its own, because payment,
    # transit and access-badge apps all use NFC legitimately.
    "android.permission.NFC",
    "android.permission.BIND_NFC_SERVICE",
}

ANDROID_NS = "http://schemas.android.com/apk/res/android"


_PERMISSION_RE = re.compile(r"android\.permission\.[A-Z][A-Z0-9_]{2,}")


def _scan_manifest_strings(raw_bytes: bytes) -> list:
    """Recover permission names from a *binary* AndroidManifest.xml.

    Every APK produced by the Android toolchain ships its manifest as binary
    AXML, not text — so the XML parse below returned nothing for essentially
    every real APK ever scanned, and permission analysis was dead in production
    while looking like an app that simply requested none.

    AXML keeps every string the document uses in a string pool, and permission
    names survive there as readable text (UTF-16LE in older builds, UTF-8 in
    newer ones). Reading the pool is not a full AXML parse — it cannot tell a
    <uses-permission> from a string referenced elsewhere — but a permission name
    present in the pool was put there because the manifest names it, so the
    over-detection risk is small and the alternative was detecting nothing.
    """
    found = set()
    for encoding in ("utf-16-le", "utf-8", "latin-1"):
        try:
            found.update(_PERMISSION_RE.findall(raw_bytes.decode(encoding, errors="ignore")))
        except Exception:
            continue
    return sorted(found)


def _parse_manifest_xml(raw_bytes: bytes) -> dict:
    """Parse AndroidManifest.xml, plain-text or binary AXML."""
    info = {"package": None, "app_label": None, "permissions": [], "dangerous_permissions": []}
    try:
        # Defense-in-depth when defusedxml is unavailable: refuse any document
        # that declares a DTD or entities — that's the entity-expansion DoS vector.
        if not _DEFUSED_XML and re.search(rb"<!DOCTYPE|<!ENTITY", raw_bytes, re.IGNORECASE):
            logger.warning("APK manifest declares a DTD/entities — skipping XML parse (possible entity-expansion attack)")
            return info
        tree = _xml_fromstring(raw_bytes)
        info["package"] = tree.attrib.get("package")

        for uses in tree.iter("uses-permission"):
            perm = uses.attrib.get(f"{{{ANDROID_NS}}}name") or uses.attrib.get("name", "")
            if perm:
                info["permissions"].append(perm)
                if perm in DANGEROUS_PERMISSIONS:
                    info["dangerous_permissions"].append(perm)

        app_el = tree.find("application")
        if app_el is not None:
            info["app_label"] = app_el.attrib.get(f"{{{ANDROID_NS}}}label") or app_el.attrib.get("label")
    except Exception:
        pass

    # Binary AXML (i.e. every real APK) reaches here with nothing found, because
    # the XML parse above cannot read it. Fall back to the string pool.
    if not info["permissions"]:
        info["permissions"] = _scan_manifest_strings(raw_bytes)
        info["manifest_parse"] = "binary-axml-strings"

    info["dangerous_permissions"] = [p for p in info["permissions"] if p in DANGEROUS_PERMISSIONS]
    return info


# Decompression budget for DEX scanning — a 50 MB APK can claim to inflate to
# gigabytes (zip bomb); never read more than this in total.
MAX_DEX_BYTES = 100 * 1024 * 1024

# Real AndroidManifest.xml files are tiny (well under 1 MB). Cap the read so a
# malicious APK can't claim a multi-GB manifest and exhaust memory on read.
MAX_MANIFEST_BYTES = 5 * 1024 * 1024


def _scan_dex_strings(zf: zipfile.ZipFile) -> dict:
    """Extract URLs and IPs from all .dex files inside the APK."""
    urls, ips = set(), set()
    ip_re = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    url_re = re.compile(rb'https?://[^\x00\s\'\"\<\>\]]{4,}')

    budget = MAX_DEX_BYTES
    for name in zf.namelist():
        if name.endswith(".dex"):
            try:
                declared = zf.getinfo(name).file_size
                if declared > budget:
                    logger.warning(f"Skipping oversized DEX entry {name} ({declared} bytes) — decompression budget exceeded")
                    continue
                budget -= declared
                data = zf.read(name)
                for m in url_re.findall(data):
                    urls.add(m.decode("utf-8", errors="ignore"))
                for m in ip_re.findall(data):
                    ips.add(m.decode("utf-8", errors="ignore"))
            except Exception:
                continue
    return {"urls": list(urls)[:50], "ips": list(ips)[:50]}


def analyze_apk(file_path: str) -> dict:
    """
    Main entry point.  Returns dict with:
      is_apk, package, app_label, permissions, dangerous_permissions,
      dex_urls, dex_ips
    """
    result = {
        "is_apk": False,
        "package": None,
        "app_label": None,
        "permissions": [],
        "dangerous_permissions": [],
        "dex_urls": [],
        "dex_ips": [],
    }

    try:
        if not zipfile.is_zipfile(file_path):
            return result

        with zipfile.ZipFile(file_path, "r") as zf:
            names = zf.namelist()
            # An APK must contain AndroidManifest.xml and at least one .dex
            if "AndroidManifest.xml" not in names:
                return result

            result["is_apk"] = True

            # Parse manifest (size-capped: reject an over-large declared manifest
            # before reading it into memory).
            manifest_size = zf.getinfo("AndroidManifest.xml").file_size
            if manifest_size > MAX_MANIFEST_BYTES:
                logger.warning(f"Skipping oversized AndroidManifest.xml ({manifest_size} bytes) — exceeds {MAX_MANIFEST_BYTES} byte cap")
            else:
                manifest_bytes = zf.read("AndroidManifest.xml")
                manifest_info = _parse_manifest_xml(manifest_bytes)
                result.update(manifest_info)

            # Scan DEX for embedded IOCs
            dex_data = _scan_dex_strings(zf)
            result["dex_urls"] = dex_data["urls"]
            result["dex_ips"] = dex_data["ips"]

    except Exception as e:
        logger.error(f"APK analysis error: {e}")

    return result
