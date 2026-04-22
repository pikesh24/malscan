import whois
import dns.resolver
import requests

def get_whois(domain: str) -> dict:
    """
    Queries WHOIS data for a given domain to find registrar and registration dates.
    """
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
            "emails": w.emails
        }
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain: str) -> dict:
    """
    Resolves basic DNS records (A, MX, TXT) for a domain.
    """
    records = {"A": [], "MX": [], "TXT": []}
    
    for record_type in records.keys():
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [rdata.to_text() for rdata in answers]
        except Exception:
            pass
            
    return records

def get_geoip(ip_address: str) -> dict:
    """
    Queries ip-api.com for geolocation, ASN, and lat/lon coordinates.
    """
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,isp,org,as,lat,lon",
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country":     data.get("country"),
                    "countryCode": data.get("countryCode"),
                    "isp":         data.get("isp"),
                    "asn":         data.get("as"),
                    "lat":         data.get("lat"),
                    "lon":         data.get("lon"),
                }
            else:
                return {"error": data.get("message")}
    except Exception as e:
        return {"error": str(e)}
    return {"error": "Unknown error in GeoIP lookup"}


def get_all_geoip(ip_list: list) -> list:
    """
    Resolves geolocation for a list of IPs. Skips private/reserved ranges.
    Returns a list of dicts with ip + geo fields for map pin rendering.
    """
    import ipaddress
    results = []
    seen = set()
    for ip in ip_list:
        if ip in seen:
            continue
        seen.add(ip)
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                # Include private IPs in results but flag them so the UI can label them
                results.append({"ip": ip, "private": True, "country": "Private/LAN"})
                continue
        except ValueError:
            continue
        geo = get_geoip(ip)
        if "error" not in geo and geo.get("lat") is not None:
            results.append({"ip": ip, **geo})
    return results
