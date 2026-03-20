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
            # Common to not find certain records
            pass
            
    return records

def get_geoip(ip_address: str) -> dict:
    """
    Queries a free GeoIP service (ip-api.com) for geolocation and ASN data.
    Note: For production, a reliable/paid API or local MaxMind database is recommended.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,isp,org,as")
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "isp": data.get("isp"),
                    "asn": data.get("as")
                }
            else:
                return {"error": data.get("message")}
    except Exception as e:
         return {"error": str(e)}
    return {"error": "Unknown error in GeoIP lookup"}
