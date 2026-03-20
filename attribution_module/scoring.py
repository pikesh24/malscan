from datetime import datetime

def calculate_score(analysis_data: dict) -> dict:
    """
    Calculates a confidence score (0-100) based on accumulated intelligence.
    
    Expected analysis_data structure:
    {
        "static": { ... results from static_analyzer ... },
        "osint": { ... results from osint_enricher ... },
        "url": { ... results from url_processor ... }
    }
    """
    score = 0
    reasons = []

    # 1. Static Analysis Weights
    static = analysis_data.get("static", {})
    if static.get("suspicious_sections"):
        score += 30
        reasons.append("High entropy sections detected in PE file (potential packing).")

    # 2. OSINT Weights
    osint = analysis_data.get("osint", {})
    whois_data = osint.get("whois", {})
    if "creation_date" in whois_data and whois_data["creation_date"]:
        try:
            # Handle list of dates if multiple exist, otherwise single string
            creation_str = whois_data["creation_date"]
            if isinstance(creation_str, list):
                creation_str = creation_str[0]
                
            # Basic parsing - in production this needs robust date parsing 
            # across different WHOIS string formats
            creation_date = datetime.strptime(str(creation_str)[:10], "%Y-%m-%d")
            delta = datetime.now() - creation_date
            if delta.days < 30:
                score += 40
                reasons.append(f"Domain is newly registered ({delta.days} days old).")
        except Exception:
            pass # Ignore parsing errors for mock logic

    geoip_data = osint.get("geoip", {})
    high_risk_countries = ["RU", "KP", "CN", "IR"] # Example mock list
    if geoip_data.get("countryCode") in high_risk_countries:
        score += 20
        reasons.append(f"Hosted in high-risk country: {geoip_data['countryCode']}.")

    # 3. URL Analysis Weights
    url_data = analysis_data.get("url", {})
    suspicious_flags = url_data.get("suspicious_flags", [])
    if suspicious_flags:
        score += 10 * len(suspicious_flags)
        for flag in suspicious_flags:
            reasons.append(f"URL Anomaly: {flag}")

    # Cap score at 100
    final_score = min(score, 100)
    
    verdict = "Clear"
    if final_score >= 70:
        verdict = "Malicious"
    elif final_score >= 40:
        verdict = "Suspicious"

    return {
        "score": final_score,
        "verdict": verdict,
        "reasons": reasons
    }
