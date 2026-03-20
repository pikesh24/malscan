from urllib.parse import urlparse

def analyze_url(url: str) -> dict:
    """
    Parses a URL to flag potentially suspicious structures.
    """
    result = {
        "scheme": None,
        "domain": None,
        "path": None,
        "query": None,
        "suspicious_flags": []
    }
    
    try:
        parsed = urlparse(url)
        result["scheme"] = parsed.scheme
        result["domain"] = parsed.netloc
        result["path"] = parsed.path
        result["query"] = parsed.query
        
        # Basic heuristic flags
        if parsed.scheme and parsed.scheme.lower() != "https":
            result["suspicious_flags"].append("Not using HTTPS protocol.")
            
        if parsed.netloc:
             domain_parts = parsed.netloc.split('.')
             if len(domain_parts) > 4:
                 result["suspicious_flags"].append("Unusually high number of subdomains.")
                 
             if len(parsed.netloc) > 50:
                  result["suspicious_flags"].append("Domain length unusually long.")
                  
    except Exception as e:
        result["error"] = f"Failed to parse URL: {str(e)}"
        
    return result
