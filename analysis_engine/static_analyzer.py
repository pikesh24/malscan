import re
import pefile
import os

def extract_iocs(file_path: str) -> dict:
    """
    Scrapes a file's raw content for potential Indicators of Compromise (IoCs)
    such as IPs, domains, and URLs.
    """
    iocs = {
        "ips": set(),
        "domains": set(),
        "urls": set()
    }
    
    if not os.path.exists(file_path):
        return iocs

    # basic regexes for extraction
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    url_pattern = re.compile(r'https?://[^\s\'"<>\]]+')

    
    try:
        # Read file in binary mode but decode with errors='ignore' to find strings
        with open(file_path, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
            
            # Extract IPs
            for ip in ip_pattern.findall(content):
                iocs["ips"].add(ip)
                
            # Extract URLs
            for url in url_pattern.findall(content):
                iocs["urls"].add(url)
                
            # Note: Robust domain extraction from raw strings is complex and prone to false positives.
            # In a real scenario, we might use a specialized library or more complex regex.
            
    except Exception as e:
        print(f"Error extracting IoCs from {file_path}: {e}")
        
    # Convert sets to lists for JSON serialization later
    iocs["ips"] = list(iocs["ips"])
    iocs["urls"] = list(iocs["urls"])
    iocs["domains"] = list(iocs["domains"])
    
    return iocs

def analyze_pe(file_path: str) -> dict:
    """
    Analyzes Windows Executable (PE) metadata and anomalies.
    """
    results = {
        "is_pe": False,
        "imphash": None,
        "suspicious_sections": []
    }
    
    if not os.path.exists(file_path):
        return results
        
    try:
        pe = pefile.PE(file_path)
        results["is_pe"] = True
        results["imphash"] = pe.get_imphash()
        
        # Check for suspicious section characteristics (e.g., entropy, unusal names)
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = section.get_entropy()
            if entropy > 7.5:
                 results["suspicious_sections"].append({
                     "name": section_name,
                     "reason": f"High entropy ({entropy:.2f}) suggesting packing or encryption."
                 })
                 
    except pefile.PEFormatError:
        # Not a valid PE file
        pass
    except Exception as e:
         print(f"Error analyzing PE {file_path}: {e}")
         
    return results
