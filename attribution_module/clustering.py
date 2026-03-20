def cluster_iocs(jobs_data: list) -> dict:
    """
    Analyzes multiple jobs to find overlapping infrastructure.
    
    Expected jobs_data structure:
    [
        {"job_id": "123", "iocs": {"ips": ["1.1.1.1"], "domains": ["evil.com"]}},
        {"job_id": "456", "iocs": {"ips": ["1.1.1.1"], "domains": ["bad.org"]}}
    ]
    """
    clusters = {
        "shared_ips": {},
        "shared_domains": {}
    }

    ip_map = {}
    domain_map = {}

    for job in jobs_data:
        job_id = job.get("job_id")
        iocs = job.get("iocs", {})
        
        # Map IPs
        for ip in iocs.get("ips", []):
            if ip not in ip_map:
                ip_map[ip] = []
            ip_map[ip].append(job_id)
            
        # Map Domains
        for domain in iocs.get("domains", []):
            if domain not in domain_map:
                domain_map[domain] = []
            domain_map[domain].append(job_id)

    # Filter for shared infrastructure (present in >1 job)
    for ip, jobs in ip_map.items():
        if len(jobs) > 1:
            clusters["shared_ips"][ip] = jobs

    for domain, jobs in domain_map.items():
        if len(jobs) > 1:
            clusters["shared_domains"][domain] = jobs

    return clusters
