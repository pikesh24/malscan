"""
attribution_module/clustering.py
Team Member 4 — Attribution & Security Engineer

Called by backend/app/main.py after calculate_score() completes.
Takes the current job's results + all previous completed jobs from the DB
and identifies shared infrastructure (same IP, ASN, registrar).

cluster_iocs(current_job_id, current_results, all_jobs) -> dict

Output is merged into ScanJob.results under the "clusters" key.
"""

from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


# ── Risk signals ─────────────────────────────────────────────────────────────

RISK_SIGNALS = {
    "shared_ip":        "Multiple jobs resolve to the same IP — strong indicator of shared phishing infrastructure.",
    "shared_asn":       "Multiple artifacts hosted under the same ASN — possible bulk-registered campaign.",
    "shared_registrar": "Multiple domains share a registrar frequently abused for throwaway phishing domains.",
    "shared_domain":    "The same domain appears across multiple submitted artifacts.",
}


# ── Graph extension ───────────────────────────────────────────────────────────

def extend_graph_with_clusters(graph_nodes: list, graph_edges: list, clusters: dict) -> tuple[list, list]:
    """
    Adds cluster-level cross-job edges to an existing graph node/edge list.
    e.g. two jobs that share an IP get a "shared_infrastructure" edge added.
    """
    node_ids = {n["id"] for n in graph_nodes}
    edges = list(graph_edges)

    for ip, job_ids in clusters.get("shared_ips", {}).items():
        if ip not in node_ids:
            graph_nodes.append({"id": ip, "label": ip, "type": "ip", "risk": "high"})
            node_ids.add(ip)
        for job_id in job_ids:
            cluster_node_id = f"job_{job_id[:8]}"
            if cluster_node_id not in node_ids:
                graph_nodes.append({"id": cluster_node_id, "label": f"Job {job_id[:8]}", "type": "job", "risk": "medium"})
                node_ids.add(cluster_node_id)
            edges.append({"source": ip, "target": cluster_node_id, "relationship": "shared_infrastructure"})

    return graph_nodes, edges


# ── Main clustering function ──────────────────────────────────────────────────

def cluster_iocs(current_job_id: str, current_results: dict, all_jobs: list) -> dict:
    """
    Called from main.py after scoring completes.

    Args:
        current_job_id:  The job being processed right now.
        current_results: The dict returned by calculate_score() for this job.
        all_jobs:        List of ScanJob ORM objects from the DB
                         (only 'Completed' jobs with results will be used).

    Returns a dict:
    {
        "shared_ips":        { "1.2.3.4": ["job-abc", "job-def"], ... },
        "shared_domains":    { "evil.com": ["job-abc"], ... },
        "shared_asns":       { "AS9009":   ["job-abc", "job-def"], ... },
        "shared_registrars": { "Namecheap": ["job-abc"], ... },
        "risk_signals":      ["...human readable strings..."],
        "cluster_count":     int,
    }
    """
    clusters = {
        "shared_ips":        defaultdict(list),
        "shared_domains":    defaultdict(list),
        "shared_asns":       defaultdict(list),
        "shared_registrars": defaultdict(list),
    }

    # Build map from all previous completed jobs
    for job in all_jobs:
        job_id = job.job_id
        if job_id == current_job_id:
            continue
        results = job.results
        if not results or not isinstance(results, dict):
            continue

        prev_indicators = results.get("indicators", {})
        prev_osint      = results.get("osint_summary", {})

        for ip in (prev_indicators.get("ips") or []):
            clusters["shared_ips"][ip].append(job_id)
        for domain in (prev_indicators.get("domains") or []):
            clusters["shared_domains"][domain].append(job_id)
        asn = prev_osint.get("asn")
        if asn:
            clusters["shared_asns"][asn].append(job_id)
        registrar = prev_osint.get("registrar")
        if registrar:
            clusters["shared_registrars"][registrar].append(job_id)

    # Now check current job against those maps
    current_indicators = current_results.get("indicators", {})
    current_osint      = current_results.get("osint_summary", {})
    risk_signals       = []

    def _check_and_flag(mapping, items, cluster_key, signal_key):
        for item in (items or []):
            if item in mapping:
                mapping[item].append(current_job_id)
                signal = f"{RISK_SIGNALS[signal_key]} Shared value: '{item}' seen in {len(mapping[item])} job(s)."
                if signal not in risk_signals:
                    risk_signals.append(signal)
            else:
                mapping[item] = [current_job_id]

    _check_and_flag(clusters["shared_ips"],        current_indicators.get("ips", []),        "shared_ips",        "shared_ip")
    _check_and_flag(clusters["shared_domains"],    current_indicators.get("domains", []),    "shared_domains",    "shared_domain")

    current_asn = current_osint.get("asn")
    if current_asn:
        if current_asn in clusters["shared_asns"]:
            clusters["shared_asns"][current_asn].append(current_job_id)
            risk_signals.append(f"{RISK_SIGNALS['shared_asn']} ASN: '{current_asn}'.")
        else:
            clusters["shared_asns"][current_asn] = [current_job_id]

    current_registrar = current_osint.get("registrar")
    if current_registrar:
        if current_registrar in clusters["shared_registrars"]:
            clusters["shared_registrars"][current_registrar].append(current_job_id)
            risk_signals.append(f"{RISK_SIGNALS['shared_registrar']} Registrar: '{current_registrar}'.")
        else:
            clusters["shared_registrars"][current_registrar] = [current_job_id]

    # Filter: only keep entries shared across >1 job
    shared_ips        = {k: v for k, v in clusters["shared_ips"].items()        if len(v) > 1}
    shared_domains    = {k: v for k, v in clusters["shared_domains"].items()    if len(v) > 1}
    shared_asns       = {k: v for k, v in clusters["shared_asns"].items()       if len(v) > 1}
    shared_registrars = {k: v for k, v in clusters["shared_registrars"].items() if len(v) > 1}

    cluster_count = len(shared_ips) + len(shared_domains) + len(shared_asns) + len(shared_registrars)

    logger.info(f"Job {current_job_id}: found {cluster_count} infrastructure cluster(s).")

    return {
        "shared_ips":        shared_ips,
        "shared_domains":    shared_domains,
        "shared_asns":       shared_asns,
        "shared_registrars": shared_registrars,
        "risk_signals":      risk_signals,
        "cluster_count":     cluster_count,
    }
