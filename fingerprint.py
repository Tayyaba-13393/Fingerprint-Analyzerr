from extract import extract_features
from classify import classify
 
 
def build_fingerprint(pcap_path: str, site_url: str) -> dict:
    
  #  Read pcap_path, extract features, classify behavior,
    features = extract_features(pcap_path)
    behavior_label, confidence = classify(features)
 
    proto_dist   = features.get("protocol_distribution", [])
    top_protocol = proto_dist[0]["name"] if proto_dist else "Unknown"
 
    fingerprint = {
        "site_url":              _clean_url(site_url),
        "total_packets":         features["total_packets"],
        "total_bytes":           features["total_bytes"],
        "mean_packet_size":      features["mean_packet_size"],
        "min_packet_size":       features["min_packet_size"],
        "max_packet_size":       features["max_packet_size"],
        "top_protocol":          top_protocol,
        "protocol_distribution": proto_dist,
        "traffic_vector":        features["traffic_vector"],
        "unique_ips":            len(features["unique_ips"]),
        "ip_list":               features["unique_ips"],
        "dst_ports":             features["dst_ports"],
        "dns_queries":           features["dns_queries"],
        "mean_inter_arrival":    features["mean_inter_arrival"],
        "behavior_label":        behavior_label,
        "confidence":            confidence,
        "size_distribution":     features["size_distribution"],
        "timeline":              features["timeline"],
    }
 
    return fingerprint
 
 
def compare_fingerprints(fp_a: dict, fp_b: dict) -> dict:
    """FR-6: Compare two fingerprints."""
    metrics = [
        "total_packets", "total_bytes", "mean_packet_size",
        "max_packet_size", "unique_ips", "confidence",
    ]
    diff = {}
    for m in metrics:
        va = fp_a.get(m, 0)
        vb = fp_b.get(m, 0)
        if va > vb:
            diff[f"higher_{m}"] = "siteA"
        elif vb > va:
            diff[f"higher_{m}"] = "siteB"
        else:
            diff[f"higher_{m}"] = "equal"
 
    diff["more_packets"] = "siteA" if fp_a["total_packets"] > fp_b["total_packets"] else "siteB"
    diff["higher_bytes"] = "siteA" if fp_a["total_bytes"]   > fp_b["total_bytes"]   else "siteB"
    diff["more_hosts"]   = "siteA" if fp_a["unique_ips"]    > fp_b["unique_ips"]    else "siteB"
 
    return diff
 
 
def _clean_url(url: str) -> str:
    return (url.replace("https://", "").replace("http://", "").split("/")[0])
 