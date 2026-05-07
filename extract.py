"""
extract.py  —  FR-3: Feature Extraction
Reads a .pcap file with Scapy and computes all meaningful features.
"""
 
import collections
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
 
SIZE_BUCKETS = [(0, 100), (100, 500), (500, 1000), (1000, 1500)]
 
 
def extract_features(pcap_path: str) -> dict:
    """Read pcap_path and return a feature dictionary."""
    try:
        packets = rdpcap(pcap_path)
    except Exception:
        packets = []
 
    if not packets:
        return _empty_features()
 
    return _compute(packets)
 
 
def _compute(packets) -> dict:
    total_packets = len(packets)
 
    sizes        = []
    timestamps   = []
    dst_ips      = set()
    dst_ports    = set()
    dns_queries  = []
    proto_counts = collections.Counter()
 
    for pkt in packets:
        sizes.append(len(pkt))
 
        if hasattr(pkt, "time"):
            timestamps.append(float(pkt.time))
 
        if DNS in pkt and pkt.haslayer(DNSQR):
            proto_counts["DNS"] += 1
            dns_queries.append(_safe_dns_name(pkt[DNSQR].qname))
        elif TCP in pkt and pkt[TCP].dport in (443, 8443):
            proto_counts["HTTPS"] += 1
        elif TCP in pkt:
            proto_counts["TCP"] += 1
        elif UDP in pkt:
            proto_counts["UDP"] += 1
        else:
            proto_counts["Other"] += 1
 
        if IP in pkt:
            dst_ips.add(pkt[IP].dst)
            if TCP in pkt:
                dst_ports.add(pkt[TCP].dport)
            elif UDP in pkt:
                dst_ports.add(pkt[UDP].dport)
 
    total_bytes = sum(sizes)
    mean_size   = round(total_bytes / total_packets)
    min_size    = min(sizes)
    max_size    = max(sizes)
 
    inter_arrivals = _inter_arrival_times(timestamps)
    mean_iat = round(sum(inter_arrivals) / len(inter_arrivals), 5) if inter_arrivals else 0
 
    proto_dist     = _protocol_distribution(proto_counts, total_packets)
    traffic_vector = _normalize_vector(proto_counts, total_packets)
    size_dist      = _size_histogram(sizes)
    timeline       = _timeline(packets, timestamps, buckets=12)
 
    return {
        "total_packets":         total_packets,
        "total_bytes":           total_bytes,
        "mean_packet_size":      mean_size,
        "min_packet_size":       min_size,
        "max_packet_size":       max_size,
        "mean_inter_arrival":    mean_iat,
        "protocol_counts":       dict(proto_counts),
        "protocol_distribution": proto_dist,
        "traffic_vector":        traffic_vector,
        "unique_ips":            sorted(dst_ips),
        "dst_ports":             sorted(dst_ports),
        "dns_queries":           list(dict.fromkeys(dns_queries)),
        "size_distribution":     size_dist,
        "timeline":              timeline,
        "packet_sizes":          sizes,
    }
 
 
def _protocol_distribution(counts, total):
    dist = []
    for name in ("TCP", "HTTPS", "DNS", "UDP", "Other"):
        val = round(counts.get(name, 0) / total * 100)
        if val > 0:
            dist.append({"name": name, "value": val})
    return sorted(dist, key=lambda x: x["value"], reverse=True)
 
 
def _normalize_vector(counts, total):
    if total == 0:
        return [0.0, 0.0, 0.0, 0.0]
    return [round(counts.get(k, 0) / total, 4) for k in ("TCP", "HTTPS", "DNS", "UDP")]
 
 
def _inter_arrival_times(timestamps):
    if len(timestamps) < 2:
        return []
    return [round(timestamps[i + 1] - timestamps[i], 6) for i in range(len(timestamps) - 1)]
 
 
def _size_histogram(sizes):
    if not sizes:
        return [0, 0, 0, 0]
    bucket_counts = [0] * len(SIZE_BUCKETS)
    for s in sizes:
        for idx, (lo, hi) in enumerate(SIZE_BUCKETS):
            if lo <= s < hi:
                bucket_counts[idx] += 1
                break
        else:
            bucket_counts[-1] += 1
    total = len(sizes)
    return [round(c / total * 100) for c in bucket_counts]
 
 
def _timeline(packets, timestamps, buckets=12):
    if not timestamps or len(timestamps) < 2:
        return [0] * buckets
    t_start  = min(timestamps)
    t_end    = max(timestamps)
    duration = t_end - t_start or 1.0
    slice_w  = duration / buckets
    bytecounts = [0] * buckets
    for pkt in packets:
        if not hasattr(pkt, "time"):
            continue
        idx = int((float(pkt.time) - t_start) / slice_w)
        idx = min(idx, buckets - 1)
        bytecounts[idx] += len(pkt)
    return bytecounts
 
 
def _safe_dns_name(raw) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace").rstrip(".")
    return str(raw).rstrip(".")
 
 
def _empty_features() -> dict:
    return {
        "total_packets":         0,
        "total_bytes":           0,
        "mean_packet_size":      0,
        "min_packet_size":       0,
        "max_packet_size":       0,
        "mean_inter_arrival":    0,
        "protocol_counts":       {},
        "protocol_distribution": [],
        "traffic_vector":        [0.0, 0.0, 0.0, 0.0],
        "unique_ips":            [],
        "dst_ports":             [],
        "dns_queries":           [],
        "size_distribution":     [0, 0, 0, 0],
        "timeline":              [0] * 12,
        "packet_sizes":          [],
    }
 