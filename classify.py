"""
classify.py  —  FR-5: Traffic Classification
Rule-based heuristics to label a website's network behavior.
"""
 
from typing import Tuple
 
 
def classify(features: dict) -> Tuple[str, int]:
    scores = {
        "Streaming":      _score_streaming(features),
        "Social Media":   _score_social(features),
        "Static Content": _score_static(features),
        "API-heavy":      _score_api(features),
        "E-commerce":     _score_ecommerce(features),
        "News Portal":    _score_news(features),
    }
    best_label = max(scores, key=scores.get)
    raw_score  = scores[best_label]
    confidence = _to_confidence(raw_score)
    return best_label, confidence
 
 
def _score_streaming(f):
    score = 0.0
    avg = f.get("mean_packet_size", 0)
    if avg > 1200:  score += 3.0
    elif avg > 800: score += 2.0
    elif avg > 500: score += 1.0
 
    tb = f.get("total_bytes", 0)
    if tb > 3_000_000:   score += 3.0
    elif tb > 1_000_000: score += 2.0
    elif tb > 500_000:   score += 1.0
 
    if f.get("max_packet_size", 0) >= 1400: score += 2.0
 
    tl = f.get("timeline", [])
    if tl and _variance(tl) < 5000: score += 2.0
    return score
 
 
def _score_social(f):
    score = 0.0
    uips = len(f.get("unique_ips", []))
    if uips >= 8:   score += 3.0
    elif uips >= 5: score += 2.0
    elif uips >= 3: score += 1.0
 
    dns = len(f.get("dns_queries", []))
    if dns >= 6:   score += 2.0
    elif dns >= 3: score += 1.0
 
    tp = f.get("total_packets", 0)
    if tp > 1500:  score += 2.0
    elif tp > 700: score += 1.0
 
    avg = f.get("mean_packet_size", 0)
    if 100 <= avg <= 700: score += 1.0
 
    pd = {p["name"]: p["value"] for p in f.get("protocol_distribution", [])}
    if pd.get("TCP", 0) > 10 and pd.get("HTTPS", 0) > 10: score += 2.0
    return score
 
 
def _score_static(f):
    score = 0.0
    tp = f.get("total_packets", 0)
    if tp < 100:   score += 4.0
    elif tp < 300: score += 2.0
 
    tb = f.get("total_bytes", 0)
    if tb < 200_000:   score += 3.0
    elif tb < 500_000: score += 1.5
 
    avg = f.get("mean_packet_size", 0)
    if avg < 300:  score += 2.0
    elif avg < 600: score += 1.0
 
    if len(f.get("unique_ips", [])) <= 2: score += 1.0
    return score
 
 
def _score_api(f):
    score = 0.0
    tp  = f.get("total_packets", 0)
    tb  = f.get("total_bytes", 0)
    avg = f.get("mean_packet_size", 0)
 
    if tp > 500 and tb < 1_000_000:   score += 4.0
    elif tp > 200 and tb < 500_000:   score += 2.0
 
    if avg < 250:  score += 3.0
    elif avg < 450: score += 1.5
 
    iat = f.get("mean_inter_arrival", 999)
    if iat < 0.05:  score += 2.0
    elif iat < 0.1: score += 1.0
 
    pd = {p["name"]: p["value"] for p in f.get("protocol_distribution", [])}
    if pd.get("HTTPS", 0) >= 40: score += 1.0
    return score
 
 
def _score_ecommerce(f):
    score = 0.0
    tb = f.get("total_bytes", 0)
    if 300_000 <= tb <= 2_000_000: score += 3.0
 
    pd = {p["name"]: p["value"] for p in f.get("protocol_distribution", [])}
    if pd.get("HTTPS", 0) >= 50: score += 3.0
 
    uips = len(f.get("unique_ips", []))
    if 3 <= uips <= 7: score += 2.0
 
    tp = f.get("total_packets", 0)
    if 150 <= tp <= 800: score += 2.0
    return score
 
 
def _score_news(f):
    score = 0.0
    dns = len(f.get("dns_queries", []))
    if dns >= 5:   score += 3.0
    elif dns >= 3: score += 1.5
 
    tp = f.get("total_packets", 0)
    if 200 <= tp <= 1200: score += 2.0
 
    pd = {p["name"]: p["value"] for p in f.get("protocol_distribution", [])}
    if pd.get("HTTPS", 0) >= 30: score += 2.0
 
    tb = f.get("total_bytes", 0)
    if 200_000 <= tb <= 1_500_000: score += 2.0
    return score
 
 
def _to_confidence(raw_score: float) -> int:
    pct = 50 + int(raw_score / 10 * 47)
    return max(50, min(97, pct))
 
 
def _variance(values):
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)
 