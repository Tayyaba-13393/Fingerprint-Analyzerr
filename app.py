
from flask import Flask, request, jsonify, send_from_directory
import os
 
from capture     import capture_traffic, PCAP_A, PCAP_B
from fingerprint import build_fingerprint, compare_fingerprints
 #Backend + Route
app = Flask(__name__, static_folder="static", template_folder="templates")
# ROUTE 1: Serve Frontend

@app.route("/")
def home():
    return send_from_directory("templates", "index.html")
 
 
# Serve static files (script.js etc.)
@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)
 
 # ROUTE 2: Analyze single site  (FR-1 → FR-5)
@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(force=True)
        url  = (data or {}).get("url", "").strip()
 
        if not url:
            return jsonify({"error": "No URL provided"}), 400
 
        # FR-2: Capture traffic → .pcap
        pcap_path = capture_traffic(url)
 
        # FR-3 + FR-4 + FR-5: extract → fingerprint → classify
        fingerprint = build_fingerprint(pcap_path, url)
 
        return jsonify(fingerprint)
 
    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ROUTE 3: Compare two sites  (FR-6)
@app.route("/api/compare", methods=["POST"])
def compare():
    try:
        data = request.get_json(force=True)
        url_a = (data or {}).get("urlA", "").strip()
        url_b = (data or {}).get("urlB", "").strip()
 
        if not url_a or not url_b:
            return jsonify({"error": "Two URLs are required"}), 400
 
        # Capture both sites
        pcap_a = capture_traffic(url_a, PCAP_A)
        pcap_b = capture_traffic(url_b, PCAP_B)
 
        # Build fingerprints
        fp_a = build_fingerprint(pcap_a, url_a)
        fp_b = build_fingerprint(pcap_b, url_b)
 
        # Diff
        diff = compare_fingerprints(fp_a, fp_b)
 
        return jsonify({"siteA": fp_a, "siteB": fp_b, "diff": diff})
 
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
 