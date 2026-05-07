 Network-Fingerprint-Analyzerr
# Snoopy Net Sniffer — Network Packet Capture & Traffic Analyzer

A Flask-based web application for capturing live network traffic, analyzing packets,
extracting DNS and protocol information, generating traffic fingerprints, and visualizing
network behavior in real-time.

Built for Computer Networks and Cybersecurity learning purposes.

---

## Project Structure

```plaintext
cnproject/
├── app.py                 # Main Flask server & API routes
├── capture.py             # Live packet sniffing using Scapy
├── extract.py             # Packet feature extraction
├── fingerprint.py         # Traffic fingerprint generation
├── classify.py            # Traffic behavior classification
├── utils.py               # Helper utility functions
├── requirements.txt       # Python dependencies
├── static/
│   ├── index.html         # Frontend UI
│   ├── style.css          # Styling
│   └── app.js             # Frontend logic & API calls
└── captures/
    └── *.pcap             # Captured packet files
```

---

# Features

- Live packet sniffing using Scapy
- DNS query extraction
- Protocol distribution analysis
- Packet size histogram generation
- Traffic timeline visualization
- Inter-arrival time analysis
- Traffic fingerprint generation
- Rule-based traffic behavior detection
- Real-time frontend visualization
- REST API support

---

# Setup & Installation

## 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## 2. Run the Flask Server

### Linux/macOS

```bash
sudo python app.py
```

### Windows

Run terminal as Administrator:

```cmd
python app.py
```

> Administrator/root privileges are required for live packet sniffing.

---

## 3. Open the Application

Navigate to:

```plaintext
http://localhost:5000
```

---

# API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze` | Analyze network traffic for one website |
| POST | `/api/compare` | Compare traffic fingerprints of two websites |

---

# Example API Requests

## `/api/analyze`

### Request Body

```json
{
  "url": "https://example.com"
}
```

---

## `/api/compare`

### Request Body

```json
{
  "url1": "https://google.com",
  "url2": "https://youtube.com"
}
```

---

# Captured Traffic Features

The system extracts:

- Total packets
- Total bytes transferred
- Unique IP addresses
- DNS queries
- Protocol usage
- Packet size statistics
- Packet timing information
- Traffic duration
- Timeline traffic activity

---

# Behavior Labels

| Label | Indicators |
|-------|-------------|
| Streaming | Large packets, high byte traffic, UDP activity |
| Social Media | Multiple DNS requests, mixed protocols |
| API Heavy | Small fast packets, HTTPS dominant |
| Static Content | Few packets, low DNS activity |
| Suspicious | Abnormal traffic behavior detected |
| Unknown | No strong pattern identified |

---

# Fingerprint Output Example

```json
{
  "site_url": "https://example.com",
  "capture_timestamp": "2026-05-06T12:00:00Z",
  "total_packets": 320,
  "total_bytes": 245000,
  "top_protocol": "TCP",
  "unique_ip_count": 12,
  "dns_queries": [
    "google.com",
    "cdn.example.com"
  ],
  "mean_packet_size": 765.2,
  "max_packet_size": 1500,
  "mean_iat_ms": 11.4,
  "duration_seconds": 9.8,
  "protocol_distribution": {
    "TCP": 68,
    "UDP": 22,
    "DNS": 10
  },
  "behavior_label": "Streaming",
  "behavior_confidence": 84
}
```

---

# Technology Stack

| Component | Role |
|-----------|------|
| Python 3.x | Backend language |
| Flask | Web server & REST APIs |
| Scapy | Packet sniffing and analysis |
| HTML/CSS/JavaScript | Frontend UI |
| Chart.js | Traffic visualization charts |
| JSON | Data exchange format |
| PCAP | Packet capture storage |

---

# Core Network Analysis Functions

The project includes:

- DNS Query Record (DNSQR) extraction
- Protocol distribution calculation
- Traffic vector normalization
- Packet inter-arrival timing
- Packet size histogram generation
- Traffic timeline analysis
- Safe DNS name decoding
- Traffic fingerprint creation

---

# Educational Purpose

This project helps students understand:

- Packet sniffing
- Network protocols
- DNS analysis
- Traffic behavior profiling
- Network fingerprinting
- Flask backend development
- REST API communication
- Real-time packet analysis

---

# Notes

- Packet capture requires administrator/root privileges.
- Traffic analysis is performed locally.
- The frontend communicates with Flask APIs using JSON.
- Charts update dynamically after analysis.
- Designed for Computer Networks coursework and demonstrations.

---

# Author

Computer Networks Project — Packet Sniffing & Traffic Fingerprinting System
