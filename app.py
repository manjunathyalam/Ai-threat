import os
import json
import sqlite3
import random
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Import our custom detector and AI classifier
from detector import parse_log_file, KNOWN_BAD_IPS
from ai_classifier import analyze_logs_with_ai

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "cyber_sec_super_secret_key_2026")
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
app.config["DATABASE"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")
app.config["SETTINGS_FILE"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")

# Ensure required directories exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Helper function to get database connection
def get_db():
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn

# Initialize Database Schema
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            total_lines INTEGER NOT NULL,
            threat_score INTEGER NOT NULL,
            status TEXT NOT NULL,
            alerts_count INTEGER NOT NULL,
            detector_results TEXT NOT NULL,
            ai_report TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Load settings from file or initialize defaults
def load_settings():
    if os.path.exists(app.config["SETTINGS_FILE"]):
        try:
            with open(app.config["SETTINGS_FILE"], "r") as f:
                return json.load(f)
        except Exception:
            pass
    
    # Defaults
    defaults = {
        "openai_api_key": os.getenv("OPENAI_API_KEY", ""),
        "alert_threshold": 25,
        "auto_ai_scan": True,
        "packet_monitoring_speed": "medium"
    }
    save_settings(defaults)
    return defaults

def save_settings(settings):
    try:
        with open(app.config["SETTINGS_FILE"], "w") as f:
            json.dump(settings, f, indent=4)
        return True
    except Exception:
        return False

# Initialize DB on startup
init_db()

# Login Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# --- WEB TEMPLATE ROUTES ---

@app.route("/")
@login_required
def index():
    return render_template("dashboard.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("index"))
        
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Static Creds for SOC Portal Demo
        if username == "admin" and password == "cybersecurity2026":
            session["logged_in"] = True
            session["username"] = username
            session["login_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return redirect(url_for("index"))
        else:
            error = "Access Denied: Invalid Security Credentials."
            
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- REST API ENDPOINTS ---

@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def handle_settings():
    settings = load_settings()
    if request.method == "POST":
        data = request.json or {}
        
        # If API key is masked and unchanged, retain original key
        new_key = data.get("openai_api_key", "").strip()
        if new_key.startswith("sk-") and new_key.endswith("••••"):
            # Retain original key from settings
            pass
        else:
            settings["openai_api_key"] = new_key
            
        settings["alert_threshold"] = int(data.get("alert_threshold", 25))
        settings["auto_ai_scan"] = bool(data.get("auto_ai_scan", True))
        settings["packet_monitoring_speed"] = data.get("packet_monitoring_speed", "medium")
        
        save_settings(settings)
        return jsonify({"success": True, "message": "Settings updated successfully."})
        
    # GET - Return settings with masked API key
    key = settings.get("openai_api_key", "")
    masked_key = ""
    if key:
        masked_key = f"{key[:6]}••••••••••••••••{key[-4:]}" if len(key) > 10 else "••••••••••••"
        
    return jsonify({
        "openai_api_key": masked_key,
        "alert_threshold": settings.get("alert_threshold", 25),
        "auto_ai_scan": settings.get("auto_ai_scan", True),
        "packet_monitoring_speed": settings.get("packet_monitoring_speed", "medium")
    })

@app.route("/api/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
        
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
        
    allowed_extensions = {"txt", "log", "csv", "json"}
    ext = file.filename.split(".")[-1].lower() if "." in file.filename else ""
    if ext not in allowed_extensions:
        return jsonify({"error": f"File type .{ext} not supported. Allowed formats: .txt, .log, .csv, .json"}), 400
        
    # Save the file securely
    filename = secure_filename(file.filename)
    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    saved_filename = f"{timestamp_str}_{filename}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], saved_filename)
    file.save(filepath)
    
    # 1. Parse using rule-based detector
    detector_results = parse_log_file(filepath)
    
    # Check for parser errors
    if "error" in detector_results:
        return jsonify({"error": detector_results["error"]}), 500
        
    # 2. Get OpenAI key and run AI classifier
    settings = load_settings()
    api_key = settings.get("openai_api_key", "")
    
    ai_report = analyze_logs_with_ai(detector_results, api_key=api_key)
    
    # 3. Save report to database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO reports (filename, timestamp, total_lines, threat_score, status, alerts_count, detector_results, ai_report)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        filename,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        detector_results["total_lines"],
        ai_report.get("risk_score", detector_results["threat_score"]),
        ai_report.get("threat_level", detector_results["status"]),
        detector_results["alerts_count"],
        json.dumps(detector_results),
        json.dumps(ai_report)
    ))
    conn.commit()
    report_id = cursor.lastrowid
    conn.close()
    
    # Clean up uploaded file to save disk space
    try:
        os.remove(filepath)
    except Exception:
        pass
        
    return jsonify({
        "id": report_id,
        "filename": filename,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_lines": detector_results["total_lines"],
        "threat_score": ai_report.get("risk_score", detector_results["threat_score"]),
        "status": ai_report.get("threat_level", detector_results["status"]),
        "alerts_count": detector_results["alerts_count"],
        "detector_results": detector_results,
        "ai_report": ai_report
    })

@app.route("/api/reports", methods=["GET"])
@login_required
def get_reports():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, filename, timestamp, total_lines, threat_score, status, alerts_count FROM reports ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    
    reports = []
    for r in rows:
        reports.append({
            "id": r["id"],
            "filename": r["filename"],
            "timestamp": r["timestamp"],
            "total_lines": r["total_lines"],
            "threat_score": r["threat_score"],
            "status": r["status"],
            "alerts_count": r["alerts_count"]
        })
    return jsonify(reports)

@app.route("/api/reports/<int:report_id>", methods=["GET"])
@login_required
def get_report_detail(report_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Report not found"}), 404
        
    return jsonify({
        "id": row["id"],
        "filename": row["filename"],
        "timestamp": row["timestamp"],
        "total_lines": row["total_lines"],
        "threat_score": row["threat_score"],
        "status": row["status"],
        "alerts_count": row["alerts_count"],
        "detector_results": json.loads(row["detector_results"]),
        "ai_report": json.loads(row["ai_report"])
    })

@app.route("/api/reports/<int:report_id>/delete", methods=["DELETE"])
@login_required
def delete_report(report_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Report deleted successfully."})

# Wireshark packet capture simulation data
PACKET_DESCRIPTIONS = [
    ("TCP", "80", "443", "HTTP/HTTPS Request [GET /index.php]"),
    ("TCP", "52144", "22", "SSH Connection Initial Handshake [SYN]"),
    ("TCP", "22", "52144", "SSH Response [SYN, ACK]"),
    ("UDP", "53", "61902", "DNS Query Response - host.com A 192.0.2.1"),
    ("UDP", "61902", "53", "DNS Query - host.com A"),
    ("TCP", "443", "50121", "HTTPS TLSv1.3 Encrypted Handshake"),
    ("TCP", "8080", "1920", "Apache Tomcat Admin scan attempts"),
    ("ICMP", "0", "0", "ICMP Echo Request (Ping)"),
    ("ICMP", "8", "0", "ICMP Echo Reply"),
    ("TCP", "3306", "51242", "MySQL Connection Established"),
    ("TCP", "51242", "3306", "MySQL Query [SELECT * FROM admin]")
]

@app.route("/api/packets", methods=["GET"])
@login_required
def get_live_packets():
    """Generates a list of simulated live network packets (Wireshark-like stream)"""
    count = int(request.args.get("count", 15))
    packets = []
    
    # Seed IPs
    external_ips = ["185.220.101.5", "45.142.195.12", "198.51.100.42", "8.8.8.8", "1.1.1.1", "172.217.16.142", "203.0.113.110"]
    internal_ips = ["192.168.1.50", "192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.15", "10.0.0.24"]
    
    now = datetime.now()
    
    for i in range(count):
        # Decide if this packet is malicious/suspicious
        is_suspicious = random.random() < 0.15
        
        # Pick IPs
        if is_suspicious:
            src = random.choice([ip for ip in external_ips if ip in KNOWN_BAD_IPS])
            dest = random.choice(internal_ips)
            proto, sport, dport, info = random.choice([
                ("TCP", "41902", "22", "Brute Force SSH Attempt: invalid user root"),
                ("TCP", "51221", "3306", "SQLi Probe: UNION SELECT detected on Port 3306"),
                ("TCP", "60214", "80", "HTTP Scan: Command injection query - id; cat /etc/passwd"),
                ("UDP", "49201", "53", "DNS amplification packet attack"),
                ("TCP", "3340", "8080", "Apache Tomcat administration directory traverse scan")
            ])
            len_bytes = random.randint(1200, 1500)
        else:
            if random.random() < 0.5:
                src = random.choice(internal_ips)
                dest = random.choice(external_ips)
            else:
                src = random.choice(external_ips)
                dest = random.choice(internal_ips)
            proto, sport, dport, info = random.choice(PACKET_DESCRIPTIONS)
            len_bytes = random.randint(40, 1000)
            
        time_offset = now.strftime("%H:%M:%S.") + f"{random.randint(100, 999)}"
        
        packets.append({
            "time": time_offset,
            "source": src,
            "destination": dest,
            "protocol": proto,
            "length": len_bytes,
            "info": info,
            "sport": sport,
            "dport": dport,
            "suspicious": is_suspicious
        })
        
    return jsonify(packets)

@app.route("/api/virustotal", methods=["POST"])
@login_required
def handle_vt_scan():
    """VirusTotal style reputation lookups for IP, Domain, Hash, URL"""
    data = request.json or {}
    query_type = data.get("type", "ip")  # ip, domain, hash, url
    query_val = data.get("value", "").strip()
    
    if not query_val:
        return jsonify({"error": "Query value is empty"}), 400
        
    # Generate realistic, dynamic reputation details
    is_malicious = False
    details = {}
    
    # 1. Check against known threat intelligence
    if query_type == "ip":
        if query_val in KNOWN_BAD_IPS:
            is_malicious = True
            details = {
                "intel_source": "ThreatIntel Central",
                "classification": KNOWN_BAD_IPS[query_val],
                "country": random.choice(["Russian Federation", "China", "Netherlands", "Seychelles"]),
                "isp": "Virtual Server Network Provider",
                "hostname": "scannode.threatnet.org"
            }
        else:
            # Clean IP lookup
            details = {
                "intel_source": "Clean / Unlisted",
                "classification": "None",
                "country": "United States" if query_val.startswith("8.8.") or query_val.startswith("1.1.") else random.choice(["United States", "Germany", "Japan", "United Kingdom"]),
                "isp": "Google LLC" if query_val.startswith("8.8.") else "Cloudflare Inc." if query_val.startswith("1.1.") else "Standard ISP Services",
                "hostname": "dns.google" if query_val.startswith("8.8.") else "one.one.one.one" if query_val.startswith("1.1.") else "host.net-provider.com"
            }
            
    elif query_type == "domain":
        malicious_domains = ["evil-malware-download.com", "c2-control-server.net", "attacker-portal.org", "phishing-bank-login.icu"]
        if query_val.lower() in malicious_domains or any(m in query_val.lower() for m in malicious_domains):
            is_malicious = True
            details = {
                "registrar": "NameCheap, Inc. (Abuse Shielded)",
                "created_date": "2026-02-12 (Active 3 Months)",
                "resolved_ips": [random.choice(list(KNOWN_BAD_IPS.keys())), "198.51.100.10"],
                "categories": ["Malware Distribution", "C2 Infrastructure"]
            }
        else:
            details = {
                "registrar": "MarkMonitor, Inc." if "google" in query_val.lower() else "GoDaddy.com, LLC",
                "created_date": "1997-09-15" if "google" in query_val.lower() else "2010-05-20",
                "resolved_ips": ["142.250.190.46"] if "google" in query_val.lower() else ["104.244.42.1"],
                "categories": ["Technology", "Information Portal"]
            }
            
    elif query_type == "hash":
        # Check standard length md5/sha256
        malicious_hashes = [
            "44d88612fe831b81357c7378d46ad9d9",  # WannaCry md5
            "5e724b2e212fd26e85573426e2572e88b8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8" # mock sha256
        ]
        if query_val.lower() in malicious_hashes or len(query_val) == 32 and query_val.endswith("00"):
            is_malicious = True
            details = {
                "file_type": "Win32 EXE (Executable)",
                "file_size": "3.5 MB",
                "threat_name": "Trojan.Generic.CobaltStrike.A",
                "first_seen": "2025-11-04",
                "entropy": "7.95 (High - Packed/Encrypted)"
            }
        else:
            details = {
                "file_type": "Document PDF",
                "file_size": "245 KB",
                "threat_name": "None (Clean File)",
                "first_seen": "2026-01-20",
                "entropy": "4.21 (Normal)"
            }
            
    elif query_type == "url":
        if "evil" in query_val.lower() or "malware" in query_val.lower() or "phish" in query_val.lower() or "wp-admin" in query_val.lower():
            is_malicious = True
            details = {
                "http_status": 200,
                "server": "nginx/1.18.0",
                "payload_delivered": "exploit_kit.js",
                "categories": ["Phishing", "Exploit Kit Gateway"]
            }
        else:
            details = {
                "http_status": 200,
                "server": "gws (Google Web Server)",
                "payload_delivered": "None",
                "categories": ["Search Engine"]
            }
            
    # Calculate score
    if is_malicious:
        positives = random.randint(35, 68)
        negatives = 75 - positives
        reputation = "Malicious"
        risk_score = random.randint(75, 98)
    else:
        # Check if suspicious (simulate some low detection rates)
        is_suspicious = random.random() < 0.1 and not query_val.startswith("8.8.") and not "google" in query_val.lower()
        if is_suspicious:
            positives = random.randint(1, 4)
            negatives = 75 - positives
            reputation = "Suspicious"
            risk_score = random.randint(25, 45)
        else:
            positives = 0
            negatives = 75
            reputation = "Clean"
            risk_score = 0
            
    return jsonify({
        "value": query_val,
        "type": query_type,
        "reputation": reputation,
        "risk_score": risk_score,
        "engines_flagged": positives,
        "engines_clean": negatives,
        "engines_total": 75,
        "details": details,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
