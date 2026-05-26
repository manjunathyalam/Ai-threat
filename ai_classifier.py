import json
import logging
from openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_fallback_analysis(detector_results, error_msg=None):
    """
    Generates a high-fidelity, contextual cybersecurity threat report
    simulating OpenAI output when the API is offline or unconfigured.
    """
    threat_score = detector_results.get("threat_score", 0)
    status = detector_results.get("status", "Clean")
    category_stats = detector_results.get("category_stats", {})
    severity_stats = detector_results.get("severity_stats", {})
    ip_stats = detector_results.get("ip_stats", {})
    
    # Initialize basic structure
    report = {
        "threat_level": status,
        "risk_score": threat_score,
        "technical_explanation": "",
        "mitre_attack": [],
        "recommendations": [],
        "soc_notes": ""
    }
    
    if threat_score == 0:
        report["technical_explanation"] = "Security scan completed successfully. No threat vectors, vulnerability indicators, or suspicious activity patterns were detected within the analyzed log data."
        report["mitre_attack"] = [{"tactic": "None", "technique": "No mapped techniques (Clean Logs)"}]
        report["recommendations"] = [
            "Maintain current security policies and regular log audits.",
            "Ensure log forwarding to SIEM is active and operational.",
            "Verify file integrity monitoring (FIM) configurations."
        ]
        report["soc_notes"] = "Log review shows routine traffic profile. No immediate action required. System marked as safe."
        return report

    # Tailor analysis based on detected threats
    explanations = []
    mitre_mappings = []
    recs = []
    
    # Check for specific categories
    has_sqli = "SQL Injection" in category_stats
    has_cmd = "Command Injection" in category_stats
    has_xss = "XSS Attempts" in category_stats
    has_malware = "Malware Indicators" in category_stats
    has_brute = "Brute Force Logs" in category_stats
    has_ip = "Suspicious IP" in category_stats
    has_port = "Port Scans" in category_stats
    
    # Build explanation
    if has_sqli:
        explanations.append(
            "An adversary attempted SQL Injection (SQLi) attacks by injecting SQL verbs (e.g., UNION SELECT, INFORMATION_SCHEMA access, or logical comparisons) into application input fields or query parameters. The objective appears to be unauthorized database exploration or credential extraction."
        )
        mitre_mappings.append({"tactic": "Initial Access / Credential Access", "technique": "T1190 - Exploit Public-Facing Application (SQL Injection)"})
        recs.extend([
            "Use parameterized SQL queries and prepared statements globally.",
            "Deploy a Web Application Firewall (WAF) with updated SQL injection inspection rules.",
            "Sanitize and validate all client-supplied inputs using a strict allowlist."
        ])
        
    if has_cmd:
        explanations.append(
            "Evidence of Command Injection was identified. The log entries show shell command delimiters (e.g., semi-colons, pipe symbols, or double-ampersands) coupled with system commands (e.g., 'cat /etc/passwd', 'id', or system administration binary calls). This indicates an attempt to compromise the operating system layer."
        )
        mitre_mappings.append({"tactic": "Execution", "technique": "T1059 - Command and Scripting Interpreter"})
        recs.extend([
            "Never pass unsanitized user inputs directly into system shell executes.",
            "Run application processes with minimum privileges (non-root service accounts).",
            "Enable AppArmor or SELinux policy enforcements to isolate shell access."
        ])

    if has_xss:
        explanations.append(
            "Cross-Site Scripting (XSS) payload patterns were detected. The log captures scripts, script tags, URL-encoded '<script>' elements, or javascript event handlers (e.g., 'onerror', 'onload') submitted in HTTP requests. This target vector aims to execute malicious scripts in the security context of client sessions."
        )
        mitre_mappings.append({"tactic": "Initial Access", "technique": "T1189 - Drive-by Compromise (XSS Insertion)"})
        recs.extend([
            "Apply contextual output encoding on the frontend UI prior to rendering any user content.",
            "Implement a robust Content Security Policy (CSP) blocking inline script execution.",
            "Enable HTTPOnly flags on authentication cookies to block XSS credential theft."
        ])

    if has_malware:
        explanations.append(
            "Malware footprint and ingress download commands were detected. The log captures utility commands (`curl -O`, `wget`) pulling shell scripts or binary binaries to temporary directories (`/tmp`), followed by execution commands (`chmod +x`). This is typical of automated botnet infections or post-exploitation droppers."
        )
        mitre_mappings.append({"tactic": "Execution / Command and Control", "technique": "T1105 - Ingress Tool Transfer (Downloader Scripts)"})
        recs.extend([
            "Restrict outbound internet access from production application servers (egress filtering).",
            "Mount temporary file systems (`/tmp`, `/var/tmp`) with the `noexec` option.",
            "Ensure endpoint detection and response (EDR) agent is monitoring execution paths."
        ])

    if has_brute:
        explanations.append(
            "An automated authentication attack (Brute Force / Dictionary profiling) was identified. The log sequences display numerous failed authentication responses ('Failed password', 'invalid user') targeting sshd or admin login panels, indicative of network scanning tools attempting to brute-force system login access."
        )
        mitre_mappings.append({"tactic": "Credential Access", "technique": "T1110.001 - Brute Force: Password Guessing"})
        recs.extend([
            "Enforce strong password complexity policies and Multi-Factor Authentication (MFA).",
            "Install and configure Fail2Ban or equivalent rate-limiting blocks on login routes.",
            "Disable SSH password-based authentication and enforce SSH keys only."
        ])

    if has_ip:
        bad_ips = [ip for ip in ip_stats if ip in KNOWN_BAD_IPS]
        explanations.append(
            f"Active traffic was intercepted from known threat intelligence indicators. The following suspicious IP address(es) were present: {', '.join(bad_ips)}. These IPs correspond to known scanning botnets, malicious TOR exit nodes, or Command & Control (C2) servers."
        )
        mitre_mappings.append({"tactic": "Command and Control / Reconnaissance", "technique": "T1589 - Gather Victim Identity Information"})
        recs.extend([
            "Immediately block the offending IP address(es) at the perimeter firewall layer.",
            "Audit all network traffic logs for historical sessions associated with the flagged IPs."
        ])

    if has_port:
        explanations.append(
            "Port scanning or network enumeration patterns were identified, characterized by sequential connection failures and connection-limit errors. This indicates an adversary conducting active reconnaissance to discover open listening ports and service versions."
        )
        mitre_mappings.append({"tactic": "Reconnaissance", "technique": "T1046 - Active Network Scanning"})
        recs.extend([
            "Enable port-knocking or restrict sensitive administration ports (SSH, RDP, Database) from public exposure.",
            "Configure firewall rules to dynamically block hosts exhibiting aggressive port scanning metrics."
        ])

    # General explanation filler if none of the above matched but score is high
    if not explanations:
        explanations.append(
            "A security threat was flagged based on anomalous log markers and rules. Indicators matching high-severity metrics were present, raising the threat profile to suspicious."
        )
        mitre_mappings.append({"tactic": "Anomalous Activity", "technique": "T1046 - Network Discovery / Unmapped Recon"})
        recs.append("Conduct manual inspection of log files for anomalies.")

    # Format technical explanation
    report["technical_explanation"] = " ".join(explanations)
    report["mitre_attack"] = mitre_mappings
    
    # Deduplicate recommendations and select top 4
    unique_recs = []
    for r in recs:
        if r not in unique_recs:
            unique_recs.append(r)
    report["recommendations"] = unique_recs[:5]
    
    # Build SOC Analyst Notes
    critical_count = severity_stats.get("Critical", 0)
    high_count = severity_stats.get("High", 0)
    
    api_key_note = " (Simulated Model Fallback)"
    if error_msg:
        api_key_note = f" (OpenAI API Error Fallback: {error_msg})"
        
    soc_text = f"ANALYSIS LEVEL: {status}{api_key_note}. "
    if critical_count > 0 or high_count > 0:
        soc_text += f"ALERT: High-severity vulnerabilities detected ({critical_count} critical, {high_count} high alerts). Immediate containment protocol recommended. "
        soc_text += "Action plan: 1. Isolate the target servers from public access. 2. Null-route the attacking IPs. 3. Back up and inspect target databases for SQL injection modifications. 4. Reset credentials for any accounts targeted in authentication logs."
    else:
        soc_text += "System exhibits low-to-medium risk. Recommend standard firewall policies, IP blacklisting of scanners, and routine log audits. No server compromises are immediately evident."
        
    report["soc_notes"] = soc_text
    
    return report

def analyze_logs_with_ai(detector_results, api_key=None):
    """
    Analyzes log results using OpenAI. If api_key is missing or a failure occurs,
    automatically falls back to generate_fallback_analysis.
    """
    if not api_key:
        logger.info("OpenAI API key not configured. Generating high-fidelity fallback analysis.")
        return generate_fallback_analysis(detector_results)
        
    try:
        # Initialize OpenAI Client
        client = OpenAI(api_key=api_key)
        
        # Prepare log summaries for OpenAI prompt
        total_lines = detector_results.get("total_lines", 0)
        threat_score = detector_results.get("threat_score", 0)
        status = detector_results.get("status", "Clean")
        category_stats = detector_results.get("category_stats", {})
        severity_stats = detector_results.get("severity_stats", {})
        alerts = detector_results.get("alerts", [])
        
        # Take a representitive sample of the alerts (up to 15) to minimize context size
        alert_samples = []
        for a in alerts[:15]:
            alert_samples.append({
                "line": a.get("line"),
                "category": a.get("category"),
                "severity": a.get("severity"),
                "ip": a.get("ip"),
                "evidence": a.get("evidence"),
                "raw_snippet": a.get("raw")
            })

        system_prompt = (
            "You are an expert SOC Analyst and Cyber Threat Intelligence AI. "
            "Analyze the provided log analysis metrics and raw alert snippets. "
            "Generate a highly detailed, professional cybersecurity report. "
            "You must return the response strictly as a JSON object with the following fields:\n"
            "{\n"
            "  \"threat_level\": \"Clean\" | \"Suspicious\" | \"Malicious\" | \"Critical\",\n"
            "  \"risk_score\": 0-100 (integer),\n"
            "  \"technical_explanation\": \"A detailed technical summary of what happened, mapping out attacker intentions and activity,\",\n"
            "  \"mitre_attack\": [ {\"tactic\": \"Tactic Name\", \"technique\": \"Txxxx - Technique Name\"} ],\n"
            "  \"recommendations\": [ \"Mitigation Step 1\", \"Mitigation Step 2\", ... ],\n"
            "  \"soc_notes\": \"Immediate tactical notes for a SOC analyst (e.g. block IP, isolate node)\"\n"
            "}\n"
            "Ensure the technical explanation is verbose and professional. Do not wrap code in markdown or triple backticks, output raw JSON."
        )

        user_content = {
            "overall_metrics": {
                "total_lines_scanned": total_lines,
                "initial_threat_score": threat_score,
                "initial_status": status,
                "alerts_by_category": category_stats,
                "alerts_by_severity": severity_stats
            },
            "alert_examples": alert_samples
        }

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_content)}
            ],
            response_format={"type": "json_object"},
            temperature=0.2
        )
        
        raw_response = response.choices[0].message.content
        parsed = json.loads(raw_response)
        
        # Verify keys are present, if not throw to fall back
        required_keys = ["threat_level", "risk_score", "technical_explanation", "mitre_attack", "recommendations", "soc_notes"]
        for key in required_keys:
            if key not in parsed:
                raise ValueError(f"Missing required key in AI response: {key}")
                
        return parsed
        
    except Exception as e:
        logger.error(f"OpenAI API analysis failed: {str(e)}. Falling back to local analytics engine.")
        return generate_fallback_analysis(detector_results, error_msg=str(e))
