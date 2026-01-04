import requests
import os
import sqlite3
import threading
import subprocess
from datetime import datetime
from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
import socket
import ipaddress

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "123"),
    ("admin", "1234"),
    ("root", "root"),
]
def check_default_password(ip):
    URLS = [
        f"http://{ip}:8080/",
        f"http://{ip}:8080/browser.html",
        f"http://{ip}:8080/videofeed"
    ]

    # 1️⃣ No authentication check
    for url in URLS:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                return "weak"
        except:
            pass

    # 2️⃣ Default credential check
    for url in URLS:
        for username, password in DEFAULT_CREDENTIALS:
            try:
                r = requests.get(
                    url,
                    auth=HTTPBasicAuth(username, password),
                    timeout=3
                )
                if r.status_code == 200:
                    return "weak"
            except:
                pass

    # 3️⃣ Authentication enforced
    return "strong"

HERE = os.path.dirname(__file__)
FRONTEND_DIR = os.path.abspath(os.path.join(HERE, "..", "frontend"))
DATA_DIR = os.path.abspath(os.path.join(HERE, "..", "data"))
DB_PATH = os.path.join(DATA_DIR, "iot_data.db")
LOGS_DIR = os.path.abspath(os.path.join(HERE, "..", "logs"))
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

def get_local_network_cidr():
    """
    Automatically detect current WiFi/LAN subnet
    Works on Windows, Linux, macOS
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)

DEFAULT_SCAN_CIDR = get_local_network_cidr()
API_PORT = int(os.getenv("API_PORT", "8000"))

app = FastAPI(title="IoT Analyzer Backend")

# Mount frontend static files
app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")
# Serve index.html at root
@app.get("/", response_class=HTMLResponse)
def index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    return HTMLResponse("<h1>Frontend not found</h1>", status_code=404)
NON_IOT_KEYWORDS = [
    "apple", "samsung", "xiaomi", "oneplus", "oppo", "vivo",
    "dell", "hp", "lenovo", "asus", "acer", "microsoft"
]
PORT_LABELS = {
    "8080": "HTTP Web Interface",
    "554": "RTSP Video Stream",
    "1883": "MQTT (Unencrypted)",
    "8883": "MQTT (TLS)",
    "23": "Telnet (Insecure)"
}
IOT_PORTS = ["80/tcp open", "8080/tcp open", "554/tcp open"]
# --- DB helpers ---
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Main devices table (SIMPLIFIED)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        ip TEXT PRIMARY KEY,
        mac TEXT,
        name TEXT,
        device_type TEXT,
        open_ports TEXT,
        security_issues TEXT,
        password_status TEXT,        
        risk_score REAL DEFAULT 0.0,
        risk_level TEXT DEFAULT 'Green',
        first_seen TIMESTAMP,
        last_seen TIMESTAMP
    )
    """)
    try:
        cur.execute("ALTER TABLE devices ADD COLUMN password_status TEXT")
    except sqlite3.OperationalError:
        pass 
    # Optional: keep risk history (GOOD for demo & judges)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS risk_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT,
        risk_score REAL,
        risk_level TEXT,
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    cur.close()
    conn.close()

init_db()
def clear_devices():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM devices")
    conn.commit()
    cur.close()
    conn.close()
import os
import requests

NVD_API_KEY = os.getenv("NVD_API_KEY")

def fetch_cves_from_nvd(keyword, limit=10):
    if not keyword:
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    headers = {
        "apiKey": NVD_API_KEY
    }

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit
    }

    response = requests.get(url, headers=headers, params=params, timeout=15)

    if response.status_code != 200:
        return []

    data = response.json()
    cves = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        descs = cve.get("descriptions", [])
        metrics = cve.get("metrics", {})

        summary = ""
        for d in descs:
            if d.get("lang") == "en":
                summary = d.get("value", "")

        cvss = 0.0
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]

        cves.append({
            "cve": cve.get("id"),
            "summary": summary,
            "cvss": cvss
        })
    return cves
def format_open_ports(open_ports):
    if not open_ports:
        return ""

    ports = open_ports.split(",")
    labeled = []

    for p in ports:
        label = PORT_LABELS.get(p, "Unknown Service")
        labeled.append(f"{p} – {label}")

    return ", ".join(labeled)

def ports_to_nvd_keywords(open_ports):
    if not open_ports:
        return []

    ports = set(open_ports.split(","))
    keywords = set()

    if "554" in ports:
        keywords.add("ip camera")

    if "8080" in ports:
        keywords.add("embedded web interface")

    if "1883" in ports or "8883" in ports:
        keywords.add("mqtt iot")

    return list(keywords)

def get_cves_for_device(open_ports):
    keywords = ports_to_nvd_keywords(open_ports)
    all_cves = []

    for kw in keywords:
        cves = fetch_cves_from_nvd(kw)
        all_cves.extend(cves)

    return all_cves

def device_type_from_cves(cves):
    if not cves:
        return "Unknown"

    text = " ".join(c["summary"].lower() for c in cves)

    if any(k in text for k in ["camera", "webcam", "rtsp", "video"]):
        return "IP Camera"

    if any(k in text for k in ["mqtt", "gateway", "broker"]):
        return "IoT Gateway / Sensor"

    if any(k in text for k in ["firmware", "embedded", "web interface"]):
        return "Embedded IoT Device"

    return "Unknown IoT"

def enhanced_device_name_from_cves(ip, hostname, open_ports, cves):
    """
    Generate a short, professional (max 2 words) device name
    """

    # Default
    name = "IoT Device"

    if cves:
        text = " ".join(c["summary"].lower() for c in cves)

        if "camera" in text or "webcam" in text:
            name = "IP Camera"

        elif "mqtt" in text or "gateway" in text:
            name = "IoT Gateway"

        elif "router" in text:
            name = "Network Router"

        elif "embedded" in text or "firmware" in text:
            name = "Embedded Device"

        elif "web interface" in text or "http" in text:
            name = "Web Device"

    # Optional hostname hint (still 2 words max)
    if hostname:
        h = hostname.lower()
        if "android" in h or "ipwebcam" in h:
            name = "IP Camera"

    return name

 
def security_issues_from_cves(cves):
    if not cves:
        return "No Known Risk"

    text = " ".join(c.get("summary", "").lower() for c in cves)

    # Highest-impact risks first (real-world priority)
    if any(k in text for k in [
        "remote code execution", "rce", "arbitrary code execution"
    ]):
        return "Remote Attack"

    if any(k in text for k in [
        "unauthenticated", "authentication bypass", "no authentication"
    ]):
        return "Unauthenticated Access"

    if any(k in text for k in [
        "default credential", "hardcoded credential", "hard-coded password"
    ]):
        return "Default Credentials"

    if any(k in text for k in [
        "command injection", "os command injection"
    ]):
        return "Command Injection"

    if any(k in text for k in [
        "buffer overflow", "memory corruption", "stack overflow", "heap overflow"
    ]):
        return "Memory Corruption"

    if any(k in text for k in [
        "information disclosure", "data leak", "sensitive information"
    ]):
        return "Information Leak"

    if any(k in text for k in [
        "firmware", "insecure update", "unsigned firmware"
    ]):
        return "Firmware Weakness"

    if any(k in text for k in [
        "xss", "cross-site scripting", "csrf"
    ]):
        return "Web Interface Flaw"

    if any(k in text for k in [
        "denial of service", "dos", "service crash"
    ]):
        return "Service Disruption"

    return "Security Exposure"
def security_solution_from_issue(issue):
    SOLUTIONS = {
        "Default Credentials": "Change default passwords and enable strong authentication",
        "Unauthenticated Access": "Enable authentication and restrict public access",
        "Remote Attack": "Update firmware and apply security patches",
        "Command Injection": "Sanitize inputs and update vulnerable firmware",
        "Memory Corruption": "Apply vendor firmware updates",
        "Information Leak": "Restrict sensitive data exposure",
        "Firmware Weakness": "Enable signed firmware updates",
        "Web Interface Flaw": "Secure web interface with authentication and HTTPS",
        "Service Disruption": "Limit exposed services and apply patches",
        "Security Exposure": "Review device configuration and harden services",
        "No Known Risk": "No action required"
    }

    return SOLUTIONS.get(issue, "Review device configuration")

def risk_from_cves(cves):
    if not cves:
        return 0.0, "Green"

    max_cvss = max(c["cvss"] for c in cves)

    if max_cvss >= 7.0:
        return max_cvss, "Red"
    elif max_cvss >= 4.0:
        return max_cvss, "Yellow"
    else:
        return max_cvss, "Green"


def calculate_device_status(first_seen, last_seen):
    """
    Status based on scan observation timestamps
    """
    now = datetime.utcnow()

    # Seen only once
    if first_seen == last_seen:
        return "New Device"

    # Seen recently (within last 15 minutes)
    if now - last_seen <= timedelta(minutes=15):
        return "Active"

    return "Offline"

_scan_status = { "status":"idle","started":None,"finished":None,"message":None }
_scan_lock = threading.Lock()
import re

def parse_nmap_grep(output):
    devices = []
    current_ip = None

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("Host:"):
            current_ip = line.split()[1]

        if "Ports:" in line and current_ip:
            open_ports = []
            ports_part = line.split("Ports:", 1)[1]
            for p in ports_part.split(","):
                if "/open/" in p or "/open|" in p or "/open" in p:
                    port = p.split("/")[0].strip()
                    open_ports.append(port)
            if open_ports:
                devices.append({
                    "ip": current_ip,
                    "open_ports": ",".join(open_ports)
                })
    return devices

# def is_non_iot_device(vendor: str):
#     if not vendor:
#         return False
#     vendor = vendor.lower()
#     return any(k in vendor for k in NON_IOT_KEYWORDS)
def upsert_device(device):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO devices (
            ip, name, device_type, open_ports,
            security_issues, password_status,
            risk_score, risk_level
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            name = excluded.name,
            device_type = excluded.device_type,
            open_ports = excluded.open_ports,
            security_issues = excluded.security_issues,
            password_status = excluded.password_status,
            risk_score = excluded.risk_score,
            risk_level = excluded.risk_level,
            last_seen = datetime('now')
    """, (
        device["ip"],
        device["name"],
        device["device_type"],
        device["open_ports"],
        device["security_issues"],
        device["password_status"],
        device["risk_score"],
        device["risk_level"]
    ))

    conn.commit()
    cur.close()
    conn.close()

# def add_vulnerability(device_ip, cve_id, summary, cvss):
#     conn = get_conn(); cur = conn.cursor()
#     cur.execute("INSERT INTO vulnerabilities (device_ip, cve_id, summary, cvss) VALUES (?,?,?,?)",(device_ip, cve_id, summary, cvss))
#     conn.commit(); cur.close(); conn.close()

def add_risk_history(device_ip, score, level):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO risk_history (device_ip, risk_score, risk_level) VALUES (?,?,?)",(device_ip, score, level))
    conn.commit(); cur.close(); conn.close()

# def infer_device_type(open_ports):
#     if not open_ports:
#         return "Unknown"

#     ports = set(open_ports.split(","))

#     if "554" in ports:
#         return "IP Camera"

#     if "1883" in ports or "8883" in ports:
#         return "IoT Sensor / Gateway"

#     if "8080" in ports:
#         return "IoT Web Device"

#     if ports.issubset({"80", "443"}):
#         return "General Purpose Device"

#     return "Unknown IoT"


# def infer_security_issues(open_ports):
#     issues = []
#     ports = set(open_ports.split(",")) if open_ports else set()

#     if "23" in ports:
#         issues.append("Telnet service enabled (clear-text credentials)")

#     if "8080" in ports:
#         issues.append("Unauthenticated web camera interface exposed")

#     if "554" in ports:
#         issues.append("RTSP video stream exposed (privacy risk)")

#     if "1883" in ports:
#         issues.append("MQTT service exposed without encryption")

#     if not issues:
#         return "No obvious security issues detected"

#     return "; ".join(issues)

# def calculate_risk(open_ports):
#     if not open_ports:
#         return 0, "Green"

#     score = len(open_ports.split(",")) * 10

#     if score >= 50:
#         return score, "Red"
#     elif score >= 30:
#         return score, "Yellow"
#     else:
#         return score, "Green"

def looks_like_personal_device(open_ports):
    """
    Returns True if the device looks like a laptop/phone
    based on exposed ports.
    """
    if not open_ports:
        return True  # no services → ignore

    ports = set(open_ports.split(","))

    # Only common web ports → laptop / phone
    if ports.issubset({"80", "443"}):
        return True

    return False

def run_nmap_scan(target_cidr=DEFAULT_SCAN_CIDR):
    if _scan_lock.locked():
        return { "ok": False, "message": "scan already running" }
    def worker():
        with _scan_lock:
            _scan_status["status"]="running"
            _scan_status["started"]=datetime.utcnow().isoformat()
            try:
                cmd = [
    "nmap",
    "-sS",
    "-p", "23,554,8080,1883,8883,5683,1900,5000",
    "-oG", "-",
    target_cidr
]
                p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
                out = p.stdout
                print("\n===== RAW NMAP OUTPUT =====")
                print(out)
                print("===== END RAW NMAP OUTPUT =====\n")
                devices = parse_nmap_grep(out)
                print("PARSED DEVICES:", devices)
                for d in devices:
                    ip = d["ip"]
                    open_ports = d["open_ports"]              
                    # Exclude gateway / hotspot IP
                    if ip.endswith(".1"):
                        continue
                    cves = get_cves_for_device(open_ports)
                    device_type = device_type_from_cves(cves)
                    hostname = ""   # we don’t have MAC-based hostname, so keep blank for now
                    name = enhanced_device_name_from_cves(
                        ip=ip,
                        hostname=hostname,
                        open_ports=open_ports,
                        cves=cves
                    )
                    # ✅ ALLOW IoT-style services even if phone/laptop
                    ALLOWED_IOT_PORTS = {"8080", "554", "1883", "8883"}
                    open_ports_display = format_open_ports(open_ports)
                    ports_set = set(open_ports.split(","))

                    if not ports_set.intersection(ALLOWED_IOT_PORTS):
                        continue  # truly personal device
                    auth_status = check_default_password(ip)
                    
                    issue = security_issues_from_cves(cves)
                    solution = security_solution_from_issue(issue)
                    
                    risk_score, risk_level = risk_from_cves(cves)
                    if auth_status == "weak":
                        password_status = "Weak Password"
                        solution = "password detected. Change it immediately."
                        risk_score = max(risk_score, 7.0)
                        risk_level = "Red"
                    else:
                        password_status = "Strong Password"
                        solution = "password detected.No problem"
                    row = {
                        "ip": ip,
                        "mac": "",
                        "name": name,
                        "device_type": device_type,
                        "open_ports": open_ports_display,
                        "security_issues": solution ,
                        "password_status": password_status,
                        "risk_score": risk_score,
                        "risk_level": risk_level
                    }

                    print("INSERTING INTO DB:", row)
                    upsert_device(row)
                    add_risk_history(ip, risk_score, risk_level)
                _scan_status["status"]="finished"
                _scan_status["finished"]=datetime.utcnow().isoformat()
                _scan_status["message"]="found {} devices".format(len(devices))
            except Exception as e:
                _scan_status["status"]="failed"
                _scan_status["finished"]=datetime.utcnow().isoformat()
                _scan_status["message"]=str(e)
    t = threading.Thread(target=worker, daemon=True); t.start()
    return { "ok": True, "message": "scan started" }

@app.get("/api/health")
def api_health():
    ok = os.path.exists(DB_PATH)
    return JSONResponse({"status":"ok","db_exists": ok, "scan": _scan_status})

@app.post("/api/scan/start")
def api_scan_start():
    res = run_nmap_scan()
    return JSONResponse(res)

@app.get("/api/scan/status")
def api_scan_status():
    return JSONResponse(_scan_status)

@app.get("/api/devices")
def api_devices():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""SELECT *
FROM devices
WHERE last_seen >= datetime('now', '-10 minutes')
ORDER BY last_seen DESC
""")
    rows = [dict(r) for r in cur.fetchall()]
    cur.close()
    conn.close()
    return JSONResponse(rows)
@app.get("/api/device-presence")
def get_device_presence():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            ip,
            name,
            device_type,
            first_seen,
            last_seen,
            CASE
                WHEN last_seen >= datetime('now', '-10 minutes') THEN 'Active'
                WHEN first_seen = last_seen THEN 'New Device'
                ELSE 'Offline'
            END as status
        FROM devices
        ORDER BY last_seen DESC
    """)

    rows = cur.fetchall()
    cur.close()
    conn.close()

    return [
        {
            "ip": r[0],
            "name": r[1],
            "type": r[2],
            "first_seen": r[3],
            "last_seen": r[4],
            "status": r[5]
        }
        for r in rows
    ]
@app.get("/api/risk-trend")
def api_risk_trend():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            strftime('%Y-%m-%d %H', ts) as time,
            AVG(risk_score) as avg_risk
        FROM risk_history
        GROUP BY time
        ORDER BY time ASC
        LIMIT 20
    """)

    rows = cur.fetchall()
    cur.close()
    conn.close()

    return [
        {
            "time": r[0],
            "avg_risk": round(r[1], 2) if r[1] else 0
        }
        for r in rows
    ]

@app.get("/api/risk")
def api_risk():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("""SELECT *
FROM devices
WHERE last_seen >= datetime('now', '-2 minutes')
ORDER BY last_seen DESC
""")
    rows = [dict(r) for r in cur.fetchall()]
    summary = {"Green":0,"Yellow":0,"Red":0}
    for r in rows:
        lvl = r.get("risk_level","Green")
        summary[lvl] = summary.get(lvl,0) + 1
    cur.close(); conn.close()
    return JSONResponse({"summary": summary, "devices": rows})

if __name__ == "__main__":
    import uvicorn
    print("Starting backend. Frontend served from ../frontend. Visit http://localhost:8000")
    uvicorn.run("app:app", host="0.0.0.0", port=API_PORT, reload=True)
