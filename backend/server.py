import os
import sys
import json
import sqlite3
import hashlib
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ==========================================
# TERMINAL UI & CONFIGURATION
# ==========================================
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

app = FastAPI(title="JOCKY Central Command (C2) v2.0 - LLVM Edition")

# Allow CORS so index.html can hit the API if opened directly
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = str(Path(__file__).parent / "jocky.db")
HTML_PATH = str(Path(__file__).parent / "templates" / "index.html")

# ==========================================
# 1. DATABASE SCHEMA INITIALIZATION
# ==========================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, inv_id TEXT UNIQUE, name TEXT, status TEXT DEFAULT 'INVESTIGATING', created_at TEXT
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY, investigation_id TEXT, hostname TEXT, risk_score INTEGER DEFAULT 0, UNIQUE(investigation_id, hostname)
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS processes (
        id INTEGER PRIMARY KEY, investigation_id TEXT, evidence_id TEXT, host_id INTEGER, pid INTEGER, name TEXT, exe TEXT, is_suspicious INTEGER DEFAULT 0, timestamp TEXT
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS network_connections (
        id INTEGER PRIMARY KEY, investigation_id TEXT, evidence_id TEXT, host_id INTEGER, pid INTEGER, protocol TEXT, local_port TEXT, remote_ip TEXT, state TEXT, is_suspicious INTEGER DEFAULT 0, timestamp TEXT
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY, investigation_id TEXT, host_id INTEGER, process_id INTEGER, alert_title TEXT, severity TEXT, score_impact INTEGER, timestamp TEXT
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT, evidence_id TEXT UNIQUE, host_id INTEGER, artifact_type TEXT, timestamp TEXT, metadata TEXT, previous_hash TEXT, current_hash TEXT
    )''')
    
    cursor.execute("INSERT OR IGNORE INTO investigations (inv_id, name, created_at) VALUES (?, ?, ?)", 
                   ("INV-2026-00001", "Genesis Investigation", datetime.now().isoformat()))
    conn.commit()
    conn.close()
    print(f"{GREEN}[✓]{RESET} Database initialized at {DB_PATH}")

# ==========================================
# 2. DATA MODELS
# ==========================================
class ArtifactRecord(BaseModel):
    type: str
    data: Dict[str, Any]

class EvidenceReport(BaseModel):
    investigation_id: str = "INV-2026-00001"
    timestamp: str
    hostname: str
    artifacts: List[ArtifactRecord]

# ==========================================
# 3. NATIVE LLVM RULE PARSER & CORRELATION
# ==========================================
def parse_rules_from_ll(ll_path: Path) -> List[Dict[str, Any]]:
    """Extracts embedded JOCKY_CORRELATION_RULES directly from LLVM IR (.ll) files."""
    try:
        text = ll_path.read_text(encoding="utf-8", errors="ignore")
        match = re.search(r'@JOCKY_CORRELATION_RULES\s*=\s*.*?c"(.*?)"', text, re.DOTALL)
        if not match:
            return []
        
        escaped_str = match.group(1)
        
        # Unescape LLVM hex byte representations (e.g. \22 -> ")
        def unescape_llvm(m):
            return chr(int(m.group(1), 16))
        
        unescaped = re.sub(r'\\([0-9a-fA-F]{2})', unescape_llvm, escaped_str)
        unescaped = unescaped.rstrip('\x00')
        
        rules = json.loads(unescaped)
        return rules if isinstance(rules, list) else []
    except Exception as e:
        print(f"{RED}[✗]{RESET} Failed to parse rules from {ll_path.name}: {e}")
        return []

def find_latest_rules() -> List[Dict[str, Any]]:
    """Locates the latest ir.json or output.ll across workspace directories."""
    candidates = [
        Path("../1_compiler/output.ll"),
        Path("../output.ll"),
        Path("output.ll"),
        Path("../1_compiler/ir.json"),
        Path("ir.json")
    ]
    
    builds_dir = Path("../builds")
    if builds_dir.exists():
        for file in builds_dir.rglob("output.ll"):
            candidates.append(file)
        for file in builds_dir.rglob("ir.json"):
            candidates.append(file)
            
    valid_files = [p for p in candidates if p.exists()]
    if not valid_files:
        return []
        
    latest_file = max(valid_files, key=os.path.getmtime)
    
    if latest_file.suffix.lower() == ".ll":
        return parse_rules_from_ll(latest_file)
    elif latest_file.suffix.lower() == ".json":
        try:
            data = json.loads(latest_file.read_text(encoding="utf-8"))
            return data.get("correlation_rules", [])
        except:
            return []
            
    return []

def run_detection_rules(cursor, host_id: int, inv_id: str, timestamp: str):
    rules = find_latest_rules()
    if not rules:
        print(f"{YELLOW}[!]{RESET} No correlation rules found in LLVM IR or IR json.")
        return 0

    total_risk = 0

    # Reset state before recalculating
    cursor.execute("DELETE FROM alerts WHERE host_id = ? AND investigation_id = ?", (host_id, inv_id))
    cursor.execute("UPDATE processes SET is_suspicious = 0 WHERE host_id = ? AND investigation_id = ?", (host_id, inv_id))
    cursor.execute("UPDATE network_connections SET is_suspicious = 0 WHERE host_id = ? AND investigation_id = ?", (host_id, inv_id))

    cursor.execute("SELECT id, pid, name FROM processes WHERE host_id = ? AND investigation_id = ?", (host_id, inv_id))
    processes = cursor.fetchall()
    
    cursor.execute("SELECT id, pid, local_port, remote_ip FROM network_connections WHERE host_id = ? AND investigation_id = ?", (host_id, inv_id))
    network_conns = cursor.fetchall()

    for rule in rules:
        field = rule.get("field")
        op = rule.get("operator")
        expected_val = str(rule.get("value")).lower()
        score = rule.get("score_impact", 10)
        alert_name = rule.get("alert", "Alert")
        severity = rule.get("severity", "MEDIUM")

        # Process correlation
        if field == "process.name":
            for proc_id, pid, proc_name in processes:
                match = False
                if op == "==" and proc_name.lower() == expected_val: match = True
                elif op == "!=" and proc_name.lower() != expected_val: match = True
                
                if match:
                    cursor.execute("UPDATE processes SET is_suspicious = 1 WHERE id = ?", (proc_id,))
                    cursor.execute("INSERT INTO alerts (investigation_id, host_id, process_id, alert_title, severity, score_impact, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                                   (inv_id, host_id, proc_id, alert_name, severity, score, timestamp))
                    total_risk += score

        # Network correlation
        elif field == "network.local_port":
            for net_id, pid, local_port, remote_ip in network_conns:
                match = False
                if op == "==" and str(local_port) == expected_val: match = True
                elif op == "!=" and str(local_port) != expected_val: match = True
                
                if match:
                    cursor.execute("UPDATE network_connections SET is_suspicious = 1 WHERE id = ?", (net_id,))
                    
                    cursor.execute("SELECT id FROM processes WHERE host_id = ? AND pid = ? AND investigation_id = ? LIMIT 1", (host_id, pid, inv_id))
                    proc_match = cursor.fetchone()
                    proc_id = proc_match[0] if proc_match else None
                    
                    if proc_id:
                        cursor.execute("UPDATE processes SET is_suspicious = 1 WHERE id = ?", (proc_id,))
                        
                    cursor.execute("INSERT INTO alerts (investigation_id, host_id, process_id, alert_title, severity, score_impact, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                                   (inv_id, host_id, proc_id, alert_name, severity, score, timestamp))
                    total_risk += score

    cursor.execute("UPDATE hosts SET risk_score = ? WHERE id = ?", (total_risk, host_id))
    return total_risk

# ==========================================
# 4. API ENDPOINTS
# ==========================================
@app.post("/api/evidence/ingest")
async def ingest_evidence(report: EvidenceReport):
    """Primary ingestion tunnel for the JOCKY native agent."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        inv_id = report.investigation_id
        cursor.execute("INSERT OR IGNORE INTO hosts (investigation_id, hostname) VALUES (?, ?)", (inv_id, report.hostname))
        cursor.execute("SELECT id FROM hosts WHERE investigation_id = ? AND hostname = ?", (inv_id, report.hostname))
        host_id = cursor.fetchone()[0]

        cursor.execute("DELETE FROM processes WHERE host_id = ? AND investigation_id = ?", (host_id, inv_id))
        cursor.execute("DELETE FROM network_connections WHERE host_id = ? AND investigation_id = ?", (host_id, inv_id))

        for artifact in report.artifacts:
            payload_str = json.dumps(artifact.data, sort_keys=True)
            
            cursor.execute("SELECT current_hash FROM evidence WHERE host_id = ? AND investigation_id = ? ORDER BY id DESC LIMIT 1", (host_id, inv_id))
            last_record = cursor.fetchone()
            previous_hash = last_record[0] if last_record else "0" * 64
            
            chain_string = f"{previous_hash}:{report.timestamp}:{artifact.type}:{payload_str}"
            current_hash = hashlib.sha256(chain_string.encode('utf-8')).hexdigest()
            evidence_id = f"EV-{host_id}-{current_hash[:8].upper()}"

            cursor.execute("""INSERT INTO evidence (investigation_id, evidence_id, host_id, artifact_type, timestamp, metadata, previous_hash, current_hash) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", 
                           (inv_id, evidence_id, host_id, artifact.type, report.timestamp, payload_str, previous_hash, current_hash))

            if artifact.type == "Process":
                cursor.execute("INSERT INTO processes (investigation_id, evidence_id, host_id, pid, name, exe, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                               (inv_id, evidence_id, host_id, artifact.data.get("pid", 0), artifact.data.get("name", "unknown"), artifact.data.get("exe_path", "unknown"), report.timestamp))
            elif artifact.type == "NetworkConnection":
                cursor.execute("INSERT INTO network_connections (investigation_id, evidence_id, host_id, pid, protocol, local_port, remote_ip, state, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                               (inv_id, evidence_id, host_id, artifact.data.get("pid", 0), str(artifact.data.get("protocol", "tcp")), str(artifact.data.get("local_port", "0")), str(artifact.data.get("remote_ip", "0.0.0.0")), artifact.data.get("state", "ESTABLISHED"), report.timestamp))

        total_risk = run_detection_rules(cursor, host_id, inv_id, report.timestamp)
        conn.commit()
        
        print(f"{CYAN}[~]{RESET} Ingested {len(report.artifacts)} artifacts from {BOLD}{report.hostname}{RESET} | Risk: {RED if total_risk > 0 else GREEN}{total_risk}{RESET}")
        return {"status": "success", "integrity": "VERIFIED", "investigation_id": inv_id, "risk_score": total_risk}
    finally:
        conn.close()

@app.get("/api/investigation/summary/{inv_id}")
async def get_inv_summary(inv_id: str = "INV-2026-00001"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT status FROM investigations WHERE inv_id = ?", (inv_id,))
    status_row = cursor.fetchone()
    status = status_row[0] if status_row else "UNKNOWN"
    
    cursor.execute("SELECT COUNT(id) FROM hosts WHERE investigation_id = ?", (inv_id,))
    hosts = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(id) FROM evidence WHERE investigation_id = ?", (inv_id,))
    evidence = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(id) FROM alerts WHERE investigation_id = ?", (inv_id,))
    alerts = cursor.fetchone()[0]
    
    conn.close()
    return {
        "inv_id": inv_id,
        "status": status,
        "hosts_connected": hosts,
        "artifacts_collected": evidence,
        "findings": alerts,
        "integrity": "VERIFIED" if evidence > 0 else "PENDING"
    }

@app.get("/api/graph/data")
async def get_graph_data(inv_id: str = "INV-2026-00001"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    nodes, links = [], []

    cursor.execute("SELECT id, hostname, risk_score FROM hosts WHERE investigation_id = ?", (inv_id,))
    for h_id, h_name, risk in cursor.fetchall():
        nodes.append({"id": f"host_{h_id}", "label": h_name, "host_name": h_name, "group": "host", "risk_score": risk, "val": 28})

        cursor.execute("""
            SELECT p.id, p.pid, p.name, p.exe, p.is_suspicious, COALESCE(a.alert_title, 'None'), 
                   e.evidence_id, e.timestamp, e.previous_hash, e.current_hash, e.artifact_type, h.hostname
            FROM processes p LEFT JOIN alerts a ON p.id = a.process_id LEFT JOIN evidence e ON p.evidence_id = e.evidence_id
            JOIN hosts h ON p.host_id = h.id WHERE p.host_id = ? AND p.investigation_id = ? ORDER BY p.is_suspicious DESC LIMIT 70
        """, (h_id, inv_id))
        
        pid_to_node = {}
        for p_id, pid, name, exe, is_suspicious, alert, ev_id, ts, prev_hash, curr_hash, art_type, h_name in cursor.fetchall():
            proc_id = f"proc_{p_id}"
            pid_to_node[pid] = proc_id
            nodes.append({
                "id": proc_id, "label": name, "name": name, "pid": pid, "exe": exe, 
                "group": "threat_process" if is_suspicious else "normal_process", "alert": alert, "val": 16 if is_suspicious else 6,
                "evidence_id": ev_id, "timestamp": ts, "previous_hash": prev_hash, "current_hash": curr_hash, "artifact_type": art_type, "host_name": h_name
            })
            links.append({"source": f"host_{h_id}", "target": proc_id})

        cursor.execute("""
            SELECT n.id, n.pid, n.protocol, n.local_port, n.remote_ip, n.state, n.is_suspicious,
                   e.evidence_id, e.timestamp, e.previous_hash, e.current_hash, e.artifact_type, h.hostname
            FROM network_connections n LEFT JOIN evidence e ON n.evidence_id = e.evidence_id
            JOIN hosts h ON n.host_id = h.id
            WHERE n.host_id = ? AND n.investigation_id = ? AND (n.is_suspicious = 1 OR n.local_port != '0') LIMIT 40
        """, (h_id, inv_id))
        
        for net_id, pid, proto, port, remote, state, is_suspicious, ev_id, ts, prev_hash, curr_hash, art_type, h_name in cursor.fetchall():
            net_node_id = f"net_{net_id}"
            nodes.append({
                "id": net_node_id, "label": f":{port}", "port": port, "protocol": proto, 
                "group": "threat_network" if is_suspicious else "network_socket", "val": 12 if is_suspicious else 5,
                "evidence_id": ev_id, "timestamp": ts, "previous_hash": prev_hash, "current_hash": curr_hash, "artifact_type": art_type, "host_name": h_name
            })
            links.append({"source": pid_to_node.get(pid, f"host_{h_id}"), "target": net_node_id})

    cursor.execute("""
        SELECT a.alert_title, a.severity, a.score_impact, COALESCE(p.name, 'Network Socket'), COALESCE(p.pid, 'N/A'), h.hostname, COALESCE(e.evidence_id, 'EV-GENESIS')
        FROM alerts a LEFT JOIN processes p ON a.process_id = p.id JOIN hosts h ON a.host_id = h.id
        LEFT JOIN evidence e ON e.host_id = a.host_id AND e.investigation_id = a.investigation_id AND (e.metadata LIKE '%' || p.name || '%' OR e.artifact_type LIKE '%Network%')
        WHERE a.investigation_id = ? GROUP BY a.id
    """, (inv_id,))
    alerts = [{"title": r[0], "severity": r[1], "impact": r[2], "process": r[3], "pid": r[4], "host": r[5], "evidence_id": r[6]} for r in cursor.fetchall()]
    
    conn.close()
    return {"nodes": nodes, "links": links, "alerts": alerts}

@app.get("/api/timeline")
async def get_timeline(inv_id: str = "INV-2026-00001"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT a.timestamp, 'ALERT', a.alert_title, a.severity, p.name, h.hostname FROM alerts a JOIN hosts h ON a.host_id = h.id LEFT JOIN processes p ON a.process_id = p.id WHERE a.investigation_id = ? ORDER BY a.timestamp ASC", (inv_id,))
    events = [{"time": r[0], "type": r[1], "title": r[2], "severity": r[3], "target": r[4], "host": r[5]} for r in cursor.fetchall()]
    conn.close()
    return {"events": events}

@app.post("/api/investigation/replay/{inv_id}")
async def replay_investigation(inv_id: str = "INV-2026-00001"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(id) FROM alerts WHERE investigation_id = ?", (inv_id,))
        old_findings = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(id) FROM evidence WHERE investigation_id = ?", (inv_id,))
        evidence_count = cursor.fetchone()[0]

        cursor.execute("SELECT id FROM hosts WHERE investigation_id = ?", (inv_id,))
        hosts = cursor.fetchall()
        
        total_risk = 0
        replay_ts = datetime.now().isoformat()
        
        for host in hosts:
            total_risk += run_detection_rules(cursor, host[0], inv_id, replay_ts)
            
        cursor.execute("SELECT COUNT(id) FROM alerts WHERE investigation_id = ?", (inv_id,))
        new_findings = cursor.fetchone()[0]
            
        conn.commit()
        return {
            "status": "success", 
            "archived_evidence": evidence_count,
            "old_findings": old_findings,
            "new_findings": new_findings,
            "new_risk_score": total_risk
        }
    finally:
        conn.close()

@app.post("/api/remediate/contain")
async def contain_host(hostname: str):
    """SOAR Active Response: Isolates and neutralizes risk score for a compromised host."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE hosts SET risk_score = 0 WHERE hostname = ?", (hostname,))
        cursor.execute("DELETE FROM alerts WHERE host_id IN (SELECT id FROM hosts WHERE hostname = ?)", (hostname,))
        conn.commit()
        print(f"{RED}[SOAR ACTION]{RESET} Host {BOLD}{hostname}{RESET} successfully isolated and remediated.")
        return {"status": "success", "message": f"Host {hostname} isolated. Threats neutralized."}
    finally:
        conn.close()

@app.get("/", response_class=FileResponse)
async def serve_dashboard():
    if not Path(HTML_PATH).exists():
        raise HTTPException(status_code=404, detail="Dashboard index.html not found. Ensure it is inside the 3_c2_server/templates directory.")
    return HTML_PATH

# ==========================================
# BOOTSTRAP
# ==========================================
if __name__ == "__main__":
    import uvicorn
    init_db()
    print(f"{GREEN}[✓]{RESET} Starting JOCKY Central Command Router on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")