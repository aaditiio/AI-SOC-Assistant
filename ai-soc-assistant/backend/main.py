"""
AI SOC Assistant - FastAPI Backend Application
Provides intelligent threat detection, alert management, incident correlation,
attack path analysis via graph algorithms, and reporting.
"""
import os
import sys

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from fastapi import FastAPI, HTTPException, Query, Body
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    if __name__ == "__main__":
        print("\n" + "=" * 60)
        print("  AI SOC Assistant - FastAPI Backend")
        print("=" * 60)
        print("FastAPI / Pydantic are not yet installed in this Python environment.")
        print("To install required Python dependencies, run:")
        print("  pip install -r backend/requirements.txt")
        print("\nAlternatively, run the full-stack Express engine:")
        print("  npm run dev")
        print("=" * 60 + "\n")
        sys.exit(0)
    else:
        raise ImportError("FastAPI is required for backend/main.py. Run: pip install -r backend/requirements.txt")

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json
import csv
import io

from database import init_db, get_db_connection
from ml_engine import pipeline, CLASSES, FEATURE_NAMES
from graph_engine import graph_engine

app = FastAPI(
    title="AI SOC Assistant API",
    description="Intelligent Cyber Threat Detection & Attack Path Analysis Backend",
    version="1.0.0"
)

# CORS configuration for local frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()
    pipeline.initialize_dataset()
    # Train model on startup if not already trained
    pipeline.train_and_evaluate()

# Pydantic Schemas
class PredictRequest(BaseModel):
    flow_duration: float = Field(..., example=12000)
    tot_fwd_pkts: int = Field(..., example=2500)
    tot_bwd_pkts: int = Field(..., example=0)
    tot_len_fwd_pkts: float = Field(..., example=100000)
    tot_len_bwd_pkts: float = Field(..., example=0)
    flow_byts_s: float = Field(..., example=1200000)
    flow_pkts_s: float = Field(..., example=15000)
    fwd_pkt_len_mean: float = Field(..., example=40.0)
    bwd_pkt_len_mean: float = Field(..., example=0.0)
    flow_iat_mean: float = Field(..., example=0.8)
    syn_flag_cnt: int = Field(..., example=2400)
    rst_flag_cnt: int = Field(..., example=0)
    ack_flag_cnt: int = Field(..., example=0)
    psh_flag_cnt: int = Field(..., example=0)
    protocol_num: int = Field(..., example=0)
    dst_port: int = Field(..., example=443)
    src_port: int = Field(..., example=49201)

class GraphSearchRequest(BaseModel):
    source: str = Field(..., example="FW-EDGE-01")
    target: str = Field(..., example="DB-PROD-SQL")
    algorithm: str = Field(..., example="A*") # 'BFS', 'DFS', 'Greedy Best-First', 'A*'

class CreateIncidentRequest(BaseModel):
    title: str
    severity: str
    assignedTo: str = "Unassigned"
    linkedAlertIds: List[str] = []
    initialNote: Optional[str] = None

class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None
    assignedTo: Optional[str] = None
    severity: Optional[str] = None
    newNote: Optional[str] = None

# --- API ENDPOINTS ---

@app.get("/api/health")
def get_health():
    return {
        "status": "healthy",
        "backend": "FastAPI (Python 3)",
        "modelStatus": "trained" if pipeline.is_trained else "not_trained",
        "datasetSamples": len(pipeline.dataset) if pipeline.dataset else 0,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/dashboard/overview")
def get_dashboard_overview():
    conn = get_db_connection()
    c = conn.cursor()

    # Alerts counts
    c.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'Critical'")
    critical_alerts = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'High'")
    high_alerts = c.fetchone()[0]

    # Open incidents
    c.execute("SELECT COUNT(*) FROM incidents WHERE status != 'Resolved'")
    open_incidents = c.fetchone()[0]

    # MTTR from valid responses
    c.execute("SELECT response_duration_minutes FROM incidents WHERE response_duration_minutes IS NOT NULL")
    durations = [row[0] for row in c.fetchall()]
    mttr = round(sum(durations) / len(durations), 1) if durations else None

    # Assets at risk (risk_score >= 60.0)
    c.execute("SELECT COUNT(*) FROM assets WHERE risk_score >= 60.0")
    assets_at_risk = c.fetchone()[0]

    conn.close()

    return {
        "totalAlerts": total_alerts,
        "criticalAlerts": critical_alerts,
        "highAlerts": high_alerts,
        "openIncidents": open_incidents,
        "mttrMinutes": mttr,
        "assetsAtRisk": assets_at_risk,
        "systemStatus": {
            "backend": "connected",
            "backendType": "fastapi-python",
            "model": "trained" if pipeline.is_trained else "not_trained",
            "dataset": "loaded_5000" if pipeline.dataset and len(pipeline.dataset) == 5000 else "empty",
            "lastUpdate": datetime.now(timezone.utc).isoformat()
        }
    }

@app.get("/api/dashboard/alerts-by-severity")
def get_alerts_by_severity():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
    rows = dict(c.fetchall())
    conn.close()

    order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
    total = sum(rows.values())
    result = []
    for sev in order:
        cnt = rows.get(sev, 0)
        pct = round((cnt / total * 100), 1) if total > 0 else 0.0
        result.append({
            "severity": sev,
            "count": cnt,
            "percentage": pct
        })
    return {"total": total, "distribution": result}

@app.get("/api/dashboard/alerts-over-time")
def get_alerts_over_time():
    # Return time series bucketed by 4-hour intervals
    return {
        "isSynthetic": True,
        "label": "Synthetic Demonstration Network Timeline",
        "data": [
            {"time": "00:00", "Critical": 1, "High": 2, "Medium": 4, "Low": 6, "Informational": 12},
            {"time": "04:00", "Critical": 0, "High": 3, "Medium": 5, "Low": 8, "Informational": 15},
            {"time": "08:00", "Critical": 4, "High": 7, "Medium": 9, "Low": 12, "Informational": 24},
            {"time": "12:00", "Critical": 3, "High": 8, "Medium": 14, "Low": 15, "Informational": 30},
            {"time": "16:00", "Critical": 5, "High": 6, "Medium": 11, "Low": 14, "Informational": 28},
            {"time": "20:00", "Critical": 2, "High": 4, "Medium": 8, "Low": 10, "Informational": 18},
        ]
    }

@app.get("/api/dashboard/incident-status")
def get_incident_status():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT status, COUNT(*) FROM incidents GROUP BY status")
    rows = dict(c.fetchall())
    conn.close()

    statuses = ['New', 'In Progress', 'On Hold', 'Resolved']
    total = sum(rows.values())
    result = []
    for s in statuses:
        cnt = rows.get(s, 0)
        pct = round((cnt / total * 100), 1) if total > 0 else 0.0
        result.append({"status": s, "count": cnt, "percentage": pct})
    return {"total": total, "distribution": result}

@app.get("/api/alerts")
def get_alerts(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    conn = get_db_connection()
    c = conn.cursor()
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if category:
        query += " AND predicted_category = ?"
        params.append(category)
    if status:
        query += " AND status = ?"
        params.append(status)
    if search:
        query += " AND (title LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ? OR id LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    c.execute(query, params)
    alerts = []
    for row in c.fetchall():
        alerts.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "title": row["title"],
            "sourceIp": row["source_ip"],
            "destIp": row["dest_ip"],
            "sourcePort": row["source_port"],
            "destPort": row["dest_port"],
            "protocol": row["protocol"],
            "predictedCategory": row["predicted_category"],
            "groundTruthCategory": row["ground_truth_category"],
            "confidence": row["confidence"],
            "severity": row["severity"],
            "evidence": json.loads(row["evidence"]),
            "explanation": row["explanation"],
            "recommendation": row["recommendation"],
            "status": row["status"],
            "incidentId": row["incident_id"],
            "packetFeatures": json.loads(row["packet_features"])
        })
    conn.close()
    return alerts

@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: str):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "title": row["title"],
        "sourceIp": row["source_ip"],
        "destIp": row["dest_ip"],
        "sourcePort": row["source_port"],
        "destPort": row["dest_port"],
        "protocol": row["protocol"],
        "predictedCategory": row["predicted_category"],
        "groundTruthCategory": row["ground_truth_category"],
        "confidence": row["confidence"],
        "severity": row["severity"],
        "evidence": json.loads(row["evidence"]),
        "explanation": row["explanation"],
        "recommendation": row["recommendation"],
        "status": row["status"],
        "incidentId": row["incident_id"],
        "packetFeatures": json.loads(row["packet_features"])
    }

@app.get("/api/incidents")
def get_incidents():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM incidents ORDER BY created_at DESC")
    incidents = []
    for row in c.fetchall():
        incidents.append({
            "id": row["id"],
            "title": row["title"],
            "severity": row["severity"],
            "status": row["status"],
            "assignedTo": row["assigned_to"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
            "resolvedAt": row["resolved_at"],
            "linkedAlertIds": json.loads(row["linked_alert_ids"]),
            "notes": json.loads(row["notes"]),
            "responseDurationMinutes": row["response_duration_minutes"]
        })
    conn.close()
    return incidents

@app.post("/api/incidents")
def create_incident(req: CreateIncidentRequest):
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    inc_id = f"INC-2026-{datetime.now().microsecond:04d}"

    notes = []
    if req.initialNote:
        notes.append({
            "id": "n-init",
            "timestamp": now,
            "author": req.assignedTo,
            "content": req.initialNote
        })

    c.execute("""
    INSERT INTO incidents (id, title, severity, status, assigned_to, created_at, updated_at, resolved_at, linked_alert_ids, notes, response_duration_minutes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (inc_id, req.title, req.severity, "New", req.assignedTo, now, now, None, json.dumps(req.linkedAlertIds), json.dumps(notes), 0.0))

    # Link alerts
    for a_id in req.linkedAlertIds:
        c.execute("UPDATE alerts SET incident_id = ?, status = 'Escalated' WHERE id = ?", (inc_id, a_id))

    # Log activity
    c.execute("""
    INSERT INTO activity_logs (id, timestamp, event, source, target, severity, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (f"ACT-{datetime.now().microsecond}", now, "Incident Created", req.assignedTo, inc_id, req.severity, f"Created incident with {len(req.linkedAlertIds)} linked alert(s)."))

    conn.commit()
    conn.close()
    return {"id": inc_id, "status": "created"}

@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: str, req: UpdateIncidentRequest):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc).isoformat()
    notes = json.loads(row["notes"])
    status = req.status or row["status"]
    assigned_to = req.assignedTo or row["assigned_to"]
    severity = req.severity or row["severity"]
    resolved_at = now if status == "Resolved" else row["resolved_at"]

    if req.newNote:
        notes.append({
            "id": f"note-{datetime.now().microsecond}",
            "timestamp": now,
            "author": assigned_to,
            "content": req.newNote
        })

    c.execute("""
    UPDATE incidents
    SET status = ?, assigned_to = ?, severity = ?, updated_at = ?, resolved_at = ?, notes = ?
    WHERE id = ?
    """, (status, assigned_to, severity, now, resolved_at, json.dumps(notes), incident_id))

    conn.commit()
    conn.close()
    return {"id": incident_id, "status": status}

@app.get("/api/assets")
def get_assets():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM assets ORDER BY risk_score DESC")
    assets = []
    for r in c.fetchall():
        assets.append({
            "id": r["id"],
            "name": r["name"],
            "ip": r["ip"],
            "role": r["role"],
            "os": r["os"],
            "criticality": r["criticality"],
            "riskScore": r["risk_score"],
            "previousRiskScore": r["previous_risk_score"],
            "openAlertsCount": r["open_alerts_count"],
            "vulnerabilitiesCount": r["vulnerabilities_count"],
            "lastScanned": r["last_scanned"]
        })
    conn.close()
    return assets

@app.get("/api/vulnerabilities")
def get_vulnerabilities():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities ORDER BY cvss DESC")
    vulns = []
    for r in c.fetchall():
        vulns.append({
            "id": r["id"],
            "cve": r["cve"],
            "title": r["title"],
            "cvss": r["cvss"],
            "severity": r["severity"],
            "affectedAssets": json.loads(r["affected_assets"]),
            "remediation": r["remediation"],
            "publishedDate": r["published_date"],
            "verified": bool(r["verified"])
        })
    conn.close()
    return vulns

@app.get("/api/threat-intelligence")
def get_threat_intel():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM threat_intel ORDER BY confidence DESC")
    intel = []
    for r in c.fetchall():
        intel.append({
            "id": r["id"],
            "title": r["title"],
            "indicator": r["indicator"],
            "indicatorType": r["indicator_type"],
            "source": r["source"],
            "confidence": r["confidence"],
            "timestamp": r["timestamp"],
            "mitreTactic": r["mitre_tactic"],
            "description": r["description"]
        })
    conn.close()
    return intel

@app.get("/api/insights")
def get_insights():
    return [
        {
            "id": "INS-01",
            "title": "Correlated Kerberos Spraying on Domain Controller",
            "severity": "Critical",
            "alertId": "ALT-9041",
            "description": "Sequential authentication failures followed by successful token impersonation from host 10.0.3.45.",
            "recommendation": "Isolate host 10.0.3.45 via 802.1X dynamic VLAN assignment and revoke Active Directory Kerberos ticket cache."
        },
        {
            "id": "INS-02",
            "title": "Volumetric SYN Influx on Perimeter Web Node",
            "severity": "High",
            "alertId": "ALT-8812",
            "description": "Destination port 443 observed 14,200 pkts/s with SYN flag bit set and zero subsequent ACK completion.",
            "recommendation": "Activate edge SYN cookie defense and throttle inbound traffic from external subnet 198.51.100.0/24."
        },
        {
            "id": "INS-03",
            "title": "Horizontal Port Reconnaissance across DMZ",
            "severity": "Medium",
            "alertId": "ALT-7611",
            "description": "Rapid sequential probing of ports 22, 80, 443, 3389, and 8080 under 400 microseconds per socket.",
            "recommendation": "Add scanning origin IP to firewall drop table and inspect DMZ web reverse proxy logs."
        }
    ]

@app.get("/api/activity")
def get_activity_logs(limit: int = 50):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    logs = []
    for r in c.fetchall():
        logs.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "event": r["event"],
            "source": r["source"],
            "target": r["target"],
            "severity": r["severity"],
            "details": r["details"]
        })
    conn.close()
    return logs

# --- MACHINE LEARNING & DATASET ENDPOINTS ---

@app.get("/api/dataset/info")
def get_dataset_info():
    if pipeline.dataset is None:
        pipeline.initialize_dataset()
    
    # Calculate class distribution
    dist = {}
    for r in pipeline.dataset:
        lbl = r['label']
        dist[lbl] = dist.get(lbl, 0) + 1

    return {
        "totalRecords": len(pipeline.dataset),
        "classDistribution": dist,
        "featureNames": FEATURE_NAMES,
        "classes": CLASSES,
        "trainSplit": int(len(pipeline.dataset) * 0.8),
        "testSplit": int(len(pipeline.dataset) * 0.2),
        "isSynthetic": True,
        "description": f"{len(pipeline.dataset):,} synthetic network flow records modeled on CIC-IDS-2017 distribution using RFC 1918 private subnets."
    }

@app.post("/api/dataset/update")
def update_dataset(records: List[Dict[str, Any]] = Body(...)):
    """
    Updates the dataset with new or modified records, automatically retrains the Random Forest,
    and returns the freshly computed evaluation metrics.
    """
    if not records or len(records) < 50:
        raise HTTPException(status_code=400, detail="Dataset must contain at least 50 records with valid threat labels.")
    
    from ml_engine import DATASET_PATH, CSV_PATH
    pipeline.dataset = records

    # Save to disk
    try:
        with open(DATASET_PATH, "w") as f:
            json.dump(records, f, indent=2)
        fieldnames = list(records[0].keys())
        with open(CSV_PATH, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)
    except Exception as e:
        print("Warning saving dataset to disk:", e)

    # Immediately retrain model on updated dataset
    metrics = pipeline.train_and_evaluate()

    # Log to audit trail
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO activity_logs (id, timestamp, event, source, target, severity, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        f"ACT-DS-{datetime.now().microsecond}",
        datetime.now(timezone.utc).isoformat(),
        "Dataset Updated & Model Retrained",
        "Analyst API",
        f"FlowDataset (N={len(records)})",
        "Informational",
        f"Dataset updated with {len(records)} records. Model retrained: Accuracy {metrics['accuracy']:.4f}, Macro F1 {metrics['macroF1']:.4f}"
    ))
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "totalRecords": len(records),
        "metrics": metrics
    }

@app.post("/api/dataset/regenerate")
def regenerate_dataset(num_records: int = Query(5000, ge=100, le=50000)):
    """
    Generates a new synthetic dataset, persists it to disk, and retrains the model.
    """
    from ml_engine import generate_synthetic_dataset, DATASET_PATH, CSV_PATH
    new_data = generate_synthetic_dataset(num_records)
    pipeline.dataset = new_data

    # Save to disk
    with open(DATASET_PATH, "w") as f:
        json.dump(new_data, f, indent=2)
    fieldnames = list(new_data[0].keys())
    with open(CSV_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(new_data)

    metrics = pipeline.train_and_evaluate()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO activity_logs (id, timestamp, event, source, target, severity, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        f"ACT-DS-REGEN-{datetime.now().microsecond}",
        datetime.now(timezone.utc).isoformat(),
        "Dataset Regenerated & Model Retrained",
        "ML-Pipeline",
        f"FlowDataset (N={num_records})",
        "Informational",
        f"Regenerated {num_records} flow records. Retrained Random Forest: Accuracy {metrics['accuracy']:.4f}, Macro F1 {metrics['macroF1']:.4f}"
    ))
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "totalRecords": len(new_data),
        "metrics": metrics
    }

@app.post("/api/model/train")
def train_model():
    metrics = pipeline.train_and_evaluate()
    # Log retraining
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO activity_logs (id, timestamp, event, source, target, severity, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        f"ACT-TR-{datetime.now().microsecond}",
        datetime.now(timezone.utc).isoformat(),
        "Model Retraining",
        "ML-Pipeline",
        "RandomForestClassifier",
        "Informational",
        f"Retrained on 5,000 samples. Macro F1: {metrics['macroF1']:.4f}, Accuracy: {metrics['accuracy']:.4f}"
    ))
    conn.commit()
    conn.close()
    return metrics

@app.get("/api/model/status")
def get_model_status():
    return {
        "isTrained": pipeline.is_trained,
        "lastTrainedAt": pipeline.last_trained_at,
        "modelType": "scikit-learn RandomForestClassifier",
        "estimators": 100,
        "totalSamples": 5000,
        "featuresCount": len(FEATURE_NAMES)
    }

@app.get("/api/model/metrics")
def get_model_metrics():
    if pipeline.metrics is None:
        return pipeline.train_and_evaluate()
    return pipeline.metrics

@app.post("/api/predict")
def predict_flow(req: PredictRequest):
    return pipeline.predict(req.dict())

# --- GRAPH & ATTACK PATH ANALYSIS ENDPOINTS ---

@app.post("/api/graph/build")
def get_graph_topology():
    return {
        "nodes": graph_engine.nodes,
        "edges": graph_engine.edges
    }

@app.post("/api/graph/search")
def search_attack_path(req: GraphSearchRequest):
    algo = req.algorithm.strip()
    if algo == "BFS":
        result = graph_engine.search_bfs(req.source, req.target)
    elif algo == "DFS":
        result = graph_engine.search_dfs(req.source, req.target)
    elif algo == "Greedy Best-First":
        result = graph_engine.search_greedy_best_first(req.source, req.target)
    elif algo == "A*":
        result = graph_engine.search_a_star(req.source, req.target)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm '{algo}'. Supported: BFS, DFS, Greedy Best-First, A*")

    # Log search activity
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO activity_logs (id, timestamp, event, source, target, severity, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        f"ACT-GRAPH-{datetime.now().microsecond}",
        datetime.now(timezone.utc).isoformat(),
        "Graph Search",
        f"Algorithm: {algo}",
        f"{req.source} -> {req.target}",
        "Informational",
        f"Path found: {' -> '.join(result['path']) if result['found'] else 'No Path'} (Explored {result['totalExplored']} nodes in {result['executionTimeMs']} ms)"
    ))
    conn.commit()
    conn.close()

    return result

# --- EXPORT REPORTS ENDPOINT ---

@app.get("/api/reports/export")
def export_reports(format: str = Query("csv", enum=["csv", "json", "txt"])):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    alerts = c.fetchall()
    conn.close()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Timestamp", "Title", "Source IP", "Dest IP", "Source Port", "Dest Port", "Protocol", "Predicted Category", "Severity", "Confidence", "Status"])
        for a in alerts:
            writer.writerow([
                a["id"], a["timestamp"], a["title"], a["source_ip"], a["dest_ip"],
                a["source_port"], a["dest_port"], a["protocol"], a["predicted_category"],
                a["severity"], a["confidence"], a["status"]
            ])
        return {
            "format": "csv",
            "filename": f"soc_alerts_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "content": output.getvalue()
        }

    elif format == "json":
        summary = {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "system": "AI SOC Assistant",
            "totalAlerts": len(alerts),
            "modelMetrics": pipeline.metrics,
            "exportType": "SOC Metrics & Alerts Summary"
        }
        return {
            "format": "json",
            "filename": f"soc_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "content": json.dumps(summary, indent=2)
        }

    else: # txt
        txt_content = f"""=======================================================
AI SOC ASSISTANT - INCIDENT & THREAT INVESTIGATION REPORT
Generated: {datetime.now(timezone.utc).isoformat()}
Classification: CONFIDENTIAL / INTERNAL SOC USE ONLY
=======================================================

1. EXECUTIVE SUMMARY
--------------------
Total Processed Alerts: {len(alerts)}
Critical Alerts: {sum(1 for a in alerts if a['severity'] == 'Critical')}
High Alerts: {sum(1 for a in alerts if a['severity'] == 'High')}
Detection Engine: scikit-learn RandomForestClassifier
Dataset Baseline: 5,000 synthetic flow records

2. TOP CRITICAL THREATS
------------------------
"""
        for a in alerts[:5]:
            txt_content += f"- [{a['id']}] {a['title']} | Src: {a['source_ip']} -> Dst: {a['dest_ip']} | Status: {a['status']}\n"

        return {
            "format": "txt",
            "filename": f"soc_investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "content": txt_content
        }


if __name__ == "__main__":
    try:
        import uvicorn
        print("[AI SOC Assistant] Starting FastAPI backend on http://0.0.0.0:8000...")
        uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
    except ImportError:
        print("[AI SOC Assistant] Uvicorn is required to run the server directly. Install with: pip install uvicorn")
