"""
Database Module for AI SOC Assistant
SQLite persistence for alerts, incidents, assets, vulnerabilities, threat intelligence, and audit logs.
"""
import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "soc_assistant.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        title TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        source_port INTEGER NOT NULL,
        dest_port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        predicted_category TEXT NOT NULL,
        ground_truth_category TEXT NOT NULL,
        confidence REAL NOT NULL,
        severity TEXT NOT NULL,
        evidence TEXT NOT NULL, -- JSON array
        explanation TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        status TEXT NOT NULL,
        incident_id TEXT,
        packet_features TEXT NOT NULL -- JSON object
    )
    """)

    # Incidents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        assigned_to TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        resolved_at TEXT,
        linked_alert_ids TEXT NOT NULL, -- JSON array
        notes TEXT NOT NULL, -- JSON array
        response_duration_minutes REAL
    )
    """)

    # Assets Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        ip TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL,
        os TEXT NOT NULL,
        criticality TEXT NOT NULL,
        risk_score REAL NOT NULL,
        previous_risk_score REAL NOT NULL,
        open_alerts_count INTEGER NOT NULL,
        vulnerabilities_count INTEGER NOT NULL,
        last_scanned TEXT NOT NULL
    )
    """)

    # Vulnerabilities Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        cve TEXT NOT NULL,
        title TEXT NOT NULL,
        cvss REAL NOT NULL,
        severity TEXT NOT NULL,
        affected_assets TEXT NOT NULL, -- JSON array
        remediation TEXT NOT NULL,
        published_date TEXT NOT NULL,
        verified INTEGER NOT NULL
    )
    """)

    # Threat Intelligence Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        indicator TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        source TEXT NOT NULL,
        confidence REAL NOT NULL,
        timestamp TEXT NOT NULL,
        mitre_tactic TEXT NOT NULL,
        description TEXT NOT NULL
    )
    """)

    # Activity Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event TEXT NOT NULL,
        source TEXT NOT NULL,
        target TEXT NOT NULL,
        severity TEXT NOT NULL,
        details TEXT NOT NULL
    )
    """)

    conn.commit()

    # Seed initial data if tables are empty
    cursor.execute("SELECT COUNT(*) FROM assets")
    if cursor.fetchone()[0] == 0:
        seed_initial_data(conn)

    conn.close()

def seed_initial_data(conn):
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    # 1. Seed Assets (Private enterprise IP ranges)
    assets = [
        ("AST-001", "DC-CORP-01", "10.0.1.10", "Domain Controller", "Windows Server 2022", "Mission Critical", 92.4, 88.0, 4, 3, now),
        ("AST-002", "DB-PROD-SQL", "10.0.2.15", "Database Server", "Ubuntu 22.04 LTS", "Mission Critical", 85.0, 79.5, 3, 2, now),
        ("AST-003", "DMZ-WEB-01", "192.168.1.100", "DMZ Web Server", "Debian 12", "High", 76.8, 76.8, 5, 4, now),
        ("AST-004", "FW-EDGE-01", "192.168.1.1", "Edge Firewall", "FortiOS 7.4", "Mission Critical", 64.2, 60.0, 2, 1, now),
        ("AST-005", "WKSTN-FIN-04", "10.0.3.45", "Finance Workstation", "Windows 11 Pro", "Medium", 58.5, 52.0, 2, 2, now),
        ("AST-006", "WKSTN-DEV-12", "10.0.3.88", "Developer Machine", "macOS Sonoma", "Medium", 38.0, 38.0, 1, 1, now),
        ("AST-007", "APP-API-GATEWAY", "10.0.2.5", "Internal API Gateway", "Alpine Linux", "High", 71.0, 68.0, 2, 2, now),
        ("AST-008", "BACKUP-NAS-01", "10.0.4.200", "Storage Backup NAS", "FreeNAS", "High", 45.0, 45.0, 0, 1, now),
    ]
    cursor.executemany("""
    INSERT INTO assets (id, name, ip, role, os, criticality, risk_score, previous_risk_score, open_alerts_count, vulnerabilities_count, last_scanned)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, assets)

    # 2. Seed Vulnerabilities
    vulnerabilities = [
        ("VULN-001", "CVE-2024-21413", "Microsoft Outlook Remote Code Execution (MonikerLink)", 9.8, "Critical", json.dumps(["10.0.3.45"]), "Apply Microsoft February 2024 Security Updates; block outbound port 445 SMB.", "2024-02-13", 1),
        ("VULN-002", "CVE-2023-44487", "HTTP/2 Rapid Reset Distributed Denial of Service", 7.5, "High", json.dumps(["192.168.1.100", "10.0.2.5"]), "Update web servers to rate-limit RST_STREAM frames per connection.", "2023-10-10", 1),
        ("VULN-003", "CVE-2023-38606", "OpenSSH Privilege Escalation via PKCS#11", 7.8, "High", json.dumps(["10.0.2.15", "10.0.1.10"]), "Upgrade OpenSSH to version 9.3p2 or later.", "2023-07-20", 1),
        ("VULN-004", "CVE-2024-3400", "Palo Alto Networks PAN-OS Command Injection", 10.0, "Critical", json.dumps(["192.168.1.1"]), "Apply emergency hotfix; disable GlobalProtect telemetry if unpatched.", "2024-04-12", 1),
        ("VULN-005", "CVE-2023-22515", "Atlassian Confluence Broken Access Control", 8.8, "High", json.dumps(["10.0.2.5"]), "Restrict access to setup endpoints and apply Confluence security patch.", "2023-10-04", 1),
    ]
    cursor.executemany("""
    INSERT INTO vulnerabilities (id, cve, title, cvss, severity, affected_assets, remediation, published_date, verified)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, vulnerabilities)

    # 3. Seed Threat Intelligence
    threat_intel = [
        ("INTEL-001", "Lazarus Group SMB Lateral Spreading Tool", "198.51.100.44", "IP", "CISA / US-CERT Advisory", 92.0, now, "Lateral Movement (T1021.002)", "Observed brute-forcing admin shares and staging encrypted binaries."),
        ("INTEL-002", "Mirai Variant Botnet C2 Node", "203.0.113.88", "IP", "Shadowserver Foundation", 88.5, now, "Command and Control (T1071.001)", "Directing SYN and ACK flood attacks against financial and gaming sectors."),
        ("INTEL-003", "BlackCat Ransomware Token Staging Domain", "sync-cloud-telemetry.com", "Domain", "CrowdStrike Falcon OverWatch", 95.0, now, "Defense Evasion (T1550.002)", "Domain utilized to exfiltrate cached Kerberos tickets from compromised Domain Controllers."),
        ("INTEL-004", "CVE-2024-21413 MonikerLink Exploit Proof-of-Concept", "CVE-2024-21413", "CVE", "National Vulnerability Database", 99.0, now, "Initial Access (T1566.001)", "Active weaponization observed sending malicious file:// URLs via email."),
        ("INTEL-005", "Cobalt Strike HTTPS Malleable Profile SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Hash", "Mandiant Cyber Threat Intelligence", 85.0, now, "Execution (T1059.001)", "Signature matches staging loader delivering Cobalt Strike beacon into PowerShell memory."),
    ]
    cursor.executemany("""
    INSERT INTO threat_intel (id, title, indicator, indicator_type, source, confidence, timestamp, mitre_tactic, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, threat_intel)

    # 4. Seed Incidents
    incidents = [
        (
            "INC-2026-001",
            "Active Brute Force & Token Impersonation on Domain Controller",
            "Critical",
            "In Progress",
            "Senior Analyst Prachi",
            "2026-10-16T08:15:00Z",
            now,
            None,
            json.dumps(["ALT-9041", "ALT-9042"]),
            json.dumps([
                {"id": "n1", "timestamp": "2026-10-16T08:20:00Z", "author": "Prachi G.", "content": "Alerts ALT-9041 and ALT-9042 correlated. Suspicious NTLM relay observed from WKSTN-FIN-04 to DC-CORP-01."},
                {"id": "n2", "timestamp": "2026-10-16T08:45:00Z", "author": "Prachi G.", "content": "Host 10.0.3.45 network port isolated pending memory dump. DC logs undergoing triage."}
            ]),
            30.0
        ),
        (
            "INC-2026-002",
            "HTTP/2 Rapid Reset Volumetric DDoS on DMZ Web Server",
            "High",
            "New",
            "Unassigned",
            "2026-10-16T09:30:00Z",
            now,
            None,
            json.dumps(["ALT-8812"]),
            json.dumps([
                {"id": "n3", "timestamp": "2026-10-16T09:32:00Z", "author": "Automated Rule", "content": "Peak packet rate reached 124,000 pkts/sec on port 443. Cloudflare rate-limiting rule triggered."}
            ]),
            12.0
        ),
        (
            "INC-2026-003",
            "Suspicious Port Scan and Reconnaissance across Subnet 10.0.2.0/24",
            "Medium",
            "Resolved",
            "SecOps Auto-Remediation",
            "2026-10-16T06:00:00Z",
            "2026-10-16T06:42:00Z",
            "2026-10-16T06:42:00Z",
            json.dumps(["ALT-7611"]),
            json.dumps([
                {"id": "n4", "timestamp": "2026-10-16T06:42:00Z", "author": "Analyst David", "content": "Identified internal vulnerability scanner IP running unauthorized scan during business hours. Ticket closed after verification."}
            ]),
            42.0
        )
    ]
    cursor.executemany("""
    INSERT INTO incidents (id, title, severity, status, assigned_to, created_at, updated_at, resolved_at, linked_alert_ids, notes, response_duration_minutes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, incidents)

    # 5. Seed Activity Logs
    activity = [
        ("ACT-001", now, "Threat Classification", "ML-Engine", "ALT-9041", "Critical", "Random Forest classified flow as BruteForce (confidence: 96.4%)."),
        ("ACT-002", now, "Alert Escalated", "Analyst Prachi", "INC-2026-001", "Critical", "Correlated ALT-9041 and ALT-9042 into incident INC-2026-001."),
        ("ACT-003", now, "Graph Search", "Analyst Prachi", "NetworkX-A*", "Medium", "Executed A* shortest attack path from 192.168.1.100 to 10.0.1.10 (3 hops, cost 14.2)."),
        ("ACT-004", now, "Model Evaluation", "ML-Pipeline", "RandomForestClassifier", "Informational", "Stratified test evaluation: Macro F1 = 0.942, Accuracy = 95.8% across 5,000 samples."),
        ("ACT-005", now, "Vulnerability Ingestion", "NVD Sync", "CVE-2024-21413", "High", "Critical Outlook RCE ingested. Associated with host 10.0.3.45."),
    ]
    cursor.executemany("""
    INSERT INTO activity_logs (id, timestamp, event, source, target, severity, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, activity)

    conn.commit()
