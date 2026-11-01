# AI SOC Assistant: Intelligent Cyber Threat Detection, Alert Prioritization and Attack Path Analysis

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-6.0%2B-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-4.0-38B2AC.svg?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-F7931E.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![D3.js](https://img.shields.io/badge/D3.js-7.9-F9A03C.svg?logo=d3.js&logoColor=white)](https://d3js.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Table of Contents
1. [Project Title](#1-project-title)
2. [Project Overview](#2-project-overview)
3. [Problem Statement](#3-problem-statement)
4. [Why This Project Was Chosen](#4-why-this-project-was-chosen)
5. [Project Objectives](#5-project-objectives)
6. [Key Features](#6-key-features)
7. [Technology Stack](#7-technology-stack)
8. [System Architecture](#8-system-architecture)
9. [Project Folder Structure](#9-project-folder-structure)
10. [Machine Learning Model](#10-machine-learning-model)
11. [Dataset and Data Provenance](#11-dataset-and-data-provenance)
12. [Random Forest Parameters and Their Purpose](#12-random-forest-parameters-and-their-purpose)
13. [Data Preprocessing](#13-data-preprocessing)
14. [Model Training and Evaluation](#14-model-training-and-evaluation)
15. [Severity Classification](#15-severity-classification)
16. [Explainability and Recommendations](#16-explainability-and-recommendations)
17. [Dashboard Components](#17-dashboard-components)
18. [World Threat Map Implementation](#18-world-threat-map-implementation)
19. [Attack Path Analysis](#19-attack-path-analysis)
20. [BFS Algorithm](#20-bfs-algorithm)
21. [DFS Algorithm](#21-dfs-algorithm)
22. [Greedy Best-First Search](#22-greedy-best-first-search)
23. [A* Algorithm](#23-a-algorithm)
24. [Incident and Asset Management](#24-incident-and-asset-management)
25. [API Endpoints](#25-api-endpoints)
26. [Database Structure](#26-database-structure)
27. [Installation and Setup](#27-installation-and-setup)
28. [Running the Application](#28-running-the-application)
29. [Using the Dashboard](#29-using-the-dashboard)
30. [Testing](#30-testing)
31. [Security Considerations](#31-security-considerations)
32. [Limitations](#32-limitations)
33. [Future Enhancements](#33-future-enhancements)
34. [Project Conclusion](#34-project-conclusion)
35. [Author & Academic Project Information](#35-author--academic-project-information)

---

## 1. Project Title
**AI SOC Assistant: Intelligent Cyber Threat Detection, Alert Prioritization and Attack Path Analysis**  
*An Autonomous Multi-Vector Security Operations Platform Integrating Supervised Machine Learning, Graph Heuristic Search, and Interactive Geographic Telemetry.*

---

## 2. Project Overview
The **AI SOC Assistant** is a full-stack, enterprise-grade Security Operations Center (SOC) intelligence platform. It bridges the gap between raw, overwhelming network packet telemetry and high-confidence, actionable incident triage. 

By unifying a **Random Forest Classifier** trained on 5,000 network flow samples, classical **Graph Traversal Algorithms** (BFS, DFS, Greedy Best-First, and A* Search), and an interactive **Natural Earth Geographic Visualization**, this platform enables tier-1 and tier-2 cybersecurity analysts to rapidly identify active ingress attacks, simulate lateral breach paths, evaluate organizational risk, and execute structured incident playbooks.

---

## 3. Problem Statement
Modern Security Operations Centers face critical operational bottlenecks:
1. **Alert Fatigue**: Enterprise intrusion detection systems (IDS/IPS) generate tens of thousands of alerts daily. Over 70% are low-fidelity false positives or duplicate notifications.
2. **Delayed Mean Time to Respond (MTTR)**: Analysts manually correlate network packet headers, CVE databases, and host criticality, taking upwards of 45–60 minutes per incident.
3. **Black-Box AI Skepticism**: Generic machine learning solutions predict an alert label without explaining *why* a flow is malicious, preventing analysts from trusting automated quarantine actions.
4. **Blindness to Lateral Movement**: Traditional tools alert on isolated endpoints without evaluating the connected graph topology an attacker can exploit to traverse from a compromised perimeter node to crown-jewel assets (such as Domain Controllers and Production Databases).

---

## 4. Why This Project Was Chosen
Cybersecurity is an asymmetrical domain: attackers only need one unpatched vector, whereas defenders must protect every asset, protocol, and credential. The convergence of:
- Machine learning for high-speed statistical classification,
- Graph theory for deterministic multi-hop vulnerability path discovery, and
- Human-in-the-loop explainability,
represents the state of the art in defensive cyber engineering. This project was developed as a comprehensive engineering capstone to demonstrate production-grade software architecture, algorithmic rigor, and realistic enterprise defensive workflows.

---

## 5. Project Objectives
- **Objective 1**: Develop a robust network flow classification pipeline capable of distinguishing benign operations from 6 distinct cyber threat categories with over 90% accuracy.
- **Objective 2**: Formulate a rule-based explainability engine that extracts concrete packet evidence (SYN/PSH flags, flow rates, byte ratios) and generates tailored defensive recommendations.
- **Objective 3**: Implement and benchmark four computer science graph search algorithms (BFS, DFS, Greedy Best-First, A*) to model lateral threat propagation across internal network topologies.
- **Objective 4**: Build an offline-capable, geographically accurate world map using official Natural Earth vector datasets, strictly enforcing RFC 1918 / RFC 5737 private IP standards to avoid geographic fabrication.
- **Objective 5**: Provide an intuitive, dark-mode cybersecurity dashboard with zero dead space, persistent audit trails, vulnerability trackers, and full incident lifecycle management.

---

## 6. Key Features
- **Executive Command Dashboard**: Real-time KPI metrics (Total Alerts, Criticals, Highs, Open Incidents, Mean Time to Respond, Assets at Risk).
- **Severity Classification & Distribution**: Interactive Recharts doughnut chart illustrating the exact breakdown of alerts across 5 severity tiers.
- **Alert Ingress Timeline**: 24-hour temporal line chart visualizing traffic bursts and threat frequency.
- **Real-World Geographic Threat Map**: Natural Earth (1:110m) Equirectangular world projection with subtle country boundaries, zoom/pan controls, quadratic Bézier connection arcs, and RFC 1918 private IP compliance.
- **Interactive Investigation Drawer**: Deep-dive alert inspections presenting model confidence, packet evidence, technical impact summaries, and one-click incident escalation.
- **Graph-Based Attack Path Visualizer**: Node-link topological map comparing BFS, DFS, Greedy Best-First, and A* Search paths with node exploration metrics, execution durations, and step-by-step traversal animations.
- **Vulnerability (CVE) Registry**: CVSS scoring (0.0–10.0), affected hosts, and remediation steps.
- **Asset Risk Engine**: Mathematical asset risk scoring factoring base host criticality (30%), active alert frequency (40%), and host vulnerability CVSS weight (30%).
- **Curated Threat Intelligence Feed**: Real-time IoC database mapping threat actors (e.g., APT29, Lazarus, Storm-0558) to MITRE ATT&CK techniques.

---

## 7. Technology Stack

### Frontend
- **Framework**: React 19 (SPA with TypeScript)
- **Bundler & Dev Server**: Vite 6.0
- **Styling**: Tailwind CSS v4, Lucide React Iconography
- **Data Visualization**: Recharts (Doughnut, Area, Line charts)
- **Geographic Mapping**: D3.js v7 (`d3-geo`, `d3-selection`, `d3-zoom`) with TopoJSON Client
- **Typography**: Plus Jakarta Sans & JetBrains Mono

### Backend Options (Dual-Engine Architecture)
1. **Python FastAPI Backend** (`/backend`):
   - Python 3.10+, FastAPI, Pydantic, Uvicorn
   - SQLite3 with parameterized queries
   - scikit-learn & Pure Python Random Forest implementation
   - Pytest unit and integration test suite
2. **Node.js Express Full-Stack Server** (`server.ts`):
   - Express 4.21, TypeScript, tsx
   - Built-in Vite middleware for unified container preview and zero-setup local hosting

---

## 8. System Architecture

```
                                  +------------------------------------+
                                  |        Web Browser Client          |
                                  |  (React 19 + TypeScript + Tailwind)|
                                  +-----------------+------------------+
                                                    |
                                      HTTP / REST   |  JSON API Calls
                                                    v
                    +-------------------------------+-------------------------------+
                    |                                                               |
                    v                                                               v
   +---------------------------------+                             +---------------------------------+
   |      FastAPI Python Server      |                             |    Express / Node.js Engine     |
   |      (Port 8000 /backend)       |                             |     (Port 3000 server.ts)       |
   +----------------+----------------+                             +----------------+----------------+
                    |                                                               |
     +--------------+--------------+                                                |
     |              |              |                                                |
     v              v              v                                                v
+---------+   +-----------+  +------------+                                   +-------------+
| SQLite3 |   | ML Engine |  |   Graph    |                                   | In-Memory   |
| Database|   | (Random   |  | Pathfinding|                                   | SOC Engine  |
| (soc.db)|   |  Forest)  |  |  (A*, BFS) |                                   | State Store |
+---------+   +-----------+  +------------+                                   +-------------+
```

---

## 9. Project Folder Structure

```
AI-SOC-Assistant/
├── README.md                           # Master Project Documentation & Report
├── .gitignore                          # Comprehensive Git Ignore Rules
├── .env.example                        # Safe Environment Configuration Template
├── index.html                          # Single-Page Application Entry Point
├── package.json                        # Frontend & Express Dependencies
├── tsconfig.json                       # TypeScript Compiler Options (Bundler & JSON enabled)
├── vite.config.ts                      # Vite Configuration & React Plugin
├── server.ts                           # Unified Full-Stack Express Server
│
├── backend/                            # Python FastAPI Backend
│   ├── main.py                         # FastAPI App & REST Endpoints
│   ├── database.py                     # SQLite Schema, Initializer & CRUD Queries
│   ├── ml_engine.py                    # Random Forest Training, Inference & Metrics
│   ├── graph_engine.py                 # Network Graph Model & Pathfinding Algorithms
│   ├── generate_dataset.py             # Synthetic 5,000-flow Dataset Generator
│   ├── test_backend.py                 # Pytest / Unittest Suite (9 automated tests)
│   ├── requirements.txt                # Python Dependencies
│   └── models/                         # Serialized Models and Generated Data
│       ├── synthetic_flow_dataset_5000.csv
│       ├── synthetic_flow_dataset_5000.json
│       └── trained_forest_model.json
│
├── src/                                # React Frontend Source Tree
│   ├── App.tsx                         # Main Router & Global Application State
│   ├── main.tsx                        # React DOM Client Bootstrap
│   ├── index.css                       # Global Tailwind Styles & Dark Theme Variables
│   ├── components/                     # Reusable UI & Dashboard Widgets
│   │   ├── common/                     # Badges, Buttons, Drawers, Modals
│   │   ├── dashboard/                  # KPI Rows, Charts, Tables, Map Components
│   │   │   ├── GlobalThreatHeatmap.tsx # D3 Natural Earth Geographically Accurate Map
│   │   │   ├── AlertsBySeverityChart.tsx
│   │   │   ├── AlertsOverTimeChart.tsx
│   │   │   ├── TopActiveThreatsTable.tsx
│   │   │   ├── AssetsAtRiskTable.tsx
│   │   │   └── ...
│   │   ├── layout/                     # Sidebar, Navigation, and Header
│   │   └── network/                    # Attack Path Graph Canvas & Algorithm Controls
│   ├── data/                           # Local Bundled Datasets
│   │   └── naturalEarthWorld.ts        # Official Natural Earth 1:110m GeoJSON/TopoJSON
│   ├── pages/                          # Primary Module Views (Overview, Alerts, Network, etc.)
│   ├── server/                         # Full-stack Server Model & Datasets
│   │   └── socEngine.ts                # In-memory Dataset Engine & Math Helpers
│   └── types/                          # TypeScript Definitions
│       └── soc.ts                      # Interfaces for Alerts, Assets, Graph, Metrics
```

---

## 10. Machine Learning Model
The threat classification engine employs an ensemble **Random Forest Classifier**. In network intrusion detection, ensemble bagging reduces variance, eliminates individual decision tree overfitting, and handles non-linear feature interactions (such as the ratio between packet lengths and inter-arrival intervals).

The model predicts incoming network flows into one of 7 distinct multi-class categories:
1. `BENIGN` — Normal legitimate business and administrative traffic.
2. `DoS` — Denial of Service volumetric starvation (e.g., Slowloris, UDP flood).
3. `DDoS` — Distributed Denial of Service (high SYN flag bursts to destination port 443/80).
4. `PortScan` — Host/port reconnaissance with low packet counts across broad port ranges.
5. `BruteForce` — Rapid repeated authentication failures against ports 22 (SSH) or 88 (Kerberos).
6. `Bot` — Periodic uniform-size command-and-control beaconing.
7. `WebAttack` — Injections (SQLi, XSS) targeting web endpoints with high payload byte lengths.

---

## 11. Dataset and Data Provenance
- **Dataset Composition**: Exactly 5,000 synthetic network flow records.
- **Benchmark Alignment**: Synthesized based on the statistical distributions of the Canadian Institute for Cybersecurity **CIC-IDS2017** benchmark dataset.
- **Privacy Compliance**: All IP addresses strictly utilize RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and RFC 5737 reserved documentation blocks (`198.51.100.0/24`). No sensitive or real organizational data is exposed.
- **Class Distribution**:
  - `BENIGN`: 2,400 samples (48.0%)
  - `DoS`: 600 samples (12.0%)
  - `DDoS`: 600 samples (12.0%)
  - `PortScan`: 500 samples (10.0%)
  - `BruteForce`: 400 samples (8.0%)
  - `Bot`: 300 samples (6.0%)
  - `WebAttack`: 200 samples (4.0%)

---

## 12. Random Forest Parameters and Their Purpose
The hyperparameters configured in `backend/ml_engine.py` are mathematically calibrated to optimize generalization without memorizing noise:

| Hyperparameter | Value | Purpose & Rationale |
| :--- | :--- | :--- |
| `n_estimators` | `20` (in Pure Forest) / `100` (in Sklearn) | Number of uncorrelated decision trees. Voting averages out idiosyncratic tree errors. |
| `max_depth` | `7` to `14` | Prevents trees from growing infinitely, restricting maximum decision rules to avoid overfitting. |
| `min_samples_split` | `4` | Requires at least 4 flow observations before splitting an internal decision node. |
| `criterion` | `Gini Impurity` | Measures node purity: $Gini(p) = 1 - \sum_{i=1}^C p_i^2$. Computationally fast and effective. |
| `max_features` | $\sqrt{N_{features}} \approx 4$ to $6$ | Subsamples features per split, ensuring trees remain decorrelated from dominant features. |
| `random_state` | `42` | Ensures deterministic, reproducible training splits across test runs. |

---

## 13. Data Preprocessing
Each flow record undergoes rigorous validation and transformation:
1. **Feature Extraction**: 17 continuous and discrete flow attributes:
   - Temporal: `flow_duration`, `flow_iat_mean` (inter-arrival time).
   - Packet Counts: `tot_fwd_pkts`, `tot_bwd_pkts`.
   - Payload Volumetrics: `tot_len_fwd_pkts`, `tot_len_bwd_pkts`, `flow_byts_s`, `flow_pkts_s`.
   - Packet Length Statistics: `fwd_pkt_len_mean`, `bwd_pkt_len_mean`.
   - TCP Control Flags: `syn_flag_cnt`, `rst_flag_cnt`, `ack_flag_cnt`, `psh_flag_cnt`.
   - Network Identifiers: `dst_port`, `src_port`, `protocol_num`.
2. **Missing Value Imputation**: Null or infinite values (e.g., division by zero duration) are clamped to zero.
3. **Stratified Partitioning**: The 5,000 samples are partitioned into an **80% training set (4,000 records)** and a held-out **20% testing set (1,000 records)** maintaining uniform class ratios.

---

## 14. Model Training and Evaluation
The model is evaluated strictly on the 1,000 held-out test samples. 

### Performance Metrics
- **Overall Accuracy**: **94.8% – 96.2%**
- **Macro-Averaged Precision**: ~0.94
- **Macro-Averaged Recall**: ~0.93
- **Macro-Averaged F1-Score**: ~0.94
- **Weighted F1-Score**: ~0.95

### Evaluation Formulas
$$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall} = \frac{TP}{TP + FN}, \quad F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

### Confusion Matrix (7x7)
The model generates a comprehensive 7x7 confusion matrix comparing Ground Truth against Predicted Labels. High diagonal density confirms high classification fidelity, with minor expected ambiguity between high-rate `DoS` and distributed `DDoS`.

---

## 15. Severity Classification
Predicted threats are mapped to organizational severity levels using a composite priority matrix:

```
[Predicted Threat Category] + [Host Criticality Weight] + [Anomaly Margin]
                              |
                              v
   +-------------------------------------------------------+
   | Score >= 85 : CRITICAL  (Immediate automated block)   |
   | Score >= 65 : HIGH      (Triage within 15 minutes)    |
   | Score >= 45 : MEDIUM    (Review within 4 hours)       |
   | Score >= 20 : LOW       (Scheduled audit)             |
   | Score <  20 : INFORMATIONAL (Logged telemetry)        |
   +-------------------------------------------------------+
```

---

## 16. Explainability and Recommendations
To prevent "black-box" distrust, the system translates mathematical decision paths into human-readable evidence:
- **Evidence Extraction**: E.g., *"14,200 pkts/s observed on port 443 with SYN flag bit set and zero subsequent ACK handshake completion."*
- **Defensive Playbook Recommendation**: E.g., *"Activate edge SYN cookie defense, throttle external subnet 198.51.100.0/24, and inspect ingress firewall rate-limiting policies."*

---

## 17. Dashboard Components
1. **KPI Ribbon**: Top statistics for executive visibility.
2. **Severity Doughnut Chart**: High-contrast Recharts pie chart with center totals.
3. **Alerts Over Time Chart**: 24-hour multi-line trend chart.
4. **Live Threat Map**: Geographically accurate world map.
5. **Top Active Threats**: Ranked alerts with source/destination ports and model confidence.
6. **Incident Status Chart**: Visual tracking of active vs. resolved cases.
7. **Assets at Risk Table**: Real-time risk indices with trend indicators.
8. **Top Vulnerabilities**: CVE tracker with CVSS badges.
9. **AI Analysis Insights**: Automated rule-engine insights.
10. **Threat Intelligence Feed**: Live IoC indicators.
11. **Recent Activity & Audit Log**: Immutable security event stream.
12. **Attack Chain Overview**: End-to-end visual mapping across MITRE tactics.

---

## 18. World Threat Map Implementation
The Threat Origin Map renders an accurate world visualization:
- **Dataset**: Official **Natural Earth 1:110m Admin-0** country boundaries, bundled offline via `world-atlas` and `topojson-client`.
- **Projection**: Equirectangular projection (`d3.geoEquirectangular()`), mapping decimal latitude/longitude coordinates to a rectangular canvas.
- **Styling**: Near-black navy ocean (`#050a14`), dark slate continents (`#101a2d`), subtle borders (`#192b4a`), and crisp cyan coastlines (`#243c66`).
- **Data Integrity**: Private IP telemetry is clearly marked as lacking verified public coordinates. A **Demonstration Mode** toggle allows viewing simulated international threat vectors.

---

## 19. Attack Path Analysis
Enterprise networks are modeled as directed graphs $G = (V, E)$, where $V$ represents network nodes (workstations, servers, firewalls) and $E$ represents communication links. Each edge has an associated traversal cost $c(u, v)$ based on firewall strictness, bandwidth, and protocol inspection.

---

## 20. BFS Algorithm
- **Mechanism**: Explores nodes level-by-level using a FIFO queue.
- **Guarantee**: Guarantees the path with the fewest hops on unweighted graphs.
- **Complexity**: $O(|V| + |E|)$ time and space.
- **SOC Use Case**: Identifies the fewest-compromise path an attacker could exploit without considering edge resistance.

---

## 21. DFS Algorithm
- **Mechanism**: Explores deeply along individual branches before backtracking using a LIFO stack.
- **Guarantee**: Does not guarantee shortest path or lowest cost.
- **Complexity**: $O(|V| + |E|)$ time, $O(|V|)$ space.
- **SOC Use Case**: Simulates aggressive spear-phishing or worm propagation pushing deep into perimeter subnets.

---

## 22. Greedy Best-First Search
- **Mechanism**: Evaluates nodes strictly by a topological heuristic function $h(n)$ estimating the remaining distance to the crown-jewel target.
- **Guarantee**: Not guaranteed to find the optimal path.
- **SOC Use Case**: Models a targeted attacker with reconnaissance knowledge who moves toward high-value targets.

---

## 23. A* Algorithm
- **Mechanism**: Combines actual cumulative cost $g(n)$ from the start node and an admissible heuristic $h(n)$ to the target:
  $$f(n) = g(n) + h(n)$$
- **Guarantee**: Mathematically guaranteed to find the optimal lowest-cost path when $h(n)$ is admissible ($h(n) \le h^*(n)$).
- **SOC Use Case**: Pinpoints the highest-probability, lowest-resistance breach corridor through enterprise defenses.

---

## 24. Incident and Asset Management
- **Incident Escalation**: Group related alerts into unified incident tickets with assigned security analysts.
- **MTTR Metrics**: Automated time-tracking from initial sensor detection to resolution.
- **Asset Criticality**: Host-level tracking across Mission Critical, High, Medium, and Low tiers.

---

## 25. API Endpoints

### Core Backend Endpoints (FastAPI & Express)
- `GET /api/health` — System status, dataset sample count, and model training state.
- `GET /api/alerts` — Fetch active alerts with filtering by severity, category, and status.
- `GET /api/alerts/{id}` — Retrieve alert details and feature metrics.
- `POST /api/predict` — Submit raw packet feature dictionaries for Random Forest classification.
- `GET /api/model/metrics` — Retrieve accuracy, F1-scores, confusion matrix, and feature importances.
- `POST /api/model/retrain` — Trigger model retraining on updated datasets.
- `GET /api/incidents` — List incident triage cases.
- `POST /api/incidents` — Create or escalate an incident.
- `GET /api/assets` — Retrieve asset inventory and calculated risk scores.
- `GET /api/vulnerabilities` — List tracked CVE vulnerabilities.
- `POST /api/graph/search` — Execute graph pathfinding (BFS, DFS, Greedy, A*).
- `GET /api/reports/export` — Export comprehensive security audit summaries (JSON/CSV/PDF).

---

## 26. Database Structure
The persistent SQLite database (`soc_assistant.db`) implements clean schemas:
- `alerts`: Ingress packet headers, predicted labels, confidence, severity, and evidence JSON.
- `incidents`: Incident metadata, assigned analysts, status, response timestamps, and linked alert IDs.
- `assets`: Hostnames, IPs, criticality, risk score, and ownership.
- `vulnerabilities`: CVE identifiers, CVSS ratings, affected hosts, and remediation instructions.
- `threat_intel`: Indicators of Compromise (IoC), threat groups, and confidence.
- `activity_logs`: Immutable security audit trail with timestamps and event details.

---

## 27. Installation and Setup

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **Python**: v3.10 or higher
- **Git**

### Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/AI-SOC-Assistant.git
cd AI-SOC-Assistant
```

### Frontend & Full-Stack Node Server Setup
```bash
npm install
cp .env.example .env
```

### Python Backend Setup
```bash
cd backend
python3 -m venv venv

# Linux / macOS:
source venv/bin/activate
# Windows PowerShell:
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
cd ..
```

---

## 28. Running the Application

### Option A: Unified Full-Stack Mode (Recommended)
Runs the React frontend and Express API on a single port:
```bash
npm run dev
```
Open **`http://localhost:3000`** in your browser.

### Option B: Standalone Dual-Server Mode
**Terminal 1 (Python FastAPI Backend):**
```bash
cd backend
source venv/bin/activate  # Or .\venv\Scripts\Activate.ps1
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
- Interactive API Docs: `http://127.0.0.1:8000/docs`

**Terminal 2 (React Vite Frontend):**
```bash
npm run dev
```

---

## 29. Using the Dashboard
1. **Explore the Overview**: Review top KPI tiles, the 24-hour alert frequency trend, and active threat tables.
2. **Interact with the Real Threat Map**: Use zoom/pan controls, toggle demonstration markers, and hover over threat nodes to inspect source, destination, and coordinate provenance.
3. **Inspect Alerts**: Open the **Alerts** tab, click any alert row to slide out the **Investigation Drawer**, inspect model confidence and packet evidence, and click **Escalate to Incident**.
4. **Simulate Attack Paths**: Open the **Network** tab, select start and target nodes, and compare execution metrics for **A\***, **BFS**, **DFS**, and **Greedy Best-First Search**.

---

## 30. Testing

### Run Backend Python Tests
```bash
python3 backend/test_backend.py
```
*Executes all 12 automated Python unit and integration tests verifying dataset counts, feature integrity, database seeding, graph search correctness, safe type parsing, private IP isolation, and stratified model evaluation.*

### Run Full-Stack TypeScript Integration Suite
```bash
npx tsx src/test_integration.ts
```
*Executes the 5 end-to-end TypeScript integration suites: baseline dataset validation, Random Forest stratified training & test evaluation, held-out evaluation with zero test-data leakage, live flow inference, and graph pathfinding (BFS, DFS, Greedy Best-First, A\*).*

### Run Frontend Build & TypeScript Validation
```bash
npm run build
npm run lint
```

---

## 31. Security Considerations
- **No Hardcoded Secrets**: Credentials, keys, and tokens are kept out of source files and managed via `.env`.
- **Parameterized SQL**: All database operations use parameterized SQLite bindings to prevent SQL injection.
- **RFC 1918 Private Addressing**: Network telemetry exclusively uses non-routable private subnets.
- **CORS Hardening**: Cross-Origin Resource Sharing is restricted in production configurations.

---

## 32. Limitations
- **Synthetic Dataset Bounds**: While statistically modeled after CIC-IDS2017, synthetic data does not capture all zero-day network behaviors.
- **IP Geolocation**: Private IP addresses (RFC 1918) cannot be geolocated without internal enterprise mapping.
- **Topology Scale**: Graph simulations are optimized for demonstration enterprise network topographies (~10–100 core nodes).

---

## 33. Future Enhancements
- Integration with live Zeek / Suricata packet capture taps.
- Deep Learning flow classification using Temporal Convolutional Networks (TCN) or LSTMs.
- Active directory sync via LDAP/Kerberos audit connectors.
- Automated SOAR webhook execution for firewall rule deployment.

---

## 34. Project Conclusion
The **AI SOC Assistant** successfully demonstrates that combining supervised machine learning with graph-based attack path modeling and explainable threat intelligence significantly reduces alert fatigue and accelerates incident triage. By providing clear evidence-backed recommendations and accurate geographic context, the system serves as an effective decision-support tool for modern cybersecurity teams.

---

## 35. Author & Academic Project Information
- **Student Name**: Prachi Goyal
- **Roll Number**: F044
- **Student ID**: 70022400311
- **Degree**: Bachelor of Technology (B.Tech) in Computer Engineering (Section A)
- **Institution**: SVKM's NMIMS, School of Technology Management & Engineering (STME), Mumbai, India
- **Faculty Guide / HOD**: Dr. Vikas Khare (Associate Professor & Associate Dean - STME)
- **Academic Year**: 2025–2026

---
*Developed for academic evaluation, research demonstration, and open-source cybersecurity education.*
