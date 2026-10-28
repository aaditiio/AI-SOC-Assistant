# AI SOC Assistant - Local FastAPI Backend

Intelligent Cyber Threat Detection, Alert Prioritization, and Attack Path Analysis System.
Designed for B.Tech Computer Engineering Final / Capstone Project demonstration.

---

## 1. Quick Setup & Run Instructions

### Step 1: Create and activate a Python virtual environment
```bash
cd backend
python3 -m venv venv

# On Linux / macOS:
source venv/bin/activate

# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
```

### Step 2: Install required Python dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run the FastAPI backend server
```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
The FastAPI backend will start at:
- **API Base URL**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **Alternative ReDoc**: `http://127.0.0.1:8000/redoc`

### Step 4: Run unit and integration tests
```bash
pytest test_backend.py -v
```

---

## 2. Architecture & Algorithms Overview

### A. Machine Learning Pipeline
- **Dataset**: Exactly 5,000 synthetic network flow records generated across 7 attack classes (`BENIGN`, `DoS`, `DDoS`, `PortScan`, `BruteForce`, `Bot`, `WebAttack`) using private IP subnets (RFC 1918 & RFC 5737).
- **Model**: scikit-learn `RandomForestClassifier(n_estimators=100, max_depth=14, random_state=42)`.
- **Validation**: Stratified 80/20 train/test split (4,000 train / 1,000 test) ensuring zero target leakage.
- **Evaluation**: Accuracy, Macro Precision, Macro Recall, Macro F1, Weighted F1, 7x7 Confusion Matrix, Per-Class Classification Report, and Feature Importances.
- **Persistence**: Joblib model serialization to `backend/models/random_forest_soc.joblib`.

### B. Attack Path Analysis Graph
- **Graph Topology**: NetworkX-compatible directed graph representing enterprise SOC infrastructure (Firewall, DMZ Web Server, Internal API Gateway, Workstations, Domain Controller, Database, Backup NAS).
- **Implemented Algorithms**:
  - **BFS (Breadth-First Search)**: Explores radially, guaranteed minimum-edge path for unweighted networks.
  - **DFS (Depth-First Search)**: Explores deep paths before backtracking.
  - **Greedy Best-First Search**: Greedy search guided by topological heuristic $h(n)$.
  - **A\* Search**: Combines exact cumulative path cost $g(n)$ and admissible heuristic $h(n)$ ($f(n) = g(n) + h(n)$), providing guaranteed optimal lowest-cost traversal.

### C. Persistent Storage
- SQLite database (`soc_assistant.db`) managing alerts, incidents, assets with explainable risk scores, verified vulnerabilities, threat intelligence indicators, and immutable activity audit logs.
