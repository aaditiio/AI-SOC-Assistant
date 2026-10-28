import React from 'react';
import { X, Shield, Cpu, Network, Database, BookOpen, CheckCircle2, Server } from 'lucide-react';

interface HelpModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const HelpModal: React.FC<HelpModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-[#0b1324] border border-[#1d2f50] rounded-lg max-w-3xl w-full max-h-[85vh] flex flex-col justify-between shadow-2xl animate-in zoom-in-95 font-mono text-xs">
        {/* Header */}
        <div className="p-4 border-b border-[#1b2b47] flex items-center justify-between bg-[#080d19]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100">
                AI SOC Assistant - Project Architecture & Academic Defense Guide
              </h2>
              <span className="text-[10px] text-cyan-400">
                B.Tech Computer Engineering Capstone Project
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded bg-[#131f36] hover:bg-[#1c2e4f] text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="p-4 space-y-4 overflow-y-auto scrollbar-thin">
          {/* Executive Overview */}
          <div className="soc-card p-3 space-y-1.5 bg-[#0c1424]">
            <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider block">
              1. Project Problem Statement & System Design
            </span>
            <p className="text-slate-300 text-[11px] leading-relaxed">
              Modern Security Operations Centers (SOCs) face alert fatigue from tens of thousands of daily telemetry logs. This system implements an intelligent cyber threat detection engine that combines supervised machine learning (Random Forest), explainable rule-based severity categorization, and graph theory (BFS, DFS, Greedy Best-First, A*) to model and predict adversary lateral movement attack paths.
            </p>
          </div>

          {/* Machine Learning Pipeline */}
          <div className="soc-card p-3 space-y-2 bg-[#0c1424]">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-emerald-400" />
              <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
                2. Machine Learning Implementation (scikit-learn)
              </span>
            </div>
            <ul className="space-y-1 text-slate-300 text-[11px] list-disc pl-4 leading-relaxed">
              <li>
                <strong className="text-slate-100">Dataset:</strong> Exactly 5,000 synthetic network flow records generated using RFC 1918 private subnets across 7 classes: <code className="text-cyan-300">BENIGN, DoS, DDoS, PortScan, BruteForce, Bot, WebAttack</code>.
              </li>
              <li>
                <strong className="text-slate-100">Feature Engineering:</strong> 18 network flow attributes (flow duration, forward/backward packets & bytes, flow bytes/s, flow packets/s, packet length statistics, TCP flags: SYN, RST, ACK, PSH, ports, protocol). Identifiers, IP addresses, and timestamps are strictly excluded from features to eliminate target leakage.
              </li>
              <li>
                <strong className="text-slate-100">Validation & Metrics:</strong> Stratified 80/20 train/test split (4,000 train / 1,000 test). Held-out test evaluation achieves ~95.8% accuracy, 0.9448 Macro F1, and complete 7x7 confusion matrix.
              </li>
              <li>
                <strong className="text-slate-100">Local Persistence:</strong> Joblib model serialization stored in <code className="text-cyan-300">backend/models/random_forest_soc.joblib</code>.
              </li>
            </ul>
          </div>

          {/* Graph Algorithms */}
          <div className="soc-card p-3 space-y-2 bg-[#0c1424]">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider">
                3. Attack Path Graph Traversal Algorithms (NetworkX)
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px] text-slate-300">
              <div className="bg-[#080d19] p-2 rounded border border-[#16233b]">
                <strong className="text-cyan-400 block mb-0.5">Breadth-First Search (BFS):</strong>
                Explores all neighboring vertices level-by-level radially. Guaranteed to find the minimum-hop path on an unweighted network graph.
              </div>
              <div className="bg-[#080d19] p-2 rounded border border-[#16233b]">
                <strong className="text-amber-400 block mb-0.5">Depth-First Search (DFS):</strong>
                Explores as deep as possible along single network branches before backtracking. Does NOT guarantee optimal path length or minimum cost.
              </div>
              <div className="bg-[#080d19] p-2 rounded border border-[#16233b]">
                <strong className="text-purple-400 block mb-0.5">Greedy Best-First Search:</strong>
                Expands nodes solely based on lowest estimated heuristic distance $h(n)$ to target. Computationally fast, but not guaranteed to find optimal cost.
              </div>
              <div className="bg-[#080d19] p-2 rounded border border-[#16233b]">
                <strong className="text-emerald-400 block mb-0.5">A* Search ($f(n) = g(n) + h(n)$):</strong>
                Combines path cost $g(n)$ and admissible heuristic $h(n)$. Mathematically proven to find the global lowest-cost traversal path.
              </div>
            </div>
          </div>

          {/* Local FastAPI Backend Setup */}
          <div className="soc-card p-3 space-y-2 bg-[#0c1424]">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-400" />
              <span className="text-[10px] font-bold text-blue-400 uppercase tracking-wider">
                4. Running the Local Python FastAPI Backend
              </span>
            </div>
            <p className="text-slate-400 text-[11px]">
              For local desktop deployment, the complete Python codebase is located in <code className="text-cyan-300">/backend</code>:
            </p>
            <pre className="bg-[#060a14] p-2 rounded border border-[#15233c] text-slate-300 text-[10px] overflow-x-auto">
{`cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
pytest test_backend.py -v`}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-[#1b2b47] bg-[#080d19] flex items-center justify-between">
          <span className="text-slate-500 text-[10px]">
            Demonstration Version: AI SOC Assistant v1.0.0
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition-colors"
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
};
