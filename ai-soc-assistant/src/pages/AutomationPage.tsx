import React, { useState, useEffect } from 'react';
import { Zap, CheckCircle2, Play, Activity, Shield } from 'lucide-react';
import { AutomationPlaybook } from '../types/soc';
import { socApi } from '../services/api';

export const AutomationPage: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<AutomationPlaybook[]>([]);
  const [toast, setToast] = useState<string | null>(null);

  const loadPlaybooks = async () => {
    const pbs = await socApi.getPlaybooks();
    setPlaybooks(pbs);
  };

  useEffect(() => {
    loadPlaybooks();
  }, []);

  const handleRun = async (id: string) => {
    const res = await socApi.executePlaybook(id);
    if (res) {
      setToast(`Playbook ${res.name} executed successfully.`);
    } else {
      setToast(`Playbook execution triggered.`);
    }
    setTimeout(() => setToast(null), 4000);
    loadPlaybooks();
  };

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Security Orchestration, Automation & Response (SOAR) Playbooks
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              {playbooks.length} Active Workflows
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Automated remediation workflows for instant threat containment, IP blocking, and host quarantine upon high confidence triggers.
          </p>
        </div>
      </div>

      {toast && (
        <div className="bg-cyan-950 text-cyan-300 border border-cyan-500/40 p-2.5 rounded text-xs flex items-center justify-between">
          <span>{toast}</span>
          <button onClick={() => setToast(null)} className="text-slate-400 hover:text-white">Dismiss</button>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {playbooks.map(pb => (
          <div key={pb.id} className="soc-card p-4 bg-[#0b1324] border border-[#1b2b47] rounded space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-cyan-400 font-bold">{pb.id}: {pb.name}</span>
                <div className="text-[10px] text-slate-400 mt-0.5">Trigger: {pb.trigger}</div>
              </div>
              <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                pb.runStatus === 'Success' ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40' : 'bg-slate-800 text-slate-400'
              }`}>
                {pb.runStatus}
              </span>
            </div>

            <p className="text-slate-300 text-[11px]">{pb.description}</p>

            <div className="space-y-1 pt-2 border-t border-[#18263f]">
              <div className="text-[10px] text-slate-400 uppercase">Workflow Steps ({pb.steps.length})</div>
              {pb.steps.map((st) => (
                <div key={st.stepNumber} className="p-2 bg-[#0e172a] rounded text-[11px] text-slate-300 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                    <span>{st.stepNumber}. {st.title}</span>
                  </div>
                  <span className="text-[10px] text-emerald-400">{st.status}</span>
                </div>
              ))}
            </div>

            <div className="text-[10px] text-slate-400 pt-1">
              Target Asset: <span className="text-cyan-300 font-bold">{pb.target}</span> | Last Run: {pb.lastRun || 'Never'}
            </div>

            <div className="flex items-center gap-2 pt-2">
              <button
                onClick={() => handleRun(pb.id)}
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded transition-colors flex items-center gap-1.5"
              >
                <Play className="w-3.5 h-3.5" /> Execute Playbook
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
