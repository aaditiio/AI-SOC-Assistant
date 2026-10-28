import React, { useState, useEffect } from 'react';
import { Shield, Cpu, HardDrive, AlertTriangle, CheckCircle2, RefreshCw, Power } from 'lucide-react';
import { EndpointSensor } from '../types/soc';
import { socApi } from '../services/api';

export const EndpointsPage: React.FC = () => {
  const [endpoints, setEndpoints] = useState<EndpointSensor[]>([]);
  const [toast, setToast] = useState<string | null>(null);

  const loadEndpoints = async () => {
    const eps = await socApi.getEndpoints();
    setEndpoints(eps);
  };

  useEffect(() => {
    loadEndpoints();
  }, []);

  const handleIsolate = async (id: string, currentStatus: string) => {
    const isQuarantined = currentStatus === 'Quarantined';
    await socApi.isolateEndpoint(id, !isQuarantined);
    setToast(`Endpoint isolation toggled.`);
    setTimeout(() => setToast(null), 3000);
    loadEndpoints();
  };

  const handleScan = async (id: string) => {
    const msg = await socApi.scanEndpoint(id);
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
    loadEndpoints();
  };

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Endpoint Detection & Response (EDR) Sensor Fleet
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              {endpoints.length} Active Sensors
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time host isolation, process tree inspection, and memory integrity checks across enterprise endpoints.
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
        {endpoints.map(ep => (
          <div key={ep.id} className="soc-card p-4 bg-[#0b1324] border border-[#1b2b47] rounded space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-cyan-400 font-bold">{ep.hostname}</span>
                <span className="text-slate-400 ml-2">({ep.ip})</span>
              </div>
              <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                ep.status === 'Quarantined' ? 'bg-red-950 text-red-400 border border-red-500/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
              }`}>
                {ep.status}
              </span>
            </div>

            <div className="text-[11px] text-slate-300 space-y-1">
              <div>OS: {ep.os}</div>
              <div>Heartbeat: {ep.lastHeartbeat}</div>
            </div>

            <div className="space-y-1 pt-2 border-t border-[#18263f]">
              <div className="text-[10px] text-slate-400 uppercase">Running Processes ({ep.processes.length})</div>
              {ep.processes.map(p => (
                <div key={p.pid} className="p-2 bg-[#0e172a] rounded flex items-center justify-between text-[11px]">
                  <div>
                    <span className="text-slate-200 font-semibold">{p.name}</span>
                    <span className="text-slate-400 ml-2">PID: {p.pid} ({p.user})</span>
                  </div>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] ${p.status === 'Suspicious' ? 'bg-red-950 text-red-400' : 'bg-slate-800 text-slate-300'}`}>
                    {p.status}
                  </span>
                </div>
              ))}
            </div>

            <div className="flex items-center gap-2 pt-2">
              <button
                onClick={() => handleIsolate(ep.id, ep.status)}
                className={`px-3 py-1.5 rounded font-bold transition-colors ${
                  ep.status === 'Quarantined'
                    ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                    : 'bg-red-600 hover:bg-red-500 text-white'
                }`}
              >
                {ep.status === 'Quarantined' ? 'Restore Network' : 'Isolate Host'}
              </button>
              <button
                onClick={() => handleScan(ep.id)}
                className="px-3 py-1.5 bg-[#121c2e] hover:bg-[#1a2842] text-cyan-300 border border-[#233554] rounded font-bold transition-colors"
              >
                Run Forensic Scan
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
