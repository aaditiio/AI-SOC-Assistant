import React from 'react';
import { X, ShieldAlert, CheckCircle2, ArrowRight, Activity, Terminal } from 'lucide-react';
import { Alert } from '../../types/soc';
import { SeverityBadge, StatusBadge } from '../common/Badge';

interface AlertInvestigationDrawerProps {
  alert: Alert | null;
  onClose: () => void;
  onUpdateStatus: (alertId: string, status: Alert['status']) => void;
  onEscalateToIncident: (alert: Alert) => void;
}

export const AlertInvestigationDrawer: React.FC<AlertInvestigationDrawerProps> = ({
  alert,
  onClose,
  onUpdateStatus,
  onEscalateToIncident
}) => {
  if (!alert) return null;

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex justify-end animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-[#090f1f] border-l border-[#1d2f50] h-full flex flex-col justify-between shadow-2xl overflow-y-auto scrollbar-thin">
        {/* Drawer Header */}
        <div className="p-4 border-b border-[#1b2b47] flex items-center justify-between bg-[#080d19] sticky top-0 z-10">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded bg-red-950/60 border border-red-500/40 text-red-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-sm text-slate-100">{alert.id}</span>
                <SeverityBadge severity={alert.severity} size="xs" />
                <StatusBadge status={alert.status} size="xs" />
              </div>
              <span className="text-[10px] font-mono text-slate-400">
                Timestamp: {alert.timestamp}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded bg-[#131f36] hover:bg-[#1c2e4f] text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-4 space-y-4 text-xs font-mono">
          {/* Title & Core Classification */}
          <div className="bg-[#0c1424] p-3 rounded border border-[#1b2b47] space-y-2">
            <h3 className="font-bold text-sm text-slate-100 leading-snug">
              {alert.title}
            </h3>

            <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
              <div>
                <span className="text-slate-400 block text-[9px] uppercase">Predicted Threat:</span>
                <span className="font-bold text-cyan-300">{alert.predictedCategory}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[9px] uppercase">Confidence Score:</span>
                <span className="font-bold text-emerald-400">{(alert.confidence * 100).toFixed(1)}%</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[9px] uppercase">Source Origin:</span>
                <span className="text-slate-200">{alert.sourceIp}:{alert.sourcePort}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[9px] uppercase">Target Destination:</span>
                <span className="text-purple-300">{alert.destIp}:{alert.destPort} ({alert.protocol})</span>
              </div>
            </div>
          </div>

          {/* Evidence Breakdown */}
          <div className="bg-[#0c1424] p-3 rounded border border-[#1b2b47] space-y-2">
            <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider block">
              Observed Network Evidence
            </span>
            <ul className="space-y-1.5 list-disc pl-4 text-slate-300 text-[11px]">
              {alert.evidence.map((item, idx) => (
                <li key={idx} className="leading-relaxed">{item}</li>
              ))}
            </ul>
          </div>

          {/* Explainable Threat Insights */}
          <div className="bg-[#0c1424] p-3 rounded border border-[#1b2b47] space-y-1.5">
            <span className="text-[10px] font-bold text-amber-400 uppercase tracking-wider block">
              Classification Reasoning
            </span>
            <p className="text-slate-300 text-[11px] leading-relaxed">
              {alert.explanation}
            </p>
          </div>

          {/* Recommended Defensive Actions */}
          <div className="bg-cyan-950/30 p-3 rounded border border-cyan-500/30 space-y-1.5">
            <span className="text-[10px] font-bold text-cyan-300 uppercase tracking-wider block flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Recommended Defensive Containment
            </span>
            <p className="text-slate-200 text-[11px] leading-relaxed">
              {alert.recommendation}
            </p>
          </div>

          {/* Raw Network Flow Features */}
          <div className="bg-[#080d19] p-3 rounded border border-[#16233b] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-400 uppercase flex items-center gap-1">
                <Terminal className="w-3 h-3 text-cyan-400" />
                Raw Packet Flow Telemetry
              </span>
              <span className="text-[9px] text-slate-400">16 Features Extracted</span>
            </div>

            <div className="grid grid-cols-2 gap-1.5 text-[10px] bg-[#050811] p-2 rounded border border-[#131d30]">
              <div className="flex justify-between text-slate-400">
                <span>Flow Duration:</span>
                <span className="text-slate-200 font-semibold">{alert.packetFeatures.flowDuration} μs</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Forward Pkts:</span>
                <span className="text-slate-200 font-semibold">{alert.packetFeatures.totFwdPkts}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Backward Pkts:</span>
                <span className="text-slate-200 font-semibold">{alert.packetFeatures.totBwdPkts}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Packets / sec:</span>
                <span className="text-cyan-400 font-semibold">{alert.packetFeatures.flowPktsPerSec.toLocaleString()}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Bytes / sec:</span>
                <span className="text-cyan-400 font-semibold">{alert.packetFeatures.flowBytsPerSec.toLocaleString()}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>SYN Flag Count:</span>
                <span className="text-red-400 font-semibold">{alert.packetFeatures.synFlagCnt}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>PSH Flag Count:</span>
                <span className="text-amber-400 font-semibold">{alert.packetFeatures.pshFlagCnt}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Fwd Pkt Len Mean:</span>
                <span className="text-slate-200 font-semibold">{alert.packetFeatures.fwdPktLenMean} B</span>
              </div>
            </div>
          </div>
        </div>

        {/* Drawer Actions Footer */}
        <div className="p-4 border-t border-[#1b2b47] bg-[#080d19] sticky bottom-0 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs font-mono">
              <span className="text-slate-400 text-[10px]">Triage:</span>
              <button
                onClick={() => onUpdateStatus(alert.id, 'Investigating')}
                className={`px-2 py-1 rounded text-[10px] border transition-colors ${
                  alert.status === 'Investigating'
                    ? 'bg-amber-950 text-amber-300 border-amber-500/50'
                    : 'bg-[#121c30] text-slate-300 border-slate-700 hover:bg-[#1a2947]'
                }`}
              >
                Investigate
              </button>
              <button
                onClick={() => onUpdateStatus(alert.id, 'Resolved')}
                className={`px-2 py-1 rounded text-[10px] border transition-colors ${
                  alert.status === 'Resolved'
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-500/50'
                    : 'bg-[#121c30] text-slate-300 border-slate-700 hover:bg-[#1a2947]'
                }`}
              >
                Mark Resolved
              </button>
              <button
                onClick={() => onUpdateStatus(alert.id, 'False Positive')}
                className={`px-2 py-1 rounded text-[10px] border transition-colors ${
                  alert.status === 'False Positive'
                    ? 'bg-slate-800 text-slate-300 border-slate-600'
                    : 'bg-[#121c30] text-slate-400 border-slate-700 hover:bg-[#1a2947]'
                }`}
              >
                False Positive
              </button>
            </div>

            <button
              onClick={() => onEscalateToIncident(alert)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white font-mono text-xs font-semibold shadow-lg shadow-red-600/30 transition-all"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Escalate to Incident</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
