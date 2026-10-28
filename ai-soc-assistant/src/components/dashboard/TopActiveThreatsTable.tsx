import React from 'react';
import { ShieldAlert, ArrowUpRight } from 'lucide-react';
import { Alert } from '../../types/soc';

interface TopActiveThreatsTableProps {
  alerts: Alert[];
  onSelectAlert: (alertId: string) => void;
  className?: string;
}

export const TopActiveThreatsTable: React.FC<TopActiveThreatsTableProps> = ({
  alerts,
  onSelectAlert,
  className = 'flex-1'
}) => {
  const activeThreats = alerts.filter(a => a.predictedCategory !== 'BENIGN').slice(0, 4);

  return (
    <div className={`soc-card p-3 flex flex-col justify-between ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            Top Active Threats
          </span>
        </div>
        <span className="text-[10px] font-mono text-slate-400">
          Ranked by Model Confidence
        </span>
      </div>

      {/* Table */}
      <div className="overflow-y-auto max-h-[160px] scrollbar-thin my-1">
        <table className="w-full text-left text-[11px] font-mono border-collapse">
          <thead>
            <tr className="text-[9px] text-slate-400 uppercase border-b border-[#16233b] pb-1">
              <th className="py-1 font-medium">Threat / Category</th>
              <th className="py-1 font-medium">Source</th>
              <th className="py-1 font-medium">Target</th>
              <th className="py-1 font-medium text-center">Confidence</th>
              <th className="py-1 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#131d30]">
            {activeThreats.map(threat => (
              <tr
                key={threat.id}
                onClick={() => onSelectAlert(threat.id)}
                className="hover:bg-[#111c30] cursor-pointer transition-colors group"
              >
                <td className="py-1.5 pr-2">
                  <div className="font-semibold text-slate-100 group-hover:text-cyan-300 truncate max-w-[130px]">
                    {threat.title}
                  </div>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <span
                      className={`text-[9px] px-1 py-0.2 rounded font-bold ${
                        threat.severity === 'Critical'
                          ? 'bg-red-950 text-red-400 border border-red-500/40'
                          : 'bg-orange-950 text-orange-400 border border-orange-500/40'
                      }`}
                    >
                      {threat.predictedCategory}
                    </span>
                    <span className="text-[9px] text-slate-400">{threat.id}</span>
                  </div>
                </td>
                <td className="py-1.5 text-slate-300">
                  <span className="text-cyan-400 font-mono text-[10px]">{threat.sourceIp}</span>
                  <div className="text-[9px] text-slate-400">Port {threat.sourcePort}</div>
                </td>
                <td className="py-1.5 text-slate-300">
                  <span className="text-purple-300 font-mono text-[10px]">{threat.destIp}</span>
                  <div className="text-[9px] text-slate-400">Port {threat.destPort}</div>
                </td>
                <td className="py-1.5 text-center">
                  <span className="text-[10px] font-bold text-slate-200">
                    {(threat.confidence * 100).toFixed(1)}%
                  </span>
                </td>
                <td className="py-1.5 text-right">
                  <button className="p-1 rounded bg-[#162238] group-hover:bg-cyan-500/20 group-hover:text-cyan-300 text-slate-400 transition-colors">
                    <ArrowUpRight className="w-3 h-3" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="text-[9px] font-mono text-slate-400 flex items-center justify-between border-t border-[#16233b] pt-1">
        <span>Click row to open Investigation Drawer</span>
        <span className="text-slate-400">4 Active Ingress Vectors</span>
      </div>
    </div>
  );
};
