import React from 'react';
import { AlertCircle, ExternalLink, ArrowRight, ShieldCheck } from 'lucide-react';
import { Alert } from '../../types/soc';
import { SeverityBadge } from '../common/Badge';

interface RecentCriticalAlertsProps {
  alerts: Alert[];
  onSelectAlert: (alertId: string) => void;
  onViewAllAlerts: () => void;
  className?: string;
}

export const RecentCriticalAlerts: React.FC<RecentCriticalAlertsProps> = ({
  alerts,
  onSelectAlert,
  onViewAllAlerts,
  className = 'flex-1'
}) => {
  const criticalAndHigh = alerts
    .filter(a => a.severity === 'Critical' || a.severity === 'High')
    .slice(0, 3);

  return (
    <div className={`soc-card p-3 flex flex-col justify-between ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-1.5">
          <AlertCircle className="w-3.5 h-3.5 text-red-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            Recent Critical Alerts
          </span>
        </div>
        <button
          onClick={onViewAllAlerts}
          className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
        >
          <span>View All</span>
          <ArrowRight className="w-2.5 h-2.5" />
        </button>
      </div>

      {/* Alert List */}
      <div className="space-y-2 overflow-y-auto max-h-[200px] scrollbar-thin my-1 pr-1">
        {criticalAndHigh.map(alert => (
          <div
            key={alert.id}
            onClick={() => onSelectAlert(alert.id)}
            className="p-2 rounded bg-[#090f1e] border border-[#182640] hover:border-cyan-500/40 hover:bg-[#0d162a] transition-all cursor-pointer group"
          >
            <div className="flex items-center justify-between gap-1 mb-1">
              <div className="flex items-center gap-1.5">
                <SeverityBadge severity={alert.severity} size="xs" />
                <span className="text-[10px] font-mono font-bold text-slate-300 group-hover:text-cyan-300 truncate max-w-[140px]">
                  {alert.id}
                </span>
              </div>
              <span className="text-[9px] font-mono text-slate-400">
                {alert.timestamp.split(' ')[1] || alert.timestamp}
              </span>
            </div>

            <p className="text-[11px] font-semibold text-slate-100 truncate mb-1">
              {alert.title}
            </p>

            <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span className="truncate">
                {alert.sourceIp} → {alert.destIp}:{alert.destPort}
              </span>
              <span className="text-cyan-400 font-bold bg-cyan-950/60 px-1 py-0.2 rounded border border-cyan-500/20">
                {alert.predictedCategory}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="text-[9px] font-mono text-slate-400 flex items-center justify-between border-t border-[#16233b] pt-1">
        <span>Prioritized by RF confidence & severity</span>
        <span className="text-red-400 font-semibold">{criticalAndHigh.length} Critical/High active</span>
      </div>
    </div>
  );
};
