import React from 'react';
import { Activity, Clock } from 'lucide-react';
import { ActivityLog } from '../../types/soc';
import { SeverityBadge } from '../common/Badge';

interface RecentActivityTableProps {
  logs: ActivityLog[];
}

export const RecentActivityTable: React.FC<RecentActivityTableProps> = ({ logs }) => {
  return (
    <div className="soc-card p-3 flex flex-col justify-between h-[230px]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-1.5">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            Recent Activity & Audit Log
          </span>
        </div>
        <span className="text-[10px] font-mono text-slate-400">
          Persistent SOC Event Stream ({logs.length} logged)
        </span>
      </div>

      {/* Table */}
      <div className="overflow-y-auto max-h-[160px] scrollbar-thin my-1">
        <table className="w-full text-left text-[11px] font-mono border-collapse">
          <thead>
            <tr className="text-[9px] text-slate-400 uppercase border-b border-[#16233b] pb-1">
              <th className="py-1 font-medium w-24">Timestamp</th>
              <th className="py-1 font-medium w-36">Event</th>
              <th className="py-1 font-medium w-32">Source</th>
              <th className="py-1 font-medium w-36">Target</th>
              <th className="py-1 font-medium w-20">Severity</th>
              <th className="py-1 font-medium">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#131d30]">
            {logs.slice(0, 5).map(log => (
              <tr key={log.id} className="hover:bg-[#111c30] transition-colors">
                <td className="py-1.5 text-slate-400 text-[10px] whitespace-nowrap">
                  {log.timestamp.split(' ')[1] || log.timestamp}
                </td>
                <td className="py-1.5 font-semibold text-slate-200 whitespace-nowrap">
                  {log.event}
                </td>
                <td className="py-1.5 text-cyan-400 text-[10px] truncate max-w-[120px]">
                  {log.source}
                </td>
                <td className="py-1.5 text-slate-300 text-[10px] truncate max-w-[130px]">
                  {log.target}
                </td>
                <td className="py-1.5">
                  <SeverityBadge severity={log.severity} size="xs" />
                </td>
                <td className="py-1.5 text-slate-400 text-[10px] truncate max-w-[260px]">
                  {log.details}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="text-[9px] font-mono text-slate-400 flex items-center justify-between border-t border-[#16233b] pt-1">
        <span>Immutable tamper-evident logging records</span>
        <span className="text-emerald-400">All Operations Synchronized</span>
      </div>
    </div>
  );
};
