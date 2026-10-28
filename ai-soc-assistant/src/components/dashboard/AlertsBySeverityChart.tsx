import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Severity } from '../../types/soc';

interface AlertsBySeverityProps {
  distribution: Array<{ severity: Severity; count: number; percentage: number }>;
  total: number;
  className?: string;
}

const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#f59e0b',
  Low: '#3b82f6',
  Informational: '#64748b'
};

export const AlertsBySeverityChart: React.FC<AlertsBySeverityProps> = ({ distribution, total, className = 'flex-1' }) => {
  const chartData = distribution
    .filter(d => d.count > 0)
    .map(d => ({
      name: d.severity,
      value: d.count,
      percentage: d.percentage,
      color: SEVERITY_COLORS[d.severity]
    }));

  return (
    <div className={`soc-card p-3 flex flex-col justify-between ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-semibold text-slate-200">Alerts by Severity</span>
        </div>
        <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-500/30">
          Total: {total}
        </span>
      </div>

      {/* Doughnut Chart & Legend */}
      <div className="flex items-center justify-between gap-3 my-auto">
        {/* Doughnut with center count */}
        <div className="relative w-32 h-32 flex-shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-[#0b1120] border border-[#1b2b47] px-2 py-1 rounded shadow text-[10px] font-mono text-slate-200">
                        <span className="font-semibold" style={{ color: data.color }}>{data.name}</span>: {data.value} ({data.percentage}%)
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Pie
                data={chartData.length > 0 ? chartData : [{ name: 'None', value: 1, color: '#334155' }]}
                innerRadius={36}
                outerRadius={54}
                paddingAngle={3}
                dataKey="value"
                stroke="none"
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-lg font-bold font-mono text-slate-100 leading-tight">
              {total}
            </span>
            <span className="text-[8px] font-mono text-slate-500 uppercase tracking-widest">
              ALERTS
            </span>
          </div>
        </div>

        {/* Compact Legend */}
        <div className="flex-1 space-y-1.5 text-[11px] font-mono">
          {distribution.map(item => (
            <div key={item.severity} className="flex items-center justify-between text-slate-300">
              <div className="flex items-center gap-1.5 truncate">
                <span
                  className="w-2 h-2 rounded-full flex-shrink-0"
                  style={{ backgroundColor: SEVERITY_COLORS[item.severity] }}
                />
                <span className="truncate text-slate-400">{item.severity}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-200">{item.count}</span>
                <span className="text-[10px] text-slate-500 w-9 text-right">
                  {item.percentage}%
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
