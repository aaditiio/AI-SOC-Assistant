import React from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';

interface AlertsOverTimeProps {
  data: Array<{
    time: string;
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Informational: number;
  }>;
  className?: string;
}

export const AlertsOverTimeChart: React.FC<AlertsOverTimeProps> = ({ data, className = 'flex-1' }) => {
  return (
    <div className={`soc-card p-3 flex flex-col justify-between ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-mono font-semibold text-slate-200">Alerts Over Time</span>
        </div>
        <span className="text-[9px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
          Synthetic Demonstration
        </span>
      </div>

      {/* Chart */}
      <div className="h-44 w-full my-auto">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 8, right: 10, left: -22, bottom: 0 }}>
            <CartesianGrid stroke="#152136" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="time"
              stroke="#475569"
              tick={{ fontSize: 9, fill: '#64748b', fontFamily: 'JetBrains Mono' }}
              tickLine={false}
              axisLine={{ stroke: '#1e293b' }}
            />
            <YAxis
              stroke="#475569"
              tick={{ fontSize: 9, fill: '#64748b', fontFamily: 'JetBrains Mono' }}
              tickLine={false}
              axisLine={{ stroke: '#1e293b' }}
            />
            <Tooltip
              content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-[#090e1a] border border-[#1e2e4a] p-2 rounded shadow-lg text-[10px] font-mono space-y-1">
                      <div className="text-slate-400 border-b border-slate-800 pb-1 font-semibold">{label} UTC</div>
                      {payload.map((entry, idx) => (
                        <div key={idx} className="flex items-center justify-between gap-3" style={{ color: entry.color }}>
                          <span>{entry.name}:</span>
                          <span className="font-bold">{entry.value}</span>
                        </div>
                      ))}
                    </div>
                  );
                }
                return null;
              }}
            />
            <Line type="monotone" dataKey="Critical" stroke="#ef4444" strokeWidth={2} dot={{ r: 2, fill: '#ef4444' }} />
            <Line type="monotone" dataKey="High" stroke="#f97316" strokeWidth={1.5} dot={{ r: 2, fill: '#f97316' }} />
            <Line type="monotone" dataKey="Medium" stroke="#f59e0b" strokeWidth={1.5} dot={{ r: 2, fill: '#f59e0b' }} />
            <Line type="monotone" dataKey="Low" stroke="#3b82f6" strokeWidth={1.2} dot={{ r: 1.5, fill: '#3b82f6' }} />
            <Line type="monotone" dataKey="Informational" stroke="#64748b" strokeWidth={1} strokeDasharray="3 3" dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Mini Legend */}
      <div className="flex items-center justify-between text-[9px] font-mono text-slate-400 pt-1.5 border-t border-[#16233b]">
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
          <span>Critical</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
          <span>High</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
          <span>Med</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
          <span>Low</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
          <span>Info</span>
        </div>
      </div>
    </div>
  );
};
