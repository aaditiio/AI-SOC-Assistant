import React from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  Flame,
  FolderLock,
  Clock,
  Server,
  TrendingUp,
  Activity
} from 'lucide-react';
import { DashboardOverview } from '../../types/soc';

interface KpiRowProps {
  overview: DashboardOverview | null;
  loading?: boolean;
}

export const KpiRow: React.FC<KpiRowProps> = ({ overview, loading }) => {
  const cards = [
    {
      title: 'Total Alerts',
      value: overview?.totalAlerts ?? 7,
      icon: AlertTriangle,
      color: 'text-slate-100',
      borderColor: 'border-[#1b2b48]',
      accentBg: 'bg-cyan-500/10 text-cyan-400',
      badge: 'Synthetic baseline',
      sparkline: [3, 4, 6, 8, 5, 7, 9, 7],
      unit: ''
    },
    {
      title: 'Critical Alerts',
      value: overview?.criticalAlerts ?? 2,
      icon: ShieldAlert,
      color: 'text-red-400',
      borderColor: 'border-red-900/40 hover:border-red-700/60',
      accentBg: 'bg-red-500/10 text-red-400',
      badge: 'Immediate triage',
      sparkline: [1, 0, 2, 1, 3, 2],
      unit: ''
    },
    {
      title: 'High Alerts',
      value: overview?.highAlerts ?? 3,
      icon: Flame,
      color: 'text-orange-400',
      borderColor: 'border-orange-900/40 hover:border-orange-700/60',
      accentBg: 'bg-orange-500/10 text-orange-400',
      badge: 'Active containment',
      sparkline: [2, 3, 1, 4, 3],
      unit: ''
    },
    {
      title: 'Open Incidents',
      value: overview?.openIncidents ?? 2,
      icon: FolderLock,
      color: 'text-amber-400',
      borderColor: 'border-amber-900/40 hover:border-amber-700/60',
      accentBg: 'bg-amber-500/10 text-amber-400',
      badge: '2 in investigation',
      sparkline: [1, 2, 2, 3, 2],
      unit: ''
    },
    {
      title: 'Mean Time to Respond',
      value: overview?.mttrMinutes !== null && overview?.mttrMinutes !== undefined
        ? `${overview.mttrMinutes}m`
        : 'N/A',
      icon: Clock,
      color: 'text-cyan-400',
      borderColor: 'border-cyan-900/40 hover:border-cyan-700/60',
      accentBg: 'bg-cyan-500/10 text-cyan-400',
      badge: overview?.mttrMinutes ? 'Valid incident avg' : 'No observations',
      sparkline: [35, 32, 28, 25, 28],
      unit: ''
    },
    {
      title: 'Assets at Risk',
      value: overview?.assetsAtRisk ?? 4,
      icon: Server,
      color: 'text-rose-400',
      borderColor: 'border-rose-900/40 hover:border-rose-700/60',
      accentBg: 'bg-rose-500/10 text-rose-400',
      badge: 'Risk score ≥ 60',
      sparkline: [3, 3, 4, 4, 4],
      unit: ''
    }
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2.5">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`soc-card p-3 flex flex-col justify-between transition-all duration-150 border ${card.borderColor} bg-[#0c1424]`}
          >
            {/* Top row: Title and Icon */}
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-400 truncate tracking-tight">
                {card.title}
              </span>
              <div className={`p-1 rounded ${card.accentBg}`}>
                <Icon className="w-3.5 h-3.5" />
              </div>
            </div>

            {/* Middle row: Large Numeric Value */}
            <div className="my-1.5 flex items-baseline justify-between">
              <span className={`text-2xl font-bold font-mono tracking-tight ${card.color}`}>
                {card.value}
              </span>

              {/* Mini SVG Sparkline */}
              <div className="w-16 h-5 flex items-end">
                <svg className="w-full h-full overflow-visible" viewBox="0 0 50 20">
                  <polyline
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className={card.color}
                    points={card.sparkline
                      .map((val, i) => `${(i / (card.sparkline.length - 1)) * 48 + 1},${20 - (val / Math.max(...card.sparkline, 1)) * 16}`)
                      .join(' ')}
                  />
                </svg>
              </div>
            </div>

            {/* Bottom row: Subtitle / Trend Badge */}
            <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-[#162238]">
              <span className="truncate">{card.badge}</span>
              <span className="text-[9px] text-slate-400">Live</span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
