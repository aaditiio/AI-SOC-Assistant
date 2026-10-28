import React from 'react';
import { Cpu, ShieldCheck, AlertTriangle } from 'lucide-react';
import { SeverityBadge } from '../common/Badge';

interface AiAnalysisInsightsProps {
  className?: string;
}

export const AiAnalysisInsights: React.FC<AiAnalysisInsightsProps> = ({ className = 'flex-1' }) => {
  const insights = [
    {
      id: 'INS-01',
      title: 'Correlated Kerberos Spraying on Domain Controller',
      severity: 'Critical' as const,
      alertId: 'ALT-9041',
      evidence: '42 auth requests/sec from host 10.0.3.45 with high PSH flag count followed by RPC pipe binding.',
      recommendation: 'Quarantine host 10.0.3.45 via dynamic 802.1X VLAN isolation and invalidate Kerberos ticket cache.'
    },
    {
      id: 'INS-02',
      title: 'SYN Volumetric Influx on Perimeter Web Node',
      severity: 'High' as const,
      alertId: 'ALT-8812',
      evidence: 'Destination port 443 observed 14,200 pkts/s with SYN flag bit set and zero subsequent ACK completion.',
      recommendation: 'Activate edge SYN cookie defense and throttle inbound traffic from external subnet 198.51.100.0/24.'
    },
    {
      id: 'INS-03',
      title: 'Periodic Beaconing Pattern to Remote Port 4444',
      severity: 'High' as const,
      alertId: 'ALT-7104',
      evidence: 'Standard deviation of flow inter-arrival time < 15ms with 180-byte uniform payloads.',
      recommendation: 'Perform host memory acquisition and compare binary hashes against known C2 malleable profiles.'
    }
  ];

  return (
    <div className={`soc-card p-3 flex flex-col justify-between ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-1.5">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            AI Analysis Insights
          </span>
        </div>
        <span className="text-[9px] font-mono text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-500/30">
          Model-assisted & rule-based
        </span>
      </div>

      {/* Insights list */}
      <div className="space-y-2 overflow-y-auto max-h-[240px] scrollbar-thin my-1 pr-1">
        {insights.map(item => (
          <div
            key={item.id}
            className="p-2 rounded bg-[#090f1e] border border-[#182640] text-xs font-mono space-y-1 hover:border-slate-600 transition-colors"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-100 text-[11px] truncate max-w-[170px]">
                {item.title}
              </span>
              <SeverityBadge severity={item.severity} size="xs" />
            </div>

            <p className="text-[10px] text-slate-400 leading-tight">
              <span className="text-slate-500 font-semibold">Evidence:</span> {item.evidence}
            </p>

            <div className="bg-[#0e172a] p-1.5 rounded border border-[#1b2b47] text-[10px] text-cyan-300">
              <span className="text-slate-400 font-bold block text-[9px] uppercase">
                Defensive Action ({item.alertId}):
              </span>
              {item.recommendation}
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="text-[9px] font-mono text-slate-400 flex items-center justify-between border-t border-[#16233b] pt-1">
        <span>Transparent local rule engine & RF outputs</span>
        <span className="text-emerald-400">3 Verified Insights</span>
      </div>
    </div>
  );
};
