import React from 'react';
import { Globe2, ShieldAlert, ExternalLink, CheckCircle } from 'lucide-react';
import { ThreatIntelItem } from '../../types/soc';

interface ThreatIntelligenceFeedProps {
  items: ThreatIntelItem[];
  className?: string;
}

export const ThreatIntelligenceFeed: React.FC<ThreatIntelligenceFeedProps> = ({ items, className = 'flex-1' }) => {
  return (
    <div className={`soc-card p-3 flex flex-col justify-between ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-1.5">
          <Globe2 className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            Threat Intelligence Feed
          </span>
        </div>
        <span className="text-[9px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
          Curated Knowledge Base
        </span>
      </div>

      {/* Feed Items */}
      <div className="space-y-2 overflow-y-auto max-h-[240px] scrollbar-thin my-1 pr-1">
        {items.slice(0, 3).map(intel => (
          <div
            key={intel.id}
            className="p-2 rounded bg-[#090f1e] border border-[#182640] text-xs font-mono space-y-1 hover:border-slate-600 transition-colors"
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-100 text-[11px] truncate max-w-[170px]">
                {intel.title}
              </span>
              <span className="text-[10px] font-bold text-cyan-400 bg-cyan-950/80 px-1 py-0.2 rounded border border-cyan-500/30">
                {intel.confidence}% Conf.
              </span>
            </div>

            <div className="flex items-center gap-2 text-[10px] text-slate-400">
              <span className="bg-[#121c30] px-1.5 py-0.2 rounded text-cyan-300 font-mono">
                {intel.indicatorType}: {intel.indicator}
              </span>
              <span className="truncate text-slate-500">
                {intel.source.split(' ')[0]}
              </span>
            </div>

            <p className="text-[10px] text-slate-400 line-clamp-1">
              <span className="text-amber-400 font-semibold">{intel.mitreTactic}:</span> {intel.description}
            </p>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="text-[9px] font-mono text-slate-400 flex items-center justify-between border-t border-[#16233b] pt-1">
        <span>MITRE ATT&CK & CISA Advisories</span>
        <span className="text-slate-400">{items.length} Active IoC Records</span>
      </div>
    </div>
  );
};
