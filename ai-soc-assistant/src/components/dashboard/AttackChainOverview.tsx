import React from 'react';
import {
  Mail,
  Terminal,
  Clock,
  Key,
  Network,
  UploadCloud,
  ArrowRight,
  ExternalLink
} from 'lucide-react';
import { ATTACK_CHAIN_STAGES } from '../../server/socEngine';

interface AttackChainOverviewProps {
  onOpenAttackPath: () => void;
}

export const AttackChainOverview: React.FC<AttackChainOverviewProps> = ({ onOpenAttackPath }) => {
  const stageIcons = [
    Mail,         // Initial Access
    Terminal,     // Execution
    Clock,        // Persistence
    Key,          // Privilege Escalation
    Network,      // Lateral Movement
    UploadCloud   // Exfiltration
  ];

  return (
    <div className="soc-card p-3 flex flex-col justify-between h-[230px]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-1.5">
          <Network className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            Attack Chain Overview
          </span>
        </div>
        <button
          onClick={onOpenAttackPath}
          className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30 transition-colors"
        >
          <span>Open Attack Path Graph</span>
          <ArrowRight className="w-2.5 h-2.5" />
        </button>
      </div>

      {/* Horizontal 6-Stage Attack Chain */}
      <div className="my-auto overflow-x-auto scrollbar-thin py-2">
        <div className="flex items-center justify-between min-w-[560px] gap-2 px-1">
          {ATTACK_CHAIN_STAGES.map((stage, idx) => {
            const Icon = stageIcons[idx] || Network;
            const isCritical = stage.severity === 'Critical';
            const isHigh = stage.severity === 'High';

            return (
              <React.Fragment key={stage.stageNumber}>
                {/* Stage Node */}
                <div className="flex flex-col items-center text-center group cursor-pointer w-20">
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center border transition-transform duration-150 group-hover:scale-105 ${
                      isCritical
                        ? 'bg-red-950/70 border-red-500 text-red-400 shadow-[0_0_12px_rgba(239,68,68,0.3)]'
                        : isHigh
                        ? 'bg-orange-950/70 border-orange-500 text-orange-400 shadow-[0_0_10px_rgba(249,115,22,0.25)]'
                        : 'bg-amber-950/70 border-amber-500 text-amber-400'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>

                  <span className="text-[10px] font-bold font-mono text-slate-200 mt-1.5 truncate max-w-[80px]">
                    {stage.name}
                  </span>

                  <span className="text-[8px] font-mono text-slate-400 truncate max-w-[80px]">
                    {stage.technique.split(' ')[0]}
                  </span>

                  <span
                    className={`text-[8px] font-mono font-semibold px-1 py-0.2 rounded mt-0.5 uppercase ${
                      stage.status === 'Detected'
                        ? 'bg-red-950/80 text-red-400 border border-red-500/30'
                        : stage.status === 'Active'
                        ? 'bg-orange-950/80 text-orange-400 border border-orange-500/30'
                        : 'bg-amber-950/80 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {stage.status}
                  </span>
                </div>

                {/* Arrow Connector */}
                {idx < ATTACK_CHAIN_STAGES.length - 1 && (
                  <div className="flex-1 flex items-center justify-center -mt-6">
                    <div className="w-full h-0.5 bg-gradient-to-r from-[#1e3256] via-cyan-500/50 to-[#1e3256] relative">
                      <div className="absolute right-0 -top-1 w-0 h-0 border-t-[3px] border-t-transparent border-b-[3px] border-b-transparent border-l-[5px] border-l-cyan-400" />
                    </div>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Footer */}
      <div className="text-[9px] font-mono text-slate-400 flex items-center justify-between border-t border-[#16233b] pt-1">
        <span>MITRE ATT&CK Matrix Correlation (Corroborated by ALT-9041 & ALT-9042)</span>
        <span className="text-cyan-400 font-semibold">Stage 4 & 5 Active</span>
      </div>
    </div>
  );
};
