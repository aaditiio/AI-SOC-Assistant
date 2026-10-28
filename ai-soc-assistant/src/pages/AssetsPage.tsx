import React from 'react';
import { Server, ShieldAlert, Cpu, HardDrive, CheckCircle2, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { Asset } from '../types/soc';

interface AssetsPageProps {
  assets: Asset[];
}

export const AssetsPage: React.FC<AssetsPageProps> = ({ assets }) => {
  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Enterprise Asset Inventory & Explainable Risk Scoring
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              {assets.length} Monitored Hosts
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Risk scores dynamically computed via transparent weighting: Base Asset Criticality (30%) + Active Threat Alerts (40%) + Unpatched CVEs (30%).
          </p>
        </div>
      </div>

      {/* Asset Grid / Table */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-[#080d18] text-[10px] text-slate-400 uppercase border-b border-[#18263f]">
                <th className="py-2.5 px-3">Asset ID</th>
                <th className="py-2.5 px-3">Hostname</th>
                <th className="py-2.5 px-3">IP Address</th>
                <th className="py-2.5 px-3">Role</th>
                <th className="py-2.5 px-3">Operating System</th>
                <th className="py-2.5 px-3">Criticality</th>
                <th className="py-2.5 px-3 text-center">Alerts</th>
                <th className="py-2.5 px-3 text-center">CVEs</th>
                <th className="py-2.5 px-3 text-right">Risk Score</th>
                <th className="py-2.5 px-3 text-right">Trend</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#131d30]">
              {assets.map(asset => {
                const diff = Math.round((asset.riskScore - asset.previousRiskScore) * 10) / 10;
                return (
                  <tr key={asset.id} className="hover:bg-[#111c30] transition-colors">
                    <td className="py-2 px-3 font-bold text-cyan-400">{asset.id}</td>
                    <td className="py-2 px-3 font-semibold text-slate-200">{asset.name}</td>
                    <td className="py-2 px-3 text-cyan-300">{asset.ip}</td>
                    <td className="py-2 px-3 text-slate-300">{asset.role}</td>
                    <td className="py-2 px-3 text-slate-400 text-[11px]">{asset.os}</td>
                    <td className="py-2 px-3">
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-semibold ${
                          asset.criticality === 'Mission Critical'
                            ? 'bg-purple-950 text-purple-300 border border-purple-500/40'
                            : asset.criticality === 'High'
                            ? 'bg-red-950 text-red-400 border border-red-500/40'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {asset.criticality}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-center text-red-400 font-bold">
                      {asset.openAlertsCount}
                    </td>
                    <td className="py-2 px-3 text-center text-amber-300 font-bold">
                      {asset.vulnerabilitiesCount}
                    </td>
                    <td className="py-2 px-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <span
                          className={`font-bold ${
                            asset.riskScore >= 80
                              ? 'text-red-400'
                              : asset.riskScore >= 60
                              ? 'text-orange-400'
                              : 'text-amber-300'
                          }`}
                        >
                          {asset.riskScore.toFixed(1)}
                        </span>
                        <div className="w-12 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              asset.riskScore >= 80
                                ? 'bg-red-500'
                                : asset.riskScore >= 60
                                ? 'bg-orange-500'
                                : 'bg-amber-500'
                            }`}
                            style={{ width: `${Math.min(asset.riskScore, 100)}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-2 px-3 text-right">
                      {diff > 0 ? (
                        <span className="text-red-400 flex items-center justify-end gap-0.5">
                          <TrendingUp className="w-3 h-3" />
                          +{diff}
                        </span>
                      ) : diff < 0 ? (
                        <span className="text-emerald-400 flex items-center justify-end gap-0.5">
                          <TrendingDown className="w-3 h-3" />
                          {diff}
                        </span>
                      ) : (
                        <span className="text-slate-500 flex items-center justify-end gap-0.5">
                          <Minus className="w-3 h-3" />
                          0.0
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
