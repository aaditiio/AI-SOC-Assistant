import React from 'react';
import { Server, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { Asset } from '../../types/soc';

interface AssetsAtRiskTableProps {
  assets: Asset[];
  onSelectAsset?: (asset: Asset) => void;
  className?: string;
}

export const AssetsAtRiskTable: React.FC<AssetsAtRiskTableProps> = ({ assets, onSelectAsset, className = 'flex-1' }) => {
  // Sort by risk score descending
  const sortedAssets = [...assets].sort((a, b) => b.riskScore - a.riskScore).slice(0, 4);

  return (
    <div className={`soc-card p-3 flex flex-col justify-between ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-1.5">
          <Server className="w-3.5 h-3.5 text-rose-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">Assets at Risk</span>
        </div>
        <span className="text-[10px] font-mono text-slate-400">
          Ranked by Vulnerability & Alert Weights
        </span>
      </div>

      {/* Table */}
      <div className="overflow-y-auto max-h-[160px] scrollbar-thin my-1">
        <table className="w-full text-left text-[11px] font-mono border-collapse">
          <thead>
            <tr className="text-[9px] text-slate-400 uppercase border-b border-[#16233b] pb-1">
              <th className="py-1 font-medium">Asset / Hostname</th>
              <th className="py-1 font-medium">IP Address</th>
              <th className="py-1 font-medium text-center">Criticality</th>
              <th className="py-1 font-medium text-right">Risk Score</th>
              <th className="py-1 font-medium text-right">Change</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#131d30]">
            {sortedAssets.map(asset => {
              const diff = Math.round((asset.riskScore - asset.previousRiskScore) * 10) / 10;
              return (
                <tr
                  key={asset.id}
                  onClick={() => onSelectAsset?.(asset)}
                  className="hover:bg-[#111c30] cursor-pointer transition-colors group"
                >
                  <td className="py-1.5 pr-2">
                    <div className="font-semibold text-slate-100 group-hover:text-cyan-300 truncate max-w-[120px]">
                      {asset.name}
                    </div>
                    <div className="text-[9px] text-slate-400 truncate max-w-[120px]">
                      {asset.role}
                    </div>
                  </td>
                  <td className="py-1.5 text-cyan-400 font-mono text-[10px]">
                    {asset.ip}
                  </td>
                  <td className="py-1.5 text-center">
                    <span
                      className={`text-[9px] px-1 py-0.2 rounded font-semibold ${
                        asset.criticality === 'Mission Critical'
                          ? 'bg-purple-950 text-purple-300 border border-purple-500/40'
                          : asset.criticality === 'High'
                          ? 'bg-red-950 text-red-400 border border-red-500/40'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {asset.criticality === 'Mission Critical' ? 'CRIT' : asset.criticality}
                    </span>
                  </td>
                  <td className="py-1.5 text-right">
                    <div className="flex items-center justify-end gap-1.5">
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
                      {/* Mini Bar */}
                      <div className="w-10 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${
                            asset.riskScore >= 80 ? 'bg-red-500' : asset.riskScore >= 60 ? 'bg-orange-500' : 'bg-amber-500'
                          }`}
                          style={{ width: `${Math.min(asset.riskScore, 100)}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="py-1.5 text-right font-mono text-[10px]">
                    {diff > 0 ? (
                      <span className="text-red-400 flex items-center justify-end gap-0.5">
                        <TrendingUp className="w-2.5 h-2.5" />
                        +{diff}
                      </span>
                    ) : diff < 0 ? (
                      <span className="text-emerald-400 flex items-center justify-end gap-0.5">
                        <TrendingDown className="w-2.5 h-2.5" />
                        {diff}
                      </span>
                    ) : (
                      <span className="text-slate-400 flex items-center justify-end gap-0.5">
                        <Minus className="w-2.5 h-2.5" />
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

      {/* Footer */}
      <div className="text-[9px] font-mono text-slate-400 flex items-center justify-between border-t border-[#16233b] pt-1">
        <span>Formula: Base Criticality (30%) + Alerts (40%) + CVSS (30%)</span>
        <span className="text-slate-400">{assets.length} Total Endpoints</span>
      </div>
    </div>
  );
};
