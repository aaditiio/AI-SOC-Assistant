import React, { useState } from 'react';
import { Bug, ExternalLink, X, ShieldAlert } from 'lucide-react';
import { Vulnerability } from '../../types/soc';

interface TopVulnerabilitiesProps {
  vulnerabilities: Vulnerability[];
  className?: string;
}

export const TopVulnerabilitiesTable: React.FC<TopVulnerabilitiesProps> = ({ vulnerabilities, className = 'flex-1' }) => {
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  return (
    <div className={`soc-card p-3 flex flex-col justify-between ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2">
        <div className="flex items-center gap-1.5">
          <Bug className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">Top Vulnerabilities</span>
        </div>
        <span className="text-[10px] font-mono text-slate-400">
          {vulnerabilities.length} Tracked CVEs
        </span>
      </div>

      {/* Table */}
      <div className="overflow-y-auto max-h-[240px] scrollbar-thin my-1">
        <table className="w-full text-left text-[11px] font-mono border-collapse">
          <thead>
            <tr className="text-[9px] text-slate-400 uppercase border-b border-[#16233b] pb-1">
              <th className="py-1 font-medium">CVE / Vulnerability</th>
              <th className="py-1 font-medium text-center">CVSS</th>
              <th className="py-1 font-medium text-center">Assets</th>
              <th className="py-1 font-medium text-right">Risk</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#131d30]">
            {vulnerabilities.slice(0, 4).map(v => (
              <tr
                key={v.id}
                onClick={() => setSelectedVuln(v)}
                className="hover:bg-[#111c30] cursor-pointer transition-colors group"
              >
                <td className="py-1.5 pr-2">
                  <div className="font-semibold text-cyan-400 group-hover:text-cyan-300 truncate max-w-[130px]">
                    {v.cve}
                  </div>
                  <div className="text-[9px] text-slate-400 truncate max-w-[130px]">
                    {v.title}
                  </div>
                </td>
                <td className="py-1.5 text-center">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      v.cvss >= 9.0
                        ? 'bg-red-950 text-red-400 border border-red-500/40'
                        : v.cvss >= 7.0
                        ? 'bg-orange-950 text-orange-400 border border-orange-500/40'
                        : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                    }`}
                  >
                    {v.cvss.toFixed(1)}
                  </span>
                </td>
                <td className="py-1.5 text-center text-slate-300">
                  {v.affectedAssets.length}
                </td>
                <td className="py-1.5 text-right">
                  <span
                    className={`text-[9px] font-semibold ${
                      v.severity === 'Critical' ? 'text-red-400' : 'text-orange-400'
                    }`}
                  >
                    {v.severity}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Remediation Modal */}
      {selectedVuln && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0b1324] border border-[#1d2f50] rounded-lg max-w-md w-full p-4 text-xs font-mono space-y-3 shadow-2xl animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-[#1b2b47] pb-2">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                <span className="font-bold text-slate-100 text-sm">{selectedVuln.cve}</span>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <span className="text-slate-400 text-[10px] uppercase">Title:</span>
              <p className="text-slate-200 font-semibold">{selectedVuln.title}</p>
            </div>

            <div className="grid grid-cols-2 gap-2 bg-[#080d19] p-2 rounded border border-[#16233b]">
              <div>
                <span className="text-slate-500 text-[10px]">CVSS Base Score:</span>
                <p className="text-red-400 font-bold">{selectedVuln.cvss} ({selectedVuln.severity})</p>
              </div>
              <div>
                <span className="text-slate-500 text-[10px]">Published:</span>
                <p className="text-slate-300">{selectedVuln.publishedDate}</p>
              </div>
            </div>

            <div>
              <span className="text-slate-400 text-[10px] uppercase">Affected Target Assets:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {selectedVuln.affectedAssets.map((ip, i) => (
                  <span key={i} className="bg-cyan-950/60 text-cyan-300 border border-cyan-500/30 px-1.5 py-0.5 rounded text-[10px]">
                    {ip}
                  </span>
                ))}
              </div>
            </div>

            <div className="bg-amber-950/30 border border-amber-500/30 p-2.5 rounded">
              <span className="text-amber-400 font-bold text-[10px] uppercase flex items-center gap-1">
                Remediation Guidance:
              </span>
              <p className="text-slate-300 mt-1 leading-relaxed">{selectedVuln.remediation}</p>
            </div>

            <div className="flex justify-end pt-2 border-t border-[#1b2b47]">
              <button
                onClick={() => setSelectedVuln(null)}
                className="px-3 py-1 rounded bg-[#162238] hover:bg-[#1f2f4c] text-slate-200 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
