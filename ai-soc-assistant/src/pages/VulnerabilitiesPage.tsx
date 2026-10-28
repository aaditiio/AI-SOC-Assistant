import React, { useState } from 'react';
import { Bug, ShieldAlert, CheckCircle2, ExternalLink, X } from 'lucide-react';
import { Vulnerability } from '../types/soc';

interface VulnerabilitiesPageProps {
  vulnerabilities: Vulnerability[];
}

export const VulnerabilitiesPage: React.FC<VulnerabilitiesPageProps> = ({ vulnerabilities }) => {
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Bug className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Vulnerability Management & CVE Prioritization
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              {vulnerabilities.length} Tracked Vulnerabilities
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Verified Common Vulnerabilities and Exposures (CVEs) correlated with internal enterprise endpoints and actionable remediation patches.
          </p>
        </div>
      </div>

      {/* Vulnerabilities Table */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-[#080d18] text-[10px] text-slate-400 uppercase border-b border-[#18263f]">
                <th className="py-2.5 px-3">CVE Identifier</th>
                <th className="py-2.5 px-3">Vulnerability Title</th>
                <th className="py-2.5 px-3 text-center">CVSS Score</th>
                <th className="py-2.5 px-3 text-center">Severity</th>
                <th className="py-2.5 px-3">Affected Endpoints</th>
                <th className="py-2.5 px-3">Published Date</th>
                <th className="py-2.5 px-3 text-center">Status</th>
                <th className="py-2.5 px-3 text-right">Guidance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#131d30]">
              {vulnerabilities.map(v => (
                <tr
                  key={v.id}
                  onClick={() => setSelectedVuln(v)}
                  className="hover:bg-[#111c30] cursor-pointer transition-colors group"
                >
                  <td className="py-2 px-3 font-bold text-cyan-400 group-hover:text-cyan-300 whitespace-nowrap">
                    {v.cve}
                  </td>
                  <td className="py-2 px-3">
                    <div className="font-semibold text-slate-200 truncate max-w-[320px]">
                      {v.title}
                    </div>
                  </td>
                  <td className="py-2 px-3 text-center">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
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
                  <td className="py-2 px-3 text-center">
                    <span
                      className={`text-[10px] font-bold ${
                        v.severity === 'Critical' ? 'text-red-400' : 'text-orange-400'
                      }`}
                    >
                      {v.severity}
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    <div className="flex flex-wrap gap-1">
                      {v.affectedAssets.map((ip, i) => (
                        <span key={i} className="bg-cyan-950/60 text-cyan-300 border border-cyan-500/30 px-1.5 py-0.2 rounded text-[10px]">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-2 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                    {v.publishedDate}
                  </td>
                  <td className="py-2 px-3 text-center">
                    <span className="text-emerald-400 flex items-center justify-center gap-1 text-[10px]">
                      <CheckCircle2 className="w-3 h-3" />
                      Verified
                    </span>
                  </td>
                  <td className="py-2 px-3 text-right">
                    <button className="px-2 py-1 rounded bg-[#162238] group-hover:bg-cyan-500/20 group-hover:text-cyan-300 text-slate-300 text-[10px] transition-colors">
                      Remediation
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Remediation Modal */}
      {selectedVuln && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0b1324] border border-[#1d2f50] rounded-lg max-w-lg w-full p-4 space-y-3 shadow-2xl animate-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-[#1b2b47] pb-2">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-400" />
                <span className="font-bold text-slate-100 text-sm">{selectedVuln.cve}</span>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] uppercase">Vulnerability Description:</span>
              <p className="text-slate-200 font-semibold mt-0.5">{selectedVuln.title}</p>
            </div>

            <div className="grid grid-cols-2 gap-2 bg-[#080d19] p-2.5 rounded border border-[#16233b]">
              <div>
                <span className="text-slate-500 text-[10px]">CVSS Base Score:</span>
                <p className="text-red-400 font-bold">{selectedVuln.cvss} ({selectedVuln.severity})</p>
              </div>
              <div>
                <span className="text-slate-500 text-[10px]">Published Date:</span>
                <p className="text-slate-300">{selectedVuln.publishedDate}</p>
              </div>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] uppercase">Target Endpoints Impacted:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {selectedVuln.affectedAssets.map((ip, i) => (
                  <span key={i} className="bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded text-[10px]">
                    {ip}
                  </span>
                ))}
              </div>
            </div>

            <div className="bg-cyan-950/30 border border-cyan-500/30 p-3 rounded space-y-1">
              <span className="text-cyan-400 font-bold uppercase text-[10px] block">
                Technical Remediation Action:
              </span>
              <p className="text-slate-200 leading-relaxed text-[11px]">{selectedVuln.remediation}</p>
            </div>

            <div className="flex justify-end pt-2 border-t border-[#1b2b47]">
              <button
                onClick={() => setSelectedVuln(null)}
                className="px-3 py-1.5 rounded bg-[#162238] hover:bg-[#1e2f4c] text-slate-200"
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
