import React from 'react';
import { Database, Shield, Cloud, AlertTriangle, CheckCircle2, Lock } from 'lucide-react';
import { CloudResource } from '../types/soc';

interface CloudPageProps {
  resources: CloudResource[];
}

export const CloudPage: React.FC<CloudPageProps> = ({ resources }) => {
  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Cloud className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Cloud Security Posture Management (CSPM) & IAM Audit
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              Multi-Cloud (AWS / GCP / Azure)
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Continuous posture assessment, IAM policy auditing, and bucket misconfiguration detection across cloud workloads.
          </p>
        </div>
      </div>

      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-[#080d18] text-[10px] text-slate-400 uppercase border-b border-[#18263f]">
                <th className="py-2.5 px-3">Resource Name</th>
                <th className="py-2.5 px-3">Provider</th>
                <th className="py-2.5 px-3">Service</th>
                <th className="py-2.5 px-3">Region</th>
                <th className="py-2.5 px-3">Exposure</th>
                <th className="py-2.5 px-3 text-center">Compliance</th>
                <th className="py-2.5 px-3 text-right">Findings</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#131d30]">
              {resources.map(res => (
                <tr key={res.id} className="hover:bg-[#111c30] transition-colors">
                  <td className="py-2 px-3 font-bold text-cyan-400">{res.name}</td>
                  <td className="py-2 px-3 text-slate-200">{res.provider}</td>
                  <td className="py-2 px-3 text-slate-300">{res.service}</td>
                  <td className="py-2 px-3 text-slate-400">{res.region}</td>
                  <td className="py-2 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      res.publicExposed ? 'bg-red-950 text-red-400 border border-red-500/40' : 'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
                    }`}>
                      {res.publicExposed ? 'Public' : 'Private'}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-center font-bold text-cyan-300">
                    {res.complianceScore}%
                  </td>
                  <td className="py-2 px-3 text-right font-bold text-amber-400">
                    {res.findingsCount} findings
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
