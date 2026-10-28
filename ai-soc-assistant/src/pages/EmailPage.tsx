import React, { useState, useEffect } from 'react';
import { Mail, ShieldAlert, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';
import { EmailThreat } from '../types/soc';
import { socApi } from '../services/api';

export const EmailPage: React.FC = () => {
  const [emails, setEmails] = useState<EmailThreat[]>([]);
  const [toast, setToast] = useState<string | null>(null);

  const loadEmails = async () => {
    const ems = await socApi.getEmailThreats();
    setEmails(ems);
  };

  useEffect(() => {
    loadEmails();
  }, []);

  const handleQuarantine = async (id: string) => {
    await socApi.purgeEmail(id);
    setToast(`Email threat purged and quarantined from mailbox.`);
    setTimeout(() => setToast(null), 3000);
    loadEmails();
  };

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Mail className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Email Security & Phishing Threat Analysis (SEG)
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              {emails.length} Analyzed Threats
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Automated BEC (Business Email Compromise), phishing link detonation, and SPF/DKIM/DMARC alignment checks.
          </p>
        </div>
      </div>

      {toast && (
        <div className="bg-cyan-950 text-cyan-300 border border-cyan-500/40 p-2.5 rounded text-xs flex items-center justify-between">
          <span>{toast}</span>
          <button onClick={() => setToast(null)} className="text-slate-400 hover:text-white">Dismiss</button>
        </div>
      )}

      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse font-mono">
            <thead>
              <tr className="bg-[#080d18] text-[10px] text-slate-400 uppercase border-b border-[#18263f]">
                <th className="py-2.5 px-3">Subject / Campaign</th>
                <th className="py-2.5 px-3">Sender</th>
                <th className="py-2.5 px-3">Recipient</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">SPF / DKIM / DMARC</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#131d30]">
              {emails.map(em => (
                <tr key={em.id} className="hover:bg-[#111c30] transition-colors">
                  <td className="py-2.5 px-3">
                    <div className="font-bold text-slate-200">{em.subject}</div>
                    <div className="text-[10px] text-slate-400">{em.timestamp}</div>
                  </td>
                  <td className="py-2.5 px-3 text-cyan-300">{em.sender}</td>
                  <td className="py-2.5 px-3 text-slate-300">{em.recipient}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-red-950 text-red-400 border border-red-500/40 font-semibold">
                      {em.verdict}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-amber-300 text-[11px]">
                    SPF: {em.spf} | DKIM: {em.dkim}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      em.quarantined ? 'bg-purple-950 text-purple-300 border border-purple-500/40' : 'bg-red-950 text-red-400'
                    }`}>
                      {em.quarantined ? 'Quarantined' : 'Active Threat'}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    {!em.quarantined ? (
                      <button
                        onClick={() => handleQuarantine(em.id)}
                        className="px-2.5 py-1 bg-red-600 hover:bg-red-500 text-white rounded font-bold transition-colors"
                      >
                        Purge
                      </button>
                    ) : (
                      <span className="text-emerald-400 flex items-center justify-end gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Purged
                      </span>
                    )}
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
