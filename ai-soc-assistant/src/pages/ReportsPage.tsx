import React, { useState } from 'react';
import { FileText, Download, FileSpreadsheet, FileCode, CheckCircle2, AlertTriangle } from 'lucide-react';
import { socApi } from '../services/api';

export const ReportsPage: React.FC = () => {
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  const downloadFile = async (format: 'csv' | 'json' | 'txt') => {
    const report = await socApi.exportReport(format);

    const blob = new Blob([report.content], {
      type:
        format === 'csv'
          ? 'text/csv;charset=utf-8;'
          : format === 'json'
          ? 'application/json;charset=utf-8;'
          : 'text/plain;charset=utf-8;'
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', report.filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloadSuccess(`Successfully generated and downloaded ${report.filename}`);
    setTimeout(() => setDownloadSuccess(null), 4000);
  };

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      {/* Top Banner */}
      <div className="bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold text-slate-100">
            SOC Reports & Investigation Data Export
          </h2>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Generate comprehensive exports of alert repositories, held-out ML evaluation metrics, and incident timelines for audits and executive reporting.
        </p>
      </div>

      {downloadSuccess && (
        <div className="bg-emerald-950/60 border border-emerald-500/40 p-3 rounded flex items-center gap-2 text-emerald-300">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{downloadSuccess}</span>
        </div>
      )}

      {/* Export Options Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* CSV Export */}
        <div className="soc-card p-4 space-y-3 flex flex-col justify-between">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded bg-emerald-950/60 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <FileSpreadsheet className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-slate-100 text-sm">Alerts Repository (CSV)</h3>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Full comma-separated export containing all alert records, source/dest IP pairs, ports, model predictions, severity levels, and triage states.
            </p>
          </div>

          <button
            onClick={() => downloadFile('csv')}
            className="w-full py-2 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold flex items-center justify-center gap-2 transition-colors cursor-pointer"
          >
            <Download className="w-4 h-4" />
            <span>Export Alerts as CSV</span>
          </button>
        </div>

        {/* JSON Export */}
        <div className="soc-card p-4 space-y-3 flex flex-col justify-between">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded bg-cyan-950/60 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <FileCode className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-slate-100 text-sm">Full Telemetry & Metrics (JSON)</h3>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Complete structured JSON dataset including Random Forest model metrics, 7x7 confusion matrix, classification report, and active incident records.
            </p>
          </div>

          <button
            onClick={() => downloadFile('json')}
            className="w-full py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold flex items-center justify-center gap-2 transition-colors cursor-pointer"
          >
            <Download className="w-4 h-4" />
            <span>Export Metrics as JSON</span>
          </button>
        </div>

        {/* TXT Summary Report */}
        <div className="soc-card p-4 space-y-3 flex flex-col justify-between">
          <div className="space-y-2">
            <div className="w-9 h-9 rounded bg-amber-950/60 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <FileText className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-slate-100 text-sm">Investigation Briefing (TXT)</h3>
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Executive and SOC briefing summary report formatted for immediate inclusion in thesis papers, capstone presentations, and incident post-mortems.
            </p>
          </div>

          <button
            onClick={() => downloadFile('txt')}
            className="w-full py-2 rounded bg-amber-600 hover:bg-amber-500 text-white font-bold flex items-center justify-center gap-2 transition-colors cursor-pointer"
          >
            <Download className="w-4 h-4" />
            <span>Export Briefing as TXT</span>
          </button>
        </div>
      </div>
    </div>
  );
};
