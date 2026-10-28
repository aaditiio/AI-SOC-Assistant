import React, { useState } from 'react';
import { Server, Code2, Play, Copy, Check, Terminal, ExternalLink, ShieldCheck } from 'lucide-react';

export const ApiExplorerPage: React.FC = () => {
  const [selectedEndpoint, setSelectedEndpoint] = useState<string>('/api/health');
  const [responseOutput, setResponseOutput] = useState<string>('Click "Execute Request" to test endpoint live...');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  const endpoints = [
    { path: '/api/health', method: 'GET', description: 'System health & ML model status' },
    { path: '/api', method: 'GET', description: 'Backend REST API Index' },
    { path: '/api/alerts', method: 'GET', description: 'Active security alerts' },
    { path: '/api/incidents', method: 'GET', description: 'Correlated incident triage tickets' },
    { path: '/api/cloud', method: 'GET', description: 'Cloud security posture' },
    { path: '/api/endpoints', method: 'GET', description: 'EDR sensor inventory' },
    { path: '/api/email-security', method: 'GET', description: 'Email threat defense' },
    { path: '/api/automation', method: 'GET', description: 'SOAR automated playbooks' },
    { path: '/api/threat-intel', method: 'GET', description: 'Global IOC feeds' },
    { path: '/api/assets', method: 'GET', description: 'Critical asset inventory' },
    { path: '/api/vulnerabilities', method: 'GET', description: 'CVE vulnerability scan findings' },
    { path: '/api/cases', method: 'GET', description: 'SOC case management' }
  ];

  const handleExecute = async (path: string) => {
    setSelectedEndpoint(path);
    setIsLoading(true);
    try {
      const res = await fetch(path);
      const data = await res.json();
      setResponseOutput(JSON.stringify(data, null, 2));
    } catch (err: any) {
      setResponseOutput(JSON.stringify({ error: err.message || 'Failed to fetch endpoint' }, null, 2));
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(responseOutput);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto font-mono text-xs">
      <div className="bg-[#0b1324] border border-[#1b2b47] p-4 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-950/80 rounded-lg border border-cyan-500/30 text-cyan-400">
            <Server className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 tracking-wide">
                Backend API Gateway & REST Endpoint Explorer
              </h2>
              <span className="text-[10px] bg-emerald-950/80 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded flex items-center gap-1">
                <ShieldCheck className="w-3 h-3" /> Express on Port 3000
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Access and test live backend REST endpoints. Both frontend SPA and backend JSON API share origin port 3000.
            </p>
          </div>
        </div>
        <a
          href="/api/health"
          target="_blank"
          rel="noopener noreferrer"
          className="px-3 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded flex items-center gap-1.5 transition-colors shadow"
        >
          Open /api/health in Browser <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-5 bg-[#0b1324] border border-[#1b2b47] rounded-xl p-4 flex flex-col space-y-3">
          <div className="flex items-center justify-between border-b border-[#1b2b47] pb-2">
            <span className="font-bold text-slate-200 flex items-center gap-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              Available REST Routes ({endpoints.length})
            </span>
            <span className="text-[10px] text-slate-400">Method: GET</span>
          </div>

          <div className="space-y-1.5 overflow-y-auto max-h-[520px] pr-1">
            {endpoints.map((ep, idx) => {
              const isSelected = selectedEndpoint === ep.path;
              return (
                <div
                  key={idx}
                  onClick={() => handleExecute(ep.path)}
                  className={`p-2.5 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                    isSelected
                      ? 'bg-cyan-950/50 border-cyan-500/50 text-cyan-200 shadow'
                      : 'bg-[#070c18] border-[#16233b] text-slate-300 hover:border-slate-600 hover:bg-[#0f172a]'
                  }`}
                >
                  <div className="space-y-0.5 truncate mr-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] bg-cyan-900/60 text-cyan-300 px-1.5 py-0.2 rounded font-bold">
                        {ep.method}
                      </span>
                      <span className="font-bold text-white tracking-wide">{ep.path}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans truncate">{ep.description}</p>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleExecute(ep.path);
                    }}
                    className="p-1.5 bg-[#121c2e] hover:bg-cyan-600 text-cyan-400 hover:text-white rounded border border-[#233554] transition-colors flex-shrink-0"
                  >
                    <Play className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        <div className="lg:col-span-7 bg-[#0b1324] border border-[#1b2b47] rounded-xl p-4 flex flex-col space-y-3">
          <div className="flex items-center justify-between border-b border-[#1b2b47] pb-2">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-slate-200">
                Live Response: <span className="text-cyan-400">{selectedEndpoint}</span>
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleExecute(selectedEndpoint)}
                className="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded flex items-center gap-1 transition-colors"
              >
                <Play className="w-3 h-3" /> Execute
              </button>
              <button
                onClick={handleCopy}
                className="px-2.5 py-1 bg-[#121c2e] hover:bg-[#1a2842] text-slate-300 rounded border border-[#233554] flex items-center gap-1 transition-colors"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>

          <div className="relative flex-1 bg-[#050811] border border-[#16233b] rounded-lg p-3 overflow-hidden flex flex-col min-h-[420px]">
            {isLoading ? (
              <div className="flex-1 flex items-center justify-center text-cyan-400">
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin" />
                  <span>Querying backend REST route {selectedEndpoint}...</span>
                </div>
              </div>
            ) : (
              <pre className="flex-1 text-emerald-400 text-xs font-mono overflow-auto p-2 whitespace-pre-wrap break-all">
                {responseOutput}
              </pre>
            )}
          </div>

          <div className="bg-[#070c18] p-2.5 rounded-lg border border-[#16233b] text-slate-400 text-[11px] font-sans flex items-center justify-between">
            <span>Curl command: <code className="text-cyan-300 font-mono">curl http://localhost:3000{selectedEndpoint}</code></span>
            <span className="text-emerald-400 font-mono">HTTP 200 OK</span>
          </div>
        </div>
      </div>
    </div>
  );
};
