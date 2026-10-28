import React, { useState } from 'react';
import {
  Globe2,
  Search,
  Shield,
  ExternalLink,
  CheckCircle,
  Database,
  Plus,
  CheckCircle2,
  Copy,
  Hash
} from 'lucide-react';
import { ThreatIntelItem } from '../types/soc';
import { socApi } from '../services/api';

interface ThreatIntelligencePageProps {
  items: ThreatIntelItem[];
  onRefreshData?: () => void;
}

export const ThreatIntelligencePage: React.FC<ThreatIntelligencePageProps> = ({ items, onRefreshData }) => {
  const [search, setSearch] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [title, setTitle] = useState('');
  const [indicator, setIndicator] = useState('');
  const [indicatorType, setIndicatorType] = useState<ThreatIntelItem['indicatorType']>('IP');
  const [source, setSource] = useState('CISA Advisory Feed');
  const [confidence, setConfidence] = useState(90);
  const [mitreTactic, setMitreTactic] = useState('Command & Control (T1071.001)');
  const [description, setDescription] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !indicator.trim()) return;
    await socApi.addThreatIntelItem({
      title: title.trim(),
      indicator: indicator.trim(),
      indicatorType,
      source: source.trim(),
      confidence: Number(confidence),
      mitreTactic: mitreTactic.trim(),
      description: description.trim() || 'Custom threat intelligence indicator ingested by SOC analyst.'
    });
    setIsAdding(false);
    setTitle('');
    setIndicator('');
    setDescription('');
    setNotice(`Ingested IoC indicator "${indicator}" into Threat Intelligence repository.`);
    setTimeout(() => setNotice(null), 4000);
    onRefreshData?.();
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filtered = items.filter(
    i =>
      i.title.toLowerCase().includes(search.toLowerCase()) ||
      i.indicator.toLowerCase().includes(search.toLowerCase()) ||
      i.source.toLowerCase().includes(search.toLowerCase()) ||
      i.mitreTactic.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Curated Cyber Threat Intelligence & IoC Repository
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              {items.length} Active IoC Signatures
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Verified threat intelligence indicators with provenance tracking and MITRE ATT&CK framework mapping.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative min-w-[220px]">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IoC, Title, or Tactic..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:border-cyan-400 outline-none text-xs"
            />
          </div>
          <button
            onClick={() => setIsAdding(true)}
            className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Ingest IoC</span>
          </button>
        </div>
      </div>

      {notice && (
        <div className="bg-cyan-950/80 border border-cyan-500/40 p-2.5 rounded flex items-center gap-2 text-cyan-200 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span>{notice}</span>
        </div>
      )}

      {/* Add IoC Modal */}
      {isAdding && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0b1324] border border-[#1b2b47] rounded-lg max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-[#18263f]">
              <div className="flex items-center gap-2">
                <Globe2 className="w-4 h-4 text-cyan-400" />
                <h3 className="font-bold text-sm text-slate-100">Ingest New Threat Indicator (IoC)</h3>
              </div>
              <button
                onClick={() => setIsAdding(false)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3">
              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Threat Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Lazarus Group HTTP Beacon Ingress Node"
                  value={title}
                  onChange={e => setTitle(e.target.value)}
                  className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-3 py-2 text-slate-200 text-xs focus:border-cyan-400 outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Indicator Type</label>
                  <select
                    value={indicatorType}
                    onChange={e => setIndicatorType(e.target.value as any)}
                    className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-3 py-2 text-slate-200 text-xs outline-none"
                  >
                    <option value="IP">IP Address</option>
                    <option value="Domain">Domain / FQDN</option>
                    <option value="Hash">SHA-256 Hash</option>
                    <option value="CVE">CVE Identifier</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Indicator Value</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 198.51.100.99 or malicious-c2.net"
                    value={indicator}
                    onChange={e => setIndicator(e.target.value)}
                    className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-3 py-2 text-slate-200 text-xs focus:border-cyan-400 outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Source Provenance</label>
                  <input
                    type="text"
                    placeholder="e.g. US-CERT Advisory AA26-100"
                    value={source}
                    onChange={e => setSource(e.target.value)}
                    className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-3 py-2 text-slate-200 text-xs outline-none"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Confidence Score (%)</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={confidence}
                    onChange={e => setConfidence(Number(e.target.value))}
                    className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-3 py-2 text-slate-200 text-xs outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">MITRE ATT&CK Tactic</label>
                <input
                  type="text"
                  placeholder="e.g. Command & Control (T1071.001)"
                  value={mitreTactic}
                  onChange={e => setMitreTactic(e.target.value)}
                  className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-3 py-2 text-slate-200 text-xs outline-none"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Description & Context</label>
                <textarea
                  rows={3}
                  placeholder="Observed malicious behavior, associated adversary campaign..."
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  className="w-full bg-[#080d19] border border-[#1d2d4a] rounded p-2.5 text-slate-200 text-xs focus:border-cyan-400 outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAdding(false)}
                  className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold cursor-pointer"
                >
                  Ingest IoC
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Grid of Threat Intelligence Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {filtered.map(intel => (
          <div
            key={intel.id}
            className="soc-card p-3.5 space-y-2.5 flex flex-col justify-between hover:border-cyan-500/40 transition-colors"
          >
            <div>
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="font-bold text-cyan-400 text-xs">{intel.id}</span>
                <span className="text-[10px] font-bold text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-1.5 py-0.2 rounded">
                  {intel.confidence}% Confidence
                </span>
              </div>

              <h4 className="font-bold text-slate-100 text-xs mb-1.5 leading-snug">
                {intel.title}
              </h4>

              <div className="bg-[#080d19] p-2 rounded border border-[#16233b] space-y-1 my-2">
                <div className="flex items-center justify-between text-[10px]">
                  <span className="text-slate-400 uppercase">Indicator ({intel.indicatorType}):</span>
                  <button
                    onClick={() => handleCopy(intel.indicator, intel.id)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[9px] cursor-pointer"
                  >
                    <Copy className="w-2.5 h-2.5" />
                    <span>{copiedId === intel.id ? 'Copied!' : 'Copy'}</span>
                  </button>
                </div>
                <div className="text-cyan-300 font-bold text-xs break-all">
                  {intel.indicator}
                </div>
              </div>

              <p className="text-slate-300 text-[11px] leading-relaxed">
                {intel.description}
              </p>
            </div>

            <div className="space-y-1.5 border-t border-[#16233b] pt-2 text-[10px]">
              <div className="flex items-center justify-between text-slate-400">
                <span className="text-slate-500">MITRE Tactic:</span>
                <span className="text-amber-400 font-semibold">{intel.mitreTactic}</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span className="text-slate-500">Provenance:</span>
                <span className="text-slate-300 truncate max-w-[180px]">{intel.source}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
