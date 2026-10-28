import React, { useState, useEffect } from 'react';
import {
  Briefcase,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Search,
  Plus,
  CheckCircle2,
  AlertTriangle,
  FolderLock,
  MessageSquare,
  Paperclip,
  Download,
  Calendar,
  User,
  Clock,
  Layers
} from 'lucide-react';
import { CaseTicket, Severity } from '../types/soc';
import { socApi } from '../services/api';

interface CasesPageProps {
  onRefreshData?: () => void;
}

export const CasesPage: React.FC<CasesPageProps> = ({ onRefreshData }) => {
  const [cases, setCases] = useState<CaseTicket[]>([]);
  const [search, setSearch] = useState('');
  const [selectedCase, setSelectedCase] = useState<CaseTicket | null>(null);
  const [newNote, setNewNote] = useState('');
  const [isCreatingCase, setIsCreatingCase] = useState(false);
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseSeverity, setNewCaseSeverity] = useState<Severity>('High');
  const [newCasePriority, setNewCasePriority] = useState<CaseTicket['priority']>('P2 - High');
  const [newCaseSummary, setNewCaseSummary] = useState('');
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const loadCases = async () => {
    const data = await socApi.getCases();
    setCases(data);
    if (!selectedCase && data.length > 0) {
      setSelectedCase(data[0]);
    } else if (selectedCase) {
      const updated = data.find(c => c.id === selectedCase.id);
      if (updated) setSelectedCase(updated);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !newNote.trim()) return;
    await socApi.addCaseNote(selectedCase.id, newNote.trim());
    setNewNote('');
    await loadCases();
    setActionNotice('Case investigation note appended to audit timeline.');
    setTimeout(() => setActionNotice(null), 4000);
    onRefreshData?.();
  };

  const handleStatusChange = async (caseId: string, status: CaseTicket['status']) => {
    await socApi.updateCase(caseId, { status });
    await loadCases();
    setActionNotice(`Case status transitioned to "${status}".`);
    setTimeout(() => setActionNotice(null), 4000);
    onRefreshData?.();
  };

  const handleCreateCaseSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseTitle.trim()) return;
    const created = await socApi.createCase({
      title: newCaseTitle.trim(),
      severity: newCaseSeverity,
      priority: newCasePriority,
      summary: newCaseSummary.trim() || 'Escalated security case investigation.',
      assignedTo: 'Lead Analyst Prachi',
      evidenceItems: ['Correlated SOC telemetry stream', 'Sensor baseline logs'],
      mitreTactics: ['Initial Access', 'Lateral Movement']
    });
    setIsCreatingCase(false);
    setNewCaseTitle('');
    setNewCaseSummary('');
    await loadCases();
    setSelectedCase(created);
    setActionNotice(`Case ${created.id} initialized.`);
    setTimeout(() => setActionNotice(null), 4000);
    onRefreshData?.();
  };

  const handleExportBrief = (c: CaseTicket) => {
    const text = `=====================================================
AI SOC ASSISTANT - FORMAL INVESTIGATION CASE BRIEF
=====================================================
Case ID:       ${c.id}
Title:         ${c.title}
Severity:      ${c.severity}
Priority:      ${c.priority}
Status:        ${c.status}
Assigned To:   ${c.assignedTo}
Created At:    ${c.createdAt}
Last Updated:  ${c.updatedAt}

SUMMARY & HYPOTHESIS:
${c.summary}

MITRE ATT&CK TACTICS:
${c.mitreTactics.join(', ')}

EVIDENCE REPOSITORY:
${c.evidenceItems.map(e => ` - ${e}`).join('\n')}

INVESTIGATION TIMELINE & ANALYST LOGS:
${c.notes.map(n => ` [${n.timestamp}] ${n.author}: ${n.text}`).join('\n')}
=====================================================`;

    const blob = new Blob([text], { type: 'text/plain;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `${c.id}_Investigation_Brief.txt`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setActionNotice(`Exported formal brief for ${c.id}`);
    setTimeout(() => setActionNotice(null), 4000);
  };

  const filtered = cases.filter(c =>
    c.title.toLowerCase().includes(search.toLowerCase()) ||
    c.id.toLowerCase().includes(search.toLowerCase()) ||
    c.assignedTo.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              SOC Security Case Management & Escalation Queue
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              {cases.length} Open Cases
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Formal multi-vector investigation tracking, chain of custody evidence preservation, and analyst briefs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative min-w-[200px]">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search Case ID, Title..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:border-cyan-400 outline-none text-xs"
            />
          </div>
          <button
            onClick={() => setIsCreatingCase(true)}
            className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Open New Case</span>
          </button>
        </div>
      </div>

      {actionNotice && (
        <div className="bg-cyan-950/80 border border-cyan-500/40 p-2.5 rounded flex items-center gap-2 text-cyan-200 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* New Case Modal */}
      {isCreatingCase && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0b1324] border border-[#1b2b47] rounded-lg max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-[#18263f]">
              <div className="flex items-center gap-2">
                <Briefcase className="w-4 h-4 text-cyan-400" />
                <h3 className="font-bold text-sm text-slate-100">Open Escalated Security Case</h3>
              </div>
              <button
                onClick={() => setIsCreatingCase(false)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateCaseSubmit} className="space-y-3">
              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Case Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Distributed Lateral Movement on Subnet 10.0.1.0/24"
                  value={newCaseTitle}
                  onChange={e => setNewCaseTitle(e.target.value)}
                  className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-3 py-2 text-slate-200 text-xs focus:border-cyan-400 outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Severity</label>
                  <select
                    value={newCaseSeverity}
                    onChange={e => setNewCaseSeverity(e.target.value as any)}
                    className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-3 py-2 text-slate-200 text-xs outline-none"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Priority SLA</label>
                  <select
                    value={newCasePriority}
                    onChange={e => setNewCasePriority(e.target.value as any)}
                    className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-3 py-2 text-slate-200 text-xs outline-none"
                  >
                    <option value="P1 - Urgent">P1 - Urgent (15m SLA)</option>
                    <option value="P2 - High">P2 - High (1h SLA)</option>
                    <option value="P3 - Medium">P3 - Medium (4h SLA)</option>
                    <option value="P4 - Low">P4 - Low (24h SLA)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Initial Summary / Scope</label>
                <textarea
                  rows={3}
                  placeholder="Describe initial threat hypothesis, affected hosts, and telemetry sources..."
                  value={newCaseSummary}
                  onChange={e => setNewCaseSummary(e.target.value)}
                  className="w-full bg-[#080d19] border border-[#1d2d4a] rounded p-2.5 text-slate-200 text-xs focus:border-cyan-400 outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsCreatingCase(false)}
                  className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold cursor-pointer"
                >
                  Create Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Main Grid: Cases Table & Investigation Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Cases Table */}
        <div className="lg:col-span-6 soc-card overflow-hidden">
          <div className="p-3 border-b border-[#18263f] flex items-center justify-between bg-[#080d18]">
            <span className="font-bold text-slate-200 text-xs">Active Investigation Cases</span>
            <span className="text-[10px] text-slate-400">Click to inspect evidence repository</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="bg-[#080d18] text-[10px] text-slate-400 uppercase border-b border-[#18263f]">
                  <th className="py-2.5 px-3">Case ID</th>
                  <th className="py-2.5 px-3">Title</th>
                  <th className="py-2.5 px-3 text-center">Priority</th>
                  <th className="py-2.5 px-3 text-center">Severity</th>
                  <th className="py-2.5 px-3 text-center">Status</th>
                  <th className="py-2.5 px-3 text-right">Lead</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#131d30]">
                {filtered.map(c => {
                  const isSelected = selectedCase?.id === c.id;
                  return (
                    <tr
                      key={c.id}
                      onClick={() => setSelectedCase(c)}
                      className={`hover:bg-[#111c30] cursor-pointer transition-colors ${
                        isSelected ? 'bg-cyan-950/30 border-l-2 border-cyan-400' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3 font-bold text-cyan-400 whitespace-nowrap">{c.id}</td>
                      <td className="py-2.5 px-3 max-w-[200px]">
                        <div className="font-bold text-slate-100 truncate">{c.title}</div>
                        <div className="text-[10px] text-slate-500 truncate">{c.summary}</div>
                      </td>
                      <td className="py-2.5 px-3 text-center whitespace-nowrap">
                        <span className="text-[10px] text-slate-300 bg-slate-900 border border-slate-700/60 px-1.5 py-0.2 rounded font-semibold">
                          {c.priority.split(' - ')[0]}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <span
                          className={`text-[9px] font-bold px-1.5 py-0.2 rounded ${
                            c.severity === 'Critical'
                              ? 'bg-red-950 text-red-300 border border-red-500/40'
                              : 'bg-amber-950 text-amber-300 border border-amber-500/30'
                          }`}
                        >
                          {c.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                            c.status === 'Closed'
                              ? 'bg-slate-800 text-slate-400'
                              : c.status === 'Under Investigation'
                              ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40'
                              : 'bg-blue-950 text-blue-300 border border-blue-500/30'
                          }`}
                        >
                          {c.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right text-[10px] text-slate-400 whitespace-nowrap">
                        {c.assignedTo.split(' ')[0]}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Case Workspace */}
        <div className="lg:col-span-6 soc-card p-4 space-y-3 flex flex-col justify-between">
          {selectedCase ? (
            <>
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-[#18263f]">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-base text-slate-100">{selectedCase.title}</span>
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">
                      Case ID: <strong className="text-cyan-400">{selectedCase.id}</strong> • Assigned to: {selectedCase.assignedTo}
                    </div>
                  </div>
                  <button
                    onClick={() => handleExportBrief(selectedCase)}
                    className="px-2.5 py-1 bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 rounded text-[10px] font-bold flex items-center gap-1 cursor-pointer"
                  >
                    <Download className="w-3 h-3" />
                    <span>Export Brief</span>
                  </button>
                </div>

                {/* Status Toggle Bar */}
                <div className="flex items-center gap-2 bg-[#080d19] p-2 rounded border border-[#162238]">
                  <span className="text-[10px] text-slate-400 uppercase font-bold">Status:</span>
                  {(['Open', 'Under Investigation', 'Pending Review', 'Closed'] as CaseTicket['status'][]).map(st => (
                    <button
                      key={st}
                      onClick={() => handleStatusChange(selectedCase.id, st)}
                      className={`px-2 py-0.5 rounded text-[10px] font-bold transition-colors cursor-pointer ${
                        selectedCase.status === st
                          ? 'bg-cyan-600 text-white'
                          : 'bg-slate-900 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>

                {/* Case Summary */}
                <div className="p-2.5 rounded bg-[#080d19] border border-[#162238] space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-bold">Scope & Hypothesis</span>
                  <p className="text-slate-200 text-xs leading-relaxed">{selectedCase.summary}</p>
                </div>

                {/* MITRE ATT&CK Mappings */}
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">
                    Mapped MITRE ATT&CK Techniques
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedCase.mitreTactics.map((tac, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] font-mono bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 px-2 py-0.5 rounded"
                      >
                        {tac}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Evidence Chain */}
                <div className="space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block">
                    Preserved Evidence & Chain of Custody ({selectedCase.evidenceItems.length})
                  </span>
                  <div className="space-y-1 max-h-[120px] overflow-y-auto pr-1">
                    {selectedCase.evidenceItems.map((evi, idx) => (
                      <div
                        key={idx}
                        className="p-1.5 rounded bg-[#060a14] border border-[#131d2f] text-[11px] text-slate-300 flex items-center gap-1.5 font-mono"
                      >
                        <Paperclip className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                        <span className="truncate">{evi}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Analyst Notes Timeline */}
                <div className="space-y-1.5">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block">
                    Analyst Investigation Log
                  </span>
                  <div className="space-y-1.5 max-h-[150px] overflow-y-auto pr-1">
                    {selectedCase.notes.map(n => (
                      <div
                        key={n.id}
                        className="p-2 rounded bg-[#080d19] border border-[#162238] space-y-1 text-xs"
                      >
                        <div className="flex items-center justify-between text-[10px] text-slate-400">
                          <span className="font-bold text-cyan-300">{n.author}</span>
                          <span>{n.timestamp}</span>
                        </div>
                        <p className="text-slate-300 text-[11px] leading-relaxed">{n.text}</p>
                      </div>
                    ))}
                  </div>

                  {/* Add Note Form */}
                  <form onSubmit={handleAddNote} className="flex gap-2 pt-1">
                    <input
                      type="text"
                      placeholder="Add investigation finding or forensic note..."
                      value={newNote}
                      onChange={e => setNewNote(e.target.value)}
                      className="flex-1 bg-[#080d19] border border-[#1d2d4a] rounded px-2.5 py-1.5 text-slate-200 text-xs focus:border-cyan-400 outline-none"
                    />
                    <button
                      type="submit"
                      disabled={!newNote.trim()}
                      className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white rounded text-xs font-bold cursor-pointer whitespace-nowrap"
                    >
                      Post Note
                    </button>
                  </form>
                </div>
              </div>

              <div className="pt-2 border-t border-[#18263f] text-[10px] text-slate-500 flex items-center justify-between">
                <span>Created: {selectedCase.createdAt}</span>
                <span className="text-cyan-400">Compliance: ISO 27001 Evidence Kept</span>
              </div>
            </>
          ) : (
            <div className="py-12 text-center text-slate-500">
              Select a case to view investigation details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
