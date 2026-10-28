import React, { useState } from 'react';
import {
  FolderLock,
  Plus,
  Clock,
  User,
  ShieldAlert,
  CheckCircle2,
  MessageSquare,
  AlertTriangle,
  X
} from 'lucide-react';
import { Incident, Alert, Severity, IncidentStatus } from '../types/soc';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';

interface IncidentsPageProps {
  incidents: Incident[];
  alerts: Alert[];
  onCreateIncident: (data: {
    title: string;
    severity: Severity;
    assignedTo?: string;
    linkedAlertIds: string[];
    initialNote?: string;
  }) => Promise<Incident>;
  onUpdateIncident: (
    id: string,
    updates: {
      status?: Incident['status'];
      assignedTo?: string;
      severity?: Severity;
      newNote?: string;
    }
  ) => Promise<Incident | undefined>;
}

export const IncidentsPage: React.FC<IncidentsPageProps> = ({
  incidents,
  alerts,
  onCreateIncident,
  onUpdateIncident
}) => {
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState<Severity>('High');
  const [newAssignedTo, setNewAssignedTo] = useState('Prachi G. (Lead)');
  const [selectedAlerts, setSelectedAlerts] = useState<string[]>([]);
  const [initialNote, setInitialNote] = useState('');
  const [newNoteInput, setNewNoteInput] = useState('');

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    await onCreateIncident({
      title: newTitle,
      severity: newSeverity,
      assignedTo: newAssignedTo,
      linkedAlertIds: selectedAlerts,
      initialNote
    });

    setShowCreateModal(false);
    setNewTitle('');
    setSelectedAlerts([]);
    setInitialNote('');
  };

  const handleAddNote = async () => {
    if (!selectedIncident || !newNoteInput.trim()) return;
    const updated = await onUpdateIncident(selectedIncident.id, {
      newNote: newNoteInput
    });
    if (updated) setSelectedIncident(updated);
    setNewNoteInput('');
  };

  const handleStatusChange = async (status: IncidentStatus) => {
    if (!selectedIncident) return;
    const updated = await onUpdateIncident(selectedIncident.id, { status });
    if (updated) setSelectedIncident(updated);
  };

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <FolderLock className="w-4 h-4 text-amber-400" />
            <h2 className="text-sm font-bold text-slate-100">
              SOC Incident Management & Response
            </h2>
            <span className="text-[10px] bg-amber-950/80 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded">
              {incidents.length} Tracked Incidents
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Correlates individual threat alerts into coordinated security response investigations and logs MTTR.
          </p>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-lg shadow-cyan-600/30 transition-all self-start md:self-auto cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Create New Incident</span>
        </button>
      </div>

      {/* Incident List and Detail Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Incident List (7 cols) */}
        <div className="lg:col-span-7 space-y-3">
          {incidents.map(inc => (
            <div
              key={inc.id}
              onClick={() => setSelectedIncident(inc)}
              className={`p-3.5 rounded soc-card cursor-pointer transition-all duration-150 border ${
                selectedIncident?.id === inc.id
                  ? 'border-cyan-400 bg-[#0e172a]'
                  : 'border-[#1b2b47] hover:border-slate-500 bg-[#0c1424]'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-slate-100 text-xs">{inc.id}</span>
                  <SeverityBadge severity={inc.severity} size="xs" />
                  <StatusBadge status={inc.status} size="xs" />
                </div>
                <div className="flex items-center gap-1.5 text-slate-400 text-[10px]">
                  <Clock className="w-3 h-3" />
                  <span>MTTR: {inc.responseDurationMinutes ? `${inc.responseDurationMinutes} min` : 'Pending'}</span>
                </div>
              </div>

              <h4 className="font-bold text-slate-100 text-xs mb-1.5">{inc.title}</h4>

              <div className="flex items-center justify-between text-[10px] text-slate-400 border-t border-[#16233b] pt-1.5">
                <span className="flex items-center gap-1 text-slate-300">
                  <User className="w-3 h-3 text-cyan-400" />
                  {inc.assignedTo}
                </span>
                <span className="text-slate-400">
                  {inc.linkedAlertIds.length} Linked Alert(s)
                </span>
                <span>Created: {inc.createdAt.split('T')[0]}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Incident Details & Notes Panel (5 cols) */}
        <div className="lg:col-span-5 soc-card p-4 space-y-4">
          {selectedIncident ? (
            <>
              <div className="flex items-center justify-between border-b border-[#18263f] pb-2">
                <div>
                  <span className="font-bold text-slate-100 text-sm block">{selectedIncident.id}</span>
                  <span className="text-[10px] text-slate-400">Assigned: {selectedIncident.assignedTo}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <SeverityBadge severity={selectedIncident.severity} size="xs" />
                  <StatusBadge status={selectedIncident.status} size="xs" />
                </div>
              </div>

              <h3 className="font-bold text-slate-200 text-xs">{selectedIncident.title}</h3>

              {/* Status Update Quick Toggles */}
              <div className="space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Update Incident State:</span>
                <div className="grid grid-cols-4 gap-1">
                  {(['New', 'In Progress', 'On Hold', 'Resolved'] as const).map(s => (
                    <button
                      key={s}
                      onClick={() => handleStatusChange(s)}
                      className={`py-1 px-1.5 rounded text-[10px] border transition-colors ${
                        selectedIncident.status === s
                          ? 'bg-cyan-950 border-cyan-400 text-cyan-300 font-bold'
                          : 'bg-[#080d19] border-[#1d2d4a] text-slate-400 hover:text-white'
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>

              {/* Linked Alerts */}
              <div className="space-y-1.5">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Correlated Security Alerts:</span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedIncident.linkedAlertIds.map(aId => {
                    const alt = alerts.find(a => a.id === aId);
                    return (
                      <span
                        key={aId}
                        className="px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/30 text-cyan-300 text-[10px] flex items-center gap-1"
                      >
                        <ShieldAlert className="w-2.5 h-2.5" />
                        {aId} {alt ? `(${alt.predictedCategory})` : ''}
                      </span>
                    );
                  })}
                </div>
              </div>

              {/* Timeline Notes */}
              <div className="space-y-2 border-t border-[#18263f] pt-2">
                <span className="text-[10px] text-slate-400 uppercase font-semibold flex items-center gap-1">
                  <MessageSquare className="w-3 h-3 text-cyan-400" />
                  Investigation Timeline & Notes ({selectedIncident.notes.length})
                </span>

                <div className="space-y-2 max-h-[160px] overflow-y-auto scrollbar-thin pr-1">
                  {selectedIncident.notes.map(note => (
                    <div key={note.id} className="p-2 rounded bg-[#080d19] border border-[#16233b] text-[10px] space-y-0.5">
                      <div className="flex items-center justify-between text-slate-400">
                        <span className="font-semibold text-cyan-300">{note.author}</span>
                        <span className="text-[9px]">{note.timestamp.replace('T', ' ').substring(0, 16)}</span>
                      </div>
                      <p className="text-slate-300 leading-relaxed">{note.content}</p>
                    </div>
                  ))}
                </div>

                {/* Add Note Input */}
                <div className="flex gap-2 pt-1">
                  <input
                    type="text"
                    placeholder="Enter analyst investigation note..."
                    value={newNoteInput}
                    onChange={e => setNewNoteInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleAddNote()}
                    className="flex-1 bg-[#080d19] border border-[#1d2d4a] rounded px-2.5 py-1 text-slate-200 text-xs focus:border-cyan-400 outline-none"
                  />
                  <button
                    onClick={handleAddNote}
                    className="px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition-colors"
                  >
                    Post Note
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-slate-400">
              Select an incident from the left to inspect correlation, notes, and lifecycle status.
            </div>
          )}
        </div>
      </div>

      {/* Create Incident Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreate}
            className="bg-[#0b1324] border border-[#1d2f50] rounded-lg max-w-lg w-full p-4 space-y-3 shadow-2xl animate-in zoom-in-95"
          >
            <div className="flex items-center justify-between border-b border-[#1b2b47] pb-2">
              <span className="font-bold text-slate-100 text-sm">Escalate New SOC Incident</span>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] text-slate-400 uppercase">Incident Title</label>
              <input
                type="text"
                required
                placeholder="e.g. Distributed Credential Spray on Domain Controller"
                value={newTitle}
                onChange={e => setNewTitle(e.target.value)}
                className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2.5 py-1.5 text-slate-200 text-xs focus:border-cyan-400 outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Severity</label>
                <select
                  value={newSeverity}
                  onChange={e => setNewSeverity(e.target.value as Severity)}
                  className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1.5 text-slate-200 text-xs focus:border-cyan-400 outline-none"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Assignee</label>
                <input
                  type="text"
                  value={newAssignedTo}
                  onChange={e => setNewAssignedTo(e.target.value)}
                  className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2.5 py-1.5 text-slate-200 text-xs focus:border-cyan-400 outline-none"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] text-slate-400 uppercase">Link Alerts</label>
              <div className="max-h-28 overflow-y-auto bg-[#080d19] p-2 rounded border border-[#1d2d4a] space-y-1 scrollbar-thin">
                {alerts.map(a => (
                  <label key={a.id} className="flex items-center gap-2 cursor-pointer text-[10px] text-slate-300 hover:text-white">
                    <input
                      type="checkbox"
                      checked={selectedAlerts.includes(a.id)}
                      onChange={e => {
                        if (e.target.checked) setSelectedAlerts([...selectedAlerts, a.id]);
                        else setSelectedAlerts(selectedAlerts.filter(id => id !== a.id));
                      }}
                      className="accent-cyan-500"
                    />
                    <span className="font-bold text-cyan-400">{a.id}</span>
                    <span className="truncate">{a.title} ({a.severity})</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] text-slate-400 uppercase">Initial Investigation Note</label>
              <textarea
                rows={2}
                placeholder="Initial containment steps and correlation notes..."
                value={initialNote}
                onChange={e => setInitialNote(e.target.value)}
                className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2.5 py-1.5 text-slate-200 text-xs focus:border-cyan-400 outline-none"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-[#1b2b47]">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-3 py-1.5 rounded bg-[#162238] text-slate-300 hover:bg-[#1e2f4c]"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold"
              >
                Create Incident
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
