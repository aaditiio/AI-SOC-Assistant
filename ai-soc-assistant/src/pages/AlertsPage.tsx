import React, { useState } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  Play,
  RotateCcw,
  ShieldAlert,
  ArrowUpRight,
  ExternalLink
} from 'lucide-react';
import { Alert, ThreatCategory, Severity } from '../types/soc';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { THREAT_CLASSES } from '../server/socEngine';

interface AlertsPageProps {
  alerts: Alert[];
  onSelectAlert: (alertId: string) => void;
  onSimulateAlert: () => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({
  alerts,
  onSelectAlert,
  onSimulateAlert
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('All');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedStatus, setSelectedStatus] = useState<string>('All');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 8;

  const filteredAlerts = alerts.filter(a => {
    if (selectedSeverity !== 'All' && a.severity !== selectedSeverity) return false;
    if (selectedCategory !== 'All' && a.predictedCategory !== selectedCategory) return false;
    if (selectedStatus !== 'All' && a.status !== selectedStatus) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        a.title.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q) ||
        a.sourceIp.includes(q) ||
        a.destIp.includes(q)
      );
    }
    return true;
  });

  const totalPages = Math.ceil(filteredAlerts.length / pageSize) || 1;
  const paginatedAlerts = filteredAlerts.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono">
      {/* Top Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Security Alert Repository & Prioritization
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              {alerts.length} Total Alerts
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Machine learning threat classifications cross-referenced with rule-based severity weighting.
          </p>
        </div>

        <button
          onClick={onSimulateAlert}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-lg shadow-cyan-600/30 transition-all self-start md:self-auto cursor-pointer"
        >
          <Play className="w-3.5 h-3.5 fill-white" />
          <span>Inject Synthetic Packet Flow</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="soc-card p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by Alert ID, IP, or Title..."
            value={searchQuery}
            onChange={e => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-[#080d19] border border-[#1d2d4a] rounded pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:border-cyan-400 outline-none text-xs"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity */}
          <div className="flex items-center gap-1">
            <span className="text-slate-400 text-[10px] uppercase">Severity:</span>
            <select
              value={selectedSeverity}
              onChange={e => {
                setSelectedSeverity(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1 text-slate-200 text-xs focus:border-cyan-400 outline-none"
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Informational">Informational</option>
            </select>
          </div>

          {/* Category */}
          <div className="flex items-center gap-1">
            <span className="text-slate-400 text-[10px] uppercase">Category:</span>
            <select
              value={selectedCategory}
              onChange={e => {
                setSelectedCategory(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1 text-slate-200 text-xs focus:border-cyan-400 outline-none"
            >
              <option value="All">All Categories</option>
              {THREAT_CLASSES.map(cls => (
                <option key={cls} value={cls}>{cls}</option>
              ))}
            </select>
          </div>

          {/* Status */}
          <div className="flex items-center gap-1">
            <span className="text-slate-400 text-[10px] uppercase">Status:</span>
            <select
              value={selectedStatus}
              onChange={e => {
                setSelectedStatus(e.target.value);
                setCurrentPage(1);
              }}
              className="bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1 text-slate-200 text-xs focus:border-cyan-400 outline-none"
            >
              <option value="All">All Statuses</option>
              <option value="New">New</option>
              <option value="Investigating">Investigating</option>
              <option value="Escalated">Escalated</option>
              <option value="Resolved">Resolved</option>
              <option value="False Positive">False Positive</option>
            </select>
          </div>

          {/* Reset button */}
          {(selectedSeverity !== 'All' || selectedCategory !== 'All' || selectedStatus !== 'All' || searchQuery) && (
            <button
              onClick={() => {
                setSelectedSeverity('All');
                setSelectedCategory('All');
                setSelectedStatus('All');
                setSearchQuery('');
                setCurrentPage(1);
              }}
              className="p-1 rounded bg-[#162238] hover:bg-[#1f2f4c] text-slate-400 hover:text-white"
              title="Reset Filters"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Alerts Table */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#080d18] text-[10px] text-slate-400 uppercase border-b border-[#18263f]">
                <th className="py-2.5 px-3">Alert ID</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Title / Description</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Origin (Src)</th>
                <th className="py-2.5 px-3">Target (Dst)</th>
                <th className="py-2.5 px-3 text-center">Confidence</th>
                <th className="py-2.5 px-3 text-center">Status</th>
                <th className="py-2.5 px-3 text-right">Triage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#131d30]">
              {paginatedAlerts.length > 0 ? (
                paginatedAlerts.map(alert => (
                  <tr
                    key={alert.id}
                    onClick={() => onSelectAlert(alert.id)}
                    className="hover:bg-[#111c30] cursor-pointer transition-colors group"
                  >
                    <td className="py-2 px-3 font-bold text-cyan-400 group-hover:text-cyan-300 whitespace-nowrap">
                      {alert.id}
                    </td>
                    <td className="py-2 px-3 text-slate-400 text-[10px] whitespace-nowrap">
                      {alert.timestamp}
                    </td>
                    <td className="py-2 px-3">
                      <SeverityBadge severity={alert.severity} size="xs" />
                    </td>
                    <td className="py-2 px-3">
                      <div className="font-semibold text-slate-200 group-hover:text-cyan-200 truncate max-w-[240px]">
                        {alert.title}
                      </div>
                      <div className="text-[10px] text-slate-400 truncate max-w-[240px]">
                        {alert.explanation}
                      </div>
                    </td>
                    <td className="py-2 px-3">
                      <span className="font-bold text-cyan-300 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-500/30 text-[10px]">
                        {alert.predictedCategory}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-300 text-[11px] whitespace-nowrap">
                      {alert.sourceIp}:{alert.sourcePort}
                    </td>
                    <td className="py-2 px-3 text-purple-300 text-[11px] whitespace-nowrap">
                      {alert.destIp}:{alert.destPort}
                    </td>
                    <td className="py-2 px-3 text-center font-bold text-slate-200">
                      {(alert.confidence * 100).toFixed(1)}%
                    </td>
                    <td className="py-2 px-3 text-center">
                      <StatusBadge status={alert.status} size="xs" />
                    </td>
                    <td className="py-2 px-3 text-right">
                      <button className="px-2 py-1 rounded bg-[#162238] group-hover:bg-cyan-500/20 group-hover:text-cyan-300 text-slate-400 text-[10px] transition-colors">
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-slate-400 text-xs">
                    No alerts match the selected search and filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-3 border-t border-[#18263f] flex items-center justify-between text-xs text-slate-400 bg-[#080d18]">
          <span>
            Showing {filteredAlerts.length > 0 ? (currentPage - 1) * pageSize + 1 : 0} to{' '}
            {Math.min(currentPage * pageSize, filteredAlerts.length)} of {filteredAlerts.length} alerts
          </span>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setCurrentPage(p => Math.max(p - 1, 1))}
              disabled={currentPage === 1}
              className="px-2.5 py-1 rounded bg-[#131f36] border border-[#1e2e4a] disabled:opacity-40 hover:bg-[#1a2d52] transition-colors"
            >
              Previous
            </button>
            <span className="px-2 py-1 text-slate-300">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(p => Math.min(p + 1, totalPages))}
              disabled={currentPage === totalPages}
              className="px-2.5 py-1 rounded bg-[#131f36] border border-[#1e2e4a] disabled:opacity-40 hover:bg-[#1a2d52] transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
