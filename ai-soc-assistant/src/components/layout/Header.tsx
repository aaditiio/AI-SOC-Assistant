import React, { useState } from 'react';
import {
  Bell,
  HelpCircle,
  Play,
  RotateCw,
  Server,
  User,
  ExternalLink,
  Check,
  CheckCircle2,
  Database,
  Radio,
  UploadCloud
} from 'lucide-react';
import { NavTab } from './Sidebar';
import { socApi, BackendMode } from '../../services/api';

interface HeaderProps {
  activeTab: NavTab;
  onSimulatePacket: () => void;
  onRefreshData: () => void;
  onOpenHelpModal: () => void;
  onOpenDatasetModal?: () => void;
  onOpenSecurityCenterModal?: () => void;
  backendMode: BackendMode;
  onToggleBackendMode: (mode: BackendMode) => void;
  unreadCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onSimulatePacket,
  onRefreshData,
  onOpenHelpModal,
  onOpenDatasetModal,
  onOpenSecurityCenterModal,
  backendMode,
  onToggleBackendMode,
  unreadCount = 2
}) => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await onRefreshData();
    setTimeout(() => setIsRefreshing(false), 500);
  };

  return (
    <header className="h-14 bg-[#090e1a]/90 backdrop-blur-md border-b border-[#162238] px-5 flex items-center justify-between sticky top-0 z-30">
      {/* Breadcrumb & Title */}
      <div className="flex items-center gap-3">
        <span className="text-xs text-slate-500 font-mono">SOC Console</span>
        <span className="text-slate-600 font-mono">/</span>
        <h1 className="text-sm font-semibold text-slate-100 font-mono tracking-wide flex items-center gap-2">
          {activeTab}
          {activeTab === 'Overview' && (
            <span className="text-[10px] bg-cyan-950/70 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded font-mono">
              REAL-TIME MONITORING
            </span>
          )}
        </h1>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-2">
        {/* Security Center Connect Trigger */}
        <button
          onClick={onOpenSecurityCenterModal}
          className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono font-medium rounded bg-emerald-950/40 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-900/50 hover:border-emerald-400 transition-all duration-150 shadow-[0_0_10px_rgba(16,185,129,0.2)] cursor-pointer"
          title="Connect to Real-World Security Center (Syslog, Splunk, Zeek, Suricata, AWS GuardDuty) and Deep Network Flow Inspector"
        >
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <Radio className="w-3 h-3 text-emerald-400" />
          <span className="hidden sm:inline font-semibold">Security Center</span>
        </button>

        {/* Upload Dataset & Retrain Trigger */}
        <button
          onClick={onOpenDatasetModal}
          className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono font-medium rounded bg-blue-950/40 text-blue-300 border border-blue-500/40 hover:bg-blue-900/50 hover:border-blue-400 transition-all duration-150 shadow-[0_0_10px_rgba(59,130,246,0.15)] cursor-pointer"
          title="Upload new CSV/JSON dataset - dynamically retrains model, recomputes metrics, risk scores, and updates all parameters"
        >
          <UploadCloud className="w-3.5 h-3.5 text-blue-400" />
          <span className="hidden sm:inline font-semibold">Dataset & ML</span>
        </button>

        {/* Dynamic Dataset Preset Switcher */}
        <div className="hidden xl:flex items-center gap-1.5 bg-[#0d1527] border border-[#1b2a47] rounded px-2 py-1 text-xs font-mono">
          <Database className="w-3 h-3 text-cyan-400" />
          <select
            value={socApi.getActivePresetId()}
            onChange={async (e) => {
              await socApi.applyDatasetPreset(e.target.value);
              onRefreshData();
            }}
            className="bg-transparent text-cyan-300 text-[11px] outline-none cursor-pointer font-medium"
            title="Switch synthetic network flow dataset profile - retrains model & updates entire application"
          >
            {socApi.getDatasetPresets().map(p => (
              <option key={p.id} value={p.id} className="bg-[#0b1324] text-slate-200">
                Preset: {p.name.split(' (')[0]}
              </option>
            ))}
          </select>
        </div>

        {/* Simulate Live Flow Button */}
        <button
          onClick={onSimulatePacket}
          className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono font-medium rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/20 transition-all duration-150 shadow-[0_0_8px_rgba(6,182,212,0.15)] cursor-pointer"
          title="Inject a realistic synthetic network flow record through the Random Forest classifier"
        >
          <Play className="w-3 h-3 text-cyan-400 fill-cyan-400" />
          <span className="hidden md:inline">Simulate Flow</span>
        </button>


        {/* Backend Mode Selector */}
        <div className="flex items-center bg-[#0d1527] border border-[#1b2a47] rounded p-0.5 text-[11px] font-mono">
          <button
            onClick={() => onToggleBackendMode('aistudio')}
            className={`px-2 py-0.5 rounded transition-colors flex items-center gap-1 ${
              backendMode === 'aistudio'
                ? 'bg-cyan-600/30 text-cyan-300 font-medium border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            title="Running AI Studio Express full-stack engine with 5,000 synthetic records and local graph engine"
          >
            <Server className="w-3 h-3" />
            <span>AI Studio Engine</span>
          </button>

          <button
            onClick={() => onToggleBackendMode('fastapi')}
            className={`px-2 py-0.5 rounded transition-colors flex items-center gap-1 ${
              backendMode === 'fastapi'
                ? 'bg-cyan-600/30 text-cyan-300 font-medium border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            title="Toggle to connect directly to local Python FastAPI backend (http://127.0.0.1:8000)"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span>FastAPI:8000</span>
          </button>
        </div>

        {/* Refresh button */}
        <button
          onClick={handleRefresh}
          className="p-1.5 rounded bg-[#0d1527] border border-[#1b2a47] text-slate-400 hover:text-slate-200 hover:border-slate-600 transition-colors"
          title="Refresh dashboard metrics"
        >
          <RotateCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>

        {/* Notification Bell */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-1.5 rounded bg-[#0d1527] border border-[#1b2a47] text-slate-400 hover:text-slate-200 hover:border-slate-600 transition-colors relative"
            title="Alert Notifications"
          >
            <Bell className="w-3.5 h-3.5" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-red-500 text-[9px] font-mono text-white flex items-center justify-center font-bold">
                {unreadCount}
              </span>
            )}
          </button>

          {/* Notifications Dropdown */}
          {showNotifications && (
            <div className="absolute right-0 mt-2 w-72 bg-[#0c1424] border border-[#1e2e4f] rounded shadow-xl p-3 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
              <div className="flex items-center justify-between pb-2 border-b border-[#1b2a47] mb-2">
                <span className="text-xs font-mono font-semibold text-slate-200">Recent Notifications</span>
                <span className="text-[10px] text-cyan-400 font-mono cursor-pointer" onClick={() => setShowNotifications(false)}>
                  Close
                </span>
              </div>
              <div className="space-y-2 text-xs">
                <div className="p-2 rounded bg-red-950/40 border border-red-500/30">
                  <div className="flex items-center justify-between font-mono text-red-400 text-[11px]">
                    <span>ALT-9041 Escalated</span>
                    <span className="text-[9px] text-slate-400">2m ago</span>
                  </div>
                  <p className="text-slate-300 text-[11px] mt-0.5">Kerberos pre-authentication brute force on DC-CORP-01 escalated to critical incident.</p>
                </div>
                <div className="p-2 rounded bg-amber-950/40 border border-amber-500/30">
                  <div className="flex items-center justify-between font-mono text-amber-400 text-[11px]">
                    <span>SYN Surge Warning</span>
                    <span className="text-[9px] text-slate-400">14m ago</span>
                  </div>
                  <p className="text-slate-300 text-[11px] mt-0.5">Volumetric SYN flood packet rate hit 14,200 pkts/s on port 443.</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Help / Thesis Info */}
        <button
          onClick={onOpenHelpModal}
          className="p-1.5 rounded bg-[#0d1527] border border-[#1b2a47] text-slate-400 hover:text-cyan-300 hover:border-cyan-500/40 transition-colors"
          title="Project documentation, ML pipeline architecture, and Graph algorithms guide"
        >
          <HelpCircle className="w-3.5 h-3.5" />
        </button>

        {/* Analyst Profile */}
        <div className="flex items-center gap-2 pl-2 border-l border-[#162238]">
          <div className="w-7 h-7 rounded-full bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-300 font-mono text-xs font-bold">
            PG
          </div>
          <div className="hidden lg:flex flex-col">
            <span className="text-xs font-medium text-slate-200 font-mono leading-none">
              Prachi G.
            </span>
            <span className="text-[10px] text-slate-400 font-mono mt-0.5">
              SOC Tier-3 Lead
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
