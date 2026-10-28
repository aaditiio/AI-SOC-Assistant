import React from 'react';
import {
  LayoutDashboard,
  AlertTriangle,
  FolderLock,
  Globe2,
  Bug,
  Server,
  Network,
  Mail,
  Fingerprint,
  FileText,
  Briefcase,
  Settings,
  Shield,
  Activity,
  CheckCircle2,
  Database,
  Cloud,
  Zap
} from 'lucide-react';
import { DashboardOverview } from '../../types/soc';

export type NavTab =
  | 'Overview'
  | 'Dashboards'
  | 'Alerts'
  | 'Incidents'
  | 'Threat Intelligence'
  | 'Vulnerabilities'
  | 'Assets'
  | 'Cloud'
  | 'Endpoints'
  | 'Network'
  | 'Email'
  | 'Identity'
  | 'Automation'
  | 'Reports'
  | 'Cases'
  | 'API Gateway'
  | 'Settings';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  overview?: DashboardOverview | null;
  onOpenModelModal?: () => void;
  onOpenDatasetModal?: () => void;
  onOpenSecurityCenterModal?: () => void;
}

export const NAV_ITEMS: Array<{ id: NavTab; label: string; icon: React.ElementType; badge?: string }> = [
  { id: 'Overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'Dashboards', label: 'Dashboards', icon: Activity, badge: 'New' },
  { id: 'Alerts', label: 'Alerts', icon: AlertTriangle, badge: '7' },
  { id: 'Incidents', label: 'Incidents', icon: FolderLock, badge: '2' },
  { id: 'Threat Intelligence', label: 'Threat Intelligence', icon: Globe2 },
  { id: 'Vulnerabilities', label: 'Vulnerabilities', icon: Bug },
  { id: 'Assets', label: 'Assets', icon: Server },
  { id: 'Cloud', label: 'Cloud Security', icon: Cloud },
  { id: 'Endpoints', label: 'Endpoints (EDR)', icon: Shield },
  { id: 'Network', label: 'Network (Attack Path)', icon: Network, badge: 'Graph' },
  { id: 'Email', label: 'Email Security', icon: Mail },
  { id: 'Identity', label: 'Identity & Access', icon: Fingerprint },
  { id: 'Automation', label: 'Automation (SOAR)', icon: Zap },
  { id: 'Reports', label: 'Reports', icon: FileText },
  { id: 'Cases', label: 'Cases', icon: Briefcase },
  { id: 'API Gateway', label: 'API Gateway', icon: Database, badge: 'REST' },
  { id: 'Settings', label: 'Settings', icon: Settings },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  overview,
  onOpenModelModal,
  onOpenDatasetModal,
  onOpenSecurityCenterModal
}) => {
  return (
    <aside className="w-56 flex-shrink-0 bg-[#090e1a] border-r border-[#162238] flex flex-col justify-between h-screen sticky top-0 z-40 select-none">
      {/* Brand Header */}
      <div className="flex flex-col">
        <div className="h-14 flex items-center px-4 border-b border-[#162238] gap-2.5 bg-[#080d17]/80">
          <div className="w-8 h-8 rounded bg-gradient-to-br from-cyan-500 to-blue-700 flex items-center justify-center text-white shadow-[0_0_12px_rgba(6,182,212,0.4)]">
            <Shield className="w-5 h-5 text-white stroke-[2.2]" />
          </div>
          <div className="flex flex-col">
            <span className="font-bold text-sm text-slate-100 tracking-wide font-mono leading-tight">
              AI SOC Assistant
            </span>
            <span className="text-[10px] text-cyan-400 font-mono tracking-wider uppercase">
              Threat Engine v1.0
            </span>
          </div>
        </div>

        {/* Navigation Items (Exact 16 Order) */}
        <nav className="p-2 space-y-0.5 overflow-y-auto max-h-[calc(100vh-220px)] scrollbar-thin">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-1.5 rounded text-xs transition-colors duration-150 text-left ${
                  isActive
                    ? 'bg-cyan-950/60 text-cyan-300 font-medium border-l-2 border-cyan-400 pl-[10px]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#10192c]'
                }`}
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Icon
                    className={`w-4 h-4 flex-shrink-0 ${
                      isActive ? 'text-cyan-400' : 'text-slate-500'
                    }`}
                  />
                  <span className="truncate tracking-tight">{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.2 rounded-full ${
                      isActive
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* System Status Panel at Bottom */}
      <div className="p-2.5 border-t border-[#162238] bg-[#070c16]/95">
        <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-1.5 flex items-center justify-between">
          <span className="flex items-center gap-1">
            <Activity className="w-3 h-3 text-cyan-400 animate-pulse" />
            System Status
          </span>
          <span className="text-[9px] text-emerald-400 flex items-center gap-0.5">
            <CheckCircle2 className="w-2.5 h-2.5" />
            LIVE
          </span>
        </div>

        <div className="space-y-1 text-[11px] font-mono bg-[#0c1424] p-2 rounded border border-[#18253d]">
          {/* Backend Status */}
          <div className="flex items-center justify-between text-slate-400">
            <span>Backend:</span>
            <span className="text-cyan-300 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
              {overview?.systemStatus.backendType === 'fastapi-python' ? 'FastAPI 8000' : 'Node Express'}
            </span>
          </div>

          {/* Model Status */}
          <div 
            onClick={onOpenModelModal}
            className="flex items-center justify-between text-slate-400 cursor-pointer hover:text-cyan-300"
            title="Click to view Random Forest hyperparameters and metrics"
          >
            <span>Model:</span>
            <span className="text-emerald-400">RandomForest</span>
          </div>

          {/* Dataset Status */}
          <div 
            onClick={onOpenDatasetModal}
            className="flex items-center justify-between text-slate-400 cursor-pointer hover:text-blue-300 transition-colors"
            title="Click to upload custom dataset, view presets, or retrain model"
          >
            <span>Dataset:</span>
            <span className="text-blue-300 flex items-center gap-1 font-semibold underline decoration-dotted decoration-blue-500/50">
              <Database className="w-2.5 h-2.5 text-blue-400" />
              Upload & Retrain
            </span>
          </div>

          {/* Security Center Link */}
          <div 
            onClick={onOpenSecurityCenterModal}
            className="flex items-center justify-between text-slate-400 cursor-pointer hover:text-emerald-300 transition-colors"
            title="Click to inspect real-world network connectors and live packet flows"
          >
            <span>Sec Center:</span>
            <span className="text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Connected
            </span>
          </div>

          {/* Last Update */}
          <div className="flex items-center justify-between text-slate-500 text-[9px] pt-1 border-t border-[#162238]">
            <span>Synced:</span>
            <span>Just now</span>
          </div>
        </div>

        <div className="mt-1.5 text-center">
          <span className="text-[9px] text-slate-500 font-mono">
            B.Tech Capstone Project
          </span>
        </div>
      </div>
    </aside>
  );
};
