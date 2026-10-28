import React, { useState } from 'react';
import { LayoutDashboard, Activity, Shield, AlertTriangle, Cpu, HardDrive, Zap, RefreshCw, BarChart3, PieChart } from 'lucide-react';
import { DashboardOverview, Alert, Incident } from '../types/soc';

interface DashboardsPageProps {
  overview: DashboardOverview | null;
  alerts: Alert[];
  incidents: Incident[];
  onRefreshData: () => void;
}

export const DashboardsPage: React.FC<DashboardsPageProps> = ({ overview, alerts, incidents, onRefreshData }) => {
  const [selectedDashboard, setSelectedDashboard] = useState<'executive' | 'soc-tier1' | 'threat-intel' | 'compliance'>('executive');

  const criticalCount = alerts.filter(a => a.severity === 'Critical').length;
  const highCount = alerts.filter(a => a.severity === 'High').length;
  const mediumCount = alerts.filter(a => a.severity === 'Medium').length;
  const lowCount = alerts.filter(a => a.severity === 'Low').length;

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      {/* Top Banner & Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <LayoutDashboard className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Executive & Operational Security Dashboards
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded">
              Real-Time Telemetry
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Customizable SOC viewports for executive risk reporting, tier-1 incident response triage, and threat posture analysis.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setSelectedDashboard('executive')}
            className={`px-3 py-1.5 rounded font-bold transition-colors ${
              selectedDashboard === 'executive'
                ? 'bg-cyan-600 text-white shadow-[0_0_10px_rgba(6,182,212,0.4)]'
                : 'bg-[#121c2e] text-slate-300 hover:bg-[#1a2842]'
            }`}
          >
            Executive Risk
          </button>
          <button
            onClick={() => setSelectedDashboard('soc-tier1')}
            className={`px-3 py-1.5 rounded font-bold transition-colors ${
              selectedDashboard === 'soc-tier1'
                ? 'bg-cyan-600 text-white shadow-[0_0_10px_rgba(6,182,212,0.4)]'
                : 'bg-[#121c2e] text-slate-300 hover:bg-[#1a2842]'
            }`}
          >
            SOC Tier-1 Triage
          </button>
          <button
            onClick={() => setSelectedDashboard('compliance')}
            className={`px-3 py-1.5 rounded font-bold transition-colors ${
              selectedDashboard === 'compliance'
                ? 'bg-cyan-600 text-white shadow-[0_0_10px_rgba(6,182,212,0.4)]'
                : 'bg-[#121c2e] text-slate-300 hover:bg-[#1a2842]'
            }`}
          >
            Compliance & Posture
          </button>
          <button
            onClick={onRefreshData}
            className="p-1.5 bg-[#121c2e] text-cyan-400 hover:text-white rounded border border-[#233554] transition-colors"
            title="Refresh Telemetry"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Dashboard Viewport Content */}
      {selectedDashboard === 'executive' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="soc-card p-3 bg-[#0b1324] border border-[#1b2b47] rounded">
              <span className="text-slate-400 text-[10px] uppercase">Overall Risk Index</span>
              <div className="text-2xl font-bold text-red-400 mt-1">84.2 / 100</div>
              <span className="text-[10px] text-red-400 flex items-center gap-1 mt-1">
                <AlertTriangle className="w-3 h-3" /> Elevated Threat Level
              </span>
            </div>
            <div className="soc-card p-3 bg-[#0b1324] border border-[#1b2b47] rounded">
              <span className="text-slate-400 text-[10px] uppercase">Mean Time to Resolution (MTTR)</span>
              <div className="text-2xl font-bold text-cyan-300 mt-1">{overview?.mttrMinutes ?? 21.4} mins</div>
              <span className="text-[10px] text-emerald-400 flex items-center gap-1 mt-1">
                -14% vs last week SLA
              </span>
            </div>
            <div className="soc-card p-3 bg-[#0b1324] border border-[#1b2b47] rounded">
              <span className="text-slate-400 text-[10px] uppercase">Assets at Critical Risk</span>
              <div className="text-2xl font-bold text-amber-400 mt-1">{overview?.assetsAtRisk ?? 3} / 8</div>
              <span className="text-[10px] text-slate-400 mt-1">Domain Controller & DB Prods</span>
            </div>
            <div className="soc-card p-3 bg-[#0b1324] border border-[#1b2b47] rounded">
              <span className="text-slate-400 text-[10px] uppercase">ML Model Accuracy</span>
              <div className="text-2xl font-bold text-emerald-400 mt-1">99.4%</div>
              <span className="text-[10px] text-cyan-400 mt-1">RandomForest (100 Trees)</span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="soc-card p-4 bg-[#0b1324] border border-[#1b2b47] rounded space-y-3">
              <h3 className="text-xs font-bold text-slate-200 uppercase flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                Alert Severity Distribution
              </h3>
              <div className="space-y-2 text-xs">
                <div>
                  <div className="flex justify-between text-slate-300 mb-1">
                    <span>Critical ({criticalCount})</span>
                    <span className="text-red-400 font-bold">{Math.round((criticalCount / (alerts.length || 1)) * 100)}%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded overflow-hidden">
                    <div className="bg-red-500 h-full" style={{ width: `${(criticalCount / (alerts.length || 1)) * 100}%` }} />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-slate-300 mb-1">
                    <span>High ({highCount})</span>
                    <span className="text-orange-400 font-bold">{Math.round((highCount / (alerts.length || 1)) * 100)}%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded overflow-hidden">
                    <div className="bg-orange-500 h-full" style={{ width: `${(highCount / (alerts.length || 1)) * 100}%` }} />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-slate-300 mb-1">
                    <span>Medium ({mediumCount})</span>
                    <span className="text-amber-400 font-bold">{Math.round((mediumCount / (alerts.length || 1)) * 100)}%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded overflow-hidden">
                    <div className="bg-amber-500 h-full" style={{ width: `${(mediumCount / (alerts.length || 1)) * 100}%` }} />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-slate-300 mb-1">
                    <span>Low / Informational ({lowCount})</span>
                    <span className="text-emerald-400 font-bold">{Math.round((lowCount / (alerts.length || 1)) * 100)}%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded overflow-hidden">
                    <div className="bg-emerald-500 h-full" style={{ width: `${(lowCount / (alerts.length || 1)) * 100}%` }} />
                  </div>
                </div>
              </div>
            </div>

            <div className="soc-card p-4 bg-[#0b1324] border border-[#1b2b47] rounded space-y-3">
              <h3 className="text-xs font-bold text-slate-200 uppercase flex items-center gap-2">
                <PieChart className="w-4 h-4 text-cyan-400" />
                Active Incident Pipeline
              </h3>
              <div className="space-y-2">
                {incidents.slice(0, 4).map(inc => (
                  <div key={inc.id} className="p-2.5 bg-[#0e172a] border border-[#1d2d4a] rounded flex items-center justify-between">
                    <div>
                      <span className="text-cyan-400 font-bold">{inc.id}</span>
                      <span className="text-slate-200 ml-2">{inc.title}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      inc.severity === 'Critical' ? 'bg-red-950 text-red-400 border border-red-500/40' : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                    }`}>
                      {inc.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {selectedDashboard === 'soc-tier1' && (
        <div className="space-y-4">
          <div className="soc-card p-4 bg-[#0b1324] border border-[#1b2b47] rounded space-y-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Tier-1 Analyst Live Feed & Triage Queue
            </h3>
            <div className="space-y-2">
              {alerts.slice(0, 8).map(alert => (
                <div key={alert.id} className="p-3 bg-[#0e172a] border border-[#1d2d4a] rounded flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`w-2 h-2 rounded-full ${alert.severity === 'Critical' ? 'bg-red-500 animate-ping' : 'bg-amber-500'}`} />
                    <div>
                      <div className="font-bold text-slate-200">{alert.id}: {alert.title}</div>
                      <div className="text-[10px] text-slate-400">Src: {alert.sourceIp} to Dst: {alert.destIp} ({alert.protocol}) | Conf: {(alert.confidence * 100).toFixed(1)}%</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                      {alert.predictedCategory}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                      alert.severity === 'Critical' ? 'bg-red-950 text-red-400 border border-red-500/40' : 'bg-amber-950 text-amber-300'
                    }`}>
                      {alert.severity}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {selectedDashboard === 'compliance' && (
        <div className="space-y-4">
          <div className="soc-card p-4 bg-[#0b1324] border border-[#1b2b47] rounded space-y-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Regulatory Compliance Posture (ISO 27001, SOC 2, NIST CSF)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3 bg-[#0e172a] border border-[#1d2d4a] rounded">
                <div className="text-slate-400">ISO 27001:2022 Control Baseline</div>
                <div className="text-xl font-bold text-emerald-400 mt-1">94.8% Compliant</div>
                <div className="text-[10px] text-slate-400 mt-1">114 of 120 controls verified active</div>
              </div>
              <div className="p-3 bg-[#0e172a] border border-[#1d2d4a] rounded">
                <div className="text-slate-400">SOC 2 Trust Services Criteria</div>
                <div className="text-xl font-bold text-cyan-300 mt-1">Type II Certified</div>
                <div className="text-[10px] text-slate-400 mt-1">Continuous monitoring audit passed</div>
              </div>
              <div className="p-3 bg-[#0e172a] border border-[#1d2d4a] rounded">
                <div className="text-slate-400">NIST CSF 2.0 Framework</div>
                <div className="text-xl font-bold text-amber-300 mt-1">Tier 3 (Repeatable)</div>
                <div className="text-[10px] text-slate-400 mt-1">Automated threat detection active</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
