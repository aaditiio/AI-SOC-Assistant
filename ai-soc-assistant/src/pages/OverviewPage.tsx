import React from 'react';
import { KpiRow } from '../components/dashboard/KpiRow';
import { AlertsBySeverityChart } from '../components/dashboard/AlertsBySeverityChart';
import { AlertsOverTimeChart } from '../components/dashboard/AlertsOverTimeChart';
import { TopVulnerabilitiesTable } from '../components/dashboard/TopVulnerabilitiesTable';
import { GlobalThreatHeatmap } from '../components/dashboard/GlobalThreatHeatmap';
import { TopActiveThreatsTable } from '../components/dashboard/TopActiveThreatsTable';
import { IncidentStatusChart } from '../components/dashboard/IncidentStatusChart';
import { AssetsAtRiskTable } from '../components/dashboard/AssetsAtRiskTable';
import { RecentCriticalAlerts } from '../components/dashboard/RecentCriticalAlerts';
import { AiAnalysisInsights } from '../components/dashboard/AiAnalysisInsights';
import { ThreatIntelligenceFeed } from '../components/dashboard/ThreatIntelligenceFeed';
import { RecentActivityTable } from '../components/dashboard/RecentActivityTable';
import { AttackChainOverview } from '../components/dashboard/AttackChainOverview';

import {
  Alert,
  Asset,
  Vulnerability,
  ThreatIntelItem,
  ActivityLog,
  DashboardOverview,
  Severity
} from '../types/soc';

interface OverviewPageProps {
  overview: DashboardOverview | null;
  alerts: Alert[];
  assets: Asset[];
  vulnerabilities: Vulnerability[];
  threatIntel: ThreatIntelItem[];
  activityLogs: ActivityLog[];
  severityDistribution: Array<{ severity: Severity; count: number; percentage: number }>;
  incidentDistribution: Array<{ status: string; count: number; percentage: number }>;
  alertsOverTimeData: Array<{
    time: string;
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Informational: number;
  }>;
  onSelectAlert: (alertId: string) => void;
  onViewAllAlerts: () => void;
  onOpenAttackPath: () => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  overview,
  alerts,
  assets,
  vulnerabilities,
  threatIntel,
  activityLogs,
  severityDistribution,
  incidentDistribution,
  alertsOverTimeData,
  onSelectAlert,
  onViewAllAlerts,
  onOpenAttackPath
}) => {
  return (
    <div className="p-4 space-y-3 max-w-[1920px] mx-auto animate-in fade-in duration-150">
      {/* 1. Top KPI Row (6 Cards) */}
      <KpiRow overview={overview} />

      {/* 2. Main Three-Column Dashboard Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-stretch">
        {/* Left Analytics Column (approx 28% -> 3 cols on xl) */}
        <div className="lg:col-span-4 xl:col-span-3 flex flex-col justify-between space-y-3 h-full">
          <AlertsBySeverityChart
            distribution={severityDistribution}
            total={overview?.totalAlerts ?? alerts.length}
            className="flex-1"
          />
          <AlertsOverTimeChart data={alertsOverTimeData} className="flex-1" />
          <TopVulnerabilitiesTable vulnerabilities={vulnerabilities} className="flex-1" />
        </div>

        {/* Center Analytics Column (approx 41% -> 5 cols on xl) */}
        <div className="lg:col-span-4 xl:col-span-5 flex flex-col justify-between space-y-3 h-full">
          <GlobalThreatHeatmap alerts={alerts} onSelectAlert={onSelectAlert} />
          <TopActiveThreatsTable alerts={alerts} onSelectAlert={onSelectAlert} className="flex-1" />
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <IncidentStatusChart
              distribution={incidentDistribution}
              total={overview?.openIncidents ? overview.openIncidents + 1 : 3}
              className="h-full"
            />
            <AssetsAtRiskTable assets={assets} className="h-full" />
          </div>
        </div>

        {/* Right Alerts and Insights Column (approx 33% -> 4 cols on xl) */}
        <div className="lg:col-span-4 xl:col-span-4 flex flex-col justify-between space-y-3 h-full">
          <RecentCriticalAlerts
            alerts={alerts}
            onSelectAlert={onSelectAlert}
            onViewAllAlerts={onViewAllAlerts}
            className="flex-1"
          />
          <AiAnalysisInsights className="flex-1" />
          <ThreatIntelligenceFeed items={threatIntel} className="flex-1" />
        </div>
      </div>

      {/* 3. Bottom Panels: Recent Activity (Left) and Attack Chain Overview (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 pt-1">
        <div className="lg:col-span-7 xl:col-span-7">
          <RecentActivityTable logs={activityLogs} />
        </div>
        <div className="lg:col-span-5 xl:col-span-5">
          <AttackChainOverview onOpenAttackPath={onOpenAttackPath} />
        </div>
      </div>
    </div>
  );
};
