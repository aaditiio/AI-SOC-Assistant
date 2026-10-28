/**
 * AI SOC Assistant - Primary Application Root
 * Intelligent Cyber Threat Detection, Alert Prioritization and Attack Path Analysis System
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, NavTab } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewPage } from './pages/OverviewPage';
import { DashboardsPage } from './pages/DashboardsPage';
import { AlertsPage } from './pages/AlertsPage';
import { NetworkGraphPage } from './pages/NetworkGraphPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { ModelManagementPage } from './pages/ModelManagementPage';
import { AssetsPage } from './pages/AssetsPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';
import { CloudPage } from './pages/CloudPage';
import { EndpointsPage } from './pages/EndpointsPage';
import { EmailPage } from './pages/EmailPage';
import { AutomationPage } from './pages/AutomationPage';
import { ReportsPage } from './pages/ReportsPage';
import { IdentityPage } from './pages/IdentityPage';
import { CasesPage } from './pages/CasesPage';
import { ApiExplorerPage } from './pages/ApiExplorerPage';
import { AlertInvestigationDrawer } from './components/alerts/AlertInvestigationDrawer';
import { HelpModal } from './components/common/HelpModal';
import { DatasetUploadModal } from './components/datacenter/DatasetUploadModal';
import { SecurityCenterConnectModal } from './components/datacenter/SecurityCenterConnectModal';

import {
  Alert,
  Incident,
  Asset,
  Vulnerability,
  ThreatIntelItem,
  ActivityLog,
  DashboardOverview,
  ModelMetrics,
  Severity,
  CloudResource,
  EmailThreat
} from './types/soc';

import { socApi, BackendMode } from './services/api';
import { CheckCircle2, ShieldAlert } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('Overview');
  const [backendMode, setBackendMode] = useState<BackendMode>('aistudio');

  // Application Data States
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelItem[]>([]);
  const [activityLogs, setActivityLogs] = useState<ActivityLog[]>([]);
  const [severityDist, setSeverityDist] = useState<Array<{ severity: Severity; count: number; percentage: number }>>([]);
  const [incidentDist, setIncidentDist] = useState<Array<{ status: string; count: number; percentage: number }>>([]);
  const [alertsOverTime, setAlertsOverTime] = useState<any[]>([]);
  const [modelMetrics, setModelMetrics] = useState<ModelMetrics | null>(null);
  const [cloudResources, setCloudResources] = useState<CloudResource[]>([]);

  // Modals & Drawers
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [isHelpModalOpen, setIsHelpModalOpen] = useState<boolean>(false);
  const [isDatasetModalOpen, setIsDatasetModalOpen] = useState<boolean>(false);
  const [isSecurityCenterModalOpen, setIsSecurityCenterModalOpen] = useState<boolean>(false);
  const [simulationToast, setSimulationToast] = useState<string | null>(null);

  // Load all data
  const loadData = useCallback(async () => {
    try {
      const [
        ov,
        alts,
        incs,
        asts,
        vulns,
        intel,
        logs,
        sev,
        incD,
        aot,
        metrics,
        cld
      ] = await Promise.all([
        socApi.getDashboardOverview(),
        socApi.getAlerts(),
        socApi.getIncidents(),
        socApi.getAssets(),
        socApi.getVulnerabilities(),
        socApi.getThreatIntel(),
        socApi.getActivityLogs(),
        socApi.getAlertsBySeverity(),
        socApi.getIncidentStatus(),
        socApi.getAlertsOverTime(),
        socApi.getModelMetrics(),
        socApi.getCloudResources()
      ]);

      setOverview(ov);
      setAlerts(alts);
      setIncidents(incs);
      setAssets(asts);
      setVulnerabilities(vulns);
      setThreatIntel(intel);
      setActivityLogs(logs);
      setSeverityDist(sev.distribution);
      setIncidentDist(incD.distribution);
      setAlertsOverTime(aot.data);
      setModelMetrics(metrics);
      setCloudResources(cld);
    } catch (err) {
      console.error('Failed to load SOC telemetry:', err);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle Backend Mode switch
  const handleToggleBackend = async (mode: BackendMode) => {
    setBackendMode(mode);
    socApi.setBackendMode(mode);
    if (mode === 'fastapi') {
      const isOnline = await socApi.checkFastApiHealth();
      if (!isOnline) {
        setSimulationToast('FastAPI port 8000 is offline. Instructions in backend/README.md. Running Express mode.');
        setTimeout(() => setSimulationToast(null), 5000);
      } else {
        setSimulationToast('Successfully connected to local Python FastAPI backend at http://127.0.0.1:8000.');
        setTimeout(() => setSimulationToast(null), 4000);
      }
    }
    loadData();
  };

  // Handle Alert Selection
  const handleSelectAlert = (id: string) => {
    setSelectedAlertId(id);
  };

  // Handle Alert Status Update
  const handleUpdateAlertStatus = async (alertId: string, status: Alert['status']) => {
    await socApi.updateAlertStatus(alertId, status);
    loadData();
  };

  // Handle Alert Escalation to Incident
  const handleEscalateToIncident = async (alert: Alert) => {
    await socApi.createIncident({
      title: `Escalated Incident: ${alert.title}`,
      severity: alert.severity,
      assignedTo: 'Lead Analyst Prachi',
      linkedAlertIds: [alert.id],
      initialNote: `Auto-escalated from alert ${alert.id} due to high confidence classification (${(alert.confidence * 100).toFixed(1)}%).`
    });
    setSelectedAlertId(null);
    setSimulationToast(`Alert ${alert.id} escalated to Incident.`);
    setTimeout(() => setSimulationToast(null), 4000);
    loadData();
  };

  // Handle Injecting Live Synthetic Flow Packet
  const handleSimulatePacket = () => {
    const newAlert = socApi.generateSyntheticAlert();
    setSimulationToast(`Live Threat Injected: [${newAlert.id}] ${newAlert.title} (${newAlert.predictedCategory})`);
    setTimeout(() => setSimulationToast(null), 4000);
    loadData();
  };

  // Handle Retrain Model
  const handleRetrainModel = async () => {
    const metrics = await socApi.trainModel();
    setModelMetrics(metrics);
    setSimulationToast(`Random Forest Retrained: Accuracy ${(metrics.accuracy * 100).toFixed(2)}% on 5,000 samples.`);
    setTimeout(() => setSimulationToast(null), 4000);
    loadData();
  };

  const selectedAlert = alerts.find(a => a.id === selectedAlertId) || null;

  return (
    <div className="flex min-h-screen bg-[#070b14] text-slate-100 font-sans">
      {/* 1. Fixed Left Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        overview={overview}
        onOpenModelModal={() => setActiveTab('Settings')}
        onOpenDatasetModal={() => setIsDatasetModalOpen(true)}
        onOpenSecurityCenterModal={() => setIsSecurityCenterModalOpen(true)}
      />

      {/* 2. Main Work Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Header */}
        <Header
          activeTab={activeTab}
          onSimulatePacket={handleSimulatePacket}
          onRefreshData={loadData}
          onOpenHelpModal={() => setIsHelpModalOpen(true)}
          onOpenDatasetModal={() => setIsDatasetModalOpen(true)}
          onOpenSecurityCenterModal={() => setIsSecurityCenterModalOpen(true)}
          backendMode={backendMode}
          onToggleBackendMode={handleToggleBackend}
          unreadCount={alerts.filter(a => a.status === 'New').length}
        />

        {/* Live Notification Banner */}
        {simulationToast && (
          <div className="bg-cyan-950/90 border-b border-cyan-500/40 px-5 py-2 flex items-center justify-between text-xs font-mono text-cyan-300 animate-in fade-in slide-in-from-top-1">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span>{simulationToast}</span>
            </div>
            <button
              onClick={() => setSimulationToast(null)}
              className="text-slate-400 hover:text-white text-[10px]"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Active Page Body */}
        <main className="flex-1 pb-8">
          {activeTab === 'Overview' && (
            <OverviewPage
              overview={overview}
              alerts={alerts}
              assets={assets}
              vulnerabilities={vulnerabilities}
              threatIntel={threatIntel}
              activityLogs={activityLogs}
              severityDistribution={severityDist}
              incidentDistribution={incidentDist}
              alertsOverTimeData={alertsOverTime}
              onSelectAlert={handleSelectAlert}
              onViewAllAlerts={() => setActiveTab('Alerts')}
              onOpenAttackPath={() => setActiveTab('Network')}
            />
          )}

          {activeTab === 'Dashboards' && (
            <DashboardsPage
              overview={overview}
              alerts={alerts}
              incidents={incidents}
              onRefreshData={loadData}
            />
          )}

          {activeTab === 'Alerts' && (
            <AlertsPage
              alerts={alerts}
              onSelectAlert={handleSelectAlert}
              onSimulateAlert={handleSimulatePacket}
            />
          )}

          {activeTab === 'Incidents' && (
            <IncidentsPage
              incidents={incidents}
              alerts={alerts}
              onCreateIncident={socApi.createIncident.bind(socApi)}
              onUpdateIncident={socApi.updateIncident.bind(socApi)}
            />
          )}

          {activeTab === 'Threat Intelligence' && (
            <ThreatIntelligencePage items={threatIntel} />
          )}

          {activeTab === 'Vulnerabilities' && (
            <VulnerabilitiesPage vulnerabilities={vulnerabilities} />
          )}

          {activeTab === 'Assets' && (
            <AssetsPage assets={assets} />
          )}

          {activeTab === 'Cloud' && (
            <CloudPage resources={cloudResources} />
          )}

          {activeTab === 'Endpoints' && (
            <EndpointsPage />
          )}

          {activeTab === 'Network' && (
            <NetworkGraphPage />
          )}

          {activeTab === 'Email' && (
            <EmailPage />
          )}

          {activeTab === 'Identity' && (
            <IdentityPage onRefreshData={loadData} />
          )}

          {activeTab === 'Automation' && (
            <AutomationPage />
          )}

          {activeTab === 'Reports' && (
            <ReportsPage />
          )}

          {activeTab === 'Cases' && (
            <CasesPage onRefreshData={loadData} />
          )}

          {activeTab === 'API Gateway' && (
            <ApiExplorerPage />
          )}

          {activeTab === 'Settings' && modelMetrics && (
            <ModelManagementPage
              metrics={modelMetrics}
              onRetrainModel={handleRetrainModel}
            />
          )}
        </main>
      </div>

      {/* Alert Investigation Drawer */}
      <AlertInvestigationDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlertId(null)}
        onUpdateStatus={handleUpdateAlertStatus}
        onEscalateToIncident={handleEscalateToIncident}
      />

      {/* Help / Thesis Defense Modal */}
      <HelpModal
        isOpen={isHelpModalOpen}
        onClose={() => setIsHelpModalOpen(false)}
      />

      {/* Dynamic Dataset Upload & Retraining Modal */}
      <DatasetUploadModal
        isOpen={isDatasetModalOpen}
        onClose={() => setIsDatasetModalOpen(false)}
        onDatasetUpdated={loadData}
        currentMetrics={modelMetrics}
      />

      {/* Real-World Security Center Connect & Network Flow Inspector Modal */}
      <SecurityCenterConnectModal
        isOpen={isSecurityCenterModalOpen}
        onClose={() => setIsSecurityCenterModalOpen(false)}
        onRefreshData={loadData}
      />
    </div>
  );
}
