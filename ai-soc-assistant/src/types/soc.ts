export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export type ThreatCategory = 
  | 'BENIGN' 
  | 'DoS' 
  | 'DDoS' 
  | 'PortScan' 
  | 'BruteForce' 
  | 'Bot' 
  | 'WebAttack';

export type AlertStatus = 'New' | 'Investigating' | 'Escalated' | 'False Positive' | 'Resolved';

export interface PacketFeatures {
  flowDuration: number;
  totFwdPkts: number;
  totBwdPkts: number;
  totLenFwdPkts: number;
  totLenBwdPkts: number;
  flowBytsPerSec: number;
  flowPktsPerSec: number;
  fwdPktLenMean: number;
  bwdPktLenMean: number;
  flowIatMean: number;
  synFlagCnt: number;
  rstFlagCnt: number;
  ackFlagCnt: number;
  pshFlagCnt: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  srcPort: number;
  dstPort: number;
}

export interface Alert {
  id: string;
  timestamp: string;
  title: string;
  sourceIp: string;
  destIp: string;
  sourcePort: number;
  destPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  predictedCategory: ThreatCategory;
  groundTruthCategory: ThreatCategory;
  confidence: number; // 0.0 - 1.0
  severity: Severity;
  evidence: string[];
  explanation: string;
  recommendation: string;
  status: AlertStatus;
  incidentId?: string;
  packetFeatures: PacketFeatures;
}

export type IncidentStatus = 'New' | 'In Progress' | 'On Hold' | 'Resolved';

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  assignedTo: string;
  createdAt: string;
  updatedAt: string;
  resolvedAt?: string;
  linkedAlertIds: string[];
  notes: Array<{
    id: string;
    timestamp: string;
    author: string;
    content: string;
  }>;
  responseDurationMinutes?: number;
}

export interface Asset {
  id: string;
  name: string;
  ip: string;
  role: string;
  os: string;
  criticality: 'Mission Critical' | 'High' | 'Medium' | 'Low';
  riskScore: number; // 0 - 100
  previousRiskScore: number;
  openAlertsCount: number;
  vulnerabilitiesCount: number;
  lastScanned: string;
}

export interface Vulnerability {
  id: string;
  cve: string;
  title: string;
  cvss: number; // 0.0 - 10.0
  severity: Severity;
  affectedAssets: string[];
  remediation: string;
  publishedDate: string;
  verified: boolean;
}

export interface ThreatIntelItem {
  id: string;
  title: string;
  indicator: string;
  indicatorType: 'IP' | 'Domain' | 'Hash' | 'CVE';
  source: string;
  confidence: number;
  timestamp: string;
  mitreTactic: string;
  description: string;
}

export interface ActivityLog {
  id: string;
  timestamp: string;
  event: string;
  source: string;
  target: string;
  severity: Severity;
  details: string;
}

export interface AttackChainStage {
  stageNumber: number;
  name: string;
  technique: string;
  mitreId: string;
  status: 'Detected' | 'Active' | 'Mitigated' | 'Monitored';
  severity: Severity;
  description: string;
  evidenceAlertId?: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'Workstation' | 'Server' | 'Firewall' | 'DomainController' | 'Database' | 'CloudGateway' | 'Router';
  ip: string;
  riskScore: number;
  cvssMax: number;
  isCompromised: boolean;
  isTarget: boolean;
  x?: number;
  y?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  protocol: string;
  port: number;
  cost: number; // For A* search
  bandwidth: string;
  isObservedFlow: boolean;
}

export interface AlgorithmResult {
  algorithm: 'BFS' | 'DFS' | 'Greedy Best-First' | 'A*';
  path: string[];
  visitedNodes: string[];
  totalExplored: number;
  totalCost: number;
  pathLength: number;
  executionTimeMs: number;
  found: boolean;
  explanation: string;
}

export interface ClassMetrics {
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface ModelMetrics {
  accuracy: number;
  macroPrecision: number;
  macroRecall: number;
  macroF1: number;
  weightedF1: number;
  confusionMatrix: number[][]; // 7x7 matrix
  classNames: ThreatCategory[];
  classReport: Record<ThreatCategory, ClassMetrics>;
  featureImportances: Array<{ feature: string; importance: number }>;
  totalSamples: number;
  trainSamples: number;
  testSamples: number;
  lastTrainedAt: string;
  modelType: string;
}

export interface DashboardOverview {
  totalAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  openIncidents: number;
  mttrMinutes: number | null;
  assetsAtRisk: number;
  systemStatus: {
    backend: 'connected' | 'degraded' | 'disconnected';
    backendType: 'express-local' | 'fastapi-python';
    model: 'trained' | 'stale' | 'not_trained';
    dataset: 'loaded_5000' | 'empty';
    lastUpdate: string;
  };
}

export interface EndpointSensor {
  id: string;
  hostname: string;
  ip: string;
  agent: string;
  version: string;
  os: string;
  status: 'Online' | 'Quarantined' | 'Offline';
  cpuUsage: number;
  ramUsage: number;
  activeAlerts: number;
  lastHeartbeat: string;
  criticality: 'Mission Critical' | 'High' | 'Medium' | 'Low';
  processes: Array<{ pid: number; name: string; user: string; status: 'Running' | 'Suspicious' | 'Terminated'; command: string }>;
}

export interface IdentityUser {
  id: string;
  username: string;
  displayName: string;
  email: string;
  department: string;
  role: string;
  mfaEnabled: boolean;
  riskScore: number;
  status: 'Active' | 'Locked' | 'Suspended';
  lastLogin: string;
  lastLocation: string;
  failedLogins24h: number;
  anomalousEvents: string[];
}

export interface CloudResource {
  id: string;
  provider: 'AWS' | 'Azure' | 'GCP';
  service: string;
  name: string;
  region: string;
  complianceScore: number;
  status: 'Secure' | 'At Risk' | 'Critical';
  publicExposed: boolean;
  findingsCount: number;
  findings: string[];
}

export type FlowRecord = {
  id: string;
  label: ThreatCategory;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  protocol_num: number;
  flow_duration: number;
  tot_fwd_pkts: number;
  tot_bwd_pkts: number;
  tot_len_fwd_pkts: number;
  tot_len_bwd_pkts: number;
  flow_byts_s: number;
  flow_pkts_s: number;
  fwd_pkt_len_mean: number;
  bwd_pkt_len_mean: number;
  flow_iat_mean: number;
  syn_flag_cnt: number;
  rst_flag_cnt: number;
  ack_flag_cnt: number;
  psh_flag_cnt: number;
  category?: ThreatCategory;
  isAnomaly?: boolean;
};

export interface EmailThreat {
  id: string;
  timestamp: string;
  sender: string;
  recipient: string;
  subject: string;
  verdict: 'Malicious' | 'Phishing' | 'Suspicious' | 'Clean';
  quarantined: boolean;
  spf: 'Pass' | 'Fail' | 'SoftFail' | string;
  dkim: 'Pass' | 'Fail' | string;
  dmarc: 'Pass' | 'Fail' | string;
  attachments: string[];
  threatDetails: string;
}

export interface AutomationPlaybook {
  id: string;
  name: string;
  category: 'Containment' | 'Investigation' | 'Eradication' | 'Enrichment';
  description: string;
  target: string;
  action: string;
  trigger: string;
  lastRun?: string;
  runStatus: 'Ready' | 'Running' | 'Success' | 'Failed';
  steps: Array<{ stepNumber: number; title: string; status: 'Pending' | 'Completed' | 'Running' }>;
}

export interface CaseTicket {
  id: string;
  title: string;
  severity: Severity;
  status: 'Open' | 'Under Investigation' | 'Pending Review' | 'Closed';
  priority: 'P1 - Urgent' | 'P2 - High' | 'P3 - Medium' | 'P4 - Low';
  assignedTo: string;
  createdAt: string;
  updatedAt: string;
  summary: string;
  evidenceItems: string[];
  linkedAlertIds: string[];
  linkedIncidentIds: string[];
  mitreTactics: string[];
  notes: Array<{ id: string; author: string; timestamp: string; text: string }>;
}

export interface DatasetPreset {
  id: string;
  name: string;
  description: string;
  totalRecords: number;
  distribution: Record<ThreatCategory, number>;
}

export interface SubnetCartography {
  id: string;
  name: string;
  cidr: string;
  gateway: string;
  totalHosts: number;
  liveHosts: number;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  primaryRole: string;
  exposedServices: string[];
}

export interface NetworkProtocolStats {
  protocol: string;
  port: number;
  service: string;
  bytesTransferred: number;
  packetCount: number;
  percentage: number;
  threatCount: number;
  status: 'Normal' | 'Elevated' | 'Anomalous';
}

export interface NetworkAnomalySignal {
  id: string;
  type: string;
  severity: Severity;
  detectedAt: string;
  sourceIp: string;
  destIp: string;
  description: string;
  evidence: string;
  recommendedMitigation: string;
}

export interface LivePacketFlow {
  id: string;
  timestamp: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  length: number;
  flags: string[];
  payloadPreview: string;
  detectedCategory: ThreatCategory;
  confidence: number;
  severity: Severity;
  actionTaken: 'Allowed' | 'Inspected' | 'Blocked' | 'Alerted';
}

export interface NetworkIntelligence {
  resilienceScore: number; // 0 - 100
  totalBandwidthMbps: number;
  packetsPerSecond: number;
  totalActiveHosts: number;
  subnets: SubnetCartography[];
  protocols: NetworkProtocolStats[];
  anomalies: NetworkAnomalySignal[];
  recentFlows: LivePacketFlow[];
  postureAssessment: {
    perimeterSecurity: number;
    lateralMovementResistance: number;
    credentialResilience: number;
    criticalFindings: string[];
    recommendedAcls: string[];
  };
}

export interface SecurityCenterConnector {
  id: string;
  name: string;
  type: 'syslog' | 'splunk_hec' | 'zeek_ids' | 'suricata_eve' | 'aws_guardduty' | 'elastic_siem';
  description: string;
  status: 'connected' | 'listening' | 'idle' | 'simulated_live';
  endpoint: string;
  port: number;
  protocol: 'UDP' | 'TCP' | 'HTTPS' | 'TLS';
  eventsIngested: number;
  threatsDetected: number;
  lastEventTime: string;
  latencyMs: number;
}

export type DatasetWorkflowMode = 'train' | 'evaluate' | 'infer' | 'explore';

export interface DatasetValidationReport {
  fileName: string;
  fileSizeBytes: number;
  detectedSchema: 'CIC-IDS2017' | 'Zeek conn.log' | 'Suricata EVE-JSON' | 'Standard NetFlow CSV' | 'Custom CSV' | 'Unknown';
  recordsTotal: number;
  recordsAccepted: number;
  recordsRejected: number;
  recordsDuplicate: number;
  missingFieldWarnings: string[];
  validationWarnings: string[];
  detectedLabels: string[];
  hasGroundTruth: boolean;
  timeRange: { start: string; end: string } | null;
  workflowMode: DatasetWorkflowMode;
  modelPreserved: boolean;
  evaluationMetrics?: ModelMetrics;
  diagnosticNotes: string[];
}

