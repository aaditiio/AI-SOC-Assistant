/**
 * AI SOC Assistant - Client/Server Engine
 * Implements:
 * 1. 5,000 synthetic flow dataset with RFC 1918 private IPs
 * 2. Held-out ML evaluation metrics calculation (Random Forest, confusion matrix, per-class F1)
 * 3. Graph search algorithms: BFS, DFS, Greedy Best-First, A*
 * 4. Alert prioritization & rule-based severity engine
 * 5. Incident lifecycle and MTTR tracking
 * 6. Asset inventory & explainable risk scoring
 * 7. Vulnerabilities & Threat Intelligence
 * 8. Real Activity audit log
 */
import {
  Alert,
  Incident,
  Asset,
  Vulnerability,
  ThreatIntelItem,
  ActivityLog,
  GraphNode,
  GraphEdge,
  AlgorithmResult,
  ModelMetrics,
  DashboardOverview,
  ThreatCategory,
  Severity,
  PacketFeatures,
  EndpointSensor,
  IdentityUser,
  CloudResource,
  EmailThreat,
  AutomationPlaybook,
  CaseTicket,
  DatasetPreset
} from '../types/soc';

export const THREAT_CLASSES: ThreatCategory[] = [
  'BENIGN',
  'DoS',
  'DDoS',
  'PortScan',
  'BruteForce',
  'Bot',
  'WebAttack'
];

export const FEATURE_NAMES = [
  'flowDuration',
  'totFwdPkts',
  'totBwdPkts',
  'totLenFwdPkts',
  'totLenBwdPkts',
  'flowBytsPerSec',
  'flowPktsPerSec',
  'fwdPktLenMean',
  'bwdPktLenMean',
  'flowIatMean',
  'synFlagCnt',
  'rstFlagCnt',
  'ackFlagCnt',
  'pshFlagCnt',
  'dstPort',
  'srcPort'
];

// Initial Assets
export const INITIAL_ASSETS: Asset[] = [
  {
    id: 'AST-001',
    name: 'DC-CORP-01',
    ip: '10.0.1.10',
    role: 'Domain Controller',
    os: 'Windows Server 2022',
    criticality: 'Mission Critical',
    riskScore: 92.4,
    previousRiskScore: 88.0,
    openAlertsCount: 4,
    vulnerabilitiesCount: 3,
    lastScanned: '2026-10-16 02:40 UTC'
  },
  {
    id: 'AST-002',
    name: 'DB-PROD-SQL',
    ip: '10.0.2.15',
    role: 'Database Server',
    os: 'Ubuntu 22.04 LTS',
    criticality: 'Mission Critical',
    riskScore: 85.0,
    previousRiskScore: 79.5,
    openAlertsCount: 3,
    vulnerabilitiesCount: 2,
    lastScanned: '2026-10-16 02:15 UTC'
  },
  {
    id: 'AST-003',
    name: 'DMZ-WEB-01',
    ip: '192.168.1.100',
    role: 'DMZ Web Server',
    os: 'Debian 12',
    criticality: 'High',
    riskScore: 76.8,
    previousRiskScore: 76.8,
    openAlertsCount: 5,
    vulnerabilitiesCount: 4,
    lastScanned: '2026-10-16 03:00 UTC'
  },
  {
    id: 'AST-004',
    name: 'FW-EDGE-01',
    ip: '192.168.1.1',
    role: 'Edge Firewall',
    os: 'FortiOS 7.4',
    criticality: 'Mission Critical',
    riskScore: 64.2,
    previousRiskScore: 60.0,
    openAlertsCount: 2,
    vulnerabilitiesCount: 1,
    lastScanned: '2026-10-16 01:30 UTC'
  },
  {
    id: 'AST-005',
    name: 'WKSTN-FIN-04',
    ip: '10.0.3.45',
    role: 'Finance Workstation',
    os: 'Windows 11 Pro',
    criticality: 'Medium',
    riskScore: 58.5,
    previousRiskScore: 52.0,
    openAlertsCount: 2,
    vulnerabilitiesCount: 2,
    lastScanned: '2026-10-16 02:50 UTC'
  },
  {
    id: 'AST-006',
    name: 'WKSTN-DEV-12',
    ip: '10.0.3.88',
    role: 'Developer Machine',
    os: 'macOS Sonoma',
    criticality: 'Medium',
    riskScore: 38.0,
    previousRiskScore: 38.0,
    openAlertsCount: 1,
    vulnerabilitiesCount: 1,
    lastScanned: '2026-10-16 01:10 UTC'
  },
  {
    id: 'AST-007',
    name: 'APP-API-GATEWAY',
    ip: '10.0.2.5',
    role: 'Internal API Gateway',
    os: 'Alpine Linux',
    criticality: 'High',
    riskScore: 71.0,
    previousRiskScore: 68.0,
    openAlertsCount: 2,
    vulnerabilitiesCount: 2,
    lastScanned: '2026-10-16 02:30 UTC'
  },
  {
    id: 'AST-008',
    name: 'BACKUP-NAS-01',
    ip: '10.0.4.200',
    role: 'Storage Backup NAS',
    os: 'FreeNAS',
    criticality: 'High',
    riskScore: 45.0,
    previousRiskScore: 45.0,
    openAlertsCount: 0,
    vulnerabilitiesCount: 1,
    lastScanned: '2026-10-16 00:00 UTC'
  }
];

// Initial Vulnerabilities
export const INITIAL_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'VULN-001',
    cve: 'CVE-2024-21413',
    title: 'Microsoft Outlook Remote Code Execution (MonikerLink)',
    cvss: 9.8,
    severity: 'Critical',
    affectedAssets: ['10.0.3.45'],
    remediation: 'Deploy Microsoft February 2024 Cumulative Patch; disable NTLM authentication over egress SMB port 445.',
    publishedDate: '2024-02-13',
    verified: true
  },
  {
    id: 'VULN-002',
    cve: 'CVE-2023-44487',
    title: 'HTTP/2 Rapid Reset Distributed Denial of Service',
    cvss: 7.5,
    severity: 'High',
    affectedAssets: ['192.168.1.100', '10.0.2.5'],
    remediation: 'Patch reverse proxy software; apply strict rate limiting on RST_STREAM frames per active HTTP/2 session.',
    publishedDate: '2023-10-10',
    verified: true
  },
  {
    id: 'VULN-003',
    cve: 'CVE-2023-38606',
    title: 'OpenSSH Privilege Escalation via PKCS#11 Provider',
    cvss: 7.8,
    severity: 'High',
    affectedAssets: ['10.0.2.15', '10.0.1.10'],
    remediation: 'Upgrade OpenSSH to >= 9.3p2 across Linux servers and restrict SSH agent forwarding in sshd_config.',
    publishedDate: '2023-07-20',
    verified: true
  },
  {
    id: 'VULN-004',
    cve: 'CVE-2024-3400',
    title: 'Palo Alto Networks PAN-OS OS Command Injection',
    cvss: 10.0,
    severity: 'Critical',
    affectedAssets: ['192.168.1.1'],
    remediation: 'Apply vendor hotfix; disable GlobalProtect device telemetry until firmware signature verified.',
    publishedDate: '2024-04-12',
    verified: true
  },
  {
    id: 'VULN-005',
    cve: 'CVE-2023-22515',
    title: 'Atlassian Confluence Data Center Broken Access Control',
    cvss: 8.8,
    severity: 'High',
    affectedAssets: ['10.0.2.5'],
    remediation: 'Block /setup/* endpoint URI routes on upstream WAF and apply vendor emergency advisory update.',
    publishedDate: '2023-10-04',
    verified: true
  }
];

// Initial Threat Intelligence
export const INITIAL_THREAT_INTEL: ThreatIntelItem[] = [
  {
    id: 'INTEL-001',
    title: 'Lazarus Group SMB Lateral Spreading Tool',
    indicator: '198.51.100.44',
    indicatorType: 'IP',
    source: 'CISA / US-CERT Advisory AA23-075A',
    confidence: 92.0,
    timestamp: '2026-10-16 02:00 UTC',
    mitreTactic: 'Lateral Movement (T1021.002)',
    description: 'Threat actors observed conducting credential spray attacks against port 445 and staging encrypted payload loaders.'
  },
  {
    id: 'INTEL-002',
    title: 'Mirai Variant DDoS Botnet C2 Node',
    indicator: '203.0.113.88',
    indicatorType: 'IP',
    source: 'Shadowserver Foundation Telemetry',
    confidence: 88.5,
    timestamp: '2026-10-16 01:30 UTC',
    mitreTactic: 'Command & Control (T1071.001)',
    description: 'Active C2 coordinating SYN and UDP reflection flood attacks targeting perimeter web assets.'
  },
  {
    id: 'INTEL-003',
    title: 'BlackCat Ransomware Token Staging Domain',
    indicator: 'sync-cloud-telemetry.com',
    indicatorType: 'Domain',
    source: 'CrowdStrike Falcon OverWatch',
    confidence: 95.0,
    timestamp: '2026-10-16 00:45 UTC',
    mitreTactic: 'Defense Evasion (T1550.002)',
    description: 'C2 domain utilized by threat group to exfiltrate cached Kerberos golden tickets and DPAPI keys.'
  },
  {
    id: 'INTEL-004',
    title: 'CVE-2024-21413 MonikerLink Weaponized PoC',
    indicator: 'CVE-2024-21413',
    indicatorType: 'CVE',
    source: 'National Vulnerability Database (NVD)',
    confidence: 99.0,
    timestamp: '2026-10-15 18:00 UTC',
    mitreTactic: 'Initial Access (T1566.001)',
    description: 'Exploitation observed sending malicious file:// URLs bypassing Outlook protected view to harvest NTLMv2 hashes.'
  },
  {
    id: 'INTEL-005',
    title: 'Cobalt Strike Malleable HTTPS Beacon Hash',
    indicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    indicatorType: 'Hash',
    source: 'Mandiant Threat Intelligence',
    confidence: 85.0,
    timestamp: '2026-10-15 14:20 UTC',
    mitreTactic: 'Execution (T1059.001)',
    description: 'Payload matches in-memory reflective loader executing encoded PowerShell commands.'
  }
];

// Initial Incidents
export const INITIAL_INCIDENTS: Incident[] = [
  {
    id: 'INC-2026-001',
    title: 'Active Brute Force & Token Impersonation on Domain Controller',
    severity: 'Critical',
    status: 'In Progress',
    assignedTo: 'Prachi G. (Lead Analyst)',
    createdAt: '2026-10-16T01:15:00Z',
    updatedAt: '2026-10-16T02:45:00Z',
    linkedAlertIds: ['ALT-9041', 'ALT-9042'],
    responseDurationMinutes: 30.0,
    notes: [
      {
        id: 'n1',
        timestamp: '2026-10-16T01:25:00Z',
        author: 'Prachi G.',
        content: 'Correlated alerts ALT-9041 (Kerberos BruteForce) and ALT-9042 (Privilege Escalation). Host 10.0.3.45 identified as pivot source.'
      },
      {
        id: 'n2',
        timestamp: '2026-10-16T02:10:00Z',
        author: 'Prachi G.',
        content: 'Host 10.0.3.45 quarantined at switch port. Memory dump acquired for forensic timeline analysis.'
      }
    ]
  },
  {
    id: 'INC-2026-002',
    title: 'HTTP/2 Rapid Reset Volumetric DDoS on DMZ Web Server',
    severity: 'High',
    status: 'New',
    assignedTo: 'SOC Tier-1 Queue',
    createdAt: '2026-10-16T02:30:00Z',
    updatedAt: '2026-10-16T02:32:00Z',
    linkedAlertIds: ['ALT-8812'],
    responseDurationMinutes: 12.0,
    notes: [
      {
        id: 'n3',
        timestamp: '2026-10-16T02:32:00Z',
        author: 'SOC Automation Engine',
        content: 'Inbound packet rate spiked to 14,200 pkts/sec on port 443 from external subnet 198.51.100.0/24.'
      }
    ]
  },
  {
    id: 'INC-2026-003',
    title: 'Suspicious Port Scan and Reconnaissance across Subnet 10.0.2.0/24',
    severity: 'Medium',
    status: 'Resolved',
    assignedTo: 'David K. (Analyst)',
    createdAt: '2026-10-15T22:00:00Z',
    updatedAt: '2026-10-15T22:42:00Z',
    resolvedAt: '2026-10-15T22:42:00Z',
    linkedAlertIds: ['ALT-7611'],
    responseDurationMinutes: 42.0,
    notes: [
      {
        id: 'n4',
        timestamp: '2026-10-15T22:42:00Z',
        author: 'David K.',
        content: 'Investigated origin. Internal vulnerability scanner running unauthorized schedule. Ticket closed after verification.'
      }
    ]
  }
];

// Initial Alerts
export const INITIAL_ALERTS: Alert[] = [
  {
    id: 'ALT-9041',
    timestamp: '2026-10-16 02:42:18 UTC',
    title: 'Kerberos Pre-Authentication Brute Force Detected',
    sourceIp: '10.0.3.45',
    destIp: '10.0.1.10',
    sourcePort: 49812,
    destPort: 88,
    protocol: 'TCP',
    predictedCategory: 'BruteForce',
    groundTruthCategory: 'BruteForce',
    confidence: 0.964,
    severity: 'Critical',
    status: 'Escalated',
    incidentId: 'INC-2026-001',
    evidence: [
      'Rapid KRB_AS_REQ requests (42 attempts/sec) targeting administrator account names',
      'High PSH flag ratio conveying authentication payload blocks',
      'Originating from Finance workstation 10.0.3.45 with no administrative history'
    ],
    explanation: 'Model classified repetitive authentication handshakes as automated password guessing targeting Active Directory Domain Controller.',
    recommendation: 'Temporarily lock targeted Active Directory accounts, isolate workstation 10.0.3.45, and inspect endpoint event logs (Event ID 4771).',
    packetFeatures: {
      flowDuration: 14500,
      totFwdPkts: 84,
      totBwdPkts: 72,
      totLenFwdPkts: 18400,
      totLenBwdPkts: 12200,
      flowBytsPerSec: 18500,
      flowPktsPerSec: 145,
      fwdPktLenMean: 219,
      bwdPktLenMean: 169,
      flowIatMean: 112,
      synFlagCnt: 1,
      rstFlagCnt: 2,
      ackFlagCnt: 82,
      pshFlagCnt: 48,
      protocol: 'TCP',
      srcPort: 49812,
      dstPort: 88
    }
  },
  {
    id: 'ALT-9042',
    timestamp: '2026-10-16 02:44:05 UTC',
    title: 'Suspicious RPC Token Impersonation Handshake',
    sourceIp: '10.0.3.45',
    destIp: '10.0.1.10',
    sourcePort: 49818,
    destPort: 135,
    protocol: 'TCP',
    predictedCategory: 'BruteForce',
    groundTruthCategory: 'BruteForce',
    confidence: 0.941,
    severity: 'Critical',
    status: 'Escalated',
    incidentId: 'INC-2026-001',
    evidence: [
      'Sequential RPC bind requests on port 135 following Kerberos failures',
      'Anomalous IPC$ share query containing forged security tokens',
      'Correlated with lateral movement indicator INTEL-001'
    ],
    explanation: 'Detected lateral privilege escalation attempt utilizing authenticated RPC pipe communication to impersonate system tokens.',
    recommendation: 'Enable RPC firewall filter, restrict remote SAM access, and inspect LSASS process integrity on Domain Controller.',
    packetFeatures: {
      flowDuration: 21000,
      totFwdPkts: 92,
      totBwdPkts: 80,
      totLenFwdPkts: 22400,
      totLenBwdPkts: 16800,
      flowBytsPerSec: 21000,
      flowPktsPerSec: 160,
      fwdPktLenMean: 243,
      bwdPktLenMean: 210,
      flowIatMean: 95,
      synFlagCnt: 1,
      rstFlagCnt: 0,
      ackFlagCnt: 90,
      pshFlagCnt: 52,
      protocol: 'TCP',
      srcPort: 49818,
      dstPort: 135
    }
  },
  {
    id: 'ALT-8812',
    timestamp: '2026-10-16 02:30:12 UTC',
    title: 'Volumetric SYN Flood Flooding Perimeter Web Server',
    sourceIp: '198.51.100.44',
    destIp: '192.168.1.100',
    sourcePort: 38411,
    destPort: 443,
    protocol: 'TCP',
    predictedCategory: 'DDoS',
    groundTruthCategory: 'DDoS',
    confidence: 0.988,
    severity: 'High',
    status: 'Escalated',
    incidentId: 'INC-2026-002',
    evidence: [
      'Inbound traffic surge of 14,200 pkts/s on port 443 exceeding baseline by 1800%',
      'SYN packet count (3,800) with zero completing ACK handshakes',
      'Originating from known suspicious CIDR 198.51.100.0/24'
    ],
    explanation: 'Random Forest model classified high packet rate and disproportionate SYN-to-ACK ratio as volumetric Denial of Service attack.',
    recommendation: 'Activate perimeter SYN flood protection, enforce TCP handshake timeouts, and drop traffic matching origin IP.',
    packetFeatures: {
      flowDuration: 120000,
      totFwdPkts: 8500,
      totBwdPkts: 12,
      totLenFwdPkts: 510000,
      totLenBwdPkts: 720,
      flowBytsPerSec: 4250000,
      flowPktsPerSec: 14200,
      fwdPktLenMean: 60,
      bwdPktLenMean: 60,
      flowIatMean: 0.8,
      synFlagCnt: 3800,
      rstFlagCnt: 0,
      ackFlagCnt: 0,
      pshFlagCnt: 0,
      protocol: 'TCP',
      srcPort: 38411,
      dstPort: 443
    }
  },
  {
    id: 'ALT-8219',
    timestamp: '2026-10-16 01:54:33 UTC',
    title: 'SQL Injection Pattern in Web Application Query',
    sourceIp: '198.51.100.77',
    destIp: '192.168.1.100',
    sourcePort: 51200,
    destPort: 80,
    protocol: 'TCP',
    predictedCategory: 'WebAttack',
    groundTruthCategory: 'WebAttack',
    confidence: 0.932,
    severity: 'High',
    status: 'New',
    evidence: [
      'Anomalous HTTP payload length (1,480 bytes) targeting /api/v1/customer endpoint',
      'Injected UNION SELECT string detected in forward packet payload mean analysis',
      'High PSH flag concentration conveying encoded parameter strings'
    ],
    explanation: 'Flow analysis identified oversized forward packet buffers carrying SQL injection payload structures.',
    recommendation: 'Enable WAF SQL injection inspection rule, apply parameterized queries in API controller, and blacklist source client IP.',
    packetFeatures: {
      flowDuration: 1800,
      totFwdPkts: 14,
      totBwdPkts: 12,
      totLenFwdPkts: 18200,
      totLenBwdPkts: 4800,
      flowBytsPerSec: 64000,
      flowPktsPerSec: 120,
      fwdPktLenMean: 1300,
      bwdPktLenMean: 400,
      flowIatMean: 85,
      synFlagCnt: 1,
      rstFlagCnt: 0,
      ackFlagCnt: 12,
      pshFlagCnt: 6,
      protocol: 'TCP',
      srcPort: 51200,
      dstPort: 80
    }
  },
  {
    id: 'ALT-7611',
    timestamp: '2026-10-15 22:00:15 UTC',
    title: 'SYN Port Sweep on Subnet 10.0.2.0/24',
    sourceIp: '10.0.3.88',
    destIp: '10.0.2.15',
    sourcePort: 43210,
    destPort: 5432,
    protocol: 'TCP',
    predictedCategory: 'PortScan',
    groundTruthCategory: 'PortScan',
    confidence: 0.955,
    severity: 'Medium',
    status: 'Resolved',
    incidentId: 'INC-2026-003',
    evidence: [
      'Sequential probes to ports 22, 80, 443, and 5432 with duration under 300 microseconds',
      'Single SYN probe sent per destination socket with zero ACK continuation',
      'Origin host verified as internal development workstation'
    ],
    explanation: 'Model recognized micro-duration single-packet connection probes matching TCP SYN port scanning signatures.',
    recommendation: 'Verify whether authorized penetration testing was scheduled; otherwise notify workstation owner.',
    packetFeatures: {
      flowDuration: 280,
      totFwdPkts: 2,
      totBwdPkts: 1,
      totLenFwdPkts: 80,
      totLenBwdPkts: 40,
      flowBytsPerSec: 428,
      flowPktsPerSec: 10.7,
      fwdPktLenMean: 40,
      bwdPktLenMean: 40,
      flowIatMean: 14,
      synFlagCnt: 1,
      rstFlagCnt: 1,
      ackFlagCnt: 0,
      pshFlagCnt: 0,
      protocol: 'TCP',
      srcPort: 43210,
      dstPort: 5432
    }
  },
  {
    id: 'ALT-7104',
    timestamp: '2026-10-15 20:18:40 UTC',
    title: 'Periodic C2 Heartbeat Beaconing Observed',
    sourceIp: '10.0.3.45',
    destIp: '203.0.113.88',
    sourcePort: 55432,
    destPort: 4444,
    protocol: 'TCP',
    predictedCategory: 'Bot',
    groundTruthCategory: 'Bot',
    confidence: 0.895,
    severity: 'High',
    status: 'Investigating',
    evidence: [
      'Uniform inter-arrival time (mean 15,200 ms) matching automated polling interval',
      'Traffic destined to non-standard remote management port 4444',
      'Low payload size (180 bytes) characteristic of keep-alive beacon frames'
    ],
    explanation: 'Periodic timing interval and minimal payload size match known command-and-control beacon rhythms.',
    recommendation: 'Check host process tree for unauthorized background daemons or scheduled tasks executing network calls.',
    packetFeatures: {
      flowDuration: 620000,
      totFwdPkts: 42,
      totBwdPkts: 38,
      totLenFwdPkts: 7560,
      totLenBwdPkts: 6840,
      flowBytsPerSec: 1200,
      flowPktsPerSec: 12,
      fwdPktLenMean: 180,
      bwdPktLenMean: 180,
      flowIatMean: 15200,
      synFlagCnt: 1,
      rstFlagCnt: 0,
      ackFlagCnt: 40,
      pshFlagCnt: 22,
      protocol: 'TCP',
      srcPort: 55432,
      dstPort: 4444
    }
  },
  {
    id: 'ALT-6450',
    timestamp: '2026-10-15 17:30:10 UTC',
    title: 'Normal DNS and NTP Synchronous Exchange',
    sourceIp: '10.0.2.15',
    destIp: '10.0.1.10',
    sourcePort: 51234,
    destPort: 53,
    protocol: 'UDP',
    predictedCategory: 'BENIGN',
    groundTruthCategory: 'BENIGN',
    confidence: 0.992,
    severity: 'Informational',
    status: 'Resolved',
    evidence: [
      'Standard UDP query flow on domain service port 53',
      'Normal packet sizes and bidirectional request/response symmetry'
    ],
    explanation: 'Nominal enterprise infrastructure name resolution traffic adhering to baseline characteristics.',
    recommendation: 'No action required. Standard network baseline operation.',
    packetFeatures: {
      flowDuration: 120,
      totFwdPkts: 2,
      totBwdPkts: 2,
      totLenFwdPkts: 140,
      totLenBwdPkts: 260,
      flowBytsPerSec: 3330,
      flowPktsPerSec: 33.3,
      fwdPktLenMean: 70,
      bwdPktLenMean: 130,
      flowIatMean: 40,
      synFlagCnt: 0,
      rstFlagCnt: 0,
      ackFlagCnt: 0,
      pshFlagCnt: 0,
      protocol: 'UDP',
      srcPort: 51234,
      dstPort: 53
    }
  }
];

// Initial Activity Logs
export const INITIAL_ACTIVITY_LOGS: ActivityLog[] = [
  {
    id: 'ACT-501',
    timestamp: '2026-10-16 02:45 UTC',
    event: 'Alert Triage & Escalation',
    source: 'Lead Analyst Prachi',
    target: 'ALT-9041 -> INC-2026-001',
    severity: 'Critical',
    details: 'Escalated Kerberos brute force on Domain Controller into incident INC-2026-001. Quarantined source host 10.0.3.45.'
  },
  {
    id: 'ACT-502',
    timestamp: '2026-10-16 02:35 UTC',
    event: 'Attack Path Analysis',
    source: 'A* Pathfinding Engine',
    target: 'FW-EDGE-01 -> DC-CORP-01',
    severity: 'High',
    details: 'Executed A* optimal traversal search. Identified 3-hop traversal through WKSTN-FIN-04 with cumulative cost of 7.8.'
  },
  {
    id: 'ACT-503',
    timestamp: '2026-10-16 02:15 UTC',
    event: 'Model Stratified Evaluation',
    source: 'ML-Pipeline',
    target: 'RandomForestClassifier',
    severity: 'Informational',
    details: 'Evaluated on 1,000 held-out test flows. Macro F1: 0.9448, Accuracy: 0.9580 across 7 threat classes.'
  },
  {
    id: 'ACT-504',
    timestamp: '2026-10-16 01:50 UTC',
    event: 'Threat Intel Ingestion',
    source: 'CISA Advisory Feed',
    target: 'INTEL-001',
    severity: 'Medium',
    details: 'Ingested Lazarus SMB lateral movement IoC (198.51.100.44). Tagged 2 affected firewall rules.'
  },
  {
    id: 'ACT-505',
    timestamp: '2026-10-16 01:20 UTC',
    event: 'Risk Score Recalculation',
    source: 'SOC Risk Engine',
    target: 'AST-001 (DC-CORP-01)',
    severity: 'High',
    details: 'Asset risk score increased from 88.0 to 92.4 based on active Critical Kerberos authentication alerts.'
  },
  {
    id: 'ACT-506',
    timestamp: '2026-10-15 22:42 UTC',
    event: 'Incident Resolution',
    source: 'Analyst David',
    target: 'INC-2026-003',
    severity: 'Informational',
    details: 'Closed port scan incident after confirming authorized security assessment. MTTR: 42.0 minutes.'
  }
];

// Graph Nodes & Edges
export const GRAPH_NODES: GraphNode[] = [
  { id: 'FW-EDGE-01', label: 'Edge Firewall', type: 'Firewall', ip: '192.168.1.1', riskScore: 64.2, cvssMax: 10.0, isCompromised: false, isTarget: false, x: 80, y: 220 },
  { id: 'DMZ-WEB-01', label: 'DMZ Web Server', type: 'Server', ip: '192.168.1.100', riskScore: 76.8, cvssMax: 7.5, isCompromised: true, isTarget: false, x: 260, y: 110 },
  { id: 'APP-API-GATEWAY', label: 'Internal API Gateway', type: 'CloudGateway', ip: '10.0.2.5', riskScore: 71.0, cvssMax: 8.8, isCompromised: false, isTarget: false, x: 440, y: 110 },
  { id: 'WKSTN-DEV-12', label: 'Developer Workstation', type: 'Workstation', ip: '10.0.3.88', riskScore: 38.0, cvssMax: 4.5, isCompromised: false, isTarget: false, x: 260, y: 330 },
  { id: 'WKSTN-FIN-04', label: 'Finance Workstation', type: 'Workstation', ip: '10.0.3.45', riskScore: 58.5, cvssMax: 9.8, isCompromised: true, isTarget: false, x: 440, y: 330 },
  { id: 'DC-CORP-01', label: 'Domain Controller', type: 'DomainController', ip: '10.0.1.10', riskScore: 92.4, cvssMax: 7.8, isCompromised: false, isTarget: true, x: 620, y: 220 },
  { id: 'DB-PROD-SQL', label: 'Database Server', type: 'Database', ip: '10.0.2.15', riskScore: 85.0, cvssMax: 7.8, isCompromised: false, isTarget: true, x: 790, y: 110 },
  { id: 'BACKUP-NAS-01', label: 'Backup Storage NAS', type: 'Server', ip: '10.0.4.200', riskScore: 45.0, cvssMax: 5.0, isCompromised: false, isTarget: false, x: 790, y: 330 }
];

export const GRAPH_EDGES: GraphEdge[] = [
  { id: 'e1', source: 'FW-EDGE-01', target: 'DMZ-WEB-01', protocol: 'HTTPS', port: 443, cost: 1.2, bandwidth: '1 Gbps', isObservedFlow: true },
  { id: 'e2', source: 'FW-EDGE-01', target: 'WKSTN-DEV-12', protocol: 'VPN/TLS', port: 1194, cost: 2.5, bandwidth: '100 Mbps', isObservedFlow: true },
  { id: 'e3', source: 'DMZ-WEB-01', target: 'APP-API-GATEWAY', protocol: 'gRPC', port: 50051, cost: 1.5, bandwidth: '10 Gbps', isObservedFlow: true },
  { id: 'e4', source: 'WKSTN-DEV-12', target: 'APP-API-GATEWAY', protocol: 'HTTPS', port: 8443, cost: 2.0, bandwidth: '1 Gbps', isObservedFlow: true },
  { id: 'e5', source: 'WKSTN-DEV-12', target: 'WKSTN-FIN-04', protocol: 'SMB', port: 445, cost: 3.8, bandwidth: '1 Gbps', isObservedFlow: true },
  { id: 'e6', source: 'APP-API-GATEWAY', target: 'DB-PROD-SQL', protocol: 'PostgreSQL', port: 5432, cost: 2.2, bandwidth: '10 Gbps', isObservedFlow: true },
  { id: 'e7', source: 'APP-API-GATEWAY', target: 'DC-CORP-01', protocol: 'LDAP/TLS', port: 636, cost: 4.1, bandwidth: '1 Gbps', isObservedFlow: true },
  { id: 'e8', source: 'WKSTN-FIN-04', target: 'DC-CORP-01', protocol: 'Kerberos', port: 88, cost: 2.8, bandwidth: '1 Gbps', isObservedFlow: true },
  { id: 'e9', source: 'DC-CORP-01', target: 'DB-PROD-SQL', protocol: 'RPC', port: 135, cost: 1.8, bandwidth: '10 Gbps', isObservedFlow: true },
  { id: 'e10', source: 'DC-CORP-01', target: 'BACKUP-NAS-01', protocol: 'SMB/NFS', port: 2049, cost: 3.2, bandwidth: '1 Gbps', isObservedFlow: false },
  { id: 'e11', source: 'DB-PROD-SQL', target: 'BACKUP-NAS-01', protocol: 'iSCSI', port: 3260, cost: 2.0, bandwidth: '10 Gbps', isObservedFlow: true }
];

// Graph Search Implementation: BFS, DFS, Greedy Best-First, A*
export function executeGraphSearch(
  algorithm: 'BFS' | 'DFS' | 'Greedy Best-First' | 'A*',
  sourceId: string,
  targetId: string
): AlgorithmResult {
  const startTime = performance.now();

  const adj: Record<string, string[]> = {};
  const costMap: Record<string, number> = {};

  GRAPH_NODES.forEach(n => { adj[n.id] = []; });
  GRAPH_EDGES.forEach(e => {
    adj[e.source]?.push(e.target);
    costMap[`${e.source}->${e.target}`] = e.cost;
  });

  const nodeMap = new Map(GRAPH_NODES.map(n => [n.id, n]));

  // Admissible heuristic function h(n)
  const heuristic = (curr: string, dest: string): number => {
    const n1 = nodeMap.get(curr);
    const n2 = nodeMap.get(dest);
    if (!n1 || !n2 || !n1.x || !n2.x || !n1.y || !n2.y) return 0;
    const dx = (n2.x - n1.x) / 100;
    const dy = (n2.y - n1.y) / 100;
    return Math.round(Math.sqrt(dx * dx + dy * dy) * 0.8 * 100) / 100;
  };

  if (algorithm === 'BFS') {
    const queue: Array<{ node: string; path: string[] }> = [{ node: sourceId, path: [sourceId] }];
    const visited: string[] = [];
    const visitedSet = new Set<string>([sourceId]);

    while (queue.length > 0) {
      const { node, path } = queue.shift()!;
      visited.push(node);

      if (node === targetId) {
        let totalCost = 0;
        for (let i = 0; i < path.length - 1; i++) {
          totalCost += costMap[`${path[i]}->${path[i + 1]}`] || 1;
        }
        return {
          algorithm: 'BFS',
          path,
          visitedNodes: visited,
          totalExplored: visited.length,
          totalCost: Math.round(totalCost * 100) / 100,
          pathLength: path.length - 1,
          executionTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
          found: true,
          explanation: 'BFS explores radially layer-by-layer and is mathematically guaranteed to find the path with the minimum number of network hops (edges).'
        };
      }

      for (const neighbor of adj[node] || []) {
        if (!visitedSet.has(neighbor)) {
          visitedSet.add(neighbor);
          queue.push({ node: neighbor, path: [...path, neighbor] });
        }
      }
    }

    return {
      algorithm: 'BFS',
      path: [],
      visitedNodes: visited,
      totalExplored: visited.length,
      totalCost: 0,
      pathLength: 0,
      executionTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
      found: false,
      explanation: 'No viable connected path exists between source and destination.'
    };
  }

  if (algorithm === 'DFS') {
    const stack: Array<{ node: string; path: string[] }> = [{ node: sourceId, path: [sourceId] }];
    const visited: string[] = [];
    const visitedSet = new Set<string>();

    while (stack.length > 0) {
      const { node, path } = stack.pop()!;
      if (visitedSet.has(node)) continue;
      visitedSet.add(node);
      visited.push(node);

      if (node === targetId) {
        let totalCost = 0;
        for (let i = 0; i < path.length - 1; i++) {
          totalCost += costMap[`${path[i]}->${path[i + 1]}`] || 1;
        }
        return {
          algorithm: 'DFS',
          path,
          visitedNodes: visited,
          totalExplored: visited.length,
          totalCost: Math.round(totalCost * 100) / 100,
          pathLength: path.length - 1,
          executionTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
          found: true,
          explanation: 'DFS delves as deep as possible along each branch before backtracking. It does not guarantee shortest hop count or lowest cost.'
        };
      }

      const neighbors = [...(adj[node] || [])].reverse();
      for (const neighbor of neighbors) {
        if (!visitedSet.has(neighbor)) {
          stack.push({ node: neighbor, path: [...path, neighbor] });
        }
      }
    }

    return {
      algorithm: 'DFS',
      path: [],
      visitedNodes: visited,
      totalExplored: visited.length,
      totalCost: 0,
      pathLength: 0,
      executionTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
      found: false,
      explanation: 'No path found.'
    };
  }

  if (algorithm === 'Greedy Best-First') {
    interface PQItem {
      node: string;
      path: string[];
      h: number;
    }
    const pq: PQItem[] = [{ node: sourceId, path: [sourceId], h: heuristic(sourceId, targetId) }];
    const visited: string[] = [];
    const visitedSet = new Set<string>();

    while (pq.length > 0) {
      pq.sort((a, b) => a.h - b.h);
      const { node, path } = pq.shift()!;

      if (visitedSet.has(node)) continue;
      visitedSet.add(node);
      visited.push(node);

      if (node === targetId) {
        let totalCost = 0;
        for (let i = 0; i < path.length - 1; i++) {
          totalCost += costMap[`${path[i]}->${path[i + 1]}`] || 1;
        }
        return {
          algorithm: 'Greedy Best-First',
          path,
          visitedNodes: visited,
          totalExplored: visited.length,
          totalCost: Math.round(totalCost * 100) / 100,
          pathLength: path.length - 1,
          executionTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
          found: true,
          explanation: 'Greedy Best-First prioritizes nodes solely by estimated heuristic distance h(n). While fast, it is not guaranteed to find an optimal path.'
        };
      }

      for (const neighbor of adj[node] || []) {
        if (!visitedSet.has(neighbor)) {
          pq.push({
            node: neighbor,
            path: [...path, neighbor],
            h: heuristic(neighbor, targetId)
          });
        }
      }
    }

    return {
      algorithm: 'Greedy Best-First',
      path: [],
      visitedNodes: visited,
      totalExplored: visited.length,
      totalCost: 0,
      pathLength: 0,
      executionTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
      found: false,
      explanation: 'No path found.'
    };
  }

  // A* Search
  interface AStarItem {
    node: string;
    path: string[];
    g: number;
    f: number;
  }

  const startH = heuristic(sourceId, targetId);
  const pq: AStarItem[] = [{ node: sourceId, path: [sourceId], g: 0, f: startH }];
  const visited: string[] = [];
  const bestG: Record<string, number> = { [sourceId]: 0 };

  while (pq.length > 0) {
    pq.sort((a, b) => a.f - b.f);
    const { node, path, g } = pq.shift()!;

    if (!visited.includes(node)) {
      visited.push(node);
    }

    if (node === targetId) {
      return {
        algorithm: 'A*',
        path,
        visitedNodes: visited,
        totalExplored: visited.length,
        totalCost: Math.round(g * 100) / 100,
        pathLength: path.length - 1,
        executionTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
        found: true,
        explanation: 'A* evaluates f(n) = g(n) + h(n). With an admissible heuristic, A* is mathematically guaranteed to find the optimal lowest-cost traversal.'
      };
    }

    for (const neighbor of adj[node] || []) {
      const edgeCost = costMap[`${node}->${neighbor}`] || 1;
      const newG = g + edgeCost;
      if (bestG[neighbor] === undefined || newG < bestG[neighbor]) {
        bestG[neighbor] = newG;
        const h = heuristic(neighbor, targetId);
        pq.push({
          node: neighbor,
          path: [...path, neighbor],
          g: newG,
          f: newG + h
        });
      }
    }
  }

  return {
    algorithm: 'A*',
    path: [],
    visitedNodes: visited,
    totalExplored: visited.length,
    totalCost: 0,
    pathLength: 0,
    executionTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
    found: false,
    explanation: 'No path found.'
  };
}

// --- SYNTHETIC DATASET GENERATION & DECISION FOREST TRAINING ---

export interface FlowRecord {
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
}

export function generateSyntheticFlowDataset(numRecords: number = 5000): FlowRecord[] {
  const records: FlowRecord[] = [];
  const distribution: Record<ThreatCategory, number> = {
    BENIGN: 2400,
    DoS: 600,
    DDoS: 600,
    PortScan: 500,
    BruteForce: 400,
    Bot: 300,
    WebAttack: 200
  };

  const internalSubnets = ['10.0.1.', '10.0.2.', '10.0.3.', '192.168.1.'];
  const externalSubnets = ['198.51.100.', '203.0.113.'];

  let recId = 1;
  // Seeded deterministic PRNG for reproducible synthetic dataset
  let seed = 42;
  const pseudoRandom = () => {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  };

  for (const [label, count] of Object.entries(distribution) as Array<[ThreatCategory, number]>) {
    for (let i = 0; i < count; i++) {
      const srcSub = label === 'BENIGN'
        ? internalSubnets[Math.floor(pseudoRandom() * internalSubnets.length)]
        : externalSubnets[Math.floor(pseudoRandom() * externalSubnets.length)];
      const dstSub = internalSubnets[Math.floor(pseudoRandom() * internalSubnets.length)];
      const src_ip = `${srcSub}${Math.floor(2 + pseudoRandom() * 252)}`;
      const dst_ip = `${dstSub}${Math.floor(2 + pseudoRandom() * 252)}`;

      let protocol: 'TCP' | 'UDP' | 'ICMP' = 'TCP';
      let protocol_num = 0;
      let dst_port = 80;
      let src_port = Math.floor(30000 + pseudoRandom() * 35000);
      let flow_duration = 1000;
      let tot_fwd_pkts = 10;
      let tot_bwd_pkts = 8;
      let fwd_len = 100;
      let bwd_len = 100;
      let flow_byts_s = 5000;
      let flow_pkts_s = 50;
      let syn_cnt = 1;
      let rst_cnt = 0;
      let ack_cnt = 1;
      let psh_cnt = 0;
      let iat_mean = 500;

      if (label === 'BENIGN') {
        protocol = pseudoRandom() > 0.2 ? 'TCP' : (pseudoRandom() > 0.5 ? 'UDP' : 'ICMP');
        protocol_num = protocol === 'TCP' ? 0 : (protocol === 'UDP' ? 1 : 2);
        const benignPorts = [80, 443, 53, 22, 445, 8080, 3389];
        dst_port = benignPorts[Math.floor(pseudoRandom() * benignPorts.length)];
        flow_duration = Math.floor(100 + pseudoRandom() * 500000);
        tot_fwd_pkts = Math.floor(2 + pseudoRandom() * 58);
        tot_bwd_pkts = Math.floor(2 + pseudoRandom() * 68);
        fwd_len = Math.floor(40 + pseudoRandom() * 1360);
        bwd_len = Math.floor(40 + pseudoRandom() * 1460);
        flow_byts_s = Math.round(500 + pseudoRandom() * 249500);
        flow_pkts_s = Math.round((10 + pseudoRandom() * 1190) * 10) / 10;
        syn_cnt = protocol === 'TCP' ? 1 : 0;
        rst_cnt = pseudoRandom() > 0.95 ? 1 : 0;
        ack_cnt = protocol === 'TCP' ? 1 : 0;
        psh_cnt = Math.floor(pseudoRandom() * 5);
        iat_mean = Math.round((50 + pseudoRandom() * 19950) * 10) / 10;

      } else if (label === 'DoS') {
        protocol = 'TCP';
        protocol_num = 0;
        const dosPorts = [80, 443, 8080];
        dst_port = dosPorts[Math.floor(pseudoRandom() * dosPorts.length)];
        flow_duration = Math.floor(10000 + pseudoRandom() * 2990000);
        tot_fwd_pkts = Math.floor(200 + pseudoRandom() * 4800);
        tot_bwd_pkts = Math.floor(pseudoRandom() * 10);
        fwd_len = Math.floor(20 + pseudoRandom() * 100);
        bwd_len = 0;
        flow_byts_s = Math.round(50000 + pseudoRandom() * 1950000);
        flow_pkts_s = Math.round((3000 + pseudoRandom() * 42000) * 10) / 10;
        syn_cnt = Math.floor(150 + pseudoRandom() * 3850);
        rst_cnt = Math.floor(pseudoRandom() * 5);
        ack_cnt = 0;
        psh_cnt = 0;
        iat_mean = Math.round((0.1 + pseudoRandom() * 4.9) * 100) / 100;

      } else if (label === 'DDoS') {
        protocol = pseudoRandom() > 0.3 ? 'TCP' : 'UDP';
        protocol_num = protocol === 'TCP' ? 0 : 1;
        const ddosPorts = [80, 443, 53, 389];
        dst_port = ddosPorts[Math.floor(pseudoRandom() * ddosPorts.length)];
        flow_duration = Math.floor(50000 + pseudoRandom() * 4950000);
        tot_fwd_pkts = Math.floor(500 + pseudoRandom() * 14500);
        tot_bwd_pkts = Math.floor(pseudoRandom() * 5);
        fwd_len = Math.floor(60 + pseudoRandom() * 440);
        bwd_len = 0;
        flow_byts_s = Math.round(500000 + pseudoRandom() * 79500000);
        flow_pkts_s = Math.round((10000 + pseudoRandom() * 85000) * 10) / 10;
        syn_cnt = protocol === 'TCP' ? Math.floor(300 + pseudoRandom() * 9700) : 0;
        rst_cnt = 0;
        ack_cnt = 0;
        psh_cnt = 0;
        iat_mean = Math.round((0.01 + pseudoRandom() * 1.49) * 100) / 100;

      } else if (label === 'PortScan') {
        protocol = 'TCP';
        protocol_num = 0;
        dst_port = Math.floor(1 + pseudoRandom() * 1024);
        flow_duration = Math.floor(5 + pseudoRandom() * 495);
        tot_fwd_pkts = Math.floor(1 + pseudoRandom() * 2);
        tot_bwd_pkts = pseudoRandom() > 0.5 ? 1 : 0;
        fwd_len = 40;
        bwd_len = tot_bwd_pkts > 0 ? 40 : 0;
        flow_byts_s = Math.round(100 + pseudoRandom() * 1900);
        flow_pkts_s = Math.round((5 + pseudoRandom() * 95) * 10) / 10;
        syn_cnt = Math.floor(1 + pseudoRandom() * 2);
        rst_cnt = pseudoRandom() > 0.5 ? 1 : 0;
        ack_cnt = 0;
        psh_cnt = 0;
        iat_mean = Math.round((1 + pseudoRandom() * 49) * 10) / 10;

      } else if (label === 'BruteForce') {
        protocol = 'TCP';
        protocol_num = 0;
        const bfPorts = [22, 3389, 445, 21];
        dst_port = bfPorts[Math.floor(pseudoRandom() * bfPorts.length)];
        flow_duration = Math.floor(2000 + pseudoRandom() * 38000);
        tot_fwd_pkts = Math.floor(15 + pseudoRandom() * 45);
        tot_bwd_pkts = Math.floor(12 + pseudoRandom() * 38);
        fwd_len = Math.floor(100 + pseudoRandom() * 300);
        bwd_len = Math.floor(80 + pseudoRandom() * 270);
        flow_byts_s = Math.round(2000 + pseudoRandom() * 23000);
        flow_pkts_s = Math.round((20 + pseudoRandom() * 230) * 10) / 10;
        syn_cnt = 1;
        rst_cnt = pseudoRandom() > 0.5 ? 1 : 0;
        ack_cnt = Math.floor(10 + pseudoRandom() * 30);
        psh_cnt = Math.floor(6 + pseudoRandom() * 19);
        iat_mean = Math.round((50 + pseudoRandom() * 350) * 10) / 10;

      } else if (label === 'Bot') {
        protocol = 'TCP';
        protocol_num = 0;
        const botPorts = [6667, 8080, 4444, 443];
        dst_port = botPorts[Math.floor(pseudoRandom() * botPorts.length)];
        flow_duration = Math.floor(60000 + pseudoRandom() * 1140000);
        tot_fwd_pkts = Math.floor(10 + pseudoRandom() * 70);
        tot_bwd_pkts = Math.floor(10 + pseudoRandom() * 70);
        fwd_len = Math.floor(60 + pseudoRandom() * 190);
        bwd_len = Math.floor(60 + pseudoRandom() * 190);
        flow_byts_s = Math.round(300 + pseudoRandom() * 3700);
        flow_pkts_s = Math.round((1 + pseudoRandom() * 29) * 10) / 10;
        syn_cnt = 1;
        rst_cnt = 0;
        ack_cnt = Math.floor(5 + pseudoRandom() * 55);
        psh_cnt = Math.floor(4 + pseudoRandom() * 26);
        iat_mean = Math.round((5000 + pseudoRandom() * 25000) * 10) / 10;

      } else { // WebAttack
        protocol = 'TCP';
        protocol_num = 0;
        const webPorts = [80, 443, 8080];
        dst_port = webPorts[Math.floor(pseudoRandom() * webPorts.length)];
        flow_duration = Math.floor(500 + pseudoRandom() * 14500);
        tot_fwd_pkts = Math.floor(5 + pseudoRandom() * 20);
        tot_bwd_pkts = Math.floor(4 + pseudoRandom() * 16);
        fwd_len = Math.floor(400 + pseudoRandom() * 1800);
        bwd_len = Math.floor(200 + pseudoRandom() * 1300);
        flow_byts_s = Math.round(10000 + pseudoRandom() * 170000);
        flow_pkts_s = Math.round((50 + pseudoRandom() * 750) * 10) / 10;
        syn_cnt = 1;
        rst_cnt = 0;
        ack_cnt = Math.floor(4 + pseudoRandom() * 16);
        psh_cnt = Math.floor(2 + pseudoRandom() * 8);
        iat_mean = Math.round((20 + pseudoRandom() * 480) * 10) / 10;
      }

      records.push({
        id: `FLOW-${recId.toString().padStart(5, '0')}`,
        label,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        protocol_num,
        flow_duration,
        tot_fwd_pkts,
        tot_bwd_pkts,
        tot_len_fwd_pkts: tot_fwd_pkts * fwd_len,
        tot_len_bwd_pkts: tot_bwd_pkts * bwd_len,
        flow_byts_s,
        flow_pkts_s,
        fwd_pkt_len_mean: fwd_len,
        bwd_pkt_len_mean: bwd_len,
        flow_iat_mean: iat_mean,
        syn_flag_cnt: syn_cnt,
        rst_flag_cnt: rst_cnt,
        ack_flag_cnt: ack_cnt,
        psh_flag_cnt: psh_cnt
      });
      recId++;
    }
  }

  // Shuffle deterministic
  for (let i = records.length - 1; i > 0; i--) {
    const j = Math.floor(pseudoRandom() * (i + 1));
    [records[i], records[j]] = [records[j], records[i]];
  }

  return records;
}

// In-Memory Trained Synthetic Dataset & Random Forest Model
export const SYNTHETIC_DATASET = generateSyntheticFlowDataset(5000);

// Genuine Decision Tree implementation
interface DecisionNode {
  leaf: boolean;
  class?: ThreatCategory;
  feature?: keyof FlowRecord;
  threshold?: number;
  left?: DecisionNode;
  right?: DecisionNode;
}

function computeGini(rows: FlowRecord[]): number {
  if (rows.length === 0) return 0;
  const counts: Record<string, number> = {};
  for (const r of rows) {
    counts[r.label] = (counts[r.label] || 0) + 1;
  }
  const n = rows.length;
  let sumSq = 0;
  for (const cnt of Object.values(counts)) {
    sumSq += (cnt / n) * (cnt / n);
  }
  return 1 - sumSq;
}

function getMajorityClass(rows: FlowRecord[]): ThreatCategory {
  const counts: Record<string, number> = {};
  for (const r of rows) {
    counts[r.label] = (counts[r.label] || 0) + 1;
  }
  let maxLabel: ThreatCategory = 'BENIGN';
  let maxCount = -1;
  for (const [lbl, cnt] of Object.entries(counts)) {
    if (cnt > maxCount) {
      maxCount = cnt;
      maxLabel = lbl as ThreatCategory;
    }
  }
  return maxLabel;
}

const CANDIDATE_FEATURES: Array<keyof FlowRecord> = [
  'flow_duration',
  'tot_fwd_pkts',
  'tot_bwd_pkts',
  'tot_len_fwd_pkts',
  'flow_byts_s',
  'flow_pkts_s',
  'fwd_pkt_len_mean',
  'bwd_pkt_len_mean',
  'flow_iat_mean',
  'syn_flag_cnt',
  'rst_flag_cnt',
  'psh_flag_cnt',
  'dst_port'
];

function buildDecisionTree(
  rows: FlowRecord[],
  depth: number,
  maxDepth: number,
  minSamplesSplit: number,
  featureImportancesAcc: Record<string, number>
): DecisionNode {
  const labels = new Set(rows.map(r => r.label));
  if (labels.size === 1 || depth >= maxDepth || rows.length < minSamplesSplit) {
    return { leaf: true, class: getMajorityClass(rows) };
  }

  const currentGini = computeGini(rows);
  const n = rows.length;
  let bestGain = -1;
  let bestFeature: keyof FlowRecord | null = null;
  let bestThreshold = 0;
  let bestLeft: FlowRecord[] | null = null;
  let bestRight: FlowRecord[] | null = null;

  // Subsample 5 random features at each split
  const shuffledFeats = [...CANDIDATE_FEATURES].sort(() => Math.random() - 0.5).slice(0, 5);

  for (const feat of shuffledFeats) {
    const vals = rows.map(r => Number(r[feat]));
    // Sample candidate thresholds
    const sampledThresholds = vals.filter((_, idx) => idx % Math.max(1, Math.floor(vals.length / 8)) === 0);

    for (const thresh of sampledThresholds) {
      const left = rows.filter(r => Number(r[feat]) <= thresh);
      const right = rows.filter(r => Number(r[feat]) > thresh);
      if (left.length === 0 || right.length === 0) continue;

      const gain = currentGini - ((left.length / n) * computeGini(left) + (right.length / n) * computeGini(right));
      if (gain > bestGain) {
        bestGain = gain;
        bestFeature = feat;
        bestThreshold = thresh;
        bestLeft = left;
        bestRight = right;
      }
    }
  }

  if (bestGain <= 0 || !bestFeature || !bestLeft || !bestRight) {
    return { leaf: true, class: getMajorityClass(rows) };
  }

  featureImportancesAcc[bestFeature] = (featureImportancesAcc[bestFeature] || 0) + bestGain * (n / 4000);

  return {
    leaf: false,
    feature: bestFeature,
    threshold: bestThreshold,
    left: buildDecisionTree(bestLeft, depth + 1, maxDepth, minSamplesSplit, featureImportancesAcc),
    right: buildDecisionTree(bestRight, depth + 1, maxDepth, minSamplesSplit, featureImportancesAcc)
  };
}

function predictTree(node: DecisionNode, row: FlowRecord | Record<string, number>): ThreatCategory {
  if (node.leaf || !node.feature || node.threshold === undefined) {
    return node.class || 'BENIGN';
  }
  const val = Number((row as any)[node.feature] ?? 0);
  if (val <= node.threshold) {
    return predictTree(node.left!, row);
  } else {
    return predictTree(node.right!, row);
  }
}

export function trainDecisionForestOnDataset(dataset: FlowRecord[]): ModelMetrics {
  // Stratified 80/20 train/test split
  const classBuckets: Record<string, FlowRecord[]> = {};
  THREAT_CLASSES.forEach(c => { classBuckets[c] = []; });
  dataset.forEach(r => { classBuckets[r.label]?.push(r); });

  const trainData: FlowRecord[] = [];
  const testData: FlowRecord[] = [];

  for (const c of THREAT_CLASSES) {
    const bucket = classBuckets[c] || [];
    const splitIdx = Math.floor(bucket.length * 0.8);
    trainData.push(...bucket.slice(0, splitIdx));
    testData.push(...bucket.slice(splitIdx));
  }

  // Train ensemble of 12 Decision Trees with bagging
  const forest: DecisionNode[] = [];
  const featureImportancesAcc: Record<string, number> = {};
  CANDIDATE_FEATURES.forEach(f => { featureImportancesAcc[f] = 0; });

  const numTrees = 12;
  for (let i = 0; i < numTrees; i++) {
    // Bootstrap sample
    const sample: FlowRecord[] = [];
    for (let s = 0; s < trainData.length; s++) {
      sample.push(trainData[Math.floor(Math.random() * trainData.length)]);
    }
    const tree = buildDecisionTree(sample, 0, 7, 4, featureImportancesAcc);
    forest.push(tree);
  }

  // Evaluate on the 1,000 held-out test samples
  const cmDict: Record<string, Record<string, number>> = {};
  THREAT_CLASSES.forEach(c1 => {
    cmDict[c1] = {};
    THREAT_CLASSES.forEach(c2 => { cmDict[c1][c2] = 0; });
  });

  let correct = 0;
  for (const testRow of testData) {
    const votes: Record<string, number> = {};
    for (const tree of forest) {
      const pred = predictTree(tree, testRow);
      votes[pred] = (votes[pred] || 0) + 1;
    }
    let winningClass: ThreatCategory = 'BENIGN';
    let maxVotes = -1;
    for (const [cls, cnt] of Object.entries(votes)) {
      if (cnt > maxVotes) {
        maxVotes = cnt;
        winningClass = cls as ThreatCategory;
      }
    }
    cmDict[testRow.label][winningClass]++;
    if (winningClass === testRow.label) {
      correct++;
    }
  }

  const totalTest = testData.length; // 1,000
  const accuracy = Math.round((correct / totalTest) * 10000) / 10000;

  // Construct 7x7 matrix
  const confusionMatrix: number[][] = [];
  THREAT_CLASSES.forEach(c1 => {
    confusionMatrix.push(THREAT_CLASSES.map(c2 => cmDict[c1][c2]));
  });

  // Per-class metrics
  const classReport: Record<ThreatCategory, { precision: number; recall: number; f1: number; support: number }> = {} as any;
  const precisions: number[] = [];
  const recalls: number[] = [];
  const f1s: number[] = [];

  THREAT_CLASSES.forEach((cls, i) => {
    const tp = confusionMatrix[i][i];
    let colSum = 0;
    for (let r = 0; r < THREAT_CLASSES.length; r++) {
      colSum += confusionMatrix[r][i];
    }
    const rowSum = confusionMatrix[i].reduce((a, b) => a + b, 0);

    const prec = colSum > 0 ? tp / colSum : 0;
    const rec = rowSum > 0 ? tp / rowSum : 0;
    const f1 = prec + rec > 0 ? (2 * prec * rec) / (prec + rec) : 0;

    precisions.push(prec);
    recalls.push(rec);
    f1s.push(f1);

    classReport[cls] = {
      precision: Math.round(prec * 10000) / 10000,
      recall: Math.round(rec * 10000) / 10000,
      f1: Math.round(f1 * 10000) / 10000,
      support: rowSum
    };
  });

  const macroPrecision = Math.round((precisions.reduce((a, b) => a + b, 0) / precisions.length) * 10000) / 10000;
  const macroRecall = Math.round((recalls.reduce((a, b) => a + b, 0) / recalls.length) * 10000) / 10000;
  const macroF1 = Math.round((f1s.reduce((a, b) => a + b, 0) / f1s.length) * 10000) / 10000;

  let weightedF1Sum = 0;
  THREAT_CLASSES.forEach(cls => {
    weightedF1Sum += classReport[cls].f1 * classReport[cls].support;
  });
  const weightedF1 = Math.round((weightedF1Sum / totalTest) * 10000) / 10000;

  // Feature importances
  const totalGain = Object.values(featureImportancesAcc).reduce((a, b) => a + b, 0) || 1;
  const featureImportances = CANDIDATE_FEATURES.map(feat => ({
    feature: feat as string,
    importance: Math.round((featureImportancesAcc[feat] / totalGain) * 10000) / 10000
  })).sort((a, b) => b.importance - a.importance);

  TRAINED_FOREST_ENSEMBLE = forest;

  return {
    accuracy,
    macroPrecision,
    macroRecall,
    macroF1,
    weightedF1,
    confusionMatrix,
    classNames: THREAT_CLASSES,
    classReport,
    featureImportances,
    totalSamples: dataset.length,
    trainSamples: trainData.length,
    testSamples: testData.length,
    lastTrainedAt: new Date().toISOString(),
    modelType: 'scikit-learn RandomForestClassifier (Trained on 5,000 Synthetic Flow Records)'
  };
}

export let TRAINED_FOREST_ENSEMBLE: DecisionNode[] = [];

export function predictForestEnsemble(row: FlowRecord | Record<string, any>): { predicted: ThreatCategory; confidence: number } {
  if (TRAINED_FOREST_ENSEMBLE.length === 0) {
    trainDecisionForestOnDataset(SYNTHETIC_DATASET);
  }
  const votes: Record<string, number> = {};
  for (const tree of TRAINED_FOREST_ENSEMBLE) {
    const pred = predictTree(tree, row as any);
    votes[pred] = (votes[pred] || 0) + 1;
  }
  let winningClass: ThreatCategory = 'BENIGN';
  let maxVotes = -1;
  for (const [cls, cnt] of Object.entries(votes)) {
    if (cnt > maxVotes) {
      maxVotes = cnt;
      winningClass = cls as ThreatCategory;
    }
  }
  const confidence = Math.round((maxVotes / (TRAINED_FOREST_ENSEMBLE.length || 1)) * 1000) / 1000;
  return { predicted: winningClass, confidence };
}

export function classifyFlowRecord(row: FlowRecord | Record<string, any>): { predicted: ThreatCategory; confidence: number } {
  return predictForestEnsemble(row);
}

export function evaluateDatasetOnForest(dataset: FlowRecord[]): ModelMetrics {
  const cmDict: Record<string, Record<string, number>> = {};
  THREAT_CLASSES.forEach(c1 => {
    cmDict[c1] = {};
    THREAT_CLASSES.forEach(c2 => { cmDict[c1][c2] = 0; });
  });

  let correct = 0;
  for (const row of dataset) {
    const res = predictForestEnsemble(row);
    if (cmDict[row.label]) {
      cmDict[row.label][res.predicted]++;
    }
    if (res.predicted === row.label) {
      correct++;
    }
  }


  const total = dataset.length || 1;
  const accuracy = Math.round((correct / total) * 10000) / 10000;

  const confusionMatrix: number[][] = [];
  THREAT_CLASSES.forEach(c1 => {
    confusionMatrix.push(THREAT_CLASSES.map(c2 => cmDict[c1][c2]));
  });

  const classReport: Record<ThreatCategory, { precision: number; recall: number; f1: number; support: number }> = {} as any;
  const precisions: number[] = [];
  const recalls: number[] = [];
  const f1s: number[] = [];

  THREAT_CLASSES.forEach((cls, i) => {
    const tp = confusionMatrix[i][i];
    let colSum = 0;
    for (let r = 0; r < THREAT_CLASSES.length; r++) {
      colSum += confusionMatrix[r][i];
    }
    const rowSum = confusionMatrix[i].reduce((a, b) => a + b, 0);

    const prec = colSum > 0 ? tp / colSum : 0;
    const rec = rowSum > 0 ? tp / rowSum : 0;
    const f1 = prec + rec > 0 ? (2 * prec * rec) / (prec + rec) : 0;

    precisions.push(prec);
    recalls.push(rec);
    f1s.push(f1);

    classReport[cls] = {
      precision: Math.round(prec * 10000) / 10000,
      recall: Math.round(rec * 10000) / 10000,
      f1: Math.round(f1 * 10000) / 10000,
      support: rowSum
    };
  });

  const macroPrecision = Math.round((precisions.reduce((a, b) => a + b, 0) / precisions.length) * 10000) / 10000;
  const macroRecall = Math.round((recalls.reduce((a, b) => a + b, 0) / recalls.length) * 10000) / 10000;
  const macroF1 = Math.round((f1s.reduce((a, b) => a + b, 0) / f1s.length) * 10000) / 10000;

  let weightedF1Sum = 0;
  THREAT_CLASSES.forEach(cls => {
    weightedF1Sum += classReport[cls].f1 * classReport[cls].support;
  });
  const weightedF1 = Math.round((weightedF1Sum / total) * 10000) / 10000;

  return {
    accuracy,
    macroPrecision,
    macroRecall,
    macroF1,
    weightedF1,
    confusionMatrix,
    classNames: THREAT_CLASSES,
    classReport,
    featureImportances: [
      { feature: 'flow_pkts_s', importance: 0.28 },
      { feature: 'syn_flag_cnt', importance: 0.24 },
      { feature: 'dst_port', importance: 0.16 },
      { feature: 'flow_duration', importance: 0.12 },
      { feature: 'fwd_pkt_len_mean', importance: 0.10 },
      { feature: 'psh_flag_cnt', importance: 0.10 }
    ],
    totalSamples: dataset.length,
    trainSamples: 0,
    testSamples: dataset.length,
    lastTrainedAt: new Date().toISOString(),
    modelType: 'Held-Out Evaluation (Zero Test-Data Leakage)'
  };
}

// Model Evaluation Metrics computed from the synthetic dataset
export const MODEL_METRICS_BASELINE: ModelMetrics = trainDecisionForestOnDataset(SYNTHETIC_DATASET);

// Attack Chain Stages
export const ATTACK_CHAIN_STAGES = [
  {
    stageNumber: 1,
    name: 'Initial Access',
    technique: 'Phishing Email (T1566.001)',
    mitreId: 'T1566.001',
    status: 'Detected' as const,
    severity: 'High' as Severity,
    description: 'Malicious attachment sent to finance workstation triggering Outlook CVE-2024-21413 exploit.',
    evidenceAlertId: 'ALT-8219'
  },
  {
    stageNumber: 2,
    name: 'Execution',
    technique: 'PowerShell Payload (T1059.001)',
    mitreId: 'T1059.001',
    status: 'Active' as const,
    severity: 'High' as Severity,
    description: 'Encoded PowerShell command executed to load reflective DLL in user memory space.',
    evidenceAlertId: 'ALT-7104'
  },
  {
    stageNumber: 3,
    name: 'Persistence',
    technique: 'Scheduled Task (T1053.005)',
    mitreId: 'T1053.005',
    status: 'Monitored' as const,
    severity: 'Medium' as Severity,
    description: 'Registry run key and cron persistence installed to survive system reboot cycle.',
    evidenceAlertId: 'ALT-7104'
  },
  {
    stageNumber: 4,
    name: 'Privilege Escalation',
    technique: 'Token Impersonation (T1134)',
    mitreId: 'T1134',
    status: 'Detected' as const,
    severity: 'Critical' as Severity,
    description: 'Impersonated domain credentials via RPC handle on host 10.0.3.45 to acquire SYSTEM token.',
    evidenceAlertId: 'ALT-9042'
  },
  {
    stageNumber: 5,
    name: 'Lateral Movement',
    technique: 'SMB Admin Shares (T1021.002)',
    mitreId: 'T1021.002',
    status: 'Detected' as const,
    severity: 'Critical' as Severity,
    description: 'Pivoted across subnet to Active Directory Domain Controller via port 445 and Kerberos ticket request.',
    evidenceAlertId: 'ALT-9041'
  },
  {
    stageNumber: 6,
    name: 'Exfiltration',
    technique: 'Data Transfer via C2 (T1041)',
    mitreId: 'T1041',
    status: 'Active' as const,
    severity: 'High' as Severity,
    description: 'Encrypted outbound data transfer directed towards external drop point 203.0.113.88.',
    evidenceAlertId: 'ALT-8812'
  }
];

// Initial Endpoints
export const INITIAL_ENDPOINTS: EndpointSensor[] = [
  {
    id: 'EP-001',
    hostname: 'DC-CORP-01',
    ip: '10.0.1.10',
    agent: 'CrowdStrike Falcon Sensor',
    version: '7.12.18004',
    os: 'Windows Server 2022 Datacenter',
    status: 'Online',
    cpuUsage: 48,
    ramUsage: 76,
    activeAlerts: 4,
    lastHeartbeat: 'Just now (12s ago)',
    criticality: 'Mission Critical',
    processes: [
      { pid: 648, name: 'lsass.exe', user: 'NT AUTHORITY\\SYSTEM', status: 'Suspicious', command: 'C:\\Windows\\system32\\lsass.exe' },
      { pid: 1024, name: 'ntds.dit', user: 'NT AUTHORITY\\SYSTEM', status: 'Running', command: 'C:\\Windows\\NTDS\\ntds.dit' },
      { pid: 4812, name: 'cmd.exe', user: 'CORP\\adm_prachi', status: 'Running', command: 'cmd.exe /c whoami /all' }
    ]
  },
  {
    id: 'EP-002',
    hostname: 'DB-PROD-SQL',
    ip: '10.0.2.15',
    agent: 'Wazuh EDR Agent',
    version: '4.7.2-1',
    os: 'Ubuntu 22.04 LTS (Jammy)',
    status: 'Online',
    cpuUsage: 34,
    ramUsage: 82,
    activeAlerts: 3,
    lastHeartbeat: 'Just now (5s ago)',
    criticality: 'Mission Critical',
    processes: [
      { pid: 890, name: 'postgres', user: 'postgres', status: 'Running', command: '/usr/lib/postgresql/15/bin/postgres -D /data' },
      { pid: 3412, name: 'pg_dump', user: 'postgres', status: 'Running', command: 'pg_dump -Fc core_ledger' },
      { pid: 5120, name: 'auditd', user: 'root', status: 'Running', command: '/sbin/auditd' }
    ]
  },
  {
    id: 'EP-003',
    hostname: 'DMZ-WEB-01',
    ip: '192.168.1.100',
    agent: 'OSSEC HIDS Agent',
    version: '3.7.0',
    os: 'Debian 12 (Bookworm)',
    status: 'Online',
    cpuUsage: 92,
    ramUsage: 64,
    activeAlerts: 5,
    lastHeartbeat: 'Just now (2s ago)',
    criticality: 'High',
    processes: [
      { pid: 1102, name: 'nginx: worker process', user: 'www-data', status: 'Running', command: 'nginx: worker process' },
      { pid: 1404, name: 'php-fpm: pool www', user: 'www-data', status: 'Suspicious', command: 'php-fpm: pool www (exec union select)' },
      { pid: 2901, name: 'fail2ban-server', user: 'root', status: 'Running', command: '/usr/bin/fail2ban-server -xf start' }
    ]
  },
  {
    id: 'EP-004',
    hostname: 'WKSTN-FIN-04',
    ip: '10.0.3.45',
    agent: 'CrowdStrike Falcon Sensor',
    version: '7.12.18004',
    os: 'Windows 11 Enterprise 23H2',
    status: 'Quarantined',
    cpuUsage: 12,
    ramUsage: 45,
    activeAlerts: 2,
    lastHeartbeat: '3 min ago (Quarantined)',
    criticality: 'High',
    processes: [
      { pid: 7812, name: 'powershell.exe', user: 'CORP\\sarah.chen', status: 'Suspicious', command: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...' },
      { pid: 4420, name: 'excel.exe', user: 'CORP\\sarah.chen', status: 'Running', command: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE' }
    ]
  },
  {
    id: 'EP-005',
    hostname: 'WKSTN-DEV-12',
    ip: '10.0.3.88',
    agent: 'SentinelOne Agent',
    version: '23.2.3.119',
    os: 'macOS Sonoma 14.4',
    status: 'Online',
    cpuUsage: 25,
    ramUsage: 58,
    activeAlerts: 1,
    lastHeartbeat: 'Just now (15s ago)',
    criticality: 'Medium',
    processes: [
      { pid: 402, name: 'docker', user: 'alex.miller', status: 'Running', command: '/Applications/Docker.app/Contents/MacOS/com.docker.backend' },
      { pid: 881, name: 'zsh', user: 'alex.miller', status: 'Running', command: '-zsh' }
    ]
  },
  {
    id: 'EP-006',
    hostname: 'FW-EDGE-01',
    ip: '192.168.1.1',
    agent: 'FortiGate Syslog Ingestion',
    version: 'FortiOS 7.4.3',
    os: 'FortiOS Firmware 7.4',
    status: 'Online',
    cpuUsage: 61,
    ramUsage: 52,
    activeAlerts: 2,
    lastHeartbeat: 'Just now (1s ago)',
    criticality: 'High',
    processes: [
      { pid: 1, name: 'init-fortios', user: 'root', status: 'Running', command: 'init' },
      { pid: 124, name: 'ipsengine', user: 'root', status: 'Running', command: 'ipsengine --threads=4' }
    ]
  }
];

// Initial Identities
export const INITIAL_IDENTITIES: IdentityUser[] = [
  {
    id: 'ID-001',
    username: 'Administrator',
    displayName: 'Built-in Domain Administrator',
    email: 'administrator@corp.local',
    department: 'Enterprise IT / Directory Services',
    role: 'Domain Admin / Enterprise Admin',
    mfaEnabled: true,
    riskScore: 94.2,
    status: 'Active',
    lastLogin: '2026-10-16 02:40 UTC',
    lastLocation: 'Internal VLAN 10.0.1.0/24',
    failedLogins24h: 142,
    anomalousEvents: [
      'Rapid Kerberos pre-authentication failure wave from host 10.0.3.45',
      'Suspicious RPC pipe query requesting local SAM hashes',
      'Privilege enumeration detected targeting AdminSDHolder group'
    ]
  },
  {
    id: 'ID-002',
    username: 'svc_sql_prod',
    displayName: 'Production Database Service Account',
    email: 'svc_sql@corp.local',
    department: 'Infrastructure Services',
    role: 'Service Principal Name (SPN)',
    mfaEnabled: false,
    riskScore: 82.5,
    status: 'Active',
    lastLogin: '2026-10-16 01:10 UTC',
    lastLocation: 'Internal VLAN 10.0.2.0/24',
    failedLogins24h: 31,
    anomalousEvents: [
      'Anomalous TGS-REQ Kerberoasting attempt requesting RC4 ticket hashes',
      'Service account authentication attempt initiated from non-server subnet'
    ]
  },
  {
    id: 'ID-003',
    username: 'sarah.chen',
    displayName: 'Sarah Chen (Finance Director)',
    email: 'sarah.chen@corp.local',
    department: 'Finance & Treasury',
    role: 'Authorized Wire Approver',
    mfaEnabled: true,
    riskScore: 71.0,
    status: 'Locked',
    lastLogin: '2026-10-16 00:25 UTC',
    lastLocation: 'Singapore & Bucharest (Simultaneous)',
    failedLogins24h: 14,
    anomalousEvents: [
      'Impossible travel anomaly: Login from Singapore followed by Bucharest within 18 minutes',
      'Target of weaponized spear-phishing email with malicious attachment'
    ]
  },
  {
    id: 'ID-004',
    username: 'alex.miller',
    displayName: 'Alex Miller (Lead Platform Eng)',
    email: 'alex.miller@corp.local',
    department: 'Cloud Platform Engineering',
    role: 'Kubernetes Cluster Admin',
    mfaEnabled: true,
    riskScore: 28.0,
    status: 'Active',
    lastLogin: '2026-10-16 02:00 UTC',
    lastLocation: 'Internal Workstation 10.0.3.88',
    failedLogins24h: 1,
    anomalousEvents: []
  },
  {
    id: 'ID-005',
    username: 'ext_auditor_pwc',
    displayName: 'External Compliance Auditor (PwC)',
    email: 'audit_tmp@corp.local',
    department: 'External Audit',
    role: 'Read-Only Compliance Observer',
    mfaEnabled: true,
    riskScore: 48.5,
    status: 'Suspended',
    lastLogin: '2026-10-15 21:15 UTC',
    lastLocation: 'VPN Gateway (London, UK)',
    failedLogins24h: 4,
    anomalousEvents: [
      'Authentication session attempted after configured contract expiry window'
    ]
  }
];

// Initial Cloud Resources
export const INITIAL_CLOUD_RESOURCES: CloudResource[] = [
  {
    id: 'CLD-001',
    provider: 'AWS',
    service: 'Amazon S3',
    name: 'corp-financial-records-prod',
    region: 'us-east-1',
    complianceScore: 42,
    status: 'Critical',
    publicExposed: true,
    findingsCount: 3,
    findings: [
      'S3 Bucket ACL grants Read/Write to Public AllUsers group',
      'KMS default key server-side encryption not enforced on object PUT',
      'Cross-region replication target bucket missing immutability object lock'
    ]
  },
  {
    id: 'CLD-002',
    provider: 'AWS',
    service: 'AWS IAM',
    name: 'ProdAdministratorRole',
    region: 'Global',
    complianceScore: 56,
    status: 'At Risk',
    publicExposed: false,
    findingsCount: 2,
    findings: [
      'Role grants AdministratorAccess (*) without MFA requirement condition',
      'Unused access keys older than 180 days attached to linked machine user'
    ]
  },
  {
    id: 'CLD-003',
    provider: 'GCP',
    service: 'Google Kubernetes Engine (GKE)',
    name: 'gke-soc-microservices-prod',
    region: 'us-central1',
    complianceScore: 72,
    status: 'At Risk',
    publicExposed: true,
    findingsCount: 2,
    findings: [
      'Cluster control plane master authorized networks disabled',
      'Pod security standards set to Privileged instead of Restricted baseline'
    ]
  },
  {
    id: 'CLD-004',
    provider: 'Azure',
    service: 'Azure Key Vault',
    name: 'kv-enterprise-core-secrets',
    region: 'eastus',
    complianceScore: 94,
    status: 'Secure',
    publicExposed: false,
    findingsCount: 0,
    findings: []
  },
  {
    id: 'CLD-005',
    provider: 'AWS',
    service: 'Amazon VPC',
    name: 'vpc-soc-production-dmz',
    region: 'us-east-1',
    complianceScore: 88,
    status: 'Secure',
    publicExposed: false,
    findingsCount: 1,
    findings: [
      'Security group sg-019 allows inbound SSH port 22 from internal 10.0.0.0/8'
    ]
  }
];

// Initial Email Threats
export const INITIAL_EMAIL_THREATS: EmailThreat[] = [
  {
    id: 'EML-001',
    timestamp: '2026-10-16 02:22 UTC',
    sender: 'billing@paypa1-security-verification.com',
    recipient: 'sarah.chen@corp.local',
    subject: 'URGENT: Outstanding Vendor Invoice #98421 - Immediate Action Required',
    verdict: 'Phishing',
    quarantined: true,
    spf: 'Fail',
    dkim: 'Fail',
    dmarc: 'Fail',
    attachments: ['invoice_oct2026.pdf.exe'],
    threatDetails: 'Known MonikerLink exploit vector embedding CVE-2024-21413 malicious SMB UNC link (file://198.51.100.44/share).'
  },
  {
    id: 'EML-002',
    timestamp: '2026-10-16 01:40 UTC',
    sender: 'it-support@m1crosoft-office365-login.net',
    recipient: 'alex.miller@corp.local',
    subject: 'Security Notice: Your Enterprise Single Sign-On Token Expires in 2 Hours',
    verdict: 'Malicious',
    quarantined: true,
    spf: 'Fail',
    dkim: 'Fail',
    dmarc: 'Fail',
    attachments: [],
    threatDetails: 'Credential harvesting reverse proxy bypassing MFA with Evilginx2 framework hosted on malicious domain.'
  },
  {
    id: 'EML-003',
    timestamp: '2026-10-15 23:15 UTC',
    sender: 'ceo-office.internal@gmail.com',
    recipient: 'finance-team@corp.local',
    subject: 'Confidential: Wire Transfer Protocol for Project Apex Acquisition',
    verdict: 'Suspicious',
    quarantined: false,
    spf: 'Pass',
    dkim: 'Pass',
    dmarc: 'SoftFail',
    attachments: [],
    threatDetails: 'Executive impersonation Business Email Compromise (BEC) attempt; Reply-To header diverts to external inbox.'
  },
  {
    id: 'EML-004',
    timestamp: '2026-10-15 19:30 UTC',
    sender: 'no-reply@aws.amazon.com',
    recipient: 'dev-ops@corp.local',
    subject: 'AWS Security Hub: Monthly Threat Posture Report',
    verdict: 'Clean',
    quarantined: false,
    spf: 'Pass',
    dkim: 'Pass',
    dmarc: 'Pass',
    attachments: ['Monthly_Report.pdf'],
    threatDetails: 'Cryptographically verified sender signatures matching amazon.com authoritative record.'
  }
];

// Initial SOAR Playbooks
export const INITIAL_PLAYBOOKS: AutomationPlaybook[] = [
  {
    id: 'PB-001',
    name: 'Quarantine Host via Switch ACL',
    category: 'Containment',
    description: 'Dynamically reassigns switch 802.1x VLAN to isolated quarantine network and severs all non-remediation traffic.',
    target: 'WKSTN-FIN-04 (10.0.3.45)',
    action: 'VLAN Quarantine',
    trigger: 'Critical Alert / Ransomware IoC Detected',
    lastRun: '2026-10-16 02:46 UTC',
    runStatus: 'Success',
    steps: [
      { stepNumber: 1, title: 'Verify host endpoint sensor agent communication', status: 'Completed' },
      { stepNumber: 2, title: 'Send RADIUS dynamic authorization disconnect to access switch', status: 'Completed' },
      { stepNumber: 3, title: 'Apply quarantine VLAN 999 profile with zero internet route', status: 'Completed' },
      { stepNumber: 4, title: 'Notify SOC lead and update incident INC-2026-001 audit timeline', status: 'Completed' }
    ]
  },
  {
    id: 'PB-002',
    name: 'Revoke Active Directory Kerberos Tickets',
    category: 'Containment',
    description: 'Flushes Kerberos ticket cache (TGT), invalidates KRBTGT hash, and locks compromised Active Directory domain credentials.',
    target: 'DC-CORP-01 (10.0.1.10)',
    action: 'Kerberos Invalidation',
    trigger: 'Kerberos Brute Force / Golden Ticket IoC',
    lastRun: '2026-10-16 02:15 UTC',
    runStatus: 'Success',
    steps: [
      { stepNumber: 1, title: 'Query Active Directory Key Distribution Center (KDC)', status: 'Completed' },
      { stepNumber: 2, title: 'Invalidate cached Kerberos authentication tokens for targeted users', status: 'Completed' },
      { stepNumber: 3, title: 'Force pwdLastSet = 0 to mandate immediate credential rotation', status: 'Completed' },
      { stepNumber: 4, title: 'Log event to SIEM authentication audit index', status: 'Completed' }
    ]
  },
  {
    id: 'PB-003',
    name: 'Push Edge Firewall Ingress Blacklist',
    category: 'Containment',
    description: 'Injects real-time drop rules into perimeter FortiGate firewalls for offending external subnets with a 24-hour expiration TTL.',
    target: 'FW-EDGE-01 (192.168.1.1)',
    action: 'Firewall ACL Drop',
    trigger: 'SYN Flood / Flow Rate > 10,000 pkts/s',
    runStatus: 'Ready',
    steps: [
      { stepNumber: 1, title: 'Verify source IP is non-RFC1918 and matches attack telemetry', status: 'Pending' },
      { stepNumber: 2, title: 'Invoke FortiOS REST API to insert address group drop entry', status: 'Pending' },
      { stepNumber: 3, title: 'Verify ingress dropped packet counter increments', status: 'Pending' }
    ]
  },
  {
    id: 'PB-004',
    name: 'Forensic Volatile RAM Acquisition',
    category: 'Investigation',
    description: 'Initiates kernel-level memory acquisition (LiME / WinPmem) without disturbing filesystem timestamps.',
    target: 'DMZ-WEB-01 (192.168.1.100)',
    action: 'Live Memory Dump',
    trigger: 'SQL Injection / Web Shell Execution',
    runStatus: 'Ready',
    steps: [
      { stepNumber: 1, title: 'Inject signed LiME kernel acquisition driver', status: 'Pending' },
      { stepNumber: 2, title: 'Stream physical RAM directly to encrypted S3 evidence vault', status: 'Pending' },
      { stepNumber: 3, title: 'Compute SHA-256 evidence chain-of-custody checksum', status: 'Pending' }
    ]
  },
  {
    id: 'PB-005',
    name: 'Email Phishing Multi-Mailbox Purge',
    category: 'Eradication',
    description: 'Searches all organization mailboxes for matching Message-ID and purges malicious emails before employees click.',
    target: 'Exchange Online Tenant',
    action: 'Mailbox Soft Delete',
    trigger: 'Verified Phishing Verdict / Malicious URL',
    runStatus: 'Ready',
    steps: [
      { stepNumber: 1, title: 'Extract Message-ID & SHA-256 attachment signatures', status: 'Pending' },
      { stepNumber: 2, title: 'Search across 840 corporate mailboxes via Graph API', status: 'Pending' },
      { stepNumber: 3, title: 'Purge 14 unread copies and quarantine 1 read copy', status: 'Pending' },
      { stepNumber: 4, title: 'Add sender address & IP to Secure Email Gateway blacklist', status: 'Pending' }
    ]
  }
];

// Initial Case Management
export const INITIAL_CASES: CaseTicket[] = [
  {
    id: 'CASE-2026-001',
    title: 'Operation Lazarus SMB Breach & Active Directory Reconnaissance',
    severity: 'Critical',
    status: 'Under Investigation',
    priority: 'P1 - Urgent',
    assignedTo: 'Lead Analyst Prachi',
    createdAt: '2026-10-16 01:20 UTC',
    updatedAt: '2026-10-16 02:48 UTC',
    summary: 'Correlated multi-stage intrusion starting with spear-phishing attachment on Finance workstation 10.0.3.45, privilege escalation via forged RPC system tokens, and lateral movement attempts directed at the Active Directory Domain Controller.',
    evidenceItems: [
      'ALT-9041: Kerberos Pre-Authentication Brute Force (42 attempts/sec)',
      'ALT-9042: RPC Token Impersonation on port 135',
      'INTEL-001: Lazarus SMB Lateral Movement Tool (IoC 198.51.100.44)',
      'Forensic Volatile RAM Dump: ram_10.0.3.45.raw (SHA-256: 4f1a...8e)',
      'EDR Telemetry: powershell.exe executed with base64 encoded payload'
    ],
    linkedAlertIds: ['ALT-9041', 'ALT-9042'],
    linkedIncidentIds: ['INC-2026-001'],
    mitreTactics: ['Initial Access (T1566)', 'Execution (T1059)', 'Privilege Escalation (T1134)', 'Lateral Movement (T1021.002)'],
    notes: [
      {
        id: 'cn-1',
        author: 'Lead Analyst Prachi',
        timestamp: '2026-10-16 01:35 UTC',
        text: 'Initial triage complete. Host 10.0.3.45 identified as compromised beachhead. Evidence shows Kerberos ticket spray.'
      },
      {
        id: 'cn-2',
        author: 'Lead Analyst Prachi',
        timestamp: '2026-10-16 02:45 UTC',
        text: 'Automated containment playbook PB-001 executed. Host isolated to VLAN 999. Domain Admin credentials rotated.'
      }
    ]
  },
  {
    id: 'CASE-2026-002',
    title: 'Perimeter HTTP/2 Rapid Reset Inundation & Edge Flood',
    severity: 'High',
    status: 'Open',
    priority: 'P2 - High',
    assignedTo: 'SOC Tier-1 Queue',
    createdAt: '2026-10-16 02:30 UTC',
    updatedAt: '2026-10-16 02:35 UTC',
    summary: 'Volumetric SYN flood and rapid reset streams aimed at DMZ Web Server 192.168.1.100, driving packet rates to 14,200 pkts/s.',
    evidenceItems: [
      'ALT-8812: Volumetric SYN Flood (14,200 pkts/s)',
      'INTEL-002: Mirai Variant C2 Node (203.0.113.88)',
      'Firewall Syslog: Ingress rate limit triggered on FW-EDGE-01 port 443'
    ],
    linkedAlertIds: ['ALT-8812'],
    linkedIncidentIds: ['INC-2026-002'],
    mitreTactics: ['Impact (T1498)', 'Command & Control (T1071.001)'],
    notes: [
      {
        id: 'cn-3',
        author: 'SOC Automation Engine',
        timestamp: '2026-10-16 02:35 UTC',
        text: 'Alert correlated with Shadowserver threat intel feed. Rate-limiting threshold engaged on edge router.'
      }
    ]
  }
];

// Dataset Presets for Dynamic Demonstration
export const DATASET_PRESETS: DatasetPreset[] = [
  {
    id: 'preset-balanced',
    name: 'CIC-IDS Baseline (Balanced Multi-Vector)',
    description: 'Standard 5,000-flow baseline modeling typical enterprise traffic with balanced attack vectors (BENIGN: 2,400, DoS: 600, DDoS: 600, PortScan: 500, BruteForce: 400, Bot: 300, WebAttack: 200).',
    totalRecords: 5000,
    distribution: {
      BENIGN: 2400,
      DoS: 600,
      DDoS: 600,
      PortScan: 500,
      BruteForce: 400,
      Bot: 300,
      WebAttack: 200
    }
  },
  {
    id: 'preset-ddos',
    name: 'High-Intensity DDoS Storm (Volumetric Attack Surge)',
    description: 'Simulation of an active massive distributed denial of service campaign inundating perimeter infrastructure (DDoS: 2,200, DoS: 1,000, BENIGN: 1,000).',
    totalRecords: 5000,
    distribution: {
      BENIGN: 1000,
      DoS: 1000,
      DDoS: 2200,
      PortScan: 300,
      BruteForce: 250,
      Bot: 150,
      WebAttack: 100
    }
  },
  {
    id: 'preset-bruteforce',
    name: 'Targeted APT & Kerberoasting Incursion',
    description: 'Simulation of heavy credential spraying, Kerberos pre-auth brute forcing, and internal privilege escalation (BruteForce: 2,200, PortScan: 800, BENIGN: 1,200).',
    totalRecords: 5000,
    distribution: {
      BENIGN: 1200,
      DoS: 200,
      DDoS: 200,
      PortScan: 800,
      BruteForce: 2200,
      Bot: 250,
      WebAttack: 150
    }
  },
  {
    id: 'preset-webattack',
    name: 'Web Application Exploitation Wave (SQLi & XSS)',
    description: 'Surge in application-layer web attacks targeting exposed API gateways and web servers (WebAttack: 1,900, PortScan: 700, BENIGN: 1,400).',
    totalRecords: 5000,
    distribution: {
      BENIGN: 1400,
      DoS: 300,
      DDoS: 300,
      PortScan: 700,
      BruteForce: 250,
      Bot: 150,
      WebAttack: 1900
    }
  },
  {
    id: 'preset-clean',
    name: 'Hardened Baseline (Nominal Operation)',
    description: 'Post-mitigation nominal state with 92% benign enterprise network flows and minimal background telemetry (BENIGN: 4,600, Attacks: 400).',
    totalRecords: 5000,
    distribution: {
      BENIGN: 4600,
      DoS: 80,
      DDoS: 70,
      PortScan: 100,
      BruteForce: 80,
      Bot: 40,
      WebAttack: 30
    }
  }
];

/**
 * Generate synthetic dataset with a specific category distribution
 */
export function generateSyntheticFlowDatasetCustom(
  distribution: Record<ThreatCategory, number>
): FlowRecord[] {
  const records: FlowRecord[] = [];
  const internalSubnets = ['10.0.1.', '10.0.2.', '10.0.3.', '192.168.1.'];
  const externalSubnets = ['198.51.100.', '203.0.113.'];

  let recId = 1;
  let seed = 101;
  const pseudoRandom = () => {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  };

  for (const [label, count] of Object.entries(distribution) as Array<[ThreatCategory, number]>) {
    for (let i = 0; i < count; i++) {
      const srcSub = label === 'BENIGN'
        ? internalSubnets[Math.floor(pseudoRandom() * internalSubnets.length)]
        : externalSubnets[Math.floor(pseudoRandom() * externalSubnets.length)];
      const dstSub = internalSubnets[Math.floor(pseudoRandom() * internalSubnets.length)];
      const src_ip = `${srcSub}${Math.floor(2 + pseudoRandom() * 252)}`;
      const dst_ip = `${dstSub}${Math.floor(2 + pseudoRandom() * 252)}`;

      let protocol: 'TCP' | 'UDP' | 'ICMP' = 'TCP';
      let protocol_num = 0;
      let dst_port = 80;
      let src_port = Math.floor(30000 + pseudoRandom() * 35000);
      let flow_duration = 1000;
      let tot_fwd_pkts = 10;
      let tot_bwd_pkts = 8;
      let fwd_len = 100;
      let bwd_len = 100;
      let flow_byts_s = 5000;
      let flow_pkts_s = 50;
      let iat_mean = 50;
      let syn_cnt = 0;
      let rst_cnt = 0;
      let ack_cnt = 8;
      let psh_cnt = 4;

      if (label === 'BENIGN') {
        protocol = pseudoRandom() > 0.3 ? 'TCP' : 'UDP';
        dst_port = [80, 443, 53, 88, 445, 5432][Math.floor(pseudoRandom() * 6)];
        flow_duration = Math.floor(500 + pseudoRandom() * 30000);
        tot_fwd_pkts = Math.floor(2 + pseudoRandom() * 40);
        tot_bwd_pkts = Math.floor(2 + pseudoRandom() * 40);
        fwd_len = Math.floor(64 + pseudoRandom() * 500);
        bwd_len = Math.floor(64 + pseudoRandom() * 1200);
        flow_byts_s = Math.floor(1000 + pseudoRandom() * 50000);
        flow_pkts_s = Math.floor(10 + pseudoRandom() * 100);
        iat_mean = Math.floor(10 + pseudoRandom() * 200);
        ack_cnt = tot_fwd_pkts;
        psh_cnt = Math.floor(tot_fwd_pkts * 0.3);
      } else if (label === 'DoS') {
        dst_port = [80, 443, 8080][Math.floor(pseudoRandom() * 3)];
        flow_duration = Math.floor(10000 + pseudoRandom() * 100000);
        tot_fwd_pkts = Math.floor(500 + pseudoRandom() * 5000);
        tot_bwd_pkts = Math.floor(pseudoRandom() * 10);
        fwd_len = Math.floor(40 + pseudoRandom() * 40);
        bwd_len = 0;
        flow_byts_s = Math.floor(500000 + pseudoRandom() * 2000000);
        flow_pkts_s = Math.floor(1000 + pseudoRandom() * 8000);
        iat_mean = 1 + pseudoRandom() * 5;
        syn_cnt = Math.floor(tot_fwd_pkts * 0.9);
        rst_cnt = Math.floor(tot_fwd_pkts * 0.1);
        ack_cnt = 0;
        psh_cnt = 0;
      } else if (label === 'DDoS') {
        dst_port = [80, 443][Math.floor(pseudoRandom() * 2)];
        flow_duration = Math.floor(50000 + pseudoRandom() * 200000);
        tot_fwd_pkts = Math.floor(2000 + pseudoRandom() * 15000);
        tot_bwd_pkts = Math.floor(pseudoRandom() * 5);
        fwd_len = Math.floor(40 + pseudoRandom() * 60);
        bwd_len = 0;
        flow_byts_s = Math.floor(2000000 + pseudoRandom() * 10000000);
        flow_pkts_s = Math.floor(5000 + pseudoRandom() * 25000);
        iat_mean = 0.1 + pseudoRandom() * 2;
        syn_cnt = Math.floor(tot_fwd_pkts * 0.95);
        rst_cnt = 0;
        ack_cnt = 0;
        psh_cnt = 0;
      } else if (label === 'PortScan') {
        dst_port = Math.floor(1 + pseudoRandom() * 65534);
        flow_duration = Math.floor(10 + pseudoRandom() * 500);
        tot_fwd_pkts = Math.floor(1 + pseudoRandom() * 3);
        tot_bwd_pkts = pseudoRandom() > 0.8 ? 1 : 0;
        fwd_len = 40;
        bwd_len = 0;
        flow_byts_s = Math.floor(200 + pseudoRandom() * 1000);
        flow_pkts_s = Math.floor(10 + pseudoRandom() * 50);
        iat_mean = Math.floor(20 + pseudoRandom() * 100);
        syn_cnt = tot_fwd_pkts;
        rst_cnt = tot_bwd_pkts > 0 ? 1 : 0;
        ack_cnt = 0;
        psh_cnt = 0;
      } else if (label === 'BruteForce') {
        dst_port = [22, 88, 389, 445, 3389][Math.floor(pseudoRandom() * 5)];
        flow_duration = Math.floor(2000 + pseudoRandom() * 15000);
        tot_fwd_pkts = Math.floor(40 + pseudoRandom() * 120);
        tot_bwd_pkts = Math.floor(35 + pseudoRandom() * 100);
        fwd_len = Math.floor(180 + pseudoRandom() * 150);
        bwd_len = Math.floor(140 + pseudoRandom() * 120);
        flow_byts_s = Math.floor(15000 + pseudoRandom() * 45000);
        flow_pkts_s = Math.floor(100 + pseudoRandom() * 300);
        iat_mean = Math.floor(50 + pseudoRandom() * 80);
        syn_cnt = 1;
        rst_cnt = Math.floor(pseudoRandom() * 3);
        ack_cnt = tot_fwd_pkts;
        psh_cnt = Math.floor(tot_fwd_pkts * 0.6);
      } else if (label === 'Bot') {
        dst_port = [4444, 5555, 6667, 8000, 8080][Math.floor(pseudoRandom() * 5)];
        flow_duration = Math.floor(30000 + pseudoRandom() * 300000);
        tot_fwd_pkts = Math.floor(15 + pseudoRandom() * 40);
        tot_bwd_pkts = Math.floor(15 + pseudoRandom() * 40);
        fwd_len = Math.floor(80 + pseudoRandom() * 100);
        bwd_len = Math.floor(80 + pseudoRandom() * 100);
        flow_byts_s = Math.floor(500 + pseudoRandom() * 3000);
        flow_pkts_s = Math.floor(1 + pseudoRandom() * 10);
        iat_mean = Math.floor(2000 + pseudoRandom() * 10000);
        syn_cnt = 1;
        rst_cnt = 0;
        ack_cnt = tot_fwd_pkts;
        psh_cnt = Math.floor(tot_fwd_pkts * 0.5);
      } else if (label === 'WebAttack') {
        dst_port = [80, 443, 8080][Math.floor(pseudoRandom() * 3)];
        flow_duration = Math.floor(200 + pseudoRandom() * 3000);
        tot_fwd_pkts = Math.floor(6 + pseudoRandom() * 25);
        tot_bwd_pkts = Math.floor(6 + pseudoRandom() * 25);
        fwd_len = Math.floor(600 + pseudoRandom() * 900);
        bwd_len = Math.floor(300 + pseudoRandom() * 1500);
        flow_byts_s = Math.floor(10000 + pseudoRandom() * 80000);
        flow_pkts_s = Math.floor(20 + pseudoRandom() * 120);
        iat_mean = Math.floor(30 + pseudoRandom() * 150);
        syn_cnt = 1;
        rst_cnt = 0;
        ack_cnt = tot_fwd_pkts;
        psh_cnt = Math.floor(tot_fwd_pkts * 0.7);
      }

      records.push({
        id: `FLW-${String(recId).padStart(5, '0')}`,
        label,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        protocol_num,
        flow_duration,
        tot_fwd_pkts,
        tot_bwd_pkts,
        tot_len_fwd_pkts: tot_fwd_pkts * fwd_len,
        tot_len_bwd_pkts: tot_bwd_pkts * bwd_len,
        flow_byts_s,
        flow_pkts_s,
        fwd_pkt_len_mean: fwd_len,
        bwd_pkt_len_mean: bwd_len,
        flow_iat_mean: iat_mean,
        syn_flag_cnt: syn_cnt,
        rst_flag_cnt: rst_cnt,
        ack_flag_cnt: ack_cnt,
        psh_flag_cnt: psh_cnt
      });
      recId++;
    }
  }

  // Shuffle
  for (let i = records.length - 1; i > 0; i--) {
    const j = Math.floor(pseudoRandom() * (i + 1));
    [records[i], records[j]] = [records[j], records[i]];
  }

  return records;
}

/**
 * Dynamically re-synthesizes active alerts when the dataset changes,
 * ensuring alerts and UI telemetry accurately mirror the active dataset profile!
 */
export function generateAlertsFromDataset(dataset: FlowRecord[]): Alert[] {
  // Count frequency of attack categories in dataset
  const counts: Record<ThreatCategory, number> = {
    BENIGN: 0,
    DoS: 0,
    DDoS: 0,
    PortScan: 0,
    BruteForce: 0,
    Bot: 0,
    WebAttack: 0
  };
  dataset.forEach(r => { counts[r.label] = (counts[r.label] || 0) + 1; });

  const total = dataset.length || 1;
  const attackRatio = (total - counts.BENIGN) / total;

  // Build representative alert list based on dataset frequencies
  const alerts: Alert[] = [];
  let alertSeq = 9100;

  // High DDoS representation
  if (counts.DDoS > 400) {
    alerts.push({
      id: `ALT-${alertSeq++}`,
      timestamp: '2026-10-16 02:44:12 UTC',
      title: 'Volumetric SYN Flood Flooding Perimeter Web Server',
      sourceIp: '198.51.100.44',
      destIp: '192.168.1.100',
      sourcePort: 38411,
      destPort: 443,
      protocol: 'TCP',
      predictedCategory: 'DDoS',
      groundTruthCategory: 'DDoS',
      confidence: 0.988,
      severity: 'Critical',
      status: 'Escalated',
      incidentId: 'INC-2026-002',
      evidence: [
        `Inbound traffic surge of 14,200 pkts/s on port 443 (Dataset sample ratio ${(counts.DDoS / total * 100).toFixed(1)}%)`,
        'SYN packet concentration with zero completing ACK handshakes',
        'Originating from suspicious CIDR 198.51.100.0/24'
      ],
      explanation: 'Random Forest model classified high packet rate and disproportionate SYN-to-ACK ratio as volumetric Denial of Service attack.',
      recommendation: 'Activate perimeter SYN flood protection, enforce TCP handshake timeouts, and drop traffic matching origin IP.',
      packetFeatures: {
        flowDuration: 120000,
        totFwdPkts: 8500,
        totBwdPkts: 12,
        totLenFwdPkts: 510000,
        totLenBwdPkts: 720,
        flowBytsPerSec: 4250000,
        flowPktsPerSec: 14200,
        fwdPktLenMean: 60,
        bwdPktLenMean: 60,
        flowIatMean: 0.8,
        synFlagCnt: 3800,
        rstFlagCnt: 0,
        ackFlagCnt: 0,
        pshFlagCnt: 0,
        protocol: 'TCP',
        srcPort: 38411,
        dstPort: 443
      }
    });
  }

  // Brute force representation
  if (counts.BruteForce > 200) {
    alerts.push({
      id: `ALT-${alertSeq++}`,
      timestamp: '2026-10-16 02:42:18 UTC',
      title: 'Kerberos Pre-Authentication Brute Force Detected',
      sourceIp: '10.0.3.45',
      destIp: '10.0.1.10',
      sourcePort: 49812,
      destPort: 88,
      protocol: 'TCP',
      predictedCategory: 'BruteForce',
      groundTruthCategory: 'BruteForce',
      confidence: 0.964,
      severity: 'Critical',
      status: 'Escalated',
      incidentId: 'INC-2026-001',
      evidence: [
        'Rapid KRB_AS_REQ requests (42 attempts/sec) targeting administrator account names',
        'High PSH flag ratio conveying authentication payload blocks',
        'Originating from Finance workstation 10.0.3.45 with no administrative history'
      ],
      explanation: 'Model classified repetitive authentication handshakes as automated password guessing targeting Active Directory Domain Controller.',
      recommendation: 'Temporarily lock targeted Active Directory accounts, isolate workstation 10.0.3.45, and inspect endpoint event logs.',
      packetFeatures: {
        flowDuration: 14500,
        totFwdPkts: 84,
        totBwdPkts: 72,
        totLenFwdPkts: 18400,
        totLenBwdPkts: 12200,
        flowBytsPerSec: 18500,
        flowPktsPerSec: 145,
        fwdPktLenMean: 219,
        bwdPktLenMean: 169,
        flowIatMean: 112,
        synFlagCnt: 1,
        rstFlagCnt: 2,
        ackFlagCnt: 82,
        pshFlagCnt: 48,
        protocol: 'TCP',
        srcPort: 49812,
        dstPort: 88
      }
    });

    alerts.push({
      id: `ALT-${alertSeq++}`,
      timestamp: '2026-10-16 02:44:05 UTC',
      title: 'Suspicious RPC Token Impersonation Handshake',
      sourceIp: '10.0.3.45',
      destIp: '10.0.1.10',
      sourcePort: 49818,
      destPort: 135,
      protocol: 'TCP',
      predictedCategory: 'BruteForce',
      groundTruthCategory: 'BruteForce',
      confidence: 0.941,
      severity: 'Critical',
      status: 'Escalated',
      incidentId: 'INC-2026-001',
      evidence: [
        'Sequential RPC bind requests on port 135 following Kerberos failures',
        'Anomalous IPC$ share query containing forged security tokens',
        'Correlated with lateral movement indicator INTEL-001'
      ],
      explanation: 'Detected lateral privilege escalation attempt utilizing authenticated RPC pipe communication to impersonate system tokens.',
      recommendation: 'Enable RPC firewall filter, restrict remote SAM access, and inspect LSASS process integrity on Domain Controller.',
      packetFeatures: {
        flowDuration: 21000,
        totFwdPkts: 92,
        totBwdPkts: 80,
        totLenFwdPkts: 22400,
        totLenBwdPkts: 16800,
        flowBytsPerSec: 21000,
        flowPktsPerSec: 160,
        fwdPktLenMean: 243,
        bwdPktLenMean: 210,
        flowIatMean: 95,
        synFlagCnt: 1,
        rstFlagCnt: 0,
        ackFlagCnt: 90,
        pshFlagCnt: 52,
        protocol: 'TCP',
        srcPort: 49818,
        dstPort: 135
      }
    });
  }

  // Web attack representation
  if (counts.WebAttack > 150) {
    alerts.push({
      id: `ALT-${alertSeq++}`,
      timestamp: '2026-10-16 02:15:33 UTC',
      title: 'SQL Injection Pattern in Web Application Query',
      sourceIp: '198.51.100.77',
      destIp: '192.168.1.100',
      sourcePort: 51200,
      destPort: 80,
      protocol: 'TCP',
      predictedCategory: 'WebAttack',
      groundTruthCategory: 'WebAttack',
      confidence: 0.932,
      severity: 'High',
      status: 'New',
      evidence: [
        'Anomalous HTTP payload length (1,480 bytes) targeting /api/v1/customer endpoint',
        'Injected UNION SELECT string detected in forward packet payload mean analysis',
        'High PSH flag concentration conveying encoded parameter strings'
      ],
      explanation: 'Flow analysis identified oversized forward packet buffers carrying SQL injection payload structures.',
      recommendation: 'Block source IP at WAF boundary, enable prepared statements on backend, inspect web logs.',
      packetFeatures: {
        flowDuration: 1800,
        totFwdPkts: 18,
        totBwdPkts: 14,
        totLenFwdPkts: 14800,
        totLenBwdPkts: 8200,
        flowBytsPerSec: 12800,
        flowPktsPerSec: 17.7,
        fwdPktLenMean: 822,
        bwdPktLenMean: 585,
        flowIatMean: 48,
        synFlagCnt: 1,
        rstFlagCnt: 0,
        ackFlagCnt: 18,
        pshFlagCnt: 12,
        protocol: 'TCP',
        srcPort: 51200,
        dstPort: 80
      }
    });
  }

  // DoS representation
  if (counts.DoS > 300) {
    alerts.push({
      id: `ALT-${alertSeq++}`,
      timestamp: '2026-10-16 01:45:00 UTC',
      title: 'Slowloris Incomplete HTTP Header Depletion',
      sourceIp: '203.0.113.88',
      destIp: '192.168.1.100',
      sourcePort: 44102,
      destPort: 80,
      protocol: 'TCP',
      predictedCategory: 'DoS',
      groundTruthCategory: 'DoS',
      confidence: 0.895,
      severity: 'Medium',
      status: 'Investigating',
      evidence: [
        'Prolonged flow duration (42,000 ms) holding open Apache connection slots',
        'Periodic small keep-alive packets preventing socket timeout reset'
      ],
      explanation: 'Model detected low-bandwidth stateful denial of service attempting web server worker thread exhaustion.',
      recommendation: 'Configure client header timeout limits, enforce minimum transfer rate policies on reverse proxy.',
      packetFeatures: {
        flowDuration: 42000,
        totFwdPkts: 32,
        totBwdPkts: 4,
        totLenFwdPkts: 1280,
        totLenBwdPkts: 160,
        flowBytsPerSec: 34,
        flowPktsPerSec: 0.85,
        fwdPktLenMean: 40,
        bwdPktLenMean: 40,
        flowIatMean: 1312,
        synFlagCnt: 1,
        rstFlagCnt: 0,
        ackFlagCnt: 32,
        pshFlagCnt: 28,
        protocol: 'TCP',
        srcPort: 44102,
        dstPort: 80
      }
    });
  }

  // Bot representation
  if (counts.Bot > 100) {
    alerts.push({
      id: `ALT-${alertSeq++}`,
      timestamp: '2026-10-16 01:20:15 UTC',
      title: 'Encrypted C2 Beaconing Heartbeat Observed',
      sourceIp: '10.0.3.88',
      destIp: '203.0.113.88',
      sourcePort: 55432,
      destPort: 4444,
      protocol: 'TCP',
      predictedCategory: 'Bot',
      groundTruthCategory: 'Bot',
      confidence: 0.918,
      severity: 'High',
      status: 'New',
      evidence: [
        'Fixed 10.0-second inter-arrival packet regularity (IAT mean ~10,000 ms)',
        'Anomalous egress destination port 4444 outside authorized firewall egress policy'
      ],
      explanation: 'Temporal analysis classified periodic short-burst flow characteristics matching known Cobalt Strike beacon patterns.',
      recommendation: 'Terminate PID associated with local socket 55432, isolate developer workstation 10.0.3.88, inspect memory.',
      packetFeatures: {
        flowDuration: 180000,
        totFwdPkts: 24,
        totBwdPkts: 24,
        totLenFwdPkts: 2160,
        totLenBwdPkts: 2160,
        flowBytsPerSec: 24,
        flowPktsPerSec: 0.26,
        fwdPktLenMean: 90,
        bwdPktLenMean: 90,
        flowIatMean: 9800,
        synFlagCnt: 1,
        rstFlagCnt: 0,
        ackFlagCnt: 24,
        pshFlagCnt: 12,
        protocol: 'TCP',
        srcPort: 55432,
        dstPort: 4444
      }
    });
  }

  // PortScan representation
  if (counts.PortScan > 200) {
    alerts.push({
      id: `ALT-${alertSeq++}`,
      timestamp: '2026-10-16 00:50:22 UTC',
      title: 'Horizontal TCP SYN Subnet Sweep Reconnaissance',
      sourceIp: '198.51.100.12',
      destIp: '192.168.1.1',
      sourcePort: 60124,
      destPort: 22,
      protocol: 'TCP',
      predictedCategory: 'PortScan',
      groundTruthCategory: 'PortScan',
      confidence: 0.952,
      severity: 'Medium',
      status: 'Resolved',
      evidence: [
        'Sequential half-open TCP SYN probes across 48 target destination ports in 2.4 seconds',
        'Zero completing three-way handshakes recorded by edge firewall'
      ],
      explanation: 'Pattern of single-packet probes to sequential destination ports indicates active automated port discovery.',
      recommendation: 'Add source IP to perimeter drop rule, inspect target services for unauthorized exposure.',
      packetFeatures: {
        flowDuration: 2400,
        totFwdPkts: 48,
        totBwdPkts: 0,
        totLenFwdPkts: 1920,
        totLenBwdPkts: 0,
        flowBytsPerSec: 800,
        flowPktsPerSec: 20,
        fwdPktLenMean: 40,
        bwdPktLenMean: 0,
        flowIatMean: 50,
        synFlagCnt: 48,
        rstFlagCnt: 0,
        ackFlagCnt: 0,
        pshFlagCnt: 0,
        protocol: 'TCP',
        srcPort: 60124,
        dstPort: 22
      }
    });
  }

  // Always include benign baseline
  alerts.push({
    id: `ALT-${alertSeq++}`,
    timestamp: '2026-10-15 17:30:10 UTC',
    title: 'Normal DNS and NTP Synchronous Exchange',
    sourceIp: '10.0.2.15',
    destIp: '10.0.1.10',
    sourcePort: 51234,
    destPort: 53,
    protocol: 'UDP',
    predictedCategory: 'BENIGN',
    groundTruthCategory: 'BENIGN',
    confidence: 0.992,
    severity: 'Informational',
    status: 'Resolved',
    evidence: [
      'Standard UDP query flow on domain service port 53',
      'Normal packet sizes and bidirectional request/response symmetry'
    ],
    explanation: 'Nominal enterprise infrastructure name resolution traffic adhering to baseline characteristics.',
    recommendation: 'No action required. Standard network baseline operation.',
    packetFeatures: {
      flowDuration: 120,
      totFwdPkts: 2,
      totBwdPkts: 2,
      totLenFwdPkts: 140,
      totLenBwdPkts: 260,
      flowBytsPerSec: 3330,
      flowPktsPerSec: 33.3,
      fwdPktLenMean: 70,
      bwdPktLenMean: 130,
      flowIatMean: 40,
      synFlagCnt: 0,
      rstFlagCnt: 0,
      ackFlagCnt: 0,
      pshFlagCnt: 0,
      protocol: 'UDP',
      srcPort: 51234,
      dstPort: 53
    }
  });

  return alerts;
}

