import React, { useState, useEffect } from 'react';
import {
  X,
  Radio,
  Activity,
  Shield,
  Server,
  Network,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Play,
  Square,
  ArrowRight,
  Send,
  Download,
  Filter,
  Eye,
  Lock,
  Layers,
  FileCode,
  Zap,
  Globe,
  RefreshCw
} from 'lucide-react';
import { socApi } from '../../services/api';
import {
  NetworkIntelligence,
  SecurityCenterConnector,
  LivePacketFlow,
  Severity
} from '../../types/soc';

interface SecurityCenterConnectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRefreshData: () => Promise<void>;
}

export const SecurityCenterConnectModal: React.FC<SecurityCenterConnectModalProps> = ({
  isOpen,
  onClose,
  onRefreshData
}) => {
  const [activeTab, setActiveTab] = useState<'connectors' | 'inspector' | 'intelligence' | 'ingest'>('intelligence');
  const [connectors, setConnectors] = useState<SecurityCenterConnector[]>([]);
  const [intelligence, setIntelligence] = useState<NetworkIntelligence | null>(null);
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [selectedFlow, setSelectedFlow] = useState<LivePacketFlow | null>(null);

  // Manual raw log ingest state
  const [rawLogInput, setRawLogInput] = useState<string>('');
  const [logFormat, setLogFormat] = useState<string>('syslog');
  const [ingestStatus, setIngestStatus] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen) return;

    const loadIntel = async () => {
      const conns = await socApi.getSecurityCenterConnectors();
      const intel = await socApi.getNetworkIntelligence();
      setConnectors(conns);
      setIntelligence(intel);
    };

    loadIntel();

    // Live telemetry poll interval when streaming is active
    let interval: any = null;
    if (isStreaming) {
      interval = setInterval(async () => {
        const intel = await socApi.getNetworkIntelligence();
        setIntelligence(intel);
      }, 2000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isOpen, isStreaming]);

  if (!isOpen) return null;

  const handleIngestRawLog = async () => {
    if (!rawLogInput.trim()) return;
    setIngestStatus('Ingesting & running threat classification...');
    try {
      const res = await socApi.ingestRawLog(rawLogInput, logFormat);
      setIngestStatus(`Success: ${res.details}`);
      setRawLogInput('');
      const updatedIntel = await socApi.getNetworkIntelligence();
      setIntelligence(updatedIntel);
      await onRefreshData();
      setTimeout(() => setIngestStatus(null), 5000);
    } catch (err: any) {
      setIngestStatus(`Error: ${err?.message || 'Failed to ingest log'}`);
    }
  };

  const loadSampleLog = (type: 'syn' | 'krb' | 'c2' | 'sqli') => {
    if (type === 'syn') {
      setLogFormat('syslog');
      setRawLogInput(
        '<134>1 2026-10-28T07:15:32.124Z fw-edge-01 kernel - - - [IPTABLES_SYN_FLOOD] IN=eth0 OUT=eth1 MAC=00:1a:2b:3c:4d:5e SRC=198.51.100.99 DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=54 ID=41234 DF PROTO=TCP SPT=51420 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0 attack_type="ddos"'
      );
    } else if (type === 'krb') {
      setLogFormat('suricata');
      setRawLogInput(
        '{"timestamp":"2026-10-28T07:14:10.512Z","event_type":"alert","src_ip":"10.0.3.45","src_port":49812,"dest_ip":"10.0.1.10","dest_port":88,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2014812,"rev":3,"signature":"ET POLICY Kerberos Pre-Authentication Brute-Force KRB5KDC_ERR_PREAUTH_FAILED","category":"Attempted Information Leak","severity":1}}'
      );
    } else if (type === 'c2') {
      setLogFormat('zeek');
      setRawLogInput(
        '1761635800.12\tCHa7b93WsvfqZsmAd\t10.0.3.88\t55432\t203.0.113.88\t4444\ttcp\tssl\t180.20\t2160\t2160\tSF\t-\t-\t0\tShADadFf\t24\t24\tT\tperiodic_beacon_cobalt_strike'
      );
    } else {
      setLogFormat('syslog');
      setRawLogInput(
        '<131>1 2026-10-28T07:12:00.000Z dmz-web-01 nginx - - - 198.51.100.44 - - [28/Oct/2026:07:12:00 +0000] "GET /api/v1/users?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20admin_credentials-- HTTP/1.1" 403 162 "-" "sqlmap/1.8#stable" sqli'
      );
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 bg-black/85 backdrop-blur-md animate-in fade-in duration-150">
      <div className="bg-[#070b16] border border-[#1b2f52] rounded-xl max-w-5xl w-full flex flex-col shadow-2xl overflow-hidden font-mono text-xs max-h-[92vh]">
        {/* Top Header */}
        <div className="flex items-center justify-between p-4 border-b border-[#16233b] bg-[#0c1424]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-emerald-950/70 rounded border border-emerald-500/40 text-emerald-400">
              <Radio className={`w-5 h-5 ${isStreaming ? 'animate-pulse' : ''}`} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white tracking-wide">
                  Real-World Security Center Integration & Network Intelligence
                </h2>
                <span className="text-[10px] bg-emerald-950 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/30 flex items-center gap-1 font-bold">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                  LIVE TELEMETRY INGESTION
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                Connected to enterprise Syslog (RFC 5424), Splunk HEC, Zeek IDS, and Suricata taps. Deep packet flow inspection & network posture intelligence.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsStreaming(!isStreaming)}
              className={`px-3 py-1.5 rounded text-[11px] font-bold border transition-all flex items-center gap-1.5 ${
                isStreaming
                  ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/50 shadow-lg shadow-emerald-900/30'
                  : 'bg-[#0f172a] text-slate-400 border-slate-700 hover:text-white'
              }`}
            >
              {isStreaming ? <Activity className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              <span>{isStreaming ? 'Stream: ACTIVE' : 'Resume Stream'}</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded bg-[#101b2f] hover:bg-[#162540] transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 px-4 pt-2.5 border-b border-[#16233b] bg-[#060a14]">
          <button
            onClick={() => setActiveTab('intelligence')}
            className={`px-3.5 py-1.5 rounded-t font-semibold transition-colors flex items-center gap-1.5 ${
              activeTab === 'intelligence'
                ? 'bg-[#0c162c] text-cyan-400 border-t border-x border-[#1b2b47]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            Network Intelligence ("Tell All Things")
          </button>

          <button
            onClick={() => setActiveTab('inspector')}
            className={`px-3.5 py-1.5 rounded-t font-semibold transition-colors flex items-center gap-1.5 ${
              activeTab === 'inspector'
                ? 'bg-[#0c162c] text-cyan-400 border-t border-x border-[#1b2b47]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Eye className="w-3.5 h-3.5" />
            Live Packet & Flow Inspector ({intelligence?.recentFlows.length || 0})
          </button>

          <button
            onClick={() => setActiveTab('connectors')}
            className={`px-3.5 py-1.5 rounded-t font-semibold transition-colors flex items-center gap-1.5 ${
              activeTab === 'connectors'
                ? 'bg-[#0c162c] text-cyan-400 border-t border-x border-[#1b2b47]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            Security Center Connectors (5 Active)
          </button>

          <button
            onClick={() => setActiveTab('ingest')}
            className={`px-3.5 py-1.5 rounded-t font-semibold transition-colors flex items-center gap-1.5 ${
              activeTab === 'ingest'
                ? 'bg-[#0c162c] text-cyan-400 border-t border-x border-[#1b2b47]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            Ingest Raw Log / PCAP Sample
          </button>
        </div>

        {/* Tab Body */}
        <div className="p-4 overflow-y-auto space-y-4 max-h-[75vh]">
          {/* TAB 1: NETWORK INTELLIGENCE ("TELL ALL THINGS ABOUT THE NETWORK") */}
          {activeTab === 'intelligence' && intelligence && (
            <div className="space-y-4">
              {/* Top Intelligence Ribbon */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-3 bg-[#0a1324] border border-[#182740] rounded-lg">
                  <span className="text-[10px] text-slate-400 uppercase">Network Resilience Index</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-2xl font-bold text-emerald-400">{intelligence.resilienceScore}/100</span>
                    <span className="text-[10px] text-emerald-300 font-bold">Good Defense</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1.5">
                    <div className="bg-emerald-400 h-full" style={{ width: `${intelligence.resilienceScore}%` }} />
                  </div>
                </div>

                <div className="p-3 bg-[#0a1324] border border-[#182740] rounded-lg">
                  <span className="text-[10px] text-slate-400 uppercase">Current Throughput</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-2xl font-bold text-cyan-400">{intelligence.totalBandwidthMbps}</span>
                    <span className="text-[10px] text-slate-400">Mbps</span>
                  </div>
                  <span className="text-[10px] text-slate-500">{(intelligence.packetsPerSecond).toLocaleString()} packets/sec</span>
                </div>

                <div className="p-3 bg-[#0a1324] border border-[#182740] rounded-lg">
                  <span className="text-[10px] text-slate-400 uppercase">Discovered Live Hosts</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-2xl font-bold text-purple-300">{intelligence.totalActiveHosts}</span>
                    <span className="text-[10px] text-slate-400">Endpoints</span>
                  </div>
                  <span className="text-[10px] text-slate-500">Across 5 mapped subnets</span>
                </div>

                <div className="p-3 bg-[#0a1324] border border-[#182740] rounded-lg">
                  <span className="text-[10px] text-slate-400 uppercase">Active Threat Ingress</span>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-2xl font-bold text-red-400">{intelligence.anomalies.length}</span>
                    <span className="text-[10px] text-red-300 font-bold">Critical Anomalies</span>
                  </div>
                  <span className="text-[10px] text-slate-500">Automatic mitigation triggered</span>
                </div>
              </div>

              {/* Subnet Topology Cartography */}
              <div className="p-3 bg-[#081020] border border-[#182a47] rounded-lg space-y-2">
                <div className="flex items-center justify-between border-b border-[#16233b] pb-1.5">
                  <div className="flex items-center gap-1.5 text-cyan-400 font-bold">
                    <Network className="w-4 h-4" />
                    <span>Discovered Internal Subnets & Asset Topology</span>
                  </div>
                  <span className="text-[10px] text-slate-400">5 Monitored RFC 1918 CIDR Blocks</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 pt-1">
                  {intelligence.subnets.map(sub => (
                    <div
                      key={sub.id}
                      className="p-2.5 rounded bg-[#0a1426] border border-[#152540] hover:border-cyan-500/40 transition-colors space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white text-[11px]">{sub.name}</span>
                        <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                          sub.riskLevel === 'Critical' ? 'bg-red-950 text-red-400 border border-red-500/40' :
                          sub.riskLevel === 'High' ? 'bg-orange-950 text-orange-400 border border-orange-500/40' :
                          sub.riskLevel === 'Medium' ? 'bg-amber-950 text-amber-300 border border-amber-500/40' :
                          'bg-emerald-950 text-emerald-400 border border-emerald-500/40'
                        }`}>
                          {sub.riskLevel}
                        </span>
                      </div>
                      <div className="text-[10px] text-cyan-300 font-mono">
                        CIDR: <span className="font-bold">{sub.cidr}</span> (GW: {sub.gateway})
                      </div>
                      <div className="text-[10px] text-slate-400">
                        Role: {sub.primaryRole}
                      </div>
                      <div className="flex items-center justify-between pt-1 border-t border-[#132036] text-[10px]">
                        <span className="text-slate-400">Live Endpoints:</span>
                        <span className="font-bold text-slate-200">{sub.liveHosts} / {sub.totalHosts}</span>
                      </div>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {sub.exposedServices.map((svc, i) => (
                          <span key={i} className="text-[9px] bg-[#080d19] text-slate-300 px-1 rounded border border-[#15243d]">
                            {svc}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Protocol Breakdown & Detected Anomalies */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                {/* Protocol Breakdown */}
                <div className="p-3 bg-[#081020] border border-[#182a47] rounded-lg space-y-2">
                  <div className="flex items-center justify-between border-b border-[#16233b] pb-1.5">
                    <span className="font-bold text-slate-200">Protocol & Port Bandwidth Distribution</span>
                    <span className="text-[10px] text-slate-400">Real-Time Flow Telemetry</span>
                  </div>
                  <div className="space-y-1.5 max-h-[220px] overflow-y-auto pr-1">
                    {intelligence.protocols.map((proto, idx) => (
                      <div key={idx} className="p-2 bg-[#091122] rounded border border-[#15243d] flex items-center justify-between">
                        <div>
                          <div className="flex items-center gap-1.5">
                            <span className="font-bold text-white">{proto.protocol} ({proto.port})</span>
                            <span className={`text-[9px] px-1 rounded ${
                              proto.status === 'Anomalous' ? 'bg-red-950 text-red-400 font-bold' :
                              proto.status === 'Elevated' ? 'bg-amber-950 text-amber-300' :
                              'text-slate-500'
                            }`}>
                              {proto.status}
                            </span>
                          </div>
                          <span className="text-[10px] text-slate-400">{proto.service}</span>
                        </div>
                        <div className="text-right">
                          <span className="font-bold text-cyan-400">{proto.percentage}%</span>
                          <div className="text-[10px] text-slate-400">{(proto.bytesTransferred / 1000000).toFixed(1)} MB</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Detected Anomalies */}
                <div className="p-3 bg-[#081020] border border-[#182a47] rounded-lg space-y-2">
                  <div className="flex items-center justify-between border-b border-[#16233b] pb-1.5">
                    <span className="font-bold text-red-400 flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Active Network Anomalies & Mitigations
                    </span>
                    <span className="text-[10px] text-slate-400">{intelligence.anomalies.length} Signals</span>
                  </div>
                  <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
                    {intelligence.anomalies.map(anom => (
                      <div key={anom.id} className="p-2.5 bg-[#091122] rounded border border-red-500/30 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-100">{anom.type}</span>
                          <span className="text-[9px] bg-red-950 text-red-400 font-bold px-1.5 py-0.2 rounded border border-red-500/30">
                            {anom.severity}
                          </span>
                        </div>
                        <p className="text-[10px] text-slate-300 leading-tight">{anom.description}</p>
                        <div className="p-1 bg-[#060b17] rounded text-[10px] text-cyan-300 font-mono">
                          <span className="text-slate-400 font-semibold block text-[9px] uppercase">Recommended Mitigation:</span>
                          {anom.recommendedMitigation}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Automated Security Posture & ACL Recommendations */}
              <div className="p-3 bg-[#081020] border border-[#182a47] rounded-lg space-y-2">
                <div className="flex items-center justify-between border-b border-[#16233b] pb-1.5">
                  <span className="font-bold text-cyan-300 flex items-center gap-1.5">
                    <Shield className="w-4 h-4" />
                    Automated Defensive Diagnosis & Micro-Segmentation ACLs
                  </span>
                  <span className="text-[10px] text-emerald-400 font-bold">Rule Engine Active</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                  <div className="space-y-1 bg-[#091224] p-2.5 rounded border border-[#162540]">
                    <span className="text-amber-400 font-bold uppercase text-[10px] block">Critical Findings:</span>
                    <ul className="list-disc list-inside space-y-1 text-slate-300">
                      {intelligence.postureAssessment.criticalFindings.map((f, i) => (
                        <li key={i}>{f}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="space-y-1 bg-[#091224] p-2.5 rounded border border-[#162540]">
                    <span className="text-cyan-400 font-bold uppercase text-[10px] block">Recommended Firewall ACLs:</span>
                    <ul className="space-y-1 font-mono text-[10px] text-emerald-300">
                      {intelligence.postureAssessment.recommendedAcls.map((acl, i) => (
                        <li key={i} className="bg-[#050a14] p-1 rounded border border-emerald-500/20">
                          {acl}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: LIVE PACKET & FLOW INSPECTOR ("READ AND CATCH ALL DETAILS") */}
          {activeTab === 'inspector' && intelligence && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-slate-400">
                <span>Reading live packets across all security center network taps:</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                  Live Wire Ingestion
                </span>
              </div>

              <div className="overflow-x-auto border border-[#16233b] rounded-lg bg-[#050914]">
                <table className="w-full text-left border-collapse text-[11px]">
                  <thead>
                    <tr className="border-b border-[#1b2b47] text-[10px] text-slate-400 uppercase bg-[#091122]">
                      <th className="py-2 px-2.5">Timestamp</th>
                      <th className="py-2 px-2.5">Source Endpoint</th>
                      <th className="py-2 px-2.5">Target Destination</th>
                      <th className="py-2 px-2.5">Proto / Flags</th>
                      <th className="py-2 px-2.5">Threat Category</th>
                      <th className="py-2 px-2.5 text-center">Confidence</th>
                      <th className="py-2 px-2.5 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#0f1a2e]">
                    {intelligence.recentFlows.map(flow => (
                      <tr
                        key={flow.id}
                        onClick={() => setSelectedFlow(flow)}
                        className="hover:bg-[#0c162b] cursor-pointer transition-colors"
                      >
                        <td className="py-2 px-2.5 text-slate-400 font-mono text-[10px]">{flow.timestamp.split(' ')[1] || flow.timestamp}</td>
                        <td className="py-2 px-2.5 text-cyan-400 font-semibold">{flow.sourceIp}:{flow.sourcePort}</td>
                        <td className="py-2 px-2.5 text-purple-300 font-semibold">{flow.destIp}:{flow.destPort}</td>
                        <td className="py-2 px-2.5">
                          <span className="bg-[#0e172a] px-1 py-0.2 rounded text-slate-300 border border-slate-700 font-bold mr-1">
                            {flow.protocol}
                          </span>
                          {flow.flags.map((flg, fi) => (
                            <span key={fi} className="text-[9px] text-amber-400 font-bold mr-1">
                              [{flg}]
                            </span>
                          ))}
                        </td>
                        <td className="py-2 px-2.5">
                          <span className={`px-1.5 py-0.2 rounded font-bold text-[10px] ${
                            flow.detectedCategory === 'DDoS' || flow.detectedCategory === 'DoS' ? 'bg-red-950 text-red-400 border border-red-500/30' :
                            flow.detectedCategory === 'BruteForce' ? 'bg-orange-950 text-orange-400 border border-orange-500/30' :
                            flow.detectedCategory === 'PortScan' ? 'bg-amber-950 text-amber-300 border border-amber-500/30' :
                            flow.detectedCategory === 'Bot' ? 'bg-purple-950 text-purple-300 border border-purple-500/30' :
                            'bg-emerald-950 text-emerald-400 border border-emerald-500/30'
                          }`}>
                            {flow.detectedCategory}
                          </span>
                        </td>
                        <td className="py-2 px-2.5 text-center font-bold text-slate-200">
                          {(flow.confidence * 100).toFixed(1)}%
                        </td>
                        <td className="py-2 px-2.5 text-right font-bold">
                          <span className={`text-[10px] ${
                            flow.actionTaken === 'Blocked' ? 'text-red-400' :
                            flow.actionTaken === 'Alerted' ? 'text-amber-400' :
                            'text-emerald-400'
                          }`}>
                            {flow.actionTaken}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Selected Flow Inspector Drawer / Modal */}
              {selectedFlow && (
                <div className="p-3 bg-[#091224] border border-cyan-500/40 rounded-lg space-y-2 animate-in fade-in duration-100">
                  <div className="flex items-center justify-between border-b border-[#162540] pb-1.5">
                    <span className="font-bold text-white flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-cyan-400" />
                      Deep Packet Payload & Flow Diagnostics ({selectedFlow.id})
                    </span>
                    <button onClick={() => setSelectedFlow(null)} className="text-slate-400 hover:text-white">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px]">
                    <div className="bg-[#050a14] p-1.5 rounded border border-[#14233d]">
                      <span className="text-slate-500">Source:</span>
                      <p className="font-bold text-cyan-400">{selectedFlow.sourceIp}:{selectedFlow.sourcePort}</p>
                    </div>
                    <div className="bg-[#050a14] p-1.5 rounded border border-[#14233d]">
                      <span className="text-slate-500">Destination:</span>
                      <p className="font-bold text-purple-300">{selectedFlow.destIp}:{selectedFlow.destPort}</p>
                    </div>
                    <div className="bg-[#050a14] p-1.5 rounded border border-[#14233d]">
                      <span className="text-slate-500">Frame Length:</span>
                      <p className="font-bold text-slate-200">{selectedFlow.length} Bytes</p>
                    </div>
                    <div className="bg-[#050a14] p-1.5 rounded border border-[#14233d]">
                      <span className="text-slate-500">Model Decision:</span>
                      <p className="font-bold text-red-400">{selectedFlow.detectedCategory} ({selectedFlow.severity})</p>
                    </div>
                  </div>
                  <div className="bg-[#050a14] p-2 rounded border border-[#14233d]">
                    <span className="text-slate-500 text-[10px] block mb-1">Payload Hex / ASCII Preview:</span>
                    <code className="text-cyan-300 text-[10px] font-mono break-all block">
                      {selectedFlow.payloadPreview}
                    </code>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: CONNECTORS */}
          {activeTab === 'connectors' && (
            <div className="space-y-3">
              <p className="text-slate-400 font-sans text-xs">
                Real-world enterprise telemetry collectors listening and receiving network flows:
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {connectors.map(conn => (
                  <div
                    key={conn.id}
                    className="p-3 bg-[#081020] border border-[#182740] rounded-lg space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Server className="w-4 h-4 text-cyan-400" />
                        <span className="font-bold text-white">{conn.name}</span>
                      </div>
                      <span className="text-[9px] bg-emerald-950 text-emerald-400 font-bold px-2 py-0.5 rounded border border-emerald-500/30 flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                        {conn.status.toUpperCase()}
                      </span>
                    </div>

                    <p className="text-[10px] text-slate-400 font-sans">{conn.description}</p>

                    <div className="grid grid-cols-2 gap-2 bg-[#050a14] p-2 rounded border border-[#14233d] text-[10px]">
                      <div>
                        <span className="text-slate-500">Listener Socket:</span>
                        <p className="text-cyan-300 font-mono">{conn.endpoint}</p>
                      </div>
                      <div>
                        <span className="text-slate-500">Protocol & Latency:</span>
                        <p className="text-slate-200">{conn.protocol} ({conn.latencyMs} ms)</p>
                      </div>
                      <div>
                        <span className="text-slate-500">Events Ingested:</span>
                        <p className="text-white font-bold">{conn.eventsIngested.toLocaleString()}</p>
                      </div>
                      <div>
                        <span className="text-slate-500">Threats Flagged:</span>
                        <p className="text-red-400 font-bold">{conn.threatsDetected.toLocaleString()}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: INGEST RAW LOG / PCAP SAMPLE */}
          {activeTab === 'ingest' && (
            <div className="space-y-3">
              <p className="text-slate-400 font-sans text-xs">
                Paste raw log lines from firewalls, Zeek taps, Suricata EVE JSON, or SIEM exports to parse and categorize network threats in real time:
              </p>

              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] text-slate-400">Load Live Test Samples:</span>
                <button
                  onClick={() => loadSampleLog('syn')}
                  className="px-2.5 py-1 rounded bg-[#0e192e] hover:bg-[#152544] text-red-400 border border-red-500/30 font-bold text-[10px]"
                >
                  DDoS SYN Flood Log
                </button>
                <button
                  onClick={() => loadSampleLog('krb')}
                  className="px-2.5 py-1 rounded bg-[#0e192e] hover:bg-[#152544] text-orange-400 border border-orange-500/30 font-bold text-[10px]"
                >
                  Kerberos Spray (Suricata EVE)
                </button>
                <button
                  onClick={() => loadSampleLog('c2')}
                  className="px-2.5 py-1 rounded bg-[#0e192e] hover:bg-[#152544] text-purple-400 border border-purple-500/30 font-bold text-[10px]"
                >
                  C2 Beacon (Zeek conn.log)
                </button>
                <button
                  onClick={() => loadSampleLog('sqli')}
                  className="px-2.5 py-1 rounded bg-[#0e192e] hover:bg-[#152544] text-cyan-400 border border-cyan-500/30 font-bold text-[10px]"
                >
                  SQL Injection Web Log
                </button>
              </div>

              <textarea
                value={rawLogInput}
                onChange={(e) => setRawLogInput(e.target.value)}
                placeholder="Paste raw Syslog, Zeek TSV, or Suricata JSON log lines here..."
                rows={5}
                className="w-full p-2.5 bg-[#050a14] border border-[#1b2b47] rounded text-slate-200 font-mono text-[11px] focus:outline-none focus:border-cyan-500"
              />

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Log Format:</span>
                  <select
                    value={logFormat}
                    onChange={(e) => setLogFormat(e.target.value)}
                    className="bg-[#091120] border border-[#16233b] text-slate-200 rounded px-2 py-1"
                  >
                    <option value="syslog">Syslog (RFC 5424 / Firewall)</option>
                    <option value="suricata">Suricata EVE JSON</option>
                    <option value="zeek">Zeek (Bro) TSV Log</option>
                  </select>
                </div>

                <button
                  onClick={handleIngestRawLog}
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold shadow-lg shadow-cyan-600/30 flex items-center gap-1.5 transition-all"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Ingest & Analyze Flow</span>
                </button>
              </div>

              {ingestStatus && (
                <div className="p-2.5 bg-[#0a162b] border border-cyan-500/30 rounded text-cyan-300 font-bold">
                  {ingestStatus}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 bg-[#0c1424] border-t border-[#16233b] flex items-center justify-between text-slate-400 text-[11px]">
          <div className="flex items-center gap-2">
            <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            <span>Telemetry Pipeline: Ingress Wire Tap Active</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-[#132039] hover:bg-[#1b2d4e] text-slate-200 font-bold transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
