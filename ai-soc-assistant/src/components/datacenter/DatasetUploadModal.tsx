import React, { useState } from 'react';
import {
  X,
  Upload,
  Database,
  CheckCircle2,
  AlertTriangle,
  RotateCw,
  Download,
  FileText,
  Sliders,
  Cpu,
  ShieldCheck,
  TrendingUp,
  Layers,
  ArrowRight,
  Target,
  BarChart3,
  Search,
  Zap,
  Info
} from 'lucide-react';
import { socApi } from '../../services/api';
import { ModelMetrics, DatasetWorkflowMode, DatasetValidationReport } from '../../types/soc';

interface DatasetUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDatasetUpdated: () => Promise<void>;
  currentMetrics?: ModelMetrics | null;
}

export const DatasetUploadModal: React.FC<DatasetUploadModalProps> = ({
  isOpen,
  onClose,
  onDatasetUpdated,
  currentMetrics
}) => {
  const [activeTab, setActiveTab] = useState<'upload' | 'presets' | 'schema'>('upload');
  const [workflowMode, setWorkflowMode] = useState<DatasetWorkflowMode>('train');
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingStep, setProcessingStep] = useState<string>('');
  const [validationReport, setValidationReport] = useState<DatasetValidationReport | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFileUpload = async (file: File) => {
    setIsProcessing(true);
    setErrorMsg(null);
    setValidationReport(null);

    try {
      setProcessingStep('1/4 Validating file bounds & detecting schema...');
      await new Promise(r => setTimeout(r, 350));

      setProcessingStep(`2/4 Ingesting records & checking bounds (${workflowMode.toUpperCase()} mode)...`);
      const report = await socApi.processDatasetWorkflow(file, workflowMode);

      setProcessingStep(`3/4 Executing ${workflowMode.toUpperCase()} pipeline & calculating metrics...`);
      await new Promise(r => setTimeout(r, 450));

      setProcessingStep('4/4 Synchronizing dashboard metrics & telemetry...');
      await onDatasetUpdated();

      setValidationReport(report);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Failed to process dataset file.');
    } finally {
      setIsProcessing(false);
      setProcessingStep('');
    }
  };

  const handleApplyPreset = async (presetId: string) => {
    setIsProcessing(true);
    setErrorMsg(null);
    setValidationReport(null);

    try {
      setProcessingStep('1/3 Synthesizing benchmark network flow dataset...');
      await new Promise(r => setTimeout(r, 400));

      setProcessingStep('2/3 Training Random Forest model on generated distribution...');
      const res = await socApi.generateSampleDataset(presetId);

      setProcessingStep('3/3 Synchronizing all application parameters & metrics...');
      await onDatasetUpdated();

      setValidationReport({
        fileName: `Preset Scenario: ${presetId}.csv`,
        fileSizeBytes: 5000 * 180,
        detectedSchema: 'CIC-IDS2017',
        recordsTotal: res.count,
        recordsAccepted: res.count,
        recordsRejected: 0,
        recordsDuplicate: 0,
        missingFieldWarnings: [],
        validationWarnings: [],
        detectedLabels: ['BENIGN', 'DDoS', 'DoS', 'PortScan', 'BruteForce', 'Bot', 'WebAttack'],
        hasGroundTruth: true,
        timeRange: { start: '2026-10-28 00:00:00 UTC', end: '2026-10-28 23:59:59 UTC' },
        workflowMode: 'train',
        modelPreserved: false,
        evaluationMetrics: res.metrics,
        diagnosticNotes: [res.description, `Stratified Random Forest model successfully trained on ${res.count.toLocaleString()} samples.`]
      });
    } catch (err: any) {
      setErrorMsg(err?.message || 'Failed to generate dataset.');
    } finally {
      setIsProcessing(false);
      setProcessingStep('');
    }
  };

  const downloadSampleCsv = () => {
    const headers = [
      'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'tot_len_fwd_pkts', 'tot_len_bwd_pkts',
      'flow_byts_s', 'flow_pkts_s', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'flow_iat_mean',
      'syn_flag_cnt', 'rst_flag_cnt', 'ack_flag_cnt', 'psh_flag_cnt', 'protocol_num',
      'dst_port', 'src_port', 'label'
    ].join(',');

    const samples = [
      '14200,42,0,1680,0,118.3,2.95,40,0,338,42,0,0,0,0,443,51420,DDoS',
      '5000,10,12,800,1200,400,4.4,80,100,500,1,0,10,4,0,88,49812,BruteForce',
      '2400,48,0,1920,0,800,20,40,0,50,48,0,0,0,0,22,60124,PortScan',
      '180000,24,24,2160,2160,24,0.26,90,90,9800,1,0,24,12,0,4444,55432,Bot',
      '4200,32,4,1280,160,34,0.85,40,40,1312,1,0,32,28,0,80,44102,DoS',
      '24000,14,16,1400,2400,158,1.25,100,150,1714,1,0,14,8,0,443,58430,BENIGN'
    ].join('\n');

    const csvContent = 'data:text/csv;charset=utf-8,' + encodeURIComponent(headers + '\n' + samples);
    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', 'sample_network_flow_dataset.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-[#090f1d] border border-[#1b2b47] rounded-xl max-w-3xl w-full flex flex-col shadow-2xl overflow-hidden font-mono text-xs">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-4 border-b border-[#16233b] bg-[#0c1424]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-cyan-950/60 rounded border border-cyan-500/30 text-cyan-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white tracking-wide">
                  Dynamic Dataset Management & Model Retraining
                </h2>
                <span className="text-[10px] bg-cyan-950 text-cyan-400 px-2 py-0.5 rounded border border-cyan-500/30">
                  Full Parameter Update
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                Upload new network flow datasets to immediately retrain the Random Forest model and dynamically recalibrate all SOC dashboard parameters.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded bg-[#101b2f] hover:bg-[#162540] transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Selection */}
        <div className="flex items-center gap-1 px-4 pt-3 border-b border-[#16233b] bg-[#070c18]">
          <button
            onClick={() => setActiveTab('upload')}
            className={`px-3 py-1.5 rounded-t font-semibold transition-colors flex items-center gap-1.5 ${
              activeTab === 'upload'
                ? 'bg-[#0f1a2e] text-cyan-400 border-t border-x border-[#1b2b47]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="w-3.5 h-3.5" />
            Upload Dataset File (CSV/JSON)
          </button>
          <button
            onClick={() => setActiveTab('presets')}
            className={`px-3 py-1.5 rounded-t font-semibold transition-colors flex items-center gap-1.5 ${
              activeTab === 'presets'
                ? 'bg-[#0f1a2e] text-cyan-400 border-t border-x border-[#1b2b47]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            Threat Scenario Presets
          </button>
          <button
            onClick={() => setActiveTab('schema')}
            className={`px-3 py-1.5 rounded-t font-semibold transition-colors flex items-center gap-1.5 ${
              activeTab === 'schema'
                ? 'bg-[#0f1a2e] text-cyan-400 border-t border-x border-[#1b2b47]'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            Schema Specifications
          </button>
        </div>

        {/* Body Content */}
        <div className="p-4 space-y-4 max-h-[70vh] overflow-y-auto">
          {errorMsg && (
            <div className="p-3 bg-red-950/60 border border-red-500/40 rounded flex items-center gap-2 text-red-300">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {isProcessing && (
            <div className="p-4 bg-[#0a1426] border border-cyan-500/40 rounded text-center space-y-2 animate-pulse">
              <RotateCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
              <p className="text-cyan-300 font-bold">{processingStep}</p>
              <p className="text-[10px] text-slate-400 font-sans">
                Recalibrating Confusion Matrix, Accuracy, Alert Distribution & Host Risk Indices...
              </p>
            </div>
          )}

          {validationReport && (
            <div className="p-3 bg-emerald-950/30 border border-emerald-500/40 rounded space-y-2.5">
              <div className="flex items-center justify-between border-b border-emerald-500/30 pb-2">
                <div className="flex items-center gap-2 text-emerald-400 font-bold">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Validation & Ingestion Report: {validationReport.fileName}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-500/30">
                    Schema: {validationReport.detectedSchema}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${
                    validationReport.modelPreserved
                      ? 'bg-amber-950 text-amber-300 border-amber-500/40'
                      : 'bg-emerald-950 text-emerald-300 border-emerald-500/40'
                  }`}>
                    {validationReport.modelPreserved ? 'Model Preserved (Weights Intact)' : 'Model Retrained & Deployed'}
                  </span>
                </div>
              </div>

              {/* 4 Ingestion Counts */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center font-mono">
                <div className="bg-[#081020] p-2 rounded border border-[#1b2b47]">
                  <span className="text-[10px] text-slate-400">Total Rows</span>
                  <p className="text-sm font-bold text-white">{validationReport.recordsTotal.toLocaleString()}</p>
                </div>
                <div className="bg-[#081020] p-2 rounded border border-emerald-500/30">
                  <span className="text-[10px] text-emerald-400">Accepted Flows</span>
                  <p className="text-sm font-bold text-emerald-400">{validationReport.recordsAccepted.toLocaleString()}</p>
                </div>
                <div className="bg-[#081020] p-2 rounded border border-red-500/30">
                  <span className="text-[10px] text-red-400">Rejected / Malformed</span>
                  <p className="text-sm font-bold text-red-400">{validationReport.recordsRejected}</p>
                </div>
                <div className="bg-[#081020] p-2 rounded border border-amber-500/30">
                  <span className="text-[10px] text-amber-400">Duplicates Filtered</span>
                  <p className="text-sm font-bold text-amber-400">{validationReport.recordsDuplicate}</p>
                </div>
              </div>

              {/* Evaluation Metrics if available */}
              {validationReport.evaluationMetrics && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center font-mono pt-1">
                  <div className="bg-[#0c162c] p-2 rounded border border-cyan-500/30">
                    <span className="text-[10px] text-slate-400">Evaluation Accuracy</span>
                    <p className="text-sm font-bold text-cyan-300">
                      {(validationReport.evaluationMetrics.accuracy * 100).toFixed(2)}%
                    </p>
                  </div>
                  <div className="bg-[#0c162c] p-2 rounded border border-amber-500/30">
                    <span className="text-[10px] text-slate-400">Macro F1 Score</span>
                    <p className="text-sm font-bold text-amber-300">
                      {validationReport.evaluationMetrics.macroF1.toFixed(4)}
                    </p>
                  </div>
                  <div className="bg-[#0c162c] p-2 rounded border border-purple-500/30">
                    <span className="text-[10px] text-slate-400">Macro Precision</span>
                    <p className="text-sm font-bold text-purple-300">
                      {validationReport.evaluationMetrics.macroPrecision.toFixed(4)}
                    </p>
                  </div>
                  <div className="bg-[#0c162c] p-2 rounded border border-emerald-500/30">
                    <span className="text-[10px] text-slate-400">Macro Recall</span>
                    <p className="text-sm font-bold text-emerald-300">
                      {validationReport.evaluationMetrics.macroRecall.toFixed(4)}
                    </p>
                  </div>
                </div>
              )}

              {/* Diagnostic Notes & Findings */}
              <div className="space-y-1 text-[11px] text-slate-300 pt-1 font-sans">
                {validationReport.diagnosticNotes.map((note, idx) => (
                  <div key={idx} className="flex items-center gap-1.5 text-emerald-300">
                    <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 text-emerald-400" />
                    <span>{note}</span>
                  </div>
                ))}
                {validationReport.validationWarnings.map((warn, idx) => (
                  <div key={idx} className="flex items-center gap-1.5 text-amber-300">
                    <Info className="w-3.5 h-3.5 flex-shrink-0 text-amber-400" />
                    <span>{warn}</span>
                  </div>
                ))}
                {validationReport.detectedLabels.length > 0 && (
                  <div className="text-[10px] text-slate-400 pt-1">
                    <span className="text-slate-300 font-semibold">Detected Ground-Truth Classes:</span>{' '}
                    {validationReport.detectedLabels.join(', ')}
                  </div>
                )}
                {validationReport.timeRange && (
                  <div className="text-[10px] text-slate-400">
                    <span className="text-slate-300 font-semibold">Timestamp Window:</span>{' '}
                    {validationReport.timeRange.start} — {validationReport.timeRange.end}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'upload' && (
            <div className="space-y-3">
              {/* 1. Distinct Workflow Mode Selector */}
              <div className="bg-[#070d18] border border-[#1b2b47] rounded-lg p-2.5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 text-xs flex items-center gap-1.5">
                    <Target className="w-3.5 h-3.5 text-cyan-400" />
                    Select Dataset Ingestion Workflow:
                  </span>
                  <span className="text-[10px] text-slate-400">Protects model state against test-data leakage</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setWorkflowMode('train')}
                    className={`p-2 rounded text-left border transition-all ${
                      workflowMode === 'train'
                        ? 'bg-cyan-950/70 border-cyan-400 text-cyan-200 shadow-[0_0_10px_rgba(6,182,212,0.15)]'
                        : 'bg-[#0a1324] border-[#18263f] text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[11px] text-cyan-300 flex items-center gap-1">
                        <Cpu className="w-3 h-3 text-cyan-400" />
                        1. Model Training
                      </span>
                      <span className="text-[9px] bg-cyan-900/60 text-cyan-300 px-1.5 py-0.2 rounded">Retrain</span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 font-sans leading-tight">
                      Fit Random Forest on labelled data. Evaluates 80/20 train/test split. Rolls back if quality drops below threshold.
                    </p>
                  </button>

                  <button
                    type="button"
                    onClick={() => setWorkflowMode('evaluate')}
                    className={`p-2 rounded text-left border transition-all ${
                      workflowMode === 'evaluate'
                        ? 'bg-amber-950/70 border-amber-400 text-amber-200 shadow-[0_0_10px_rgba(245,158,11,0.15)]'
                        : 'bg-[#0a1324] border-[#18263f] text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[11px] text-amber-300 flex items-center gap-1">
                        <BarChart3 className="w-3 h-3 text-amber-400" />
                        2. Held-Out Evaluation
                      </span>
                      <span className="text-[9px] bg-amber-900/60 text-amber-300 px-1.5 py-0.2 rounded">No Leakage</span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 font-sans leading-tight">
                      Score existing model on this test set without modifying weights. Measures accuracy, F1, and confusion matrix.
                    </p>
                  </button>

                  <button
                    type="button"
                    onClick={() => setWorkflowMode('infer')}
                    className={`p-2 rounded text-left border transition-all ${
                      workflowMode === 'infer'
                        ? 'bg-emerald-950/70 border-emerald-400 text-emerald-200 shadow-[0_0_10px_rgba(16,185,129,0.15)]'
                        : 'bg-[#0a1324] border-[#18263f] text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[11px] text-emerald-300 flex items-center gap-1">
                        <Zap className="w-3 h-3 text-emerald-400" />
                        3. Event Inference
                      </span>
                      <span className="text-[9px] bg-emerald-900/60 text-emerald-300 px-1.5 py-0.2 rounded">Classify</span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 font-sans leading-tight">
                      Classify unlabelled or live flow events using current model. Flags threats and refreshes alerts & asset risks.
                    </p>
                  </button>

                  <button
                    type="button"
                    onClick={() => setWorkflowMode('explore')}
                    className={`p-2 rounded text-left border transition-all ${
                      workflowMode === 'explore'
                        ? 'bg-purple-950/70 border-purple-400 text-purple-200 shadow-[0_0_10px_rgba(168,85,247,0.15)]'
                        : 'bg-[#0a1324] border-[#18263f] text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[11px] text-purple-300 flex items-center gap-1">
                        <Search className="w-3 h-3 text-purple-400" />
                        4. Exploratory Analysis
                      </span>
                      <span className="text-[9px] bg-purple-900/60 text-purple-300 px-1.5 py-0.2 rounded">Profile</span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 font-sans leading-tight">
                      Profile traffic volumes, protocol distributions, and network summaries without altering model or alerts.
                    </p>
                  </button>
                </div>
              </div>

              {/* 2. Drag and Drop Zone */}
              <div className="border-2 border-dashed border-[#1f3354] hover:border-cyan-500/60 rounded-xl p-5 text-center bg-[#070d1a] transition-all relative">
                <input
                  type="file"
                  accept=".csv,.json,.log,.txt"
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  disabled={isProcessing}
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleFileUpload(f);
                  }}
                />
                <div className="flex flex-col items-center justify-center space-y-2 pointer-events-none">
                  <div className="p-2.5 bg-cyan-950/60 rounded-full text-cyan-400 border border-cyan-500/30">
                    <Upload className="w-5 h-5" />
                  </div>
                  <div>
                    <span className="text-sm font-bold text-white">Click or drag & drop dataset here</span>
                    <p className="text-[11px] text-slate-400 mt-0.5">Supports CSV, JSON, Zeek conn.log, or Suricata EVE</p>
                  </div>
                  <span className="text-[10px] bg-[#0d182b] text-cyan-300 px-2.5 py-0.5 rounded border border-[#1b2b47]">
                    Selected Mode: {workflowMode.toUpperCase()} • Schema Auto-Detection Active
                  </span>
                </div>
              </div>

              {/* 3. Sample Download Strip */}
              <div className="flex items-center justify-between p-2.5 bg-[#0a1222] rounded border border-[#16233b]">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <div>
                    <span className="font-bold text-slate-200">Need a sample CSV to test?</span>
                    <p className="text-[10px] text-slate-400 font-sans">
                      Download a pre-formatted 6-record template with valid network flow features.
                    </p>
                  </div>
                </div>
                <button
                  onClick={downloadSampleCsv}
                  className="px-3 py-1.5 rounded bg-[#101b2f] hover:bg-[#162642] text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 transition-colors font-bold"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Sample CSV</span>
                </button>
              </div>
            </div>
          )}

          {activeTab === 'presets' && (
            <div className="space-y-3">
              <p className="text-slate-400 font-sans text-xs">
                Select an enterprise scenario preset to generate an exact 5,000-flow dataset and observe the real-time parameter changes across all charts, KPIs, and models:
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <div
                  onClick={() => handleApplyPreset('ddos-surge')}
                  className="p-3 bg-[#081020] hover:bg-[#0c162c] border border-[#1a2b4a] hover:border-red-500/50 rounded-lg cursor-pointer transition-all group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-red-400">DDoS & Volumetric Surge</span>
                    <span className="text-[9px] bg-red-950 text-red-300 px-1.5 py-0.5 rounded border border-red-500/30">
                      70% Attacks
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 font-sans">
                    Simulates a massive SYN flood on perimeter web nodes. Spikes Critical alerts, increases MTTR, and elevates edge asset risk.
                  </p>
                  <div className="flex items-center gap-1 text-[10px] text-cyan-400 mt-2 font-bold group-hover:translate-x-1 transition-transform">
                    <span>Apply Preset & Retrain</span>
                    <ArrowRight className="w-3 h-3" />
                  </div>
                </div>

                <div
                  onClick={() => handleApplyPreset('lateral-movement')}
                  className="p-3 bg-[#081020] hover:bg-[#0c162c] border border-[#1a2b4a] hover:border-amber-500/50 rounded-lg cursor-pointer transition-all group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-amber-400">APT Lateral Movement</span>
                    <span className="text-[9px] bg-amber-950 text-amber-300 px-1.5 py-0.5 rounded border border-amber-500/30">
                      High Severity
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 font-sans">
                    Simulates Kerberos spraying, SMB pivoting, and C2 beaconing. Updates Active Directory host risks and attack path models.
                  </p>
                  <div className="flex items-center gap-1 text-[10px] text-cyan-400 mt-2 font-bold group-hover:translate-x-1 transition-transform">
                    <span>Apply Preset & Retrain</span>
                    <ArrowRight className="w-3 h-3" />
                  </div>
                </div>

                <div
                  onClick={() => handleApplyPreset('web-api-attack')}
                  className="p-3 bg-[#081020] hover:bg-[#0c162c] border border-[#1a2b4a] hover:border-purple-500/50 rounded-lg cursor-pointer transition-all group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-purple-400">Web API & Injection Influx</span>
                    <span className="text-[9px] bg-purple-950 text-purple-300 px-1.5 py-0.5 rounded border border-purple-500/30">
                      Application Layer
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 font-sans">
                    Heavy SQL injection and directory traversal attacks against ingress API gateway and production databases.
                  </p>
                  <div className="flex items-center gap-1 text-[10px] text-cyan-400 mt-2 font-bold group-hover:translate-x-1 transition-transform">
                    <span>Apply Preset & Retrain</span>
                    <ArrowRight className="w-3 h-3" />
                  </div>
                </div>

                <div
                  onClick={() => handleApplyPreset('balanced')}
                  className="p-3 bg-[#081020] hover:bg-[#0c162c] border border-[#1a2b4a] hover:border-emerald-500/50 rounded-lg cursor-pointer transition-all group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-emerald-400">Balanced Enterprise Baseline</span>
                    <span className="text-[9px] bg-emerald-950 text-emerald-300 px-1.5 py-0.5 rounded border border-emerald-500/30">
                      CIC-IDS Standard
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 font-sans">
                    Default 48% Benign baseline with realistic proportions of PortScan, DoS, DDoS, BruteForce, and Bot traffic.
                  </p>
                  <div className="flex items-center gap-1 text-[10px] text-cyan-400 mt-2 font-bold group-hover:translate-x-1 transition-transform">
                    <span>Apply Preset & Retrain</span>
                    <ArrowRight className="w-3 h-3" />
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'schema' && (
            <div className="space-y-3 font-sans text-xs text-slate-300">
              <p>The parser automatically extracts the following 17 network flow features:</p>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 font-mono text-[11px]">
                <div className="p-2 bg-[#060b17] border border-[#16233b] rounded text-cyan-300">flow_duration (ms)</div>
                <div className="p-2 bg-[#060b17] border border-[#16233b] rounded text-cyan-300">tot_fwd_pkts</div>
                <div className="p-2 bg-[#060b17] border border-[#16233b] rounded text-cyan-300">tot_bwd_pkts</div>
                <div className="p-2 bg-[#060b17] border border-[#16233b] rounded text-cyan-300">flow_byts_s</div>
                <div className="p-2 bg-[#060b17] border border-[#16233b] rounded text-cyan-300">flow_pkts_s</div>
                <div className="p-2 bg-[#060b17] border border-[#16233b] rounded text-cyan-300">syn_flag_cnt</div>
                <div className="p-2 bg-[#060b17] border border-[#16233b] rounded text-cyan-300">psh_flag_cnt</div>
                <div className="p-2 bg-[#060b17] border border-[#16233b] rounded text-cyan-300">dst_port / src_port</div>
                <div className="p-2 bg-[#060b17] border border-[#16233b] rounded text-emerald-300">label (Target Class)</div>
              </div>
              <p className="text-slate-400 text-[11px]">
                Supported labels: <code className="text-white">BENIGN</code>, <code className="text-white">DoS</code>, <code className="text-white">DDoS</code>, <code className="text-white">PortScan</code>, <code className="text-white">BruteForce</code>, <code className="text-white">Bot</code>, <code className="text-white">WebAttack</code>.
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 bg-[#0c1424] border-t border-[#16233b] flex items-center justify-between text-slate-400">
          <div className="flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-[11px]">Model: Random Forest (Stratified 80/20 Split)</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-[#132039] hover:bg-[#1b2d4e] text-slate-200 transition-colors font-bold"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
