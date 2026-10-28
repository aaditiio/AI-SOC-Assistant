import React, { useState } from 'react';
import {
  Cpu,
  Database,
  RotateCw,
  CheckCircle2,
  AlertTriangle,
  Play,
  BarChart3,
  Layers,
  Sliders,
  ShieldCheck,
  Info
} from 'lucide-react';
import { ModelMetrics, PacketFeatures, ThreatCategory, Severity } from '../types/soc';
import { socApi } from '../services/api';
import { THREAT_CLASSES } from '../server/socEngine';

interface ModelManagementPageProps {
  metrics: ModelMetrics;
  onRetrainModel: () => Promise<void>;
}

export const ModelManagementPage: React.FC<ModelManagementPageProps> = ({
  metrics,
  onRetrainModel
}) => {
  const [isRetraining, setIsRetraining] = useState(false);
  const [predictDuration, setPredictDuration] = useState<number>(12000);
  const [predictPktsSec, setPredictPktsSec] = useState<number>(14500);
  const [predictBytsSec, setPredictBytsSec] = useState<number>(1200000);
  const [predictSynFlags, setPredictSynFlags] = useState<number>(2400);
  const [predictPshFlags, setPredictPshFlags] = useState<number>(0);
  const [predictDstPort, setPredictDstPort] = useState<number>(443);
  const [predictFwdLen, setPredictFwdLen] = useState<number>(40);

  const [predictionResult, setPredictionResult] = useState<{
    predictedCategory: ThreatCategory;
    confidence: number;
    severity: Severity;
    evidence: string[];
    explanation: string;
    recommendation: string;
  } | null>(null);

  const handleRetrain = async () => {
    setIsRetraining(true);
    await onRetrainModel();
    setIsRetraining(false);
  };

  const handlePredict = async (e: React.FormEvent) => {
    e.preventDefault();
    const result = await socApi.predictFlow({
      flowDuration: Number(predictDuration),
      flowPktsPerSec: Number(predictPktsSec),
      flowBytsPerSec: Number(predictBytsSec),
      synFlagCnt: Number(predictSynFlags),
      pshFlagCnt: Number(predictPshFlags),
      dstPort: Number(predictDstPort),
      fwdPktLenMean: Number(predictFwdLen)
    });
    setPredictionResult(result);
  };

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150 font-mono text-xs">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0b1324] border border-[#1b2b47] p-3 rounded">
        <div>
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Machine Learning Threat Detection & Classifier Architecture
            </h2>
            <span className="text-[10px] bg-emerald-950/80 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded">
              RandomForest (100 Trees)
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Trained on 5,000 synthetic network flow records using Stratified 80/20 train/test evaluation across 7 threat classes.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* File Upload Input */}
          <label className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#132039] hover:bg-[#1a2d52] border border-[#23385e] text-cyan-300 font-bold text-xs transition-colors cursor-pointer">
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            <span>Upload / Replace Dataset</span>
            <input
              type="file"
              accept=".csv,.json"
              className="hidden"
              onChange={async (e) => {
                const file = e.target.files?.[0];
                if (!file) return;
                setIsRetraining(true);
                try {
                  const res = await socApi.uploadDatasetFile(file);
                  await onRetrainModel();
                  alert(`Successfully loaded ${res.count} records from ${file.name}. Model retrained on new dataset.`);
                } catch (err: any) {
                  alert(`Failed to load dataset: ${err?.message || err}`);
                } finally {
                  setIsRetraining(false);
                  e.target.value = '';
                }
              }}
            />
          </label>

          <button
            onClick={async () => {
              setIsRetraining(true);
              try {
                await socApi.regenerateDataset(5000);
                await onRetrainModel();
              } finally {
                setIsRetraining(false);
              }
            }}
            disabled={isRetraining}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#132039] hover:bg-[#1a2d52] border border-[#23385e] text-slate-300 font-bold text-xs transition-colors cursor-pointer disabled:opacity-50"
            title="Generate a fresh synthetic dataset and train model on it"
          >
            <RotateCw className="w-3.5 h-3.5 text-slate-400" />
            <span>Regenerate Dataset</span>
          </button>

          <button
            onClick={handleRetrain}
            disabled={isRetraining}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs shadow-lg shadow-cyan-600/30 transition-all cursor-pointer disabled:opacity-50"
          >
            <RotateCw className={`w-3.5 h-3.5 ${isRetraining ? 'animate-spin' : ''}`} />
            <span>{isRetraining ? 'Retraining Model...' : 'Retrain Random Forest'}</span>
          </button>
        </div>
      </div>

      {/* KPI Row of ML Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="soc-card p-3 border-[#1d2d4a]">
          <span className="text-[10px] text-slate-400 uppercase">Test Accuracy</span>
          <p className="text-xl font-bold text-cyan-400 mt-1">
            {(metrics.accuracy * 100).toFixed(2)}%
          </p>
          <span className="text-[9px] text-slate-500">Held-out 1,000 samples</span>
        </div>

        <div className="soc-card p-3 border-[#1d2d4a]">
          <span className="text-[10px] text-slate-400 uppercase">Macro F1 Score</span>
          <p className="text-xl font-bold text-emerald-400 mt-1">
            {metrics.macroF1.toFixed(4)}
          </p>
          <span className="text-[9px] text-slate-500">Unweighted class average</span>
        </div>

        <div className="soc-card p-3 border-[#1d2d4a]">
          <span className="text-[10px] text-slate-400 uppercase">Macro Precision</span>
          <p className="text-xl font-bold text-slate-200 mt-1">
            {(metrics.macroPrecision * 100).toFixed(2)}%
          </p>
          <span className="text-[9px] text-slate-500">Low false alarm rate</span>
        </div>

        <div className="soc-card p-3 border-[#1d2d4a]">
          <span className="text-[10px] text-slate-400 uppercase">Macro Recall</span>
          <p className="text-xl font-bold text-slate-200 mt-1">
            {(metrics.macroRecall * 100).toFixed(2)}%
          </p>
          <span className="text-[9px] text-slate-500">True positive detection</span>
        </div>

        <div className="soc-card p-3 border-[#1d2d4a]">
          <span className="text-[10px] text-slate-400 uppercase">Weighted F1</span>
          <p className="text-xl font-bold text-amber-300 mt-1">
            {metrics.weightedF1.toFixed(4)}
          </p>
          <span className="text-[9px] text-slate-500">Class-weighted balance</span>
        </div>
      </div>

      {/* Dynamic Dataset Profile & Attack Scenario Lab */}
      <div className="soc-card p-4 space-y-3 border-cyan-500/30 bg-[#090f1d]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-[#18263f]">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <div>
              <h3 className="font-bold text-sm text-slate-100">
                Synthetic Dataset Scenario Lab & Dynamic Telemetry Coupling
              </h3>
              <p className="text-[11px] text-slate-400">
                Switch attack traffic profiles below to regenerate the 5,000 flow dataset, retrain the Random Forest model, and watch all SOC alerts, charts, and metrics update in real-time.
              </p>
            </div>
          </div>
          <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded font-mono whitespace-nowrap self-start sm:self-auto">
            Active: {socApi.getActivePresetId()}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-2.5 pt-1">
          {socApi.getDatasetPresets().map(preset => {
            const isActive = socApi.getActivePresetId() === preset.id;
            return (
              <div
                key={preset.id}
                onClick={async () => {
                  if (isRetraining) return;
                  setIsRetraining(true);
                  try {
                    await socApi.applyDatasetPreset(preset.id);
                    await onRetrainModel();
                  } finally {
                    setIsRetraining(false);
                  }
                }}
                className={`p-3 rounded border text-left cursor-pointer transition-all flex flex-col justify-between gap-2 ${
                  isActive
                    ? 'bg-cyan-950/60 border-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                    : 'bg-[#080d19] border-[#162238] hover:border-cyan-500/40 hover:bg-[#0c1424]'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-[10px] font-bold uppercase tracking-wider ${isActive ? 'text-cyan-300' : 'text-slate-400'}`}>
                      {isActive ? '● Active Profile' : 'Scenario'}
                    </span>
                    <span className="text-[9px] text-slate-500 font-mono">5k flows</span>
                  </div>
                  <h4 className="font-bold text-xs text-slate-100 mb-1 leading-snug">{preset.name}</h4>
                  <p className="text-[10px] text-slate-400 line-clamp-3 leading-relaxed">{preset.description}</p>
                </div>

                <div className="pt-2 border-t border-[#141e30] flex items-center justify-between">
                  <div className="flex gap-1 text-[8px] font-mono">
                    {Object.entries(preset.distribution).filter(([_, cnt]) => cnt >= 600).map(([k, cnt]) => (
                      <span key={k} className="bg-black/50 px-1 py-0.2 rounded text-cyan-400">
                        {k}:{cnt}
                      </span>
                    ))}
                  </div>
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${isActive ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-300'}`}>
                    {isActive ? 'Current' : 'Apply'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Grid: Confusion Matrix + Feature Importances */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* 7x7 Confusion Matrix (7 cols) */}
        <div className="lg:col-span-7 soc-card p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-[#18263f] pb-2">
            <span className="font-bold text-slate-100 text-xs">
              7x7 Stratified Confusion Matrix (Test Set: N = 1,000)
            </span>
            <span className="text-[10px] text-slate-400">Rows: Actual | Columns: Predicted</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-center text-[10px] border-collapse font-mono">
              <thead>
                <tr className="text-slate-400">
                  <th className="p-1.5 text-left text-[9px]">Actual \ Pred</th>
                  {metrics.classNames.map(cls => (
                    <th key={cls} className="p-1.5 font-bold text-cyan-400">{cls}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {metrics.confusionMatrix.map((row, rIdx) => {
                  const actualClass = metrics.classNames[rIdx];
                  return (
                    <tr key={actualClass} className="border-t border-[#142036]">
                      <td className="p-1.5 text-left font-bold text-slate-300">{actualClass}</td>
                      {row.map((val, cIdx) => {
                        const isDiagonal = rIdx === cIdx;
                        return (
                          <td
                            key={cIdx}
                            className={`p-1.5 font-semibold ${
                              isDiagonal
                                ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-500/30'
                                : val > 0
                                ? 'bg-red-950/50 text-red-400'
                                : 'text-slate-600'
                            }`}
                          >
                            {val}
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Per-Class Classification Report */}
          <div className="pt-2 border-t border-[#18263f] space-y-1.5">
            <span className="font-bold text-slate-300 text-[11px] block">
              Per-Class Classification Report
            </span>
            <div className="grid grid-cols-7 gap-1 text-[9px] text-center">
              {metrics.classNames.map(cls => {
                const rep = metrics.classReport[cls];
                return (
                  <div key={cls} className="bg-[#080d19] p-1.5 rounded border border-[#16233b]">
                    <span className="font-bold text-cyan-300 block">{cls}</span>
                    <span className="text-slate-400">F1: {rep?.f1.toFixed(3)}</span>
                    <span className="text-slate-500 block">N={rep?.support}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Feature Importances (5 cols) */}
        <div className="lg:col-span-5 soc-card p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-[#18263f] pb-2">
            <span className="font-bold text-slate-100 text-xs">
              Random Forest Feature Importances (MDI)
            </span>
            <span className="text-[10px] text-slate-400">Top Network Attributes</span>
          </div>

          <div className="space-y-2 max-h-[300px] overflow-y-auto scrollbar-thin pr-1">
            {metrics.featureImportances.map((item, idx) => (
              <div key={item.feature} className="space-y-0.5">
                <div className="flex items-center justify-between text-[10px]">
                  <span className="text-slate-300 font-semibold">{item.feature}</span>
                  <span className="text-cyan-400 font-bold">{(item.importance * 100).toFixed(1)}%</span>
                </div>
                <div className="w-full bg-[#080d19] h-1.5 rounded-full overflow-hidden border border-[#16233b]">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-600"
                    style={{ width: `${item.importance * 100 * 4}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Interactive Single Flow Packet Predictor */}
      <div className="soc-card p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-[#18263f] pb-2">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-slate-100 text-xs">
              Single-Flow Live Classification & Rule Scoring
            </span>
          </div>
          <span className="text-[10px] text-slate-400">
            Simulate network flow packets and observe real-time classification
          </span>
        </div>

        <form onSubmit={handlePredict} className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2.5">
          <div>
            <label className="text-slate-400 text-[10px] uppercase block mb-1">Flow Pkts / Sec</label>
            <input
              type="number"
              value={predictPktsSec}
              onChange={e => setPredictPktsSec(Number(e.target.value))}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1 text-slate-200 outline-none focus:border-cyan-400"
            />
          </div>
          <div>
            <label className="text-slate-400 text-[10px] uppercase block mb-1">Flow Bytes / Sec</label>
            <input
              type="number"
              value={predictBytsSec}
              onChange={e => setPredictBytsSec(Number(e.target.value))}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1 text-slate-200 outline-none focus:border-cyan-400"
            />
          </div>
          <div>
            <label className="text-slate-400 text-[10px] uppercase block mb-1">SYN Flags</label>
            <input
              type="number"
              value={predictSynFlags}
              onChange={e => setPredictSynFlags(Number(e.target.value))}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1 text-slate-200 outline-none focus:border-cyan-400"
            />
          </div>
          <div>
            <label className="text-slate-400 text-[10px] uppercase block mb-1">PSH Flags</label>
            <input
              type="number"
              value={predictPshFlags}
              onChange={e => setPredictPshFlags(Number(e.target.value))}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1 text-slate-200 outline-none focus:border-cyan-400"
            />
          </div>
          <div>
            <label className="text-slate-400 text-[10px] uppercase block mb-1">Dst Port</label>
            <input
              type="number"
              value={predictDstPort}
              onChange={e => setPredictDstPort(Number(e.target.value))}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1 text-slate-200 outline-none focus:border-cyan-400"
            />
          </div>
          <div>
            <label className="text-slate-400 text-[10px] uppercase block mb-1">Fwd Pkt Mean (B)</label>
            <input
              type="number"
              value={predictFwdLen}
              onChange={e => setPredictFwdLen(Number(e.target.value))}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2 py-1 text-slate-200 outline-none focus:border-cyan-400"
            />
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              className="w-full py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition-all shadow-md shadow-cyan-600/30"
            >
              Classify Flow
            </button>
          </div>
        </form>

        {/* Prediction Results Box */}
        {predictionResult && (
          <div className="bg-[#080d19] p-3 rounded border border-cyan-500/40 space-y-2 mt-2 animate-in fade-in">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-slate-400 text-[10px] uppercase">Prediction Result:</span>
                <span className="font-bold text-cyan-300 text-sm">{predictionResult.predictedCategory}</span>
                <span className="text-emerald-400 font-bold">({(predictionResult.confidence * 100).toFixed(1)}% Confidence)</span>
                <span className="bg-red-950 text-red-400 px-1.5 py-0.5 rounded text-[10px] font-bold border border-red-500/30">
                  {predictionResult.severity}
                </span>
              </div>
            </div>

            <p className="text-slate-300 text-[11px] leading-relaxed">
              {predictionResult.explanation}
            </p>

            <div className="bg-cyan-950/40 p-2 rounded border border-cyan-500/30 text-cyan-200 text-[11px]">
              <span className="text-cyan-400 font-bold uppercase block text-[9px]">Recommended Containment:</span>
              {predictionResult.recommendation}
            </div>
          </div>
        )}
      </div>

      {/* Dataset & Integrity Note */}
      <div className="bg-[#0c1424] p-3 rounded border border-[#1b2b47] flex items-start gap-2 text-xs font-mono text-slate-400">
        <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-slate-200">Data Integrity Notice:</strong> Evaluation metrics are computed strictly against the held-out 20% test partition (1,000 synthetic records) with zero target leakage. All synthetic records utilize RFC 1918 private subnets. Synthetic performance is an engineering demonstration and must not be conflated with real-world enterprise efficacy.
        </p>
      </div>
    </div>
  );
};
