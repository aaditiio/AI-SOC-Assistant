import React, { useState } from 'react';
import {
  Network,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Info,
  Server,
  Shield,
  Layers,
  ArrowRight,
  TrendingDown
} from 'lucide-react';

import { GraphNode, GraphEdge, AlgorithmResult } from '../types/soc';
import { GRAPH_NODES, GRAPH_EDGES, executeGraphSearch } from '../server/socEngine';
import { socApi } from '../services/api';

export const NetworkGraphPage: React.FC = () => {
  const [sourceNode, setSourceNode] = useState<string>('FW-EDGE-01');
  const [targetNode, setTargetNode] = useState<string>('DC-CORP-01');
  const [selectedAlgorithm, setSelectedAlgorithm] = useState<'BFS' | 'DFS' | 'Greedy Best-First' | 'A*'>('A*');
  const [searchResult, setSearchResult] = useState<AlgorithmResult | null>(() => executeGraphSearch('A*', 'FW-EDGE-01', 'DC-CORP-01'));
  const [comparisonResults, setComparisonResults] = useState<Record<string, AlgorithmResult> | null>(null);
  const [isSearching, setIsSearching] = useState<boolean>(false);

  const handleRunSearch = async () => {
    setIsSearching(true);
    const result = await socApi.searchAttackPath(sourceNode, targetNode, selectedAlgorithm);
    setSearchResult(result);
    setIsSearching(false);
  };

  const handleRunBenchmarkAll = async () => {
    setIsSearching(true);
    const algos: Array<'BFS' | 'DFS' | 'Greedy Best-First' | 'A*'> = ['BFS', 'DFS', 'Greedy Best-First', 'A*'];
    const results: Record<string, AlgorithmResult> = {};
    for (const algo of algos) {
      results[algo] = executeGraphSearch(algo, sourceNode, targetNode);
    }
    setComparisonResults(results);
    setIsSearching(false);
  };

  const isNodeInPath = (nodeId: string) => searchResult?.path.includes(nodeId);
  const isNodeVisited = (nodeId: string) => searchResult?.visitedNodes.includes(nodeId);
  const isEdgeInPath = (source: string, target: string) => {
    if (!searchResult?.path) return false;
    for (let i = 0; i < searchResult.path.length - 1; i++) {
      if (searchResult.path[i] === source && searchResult.path[i + 1] === target) return true;
    }
    return false;
  };

  return (
    <div className="p-4 space-y-4 max-w-[1920px] mx-auto animate-in fade-in duration-150">
      {/* Top Banner / Academic Context */}
      <div className="bg-[#0b1324] border border-[#1b2b47] p-3 rounded flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold font-mono text-slate-100">
              Attack Path Analysis & Graph Traversal Engine
            </h2>
            <span className="text-[10px] bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded font-mono">
              NetworkX Engine
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Traverses network topology graphs using graph search algorithms to identify potential pivot paths to high-value assets.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRunBenchmarkAll}
            className="px-3 py-1.5 rounded bg-[#132039] hover:bg-[#1a2d52] border border-[#23385e] text-cyan-300 font-mono text-xs flex items-center gap-1.5 transition-colors"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Benchmark All 4 Algorithms</span>
          </button>
        </div>
      </div>

      {/* Control Bar & Results Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
        {/* Controls Column (4 cols) */}
        <div className="lg:col-span-4 soc-card p-4 space-y-4 font-mono text-xs">
          <div className="border-b border-[#18263f] pb-2">
            <span className="font-bold text-slate-200 uppercase text-[11px] tracking-wider">
              Pathfinder Parameters
            </span>
          </div>

          {/* Source Node Selector */}
          <div className="space-y-1">
            <label className="text-slate-400 text-[10px] uppercase font-semibold">
              Source Node (Attacker Pivot / Ingress)
            </label>
            <select
              value={sourceNode}
              onChange={e => setSourceNode(e.target.value)}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2.5 py-1.5 text-slate-200 text-xs focus:border-cyan-400 outline-none"
            >
              {GRAPH_NODES.map(n => (
                <option key={n.id} value={n.id}>
                  {n.label} ({n.ip}) - Risk {n.riskScore}
                </option>
              ))}
            </select>
          </div>

          {/* Target Node Selector */}
          <div className="space-y-1">
            <label className="text-slate-400 text-[10px] uppercase font-semibold">
              Destination Target (High-Value Asset)
            </label>
            <select
              value={targetNode}
              onChange={e => setTargetNode(e.target.value)}
              className="w-full bg-[#080d19] border border-[#1d2d4a] rounded px-2.5 py-1.5 text-slate-200 text-xs focus:border-cyan-400 outline-none"
            >
              {GRAPH_NODES.map(n => (
                <option key={n.id} value={n.id}>
                  {n.label} ({n.ip}) - Risk {n.riskScore}
                </option>
              ))}
            </select>
          </div>

          {/* Algorithm Selector */}
          <div className="space-y-1">
            <label className="text-slate-400 text-[10px] uppercase font-semibold">
              Search Algorithm
            </label>
            <div className="grid grid-cols-2 gap-1.5">
              {(['A*', 'BFS', 'DFS', 'Greedy Best-First'] as const).map(algo => (
                <button
                  key={algo}
                  type="button"
                  onClick={() => setSelectedAlgorithm(algo)}
                  className={`py-1.5 px-2 rounded text-left border transition-colors ${
                    selectedAlgorithm === algo
                      ? 'bg-cyan-950/80 border-cyan-400 text-cyan-300 font-bold'
                      : 'bg-[#080d19] border-[#1d2d4a] text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {algo}
                </button>
              ))}
            </div>
          </div>

          {/* Run Search Button */}
          <button
            onClick={handleRunSearch}
            disabled={isSearching}
            className="w-full py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-lg shadow-cyan-600/30 transition-all cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-white" />
            <span>{isSearching ? 'Executing Search...' : `Execute ${selectedAlgorithm} Traversal`}</span>
          </button>

          {/* Search Result Statistics */}
          {searchResult && (
            <div className="bg-[#080d19] p-3 rounded border border-[#16233b] space-y-2 mt-2">
              <div className="flex items-center justify-between border-b border-[#16233b] pb-1.5">
                <span className="font-bold text-slate-200">Traversal Metrics</span>
                <span className={`text-[10px] font-bold ${searchResult.found ? 'text-emerald-400' : 'text-red-400'}`}>
                  {searchResult.found ? 'PATH IDENTIFIED' : 'NO PATH'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <span className="text-slate-500 text-[10px] block">Algorithm:</span>
                  <span className="font-bold text-cyan-400">{searchResult.algorithm}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">Execution Time:</span>
                  <span className="text-slate-200">{searchResult.executionTimeMs} ms</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">Hop Count:</span>
                  <span className="text-slate-200">{searchResult.pathLength} hops</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">Total Path Cost g(n):</span>
                  <span className="font-bold text-amber-300">{searchResult.totalCost}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">Explored Nodes:</span>
                  <span className="text-slate-200">{searchResult.totalExplored} nodes</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">Exploration Ratio:</span>
                  <span className="text-slate-200">
                    {Math.round((searchResult.totalExplored / GRAPH_NODES.length) * 100)}%
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-[#16233b] text-[10px] text-slate-400 leading-relaxed">
                <span className="text-cyan-400 font-semibold block mb-0.5">Algorithm Property:</span>
                {searchResult.explanation}
              </div>
            </div>
          )}
        </div>

        {/* Graph Visualizer (8 cols) */}
        <div className="lg:col-span-8 soc-card p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-[#18263f] pb-2 mb-2 font-mono text-xs">
            <span className="font-bold text-slate-200">Interactive Network Topology & Traversal Overlay</span>
            <div className="flex items-center gap-3 text-[10px]">
              <span className="flex items-center gap-1 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
                Active Path
              </span>
              <span className="flex items-center gap-1 text-amber-400">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                Visited / Explored
              </span>
              <span className="flex items-center gap-1 text-slate-400">
                <span className="w-2.5 h-2.5 rounded-full bg-slate-600" />
                Unvisited
              </span>
            </div>
          </div>

          {/* SVG Graph Canvas */}
          <div className="w-full h-[400px] bg-[#070c17] rounded border border-[#16233b] relative overflow-hidden flex items-center justify-center p-2">
            <svg viewBox="0 0 880 440" className="w-full h-full select-none">
              <defs>
                <filter id="glow-path" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <marker
                  id="arrow-default"
                  viewBox="0 0 10 10"
                  refX="18"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#334155" />
                </marker>
                <marker
                  id="arrow-active"
                  viewBox="0 0 10 10"
                  refX="18"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#06b6d4" />
                </marker>
              </defs>

              {/* Draw Edges */}
              {GRAPH_EDGES.map(edge => {
                const srcNode = GRAPH_NODES.find(n => n.id === edge.source);
                const dstNode = GRAPH_NODES.find(n => n.id === edge.target);
                if (!srcNode || !dstNode) return null;

                const inPath = isEdgeInPath(edge.source, edge.target);

                return (
                  <g key={edge.id}>
                    <line
                      x1={srcNode.x}
                      y1={srcNode.y}
                      x2={dstNode.x}
                      y2={dstNode.y}
                      stroke={inPath ? '#06b6d4' : '#1e2d48'}
                      strokeWidth={inPath ? 3 : 1.2}
                      strokeDasharray={edge.isObservedFlow ? undefined : '4 4'}
                      markerEnd={inPath ? 'url(#arrow-active)' : 'url(#arrow-default)'}
                      filter={inPath ? 'url(#glow-path)' : undefined}
                    />
                    {/* Edge Label: Protocol & Cost */}
                    <text
                      x={(srcNode.x! + dstNode.x!) / 2}
                      y={(srcNode.y! + dstNode.y!) / 2 - 5}
                      fill={inPath ? '#22d3ee' : '#64748b'}
                      fontSize="8"
                      fontFamily="JetBrains Mono"
                      textAnchor="middle"
                      className="font-mono select-none"
                    >
                      {edge.protocol} (cost: {edge.cost})
                    </text>
                  </g>
                );
              })}

              {/* Draw Nodes */}
              {GRAPH_NODES.map(node => {
                const inPath = isNodeInPath(node.id);
                const visited = isNodeVisited(node.id);
                const isSrc = node.id === sourceNode;
                const isDst = node.id === targetNode;

                let strokeColor = '#243757';
                let fillColor = '#0d1527';
                if (inPath) {
                  strokeColor = '#06b6d4';
                  fillColor = '#083344';
                } else if (visited) {
                  strokeColor = '#f59e0b';
                  fillColor = '#451a03';
                }

                if (isSrc) strokeColor = '#10b981';
                if (isDst) strokeColor = '#ef4444';

                return (
                  <g
                    key={node.id}
                    className="cursor-pointer group"
                    onClick={() => {
                      if (sourceNode !== node.id) setTargetNode(node.id);
                    }}
                  >
                    {/* Ping for compromised or active target */}
                    {(isSrc || isDst || inPath) && (
                      <circle
                        cx={node.x}
                        cy={node.y}
                        r="24"
                        fill={isSrc ? '#10b981' : isDst ? '#ef4444' : '#06b6d4'}
                        fillOpacity="0.15"
                        className="animate-pulse"
                      />
                    )}

                    <circle
                      cx={node.x}
                      cy={node.y}
                      r="16"
                      fill={fillColor}
                      stroke={strokeColor}
                      strokeWidth={inPath || isSrc || isDst ? 2.5 : 1.5}
                    />

                    {/* Node Label Text */}
                    <text
                      x={node.x}
                      y={node.y! + 26}
                      fill={inPath ? '#f1f5f9' : '#94a3b8'}
                      fontSize="9"
                      fontFamily="JetBrains Mono"
                      fontWeight="bold"
                      textAnchor="middle"
                      className="select-none"
                    >
                      {node.label}
                    </text>

                    <text
                      x={node.x}
                      y={node.y! + 36}
                      fill="#64748b"
                      fontSize="7.5"
                      fontFamily="JetBrains Mono"
                      textAnchor="middle"
                      className="select-none"
                    >
                      {node.ip}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Active Path Visual Sequence */}
          <div className="mt-3 p-2.5 rounded bg-[#080d19] border border-[#16233b] font-mono text-xs">
            <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">
              Active Attack Vector Sequence:
            </span>
            {searchResult && searchResult.found ? (
              <div className="flex items-center flex-wrap gap-2">
                {searchResult.path.map((nodeId, idx) => {
                  const node = GRAPH_NODES.find(n => n.id === nodeId);
                  return (
                    <React.Fragment key={nodeId}>
                      <span className="px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-bold text-xs flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                        {node?.label || nodeId} ({node?.ip})
                      </span>
                      {idx < searchResult.path.length - 1 && (
                        <ArrowRight className="w-3.5 h-3.5 text-cyan-500 flex-shrink-0" />
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            ) : (
              <span className="text-red-400 text-xs">No path exists connecting the selected nodes.</span>
            )}
          </div>
        </div>
      </div>

      {/* Side-by-Side Algorithm Comparison Matrix */}
      {comparisonResults && (
        <div className="soc-card p-4 space-y-3 font-mono text-xs animate-in fade-in">
          <div className="flex items-center justify-between border-b border-[#18263f] pb-2">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-slate-100">
                Algorithm Performance Comparison Matrix ({sourceNode} → {targetNode})
              </span>
            </div>
            <span className="text-[10px] text-slate-400">
              Evaluated on same topology
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="text-[10px] text-slate-400 uppercase border-b border-[#18263f] pb-1">
                  <th className="py-2">Algorithm</th>
                  <th className="py-2 text-center">Path Found</th>
                  <th className="py-2 text-center">Hop Count</th>
                  <th className="py-2 text-center">Total Cost g(n)</th>
                  <th className="py-2 text-center">Nodes Explored</th>
                  <th className="py-2 text-center">Execution Time</th>
                  <th className="py-2">Optimality Guarantee</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#131d30]">
                {Object.values(comparisonResults).map(res => (
                  <tr key={res.algorithm} className="hover:bg-[#111c30]">
                    <td className="py-2 font-bold text-cyan-400">{res.algorithm}</td>
                    <td className="py-2 text-center">
                      <span className={`text-[10px] font-bold ${res.found ? 'text-emerald-400' : 'text-red-400'}`}>
                        {res.found ? 'YES' : 'NO'}
                      </span>
                    </td>
                    <td className="py-2 text-center text-slate-200">{res.pathLength}</td>
                    <td className="py-2 text-center font-bold text-amber-300">{res.totalCost}</td>
                    <td className="py-2 text-center text-slate-200">{res.totalExplored} / {GRAPH_NODES.length}</td>
                    <td className="py-2 text-center text-slate-300">{res.executionTimeMs} ms</td>
                    <td className="py-2 text-[10px] text-slate-400">
                      {res.algorithm === 'A*' && 'Guaranteed lowest-cost path with admissible heuristic h(n).'}
                      {res.algorithm === 'BFS' && 'Guaranteed minimum hop count for unweighted graphs.'}
                      {res.algorithm === 'DFS' && 'No optimality guarantees. Explores deep paths first.'}
                      {res.algorithm === 'Greedy Best-First' && 'Heuristic-driven speed. May return sub-optimal path.'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Critical Note */}
      <div className="bg-[#0c1424] p-3 rounded border border-[#1b2b47] flex items-start gap-2.5 text-xs font-mono text-slate-400">
        <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-slate-200">Engineering Distinction:</strong> A graph path represents mathematical connectivity and permissible routes in network access control lists. It proves traversal feasibility, not that an intrusion has definitively occurred along all hops.
        </p>
      </div>
    </div>
  );
};
