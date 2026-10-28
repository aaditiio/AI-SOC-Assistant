import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Globe,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  AlertTriangle,
  Info,
  ExternalLink,
  ShieldCheck,
  Eye,
  EyeOff
} from 'lucide-react';
import * as d3 from 'd3';
import { Alert } from '../../types/soc';
import {
  worldLandGeoJSON,
  worldCountriesGeoJSON,
  worldBordersMesh
} from '../../data/naturalEarthWorld';

export interface GeographicThreatPoint {
  source: string;
  destination: string;
  source_latitude: number;
  source_longitude: number;
  destination_latitude?: number;
  destination_longitude?: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  category: string;
  alert_id?: string;
  timestamp: string;
  coordinate_source: string;
}

interface GlobalThreatHeatmapProps {
  alerts: Alert[];
  onSelectAlert?: (alertId: string) => void;
  className?: string;
}

// Function to validate geographic coordinate ranges strictly
function isValidCoordinate(lat: number, lon: number): boolean {
  return (
    typeof lat === 'number' &&
    typeof lon === 'number' &&
    !isNaN(lat) &&
    !isNaN(lon) &&
    lat >= -90 &&
    lat <= 90 &&
    lon >= -180 &&
    lon <= 180 &&
    !(lat === 0 && lon === 0)
  );
}

// Color coding according to severity specifications
const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',     // Red
  High: '#f97316',         // Orange
  Medium: '#f59e0b',       // Amber
  Low: '#3b82f6',          // Cyan / Blue
  Informational: '#64748b' // Slate / Gray
};

export const GlobalThreatHeatmap: React.FC<GlobalThreatHeatmapProps> = ({
  alerts,
  onSelectAlert,
  className = ''
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const [demoMode, setDemoMode] = useState<boolean>(false);
  const [hoveredPoint, setHoveredPoint] = useState<GeographicThreatPoint | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);
  const [activeFilter, setActiveFilter] = useState<string>('all');
  const [currentZoom, setCurrentZoom] = useState<number>(1);

  // Demonstration dataset with validated public coordinates (strictly labeled illustrative provenance)
  const demoThreatPoints: GeographicThreatPoint[] = useMemo(() => [
    {
      source: '185.190.140.22 (Frankfurt, DE)',
      destination: '10.0.1.10 (US-East DC)',
      source_latitude: 50.1109,
      source_longitude: 8.6821,
      destination_latitude: 38.9072,
      destination_longitude: -77.0369,
      severity: 'Critical',
      category: 'APT29 / C2 Ingress',
      alert_id: alerts[0]?.id || 'ALT-3238',
      timestamp: alerts[0]?.timestamp || '10:27:19 UTC',
      coordinate_source: 'Illustrative Demo Dataset (Validated Public Coordinates)'
    },
    {
      source: '103.235.46.10 (Tokyo, JP)',
      destination: '192.168.1.100 (DMZ-WEB-01)',
      source_latitude: 35.6762,
      source_longitude: 139.6503,
      destination_latitude: 38.9072,
      destination_longitude: -77.0369,
      severity: 'Critical',
      category: 'Volumetric SYN Flood',
      alert_id: alerts[1]?.id || 'ALT-3239',
      timestamp: alerts[1]?.timestamp || '10:25:12 UTC',
      coordinate_source: 'Illustrative Demo Dataset (Validated Public Coordinates)'
    },
    {
      source: '201.86.155.44 (São Paulo, BR)',
      destination: '10.0.1.10 (US-East DC)',
      source_latitude: -23.5505,
      source_longitude: -46.6333,
      destination_latitude: 38.9072,
      destination_longitude: -77.0369,
      severity: 'High',
      category: 'Kerberos Spraying',
      alert_id: alerts[2]?.id || 'ALT-3240',
      timestamp: alerts[2]?.timestamp || '10:22:40 UTC',
      coordinate_source: 'Illustrative Demo Dataset (Validated Public Coordinates)'
    },
    {
      source: '194.26.29.112 (London, UK)',
      destination: '10.0.2.15 (Core DB)',
      source_latitude: 51.5074,
      source_longitude: -0.1278,
      destination_latitude: 50.1109,
      destination_longitude: 8.6821,
      severity: 'High',
      category: 'Credential Harvesting',
      alert_id: alerts[3]?.id || 'ALT-3241',
      timestamp: alerts[3]?.timestamp || '10:19:05 UTC',
      coordinate_source: 'Illustrative Demo Dataset (Validated Public Coordinates)'
    },
    {
      source: '118.200.74.88 (Singapore, SG)',
      destination: '10.0.1.10 (US-East DC)',
      source_latitude: 1.3521,
      source_longitude: 103.8198,
      destination_latitude: 38.9072,
      destination_longitude: -77.0369,
      severity: 'Medium',
      category: 'Port Scan Recon',
      alert_id: alerts[4]?.id || 'ALT-3242',
      timestamp: alerts[4]?.timestamp || '10:15:30 UTC',
      coordinate_source: 'Illustrative Demo Dataset (Validated Public Coordinates)'
    },
    {
      source: '139.130.4.5 (Sydney, AU)',
      destination: '192.168.1.100 (DMZ-WEB-01)',
      source_latitude: -33.8688,
      source_longitude: 151.2093,
      destination_latitude: 38.9072,
      destination_longitude: -77.0369,
      severity: 'Low',
      category: 'TLS Cipher Negotiation',
      alert_id: alerts[5]?.id || 'ALT-3243',
      timestamp: alerts[5]?.timestamp || '10:10:00 UTC',
      coordinate_source: 'Illustrative Demo Dataset (Validated Public Coordinates)'
    }
  ], [alerts]);

  // Extract any genuine geographic points from incoming alerts (filtering strictly for valid non-private coordinates)
  const actualThreatPoints: GeographicThreatPoint[] = useMemo(() => {
    const valid: GeographicThreatPoint[] = [];
    alerts.forEach((alert) => {
      // Check if alert carries genuine validated geographic coordinates metadata
      const anyAlert = alert as any;
      if (
        anyAlert.source_latitude !== undefined &&
        anyAlert.source_longitude !== undefined &&
        isValidCoordinate(anyAlert.source_latitude, anyAlert.source_longitude) &&
        anyAlert.coordinate_source
      ) {
        valid.push({
          source: anyAlert.sourceIp || alert.sourceIp,
          destination: anyAlert.destIp || alert.destIp,
          source_latitude: anyAlert.source_latitude,
          source_longitude: anyAlert.source_longitude,
          destination_latitude: anyAlert.destination_latitude,
          destination_longitude: anyAlert.destination_longitude,
          severity: alert.severity,
          category: alert.predictedCategory || alert.title,
          alert_id: alert.id,
          timestamp: alert.timestamp,
          coordinate_source: anyAlert.coordinate_source
        });
      }
    });
    return valid;
  }, [alerts]);

  // Active dataset depending on demo mode
  const activeDataset = useMemo(() => {
    const raw = demoMode ? demoThreatPoints : actualThreatPoints;
    if (activeFilter === 'all') return raw;
    return raw.filter((p) => p.severity.toLowerCase() === activeFilter.toLowerCase());
  }, [demoMode, demoThreatPoints, actualThreatPoints, activeFilter]);

  // Render Natural Earth World Map using D3
  useEffect(() => {
    if (!svgRef.current) return;

    const width = 960;
    const height = 460;
    const svg = d3.select(svgRef.current);

    // Clear dynamic layer
    svg.selectAll('.map-content-layer').remove();

    const g = svg.append('g').attr('class', 'map-content-layer');

    // Equirectangular projection for rectangular world map matching reference
    const projection = d3.geoEquirectangular()
      .scale(152)
      .translate([width / 2, height / 2 + 15]);

    const pathGenerator = d3.geoPath().projection(projection);

    // 1. Render all country polygons from official Natural Earth dataset
    g.append('g')
      .attr('class', 'countries-group')
      .selectAll('path')
      .data((worldCountriesGeoJSON as any).features)
      .enter()
      .append('path')
      .attr('d', pathGenerator as any)
      .attr('fill', '#101a2d')
      .attr('stroke', '#192b4a')
      .attr('stroke-width', 0.6)
      .attr('class', 'country-polygon transition-colors duration-150')
      .on('mouseenter', function () {
        d3.select(this).attr('fill', '#15243f');
      })
      .on('mouseleave', function () {
        d3.select(this).attr('fill', '#101a2d');
      });

    // 2. Render subtle internal borders mesh
    g.append('path')
      .datum(worldBordersMesh as any)
      .attr('d', pathGenerator as any)
      .attr('fill', 'none')
      .attr('stroke', '#1a2b47')
      .attr('stroke-width', 0.5)
      .attr('stroke-opacity', 0.8)
      .style('pointer-events', 'none');

    // 3. Render clean coastlines for high-fidelity definition
    g.append('path')
      .datum(worldLandGeoJSON as any)
      .attr('d', pathGenerator as any)
      .attr('fill', 'none')
      .attr('stroke', '#243c66')
      .attr('stroke-width', 0.8)
      .style('pointer-events', 'none');

    // 4. Render threat connection arcs & markers if valid points exist
    if (activeDataset.length > 0) {
      const arcsGroup = g.append('g').attr('class', 'arcs-group');
      const markersGroup = g.append('g').attr('class', 'markers-group');

      activeDataset.forEach((point) => {
        const sourceCoords: [number, number] = [point.source_longitude, point.source_latitude];
        const sourceProj = projection(sourceCoords);
        if (!sourceProj) return;

        const [sx, sy] = sourceProj;
        const color = SEVERITY_COLORS[point.severity] || '#3b82f6';

        // Draw curved connection arc if destination coords are valid
        if (
          point.destination_latitude !== undefined &&
          point.destination_longitude !== undefined &&
          isValidCoordinate(point.destination_latitude, point.destination_longitude)
        ) {
          const destCoords: [number, number] = [point.destination_longitude, point.destination_latitude];
          const destProj = projection(destCoords);
          if (destProj) {
            const [dx, dy] = destProj;
            const midX = (sx + dx) / 2;
            const midY = Math.min(sy, dy) - Math.abs(sx - dx) * 0.18 - 25;

            // Curved arc
            arcsGroup.append('path')
              .attr('d', `M ${sx} ${sy} Q ${midX} ${midY} ${dx} ${dy}`)
              .attr('fill', 'none')
              .attr('stroke', color)
              .attr('stroke-width', 1.2)
              .attr('stroke-opacity', 0.55)
              .attr('stroke-dasharray', '4 3')
              .attr('class', 'threat-arc');

            // Destination target marker
            markersGroup.append('circle')
              .attr('cx', dx)
              .attr('cy', dy)
              .attr('r', 3)
              .attr('fill', '#06b6d4')
              .attr('stroke', '#ffffff')
              .attr('stroke-width', 0.8)
              .attr('opacity', 0.85);
          }
        }

        // Outer glow halo
        markersGroup.append('circle')
          .attr('cx', sx)
          .attr('cy', sy)
          .attr('r', 8)
          .attr('fill', color)
          .attr('fill-opacity', 0.22)
          .attr('class', 'animate-pulse');

        // Core marker
        markersGroup.append('circle')
          .attr('cx', sx)
          .attr('cy', sy)
          .attr('r', 3.8)
          .attr('fill', color)
          .attr('stroke', '#ffffff')
          .attr('stroke-width', 1)
          .style('cursor', 'pointer')
          .on('mouseenter', (event) => {
            setHoveredPoint(point);
            if (containerRef.current) {
              const rect = containerRef.current.getBoundingClientRect();
              setTooltipPos({
                x: event.clientX - rect.left,
                y: event.clientY - rect.top
              });
            }
          })
          .on('mouseleave', () => {
            setHoveredPoint(null);
            setTooltipPos(null);
          })
          .on('click', () => {
            if (point.alert_id && onSelectAlert) {
              onSelectAlert(point.alert_id);
            }
          });
      });
    }

    // Set up D3 Zoom behavior
    const zoomBehavior = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 4])
      .translateExtent([[0, 0], [width, height]])
      .on('zoom', (event) => {
        g.attr('transform', event.transform.toString());
        setCurrentZoom(event.transform.k);
      });

    svg.call(zoomBehavior);

    // Zoom buttons handling
    (window as any).__socMapZoomIn = () => {
      svg.transition().duration(250).call(zoomBehavior.scaleBy, 1.3);
    };
    (window as any).__socMapZoomOut = () => {
      svg.transition().duration(250).call(zoomBehavior.scaleBy, 0.77);
    };
    (window as any).__socMapZoomReset = () => {
      svg.transition().duration(300).call(zoomBehavior.transform, d3.zoomIdentity);
    };

  }, [activeDataset, onSelectAlert]);

  const handleZoomIn = () => {
    if ((window as any).__socMapZoomIn) (window as any).__socMapZoomIn();
  };

  const handleZoomOut = () => {
    if ((window as any).__socMapZoomOut) (window as any).__socMapZoomOut();
  };

  const handleZoomReset = () => {
    if ((window as any).__socMapZoomReset) (window as any).__socMapZoomReset();
  };

  return (
    <div
      ref={containerRef}
      className={`soc-card p-3 flex flex-col justify-between bg-[#060b17] border border-[#16233b] rounded-lg relative overflow-hidden ${className}`}
    >
      {/* Panel Header */}
      <div className="flex items-center justify-between border-b border-[#16233b] pb-2 z-10">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <h2 className="text-xs font-mono font-bold text-slate-100 tracking-wide uppercase">
            Live Threat Map
          </h2>
          <span className="text-[10px] font-mono bg-[#0c182d] text-cyan-400 px-2 py-0.5 rounded border border-cyan-500/30">
            Natural Earth 1:110m
          </span>
        </div>

        {/* Action Controls & Demonstration Toggle */}
        <div className="flex items-center gap-2">
          {/* Demonstration Mode Toggle */}
          <button
            onClick={() => setDemoMode(!demoMode)}
            className={`px-2 py-0.5 text-[10px] font-mono rounded border transition-all flex items-center gap-1.5 ${
              demoMode
                ? 'bg-amber-950/80 text-amber-300 border-amber-500/50 shadow'
                : 'bg-[#0a1324] text-slate-400 border-[#1a2b4a] hover:text-white'
            }`}
            title="Toggle demonstration markers with validated public IP coordinates"
          >
            {demoMode ? <Eye className="w-3 h-3 text-amber-400" /> : <EyeOff className="w-3 h-3 text-slate-400" />}
            <span>{demoMode ? 'Demo Mode Active' : 'Enable Demo Markers'}</span>
          </button>
        </div>
      </div>

      {/* Main Map Viewport */}
      <div className="relative w-full h-[360px] bg-[#050914] rounded border border-[#121f36] overflow-hidden my-1">
        {/* SVG World Map */}
        <svg
          ref={svgRef}
          viewBox="0 0 960 460"
          className="w-full h-full cursor-grab active:cursor-grabbing select-none"
        >
          <defs>
            <linearGradient id="ocean-bg" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#050a14" />
              <stop offset="100%" stopColor="#070d1c" />
            </linearGradient>
            <pattern id="grid-pattern" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#0e182a" strokeWidth="0.6" strokeDasharray="2 2" />
            </pattern>
          </defs>

          <rect width="960" height="460" fill="url(#ocean-bg)" />
          <rect width="960" height="460" fill="url(#grid-pattern)" />
        </svg>

        {/* Compact Zoom Controls (Top Left, matching reference screenshot) */}
        <div className="absolute top-3 left-3 flex flex-col gap-1 bg-[#091122]/90 backdrop-blur p-1 rounded border border-[#182a47] shadow-lg z-10">
          <button
            onClick={handleZoomIn}
            className="w-6 h-6 flex items-center justify-center text-slate-300 hover:text-white hover:bg-[#121f36] rounded text-xs font-bold transition-colors"
            title="Zoom In"
          >
            +
          </button>
          <button
            onClick={handleZoomOut}
            className="w-6 h-6 flex items-center justify-center text-slate-300 hover:text-white hover:bg-[#121f36] rounded text-xs font-bold transition-colors"
            title="Zoom Out"
          >
            −
          </button>
          <button
            onClick={handleZoomReset}
            className="w-6 h-6 flex items-center justify-center text-slate-300 hover:text-white hover:bg-[#121f36] rounded text-[10px] transition-colors"
            title="Reset View"
          >
            <RotateCcw className="w-3 h-3" />
          </button>
        </div>

        {/* Notice for RFC 1918 Private / RFC 5737 Reserved IPs when Demo Mode is inactive */}
        {!demoMode && activeDataset.length === 0 && (
          <div className="absolute top-3 right-3 bg-[#0a1224]/90 backdrop-blur px-3 py-1.5 rounded border border-[#192c4d] shadow flex items-center gap-2 z-10 max-w-sm">
            <Info className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
            <span className="text-[10px] font-mono text-slate-300">
              Geographic origin unavailable for private/reserved IP telemetry (RFC 1918 / RFC 5737). Genuine Natural Earth boundaries rendered.
            </span>
          </div>
        )}

        {/* Interactive Hover Tooltip */}
        {hoveredPoint && tooltipPos && (
          <div
            className="absolute pointer-events-none bg-[#091122]/95 backdrop-blur border border-red-500/40 p-2.5 rounded shadow-2xl z-30 text-xs font-mono max-w-[260px] animate-in fade-in duration-100"
            style={{
              left: Math.min(tooltipPos.x + 12, 680),
              top: Math.max(tooltipPos.y - 100, 10)
            }}
          >
            <div className="flex items-center justify-between border-b border-[#182b47] pb-1 mb-1.5">
              <span className="font-bold text-white truncate">{hoveredPoint.category}</span>
              <span
                className="px-1.5 py-0.2 rounded text-[9px] font-bold"
                style={{
                  backgroundColor: `${SEVERITY_COLORS[hoveredPoint.severity]}25`,
                  color: SEVERITY_COLORS[hoveredPoint.severity],
                  border: `1px solid ${SEVERITY_COLORS[hoveredPoint.severity]}50`
                }}
              >
                {hoveredPoint.severity}
              </span>
            </div>
            <div className="space-y-1 text-[10px] text-slate-300">
              <div className="flex justify-between">
                <span className="text-slate-400">Source:</span>
                <span className="text-cyan-400 font-semibold">{hoveredPoint.source}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Target:</span>
                <span className="text-purple-300">{hoveredPoint.destination}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Coordinates:</span>
                <span className="text-slate-300">
                  {hoveredPoint.source_latitude.toFixed(2)}°, {hoveredPoint.source_longitude.toFixed(2)}°
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Timestamp:</span>
                <span>{hoveredPoint.timestamp}</span>
              </div>
              <div className="pt-1 border-t border-[#16253d] text-[9px] text-amber-400/90 leading-tight">
                {hoveredPoint.coordinate_source}
              </div>
            </div>
          </div>
        )}

        {/* Compact Bottom Legend (Matching Reference Screenshot) */}
        <div className="absolute bottom-2.5 left-3 bg-[#081020]/90 backdrop-blur px-2.5 py-1 rounded border border-[#162742] flex items-center gap-3 text-[10px] font-mono text-slate-300 z-10">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#ef4444]" />
            <span>Critical</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#f97316]" />
            <span>High</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#f59e0b]" />
            <span>Medium</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#3b82f6]" />
            <span>Low</span>
          </div>
          {demoMode && (
            <span className="text-[9px] text-amber-400 border-l border-slate-700 pl-2">
              Illustrative Telemetry
            </span>
          )}
        </div>
      </div>

      {/* Footer Info Strip */}
      <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 border-t border-[#16233b] pt-1.5 px-0.5">
        <div className="flex items-center gap-2">
          <span>Boundary Source: Natural Earth Public Domain</span>
          <span>•</span>
          <span>Projection: Equirectangular</span>
        </div>
        <div>
          {demoMode ? (
            <span className="text-amber-400 font-semibold">{activeDataset.length} Mapped Demo Threat Vectors</span>
          ) : (
            <span className="text-emerald-400 font-medium">Telemetry Topology Synchronized</span>
          )}
        </div>
      </div>
    </div>
  );
};
