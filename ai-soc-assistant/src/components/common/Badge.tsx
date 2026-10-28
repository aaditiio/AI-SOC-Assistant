import React from 'react';
import { Severity } from '../../types/soc';

interface BadgeProps {
  severity?: Severity;
  variant?: 'solid' | 'outline' | 'subtle';
  children: React.ReactNode;
  className?: string;
  size?: 'xs' | 'sm' | 'md';
}

export const SeverityBadge: React.FC<{ severity: Severity; size?: 'xs' | 'sm' | 'md' }> = ({
  severity,
  size = 'xs'
}) => {
  const sizeClasses = {
    xs: 'text-[10px] px-1.5 py-0.5 leading-none',
    sm: 'text-xs px-2 py-0.5',
    md: 'text-xs px-2.5 py-1'
  };

  const severityClasses: Record<Severity, string> = {
    Critical: 'bg-red-950/60 text-red-400 border border-red-500/40 shadow-[0_0_8px_rgba(239,68,68,0.2)]',
    High: 'bg-orange-950/60 text-orange-400 border border-orange-500/40 shadow-[0_0_8px_rgba(249,115,22,0.2)]',
    Medium: 'bg-amber-950/60 text-amber-300 border border-amber-500/40',
    Low: 'bg-blue-950/60 text-blue-300 border border-blue-500/40',
    Informational: 'bg-slate-800/80 text-slate-300 border border-slate-700'
  };

  return (
    <span
      className={`inline-flex items-center font-medium font-mono uppercase tracking-wider rounded ${sizeClasses[size]} ${severityClasses[severity]}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
        severity === 'Critical' ? 'bg-red-400 animate-pulse' :
        severity === 'High' ? 'bg-orange-400' :
        severity === 'Medium' ? 'bg-amber-400' :
        severity === 'Low' ? 'bg-blue-400' : 'bg-slate-400'
      }`} />
      {severity}
    </span>
  );
};

export const StatusBadge: React.FC<{ status: string; size?: 'xs' | 'sm' }> = ({
  status,
  size = 'xs'
}) => {
  const getStyle = () => {
    switch (status) {
      case 'New':
        return 'bg-cyan-950/60 text-cyan-300 border-cyan-500/40';
      case 'In Progress':
      case 'Investigating':
        return 'bg-amber-950/60 text-amber-300 border-amber-500/40';
      case 'Escalated':
        return 'bg-purple-950/60 text-purple-300 border-purple-500/40';
      case 'Resolved':
        return 'bg-emerald-950/60 text-emerald-300 border-emerald-500/40';
      case 'On Hold':
        return 'bg-slate-800 text-slate-300 border-slate-600';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <span
      className={`inline-flex items-center font-medium font-mono rounded border ${
        size === 'xs' ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2 py-0.5'
      } ${getStyle()}`}
    >
      {status}
    </span>
  );
};
