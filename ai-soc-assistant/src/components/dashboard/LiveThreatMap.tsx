import React from 'react';
import { Alert } from '../../types/soc';
import { GlobalThreatHeatmap } from './GlobalThreatHeatmap';

interface LiveThreatMapProps {
  alerts: Alert[];
  onSelectAlert?: (alertId: string) => void;
  className?: string;
}

export const LiveThreatMap: React.FC<LiveThreatMapProps> = ({
  alerts,
  onSelectAlert,
  className
}) => {
  return (
    <GlobalThreatHeatmap
      alerts={alerts}
      onSelectAlert={onSelectAlert}
      className={className}
    />
  );
};
