import React from 'react';
import { Server, ServerStatus } from '../types';

const styles: Record<ServerStatus, { label: string; classes: string }> = {
  active: { label: 'Active', classes: 'bg-success/15 text-success' },
  error: { label: 'Error', classes: 'bg-danger/15 text-danger' },
  inactive: { label: 'Inactive', classes: 'bg-on-surface-muted/15 text-on-surface-muted' },
  unknown: { label: 'Checking', classes: 'bg-on-surface-muted/15 text-on-surface-muted' },
};

export const describeServerStatus = (s: Server): string => {
  if (s.status === 'unknown') return 'Not probed yet';
  if (s.status === 'inactive') return 'No enabled rule routes to this server';
  const when = s.statusCheckedAt ? `, checked ${new Date(s.statusCheckedAt).toLocaleTimeString()}` : '';
  return `${s.upstreamsUp} of ${s.upstreamsTotal} upstreams answered${when}`;
};

const ServerStatusBadge: React.FC<{ server: Server }> = ({ server }) => {
  const { label, classes } = styles[server.status] ?? styles.unknown;
  return (
    <span
      title={describeServerStatus(server)}
      data-status={server.status}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 text-xs font-medium rounded-full ${classes}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" aria-hidden="true" />
      {label}
    </span>
  );
};

export default ServerStatusBadge;
