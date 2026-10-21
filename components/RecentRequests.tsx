import React, { useCallback, useEffect, useRef, useState } from 'react';
import Button from './Button';
import { RecentRequest, api, apiErrorMessage } from '../services/apiClient';

const FILTERS = ['', '2xx', '3xx', '4xx', '5xx'] as const;
const PAGE = 50;

const statusStyle = (status: number): string =>
  status >= 500 || status === 0 ? 'text-danger' : status >= 400 ? 'text-warning' : 'text-success';

const formatSize = (bytes: number): string =>
  bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} kB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`;

/** One rule's requests from the last 24 hours, newest first. The first page refreshes on its own. */
const RecentRequests: React.FC<{ serverId: string; ruleId: string; refreshMs?: number }> = ({ serverId, ruleId, refreshMs = 10_000 }) => {
  const [status, setStatus] = useState<(typeof FILTERS)[number]>('');
  const [requests, setRequests] = useState<RecentRequest[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [paged, setPaged] = useState(false);
  const latest = useRef(0);
  // Read by the timer, which can fire before the render that stops it.
  const pagedRef = useRef(false);

  const load = useCallback(async (before?: number) => {
    const call = ++latest.current;
    pagedRef.current = before !== undefined;
    try {
      const page = await api.servers.rules.requests(serverId, ruleId, { take: PAGE, status: status || undefined, before });
      if (call !== latest.current) return;
      setRequests(prev => (before === undefined ? page.requests : [...prev, ...page.requests]));
      setNext(page.next);
      setMessage(page.message);
      setPaged(before !== undefined);
      setError(null);
    } catch (e) {
      if (call === latest.current) setError(apiErrorMessage(e, 'The requests could not be loaded.'));
    } finally {
      if (call === latest.current) setLoaded(true);
    }
  }, [serverId, ruleId, status]);

  useEffect(() => { void load(); }, [load]);

  // Refreshing would drop the older pages the user asked for, so it waits until they go back to the newest.
  useEffect(() => {
    if (paged || refreshMs <= 0) return;
    const timer = window.setInterval(() => { if (!pagedRef.current) void load(); }, refreshMs);
    return () => window.clearInterval(timer);
  }, [load, paged, refreshMs]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div role="radiogroup" aria-label="Status" className="flex gap-1">
          {FILTERS.map(f => (
            <button key={f || 'all'} type="button" role="radio" aria-checked={status === f} onClick={() => setStatus(f)}
              className={`rounded-lg border px-2.5 py-1 text-xs ${status === f ? 'border-primary bg-primary/10 text-on-surface' : 'border-border text-on-surface-muted'}`}>
              {f || 'All'}
            </button>
          ))}
        </div>
        <Button variant="secondary" onClick={() => void load()}>Refresh</Button>
      </div>

      {error && <div role="alert" className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">{error}</div>}
      {message && <p role="status" className="text-sm text-on-surface-muted">{message}</p>}

      {loaded && requests.length === 0 && !error && !message && (
        <p className="text-sm text-on-surface-muted">No requests in the last 24 hours{status ? ` with status ${status}` : ''}.</p>
      )}

      {requests.length > 0 && (
        <div className="overflow-x-auto">
          <table aria-label="Recent requests" className="w-full text-xs">
            <thead className="text-left text-on-surface-muted">
              <tr>
                <th className="py-1 pr-3 font-medium">Time</th>
                <th className="py-1 pr-3 font-medium">Method</th>
                <th className="py-1 pr-3 font-medium">Path</th>
                <th className="py-1 pr-3 font-medium">Status</th>
                <th className="py-1 pr-3 font-medium text-right">Duration</th>
                <th className="py-1 pr-3 font-medium text-right">Size</th>
                <th className="py-1 font-medium">Client</th>
              </tr>
            </thead>
            <tbody className="font-mono text-on-surface">
              {requests.map(r => (
                <tr key={r.seq} className="border-t border-border">
                  <td className="py-1 pr-3 whitespace-nowrap" title={r.at}>{new Date(r.at).toLocaleTimeString()}</td>
                  <td className="py-1 pr-3">{r.method}</td>
                  <td className="py-1 pr-3 break-all">{r.path}</td>
                  <td className={`py-1 pr-3 ${statusStyle(r.status)}`}>{r.status || 'none'}</td>
                  <td className="py-1 pr-3 text-right tabular-nums">{r.durationMs.toFixed(1)} ms</td>
                  <td className="py-1 pr-3 text-right tabular-nums">{formatSize(r.size)}</td>
                  <td className="py-1">{r.clientIp ?? 'unknown'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {next !== null && (
        <Button variant="secondary" onClick={() => void load(next)}>Older requests</Button>
      )}
    </div>
  );
};

export default RecentRequests;
