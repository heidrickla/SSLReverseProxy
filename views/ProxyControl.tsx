import React, { useCallback, useEffect, useState } from 'react';
import Button from '../components/Button';
import { useAuth } from '../contexts/AuthContext';
import { api, ApiError, ProxyStatus, Metrics, ProxyValidation } from '../services/apiClient';

const stateColor: Record<string, string> = {
    Running: 'bg-success/20 text-success',
    Stopped: 'bg-secondary/20 text-on-surface-muted',
    Faulted: 'bg-danger/20 text-danger',
    Unavailable: 'bg-warning/20 text-warning',
    Unknown: 'bg-secondary/20 text-on-surface-muted',
};

const ProxyControl: React.FC = () => {
    const { hasPermission } = useAuth();
    const canControl = hasPermission('proxy:control');

    const [status, setStatus] = useState<ProxyStatus | null>(null);
    const [metrics, setMetrics] = useState<Metrics | null>(null);
    const [validation, setValidation] = useState<ProxyValidation | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    const refresh = useCallback(async () => {
        setError(null);
        try {
            const [s, m] = await Promise.all([api.proxy.status(), api.proxy.metrics()]);
            setStatus(s);
            setMetrics(m);
        } catch (e) {
            setError(e instanceof ApiError ? `${e.status}: ${e.message}` : 'Failed to reach the API.');
        }
    }, []);

    useEffect(() => { refresh(); }, [refresh]);

    const run = async (label: string, fn: () => Promise<unknown>) => {
        setBusy(label);
        setError(null);
        setValidation(null);
        try {
            const result = await fn();
            if (label === 'Validate') setValidation(result as ProxyValidation);
            await refresh();
        } catch (e) {
            setError(e instanceof ApiError ? `${e.status}: ${e.message}` : 'Request failed.');
        } finally {
            setBusy(null);
        }
    };

    return (
        <div className="space-y-6 h-full overflow-y-auto pr-2 pb-8">
            <div className="flex justify-between items-center">
                <h2 className="text-xl font-semibold text-on-surface">Proxy Control</h2>
                <Button variant="secondary" onClick={refresh} disabled={busy !== null}>Refresh</Button>
            </div>

            {error && (
                <div className="bg-danger/10 border-l-4 border-danger p-3 rounded-r-lg text-sm text-on-surface">{error}</div>
            )}

            {/* Status */}
            <div className="bg-surface p-6 rounded-lg shadow-lg">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-on-surface">Status</h3>
                    {status && (
                        <span className={`px-3 py-1 text-xs font-semibold rounded-full ${stateColor[status.state] ?? stateColor.Unknown}`}>
                            {status.state}
                        </span>
                    )}
                </div>
                {status ? (
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
                        <Stat label="Engine" value={status.engine} />
                        <Stat label="Process ID" value={status.processId ?? '—'} />
                        <Stat label="Active Rules" value={status.activeRuleCount} />
                        <Stat label="Started" value={status.startedAt ? new Date(status.startedAt).toLocaleTimeString() : '—'} />
                        {status.message && <div className="col-span-full text-on-surface-muted">{status.message}</div>}
                    </div>
                ) : <p className="text-on-surface-muted text-sm">Loading…</p>}

                {canControl && (
                    <div className="flex flex-wrap gap-2 mt-6 pt-4 border-t border-border">
                        <Button onClick={() => run('Start', api.proxy.start)} disabled={busy !== null}>
                            {busy === 'Start' ? 'Starting…' : 'Start'}
                        </Button>
                        <Button variant="secondary" onClick={() => run('Reload', api.proxy.reload)} disabled={busy !== null}>Reload</Button>
                        <Button variant="secondary" onClick={() => run('Validate', api.proxy.validate)} disabled={busy !== null}>Validate</Button>
                        <Button variant="danger" onClick={() => run('Stop', api.proxy.stop)} disabled={busy !== null}>Stop</Button>
                    </div>
                )}
            </div>

            {validation && (
                <div className={`p-4 rounded-lg text-sm ${validation.valid ? 'bg-success/10 text-success' : 'bg-danger/10 text-on-surface'}`}>
                    <p className="font-semibold">{validation.valid ? 'Configuration is valid.' : 'Configuration has issues:'}</p>
                    {validation.issues.length > 0 && (
                        <ul className="list-disc ml-5 mt-1">{validation.issues.map((i, idx) => <li key={idx}>{i}</li>)}</ul>
                    )}
                    <p className="text-xs text-on-surface-muted mt-1">
                        {validation.engineValidated ? 'Validated by the Caddy engine.' : 'Structural checks only (engine not available).'}
                    </p>
                </div>
            )}

            {/* Metrics */}
            <div className="bg-surface p-6 rounded-lg shadow-lg">
                <h3 className="text-lg font-semibold text-on-surface mb-4">Runtime Metrics</h3>
                {metrics?.available ? (
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-sm">
                        <Stat label="Total Requests" value={metrics.totalRequests} />
                        <Stat label="In Flight" value={metrics.requestsInFlight} />
                        <Stat label="Collected" value={new Date(metrics.collectedAt).toLocaleTimeString()} />
                    </div>
                ) : (
                    <p className="text-on-surface-muted text-sm">{metrics?.message ?? 'No metrics available.'}</p>
                )}
            </div>
        </div>
    );
};

const Stat: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
    <div>
        <p className="text-xs text-on-surface-muted uppercase tracking-wider">{label}</p>
        <p className="text-on-surface font-semibold">{value}</p>
    </div>
);

export default ProxyControl;
