import React, { useCallback, useEffect, useState } from 'react';
import Button from '../components/Button';
import Modal from '../components/Modal';
import PushPreview from '../components/PushPreview';
import { useAuth } from '../contexts/AuthContext';
import { api, ApiError, ProxyStatus, Metrics, ProxyValidation, Snapshot } from '../services/apiClient';

const stateColor: Record<string, string> = {
    Running: 'bg-success/15 text-success',
    Stopped: 'bg-on-surface-muted/15 text-on-surface-muted',
    Faulted: 'bg-danger/15 text-danger',
    Unavailable: 'bg-warning/15 text-warning',
    Unknown: 'bg-on-surface-muted/15 text-on-surface-muted',
};

const ProxyControl: React.FC = () => {
    const { hasPermission } = useAuth();
    const canControl = hasPermission('ProxyControl');
    const canReload = hasPermission('ProxyReload');

    const [status, setStatus] = useState<ProxyStatus | null>(null);
    const [metrics, setMetrics] = useState<Metrics | null>(null);
    const [validation, setValidation] = useState<ProxyValidation | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [snapshots, setSnapshots] = useState<Snapshot[] | null>(null);
    const [push, setPush] = useState<{ kind: 'reload' } | { kind: 'rollback'; snapshot: Snapshot } | null>(null);

    const refresh = useCallback(async () => {
        setError(null);
        try {
            const [s, m, h] = await Promise.all([
                api.proxy.status(), api.proxy.metrics(), canControl ? api.proxy.snapshots() : Promise.resolve(null),
            ]);
            setStatus(s);
            setMetrics(m);
            setSnapshots(h);
        } catch (e) {
            setError(e instanceof ApiError ? `${e.status}: ${e.message}` : 'Failed to reach the API.');
        }
    }, [canControl]);

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
                <h2 className="page-title">Proxy control</h2>
                <Button variant="secondary" onClick={refresh} disabled={busy !== null}>Refresh</Button>
            </div>

            {error && (
                <div className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">{error}</div>
            )}

            {/* Status */}
            <div className="card p-6">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-base font-semibold text-on-surface">Status</h3>
                    {status && (
                        <span className={`px-2.5 py-0.5 text-xs font-medium rounded-full ${stateColor[status.state] ?? stateColor.Unknown}`}>
                            {status.state}
                        </span>
                    )}
                </div>
                {status ? (
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
                        <Stat label="Engine" value={status.engine} />
                        <Stat label="Process ID" value={status.processId ?? '—'} />
                        <Stat label="Active rules" value={status.activeRuleCount} />
                        <Stat label="Started" value={status.startedAt ? new Date(status.startedAt).toLocaleTimeString() : '—'} />
                        {status.message && <div className="col-span-full text-on-surface-muted">{status.message}</div>}
                    </div>
                ) : <p className="text-on-surface-muted text-sm">Loading…</p>}

                {(canControl || canReload) && (
                    <div className="flex flex-wrap gap-2 mt-6 pt-4 border-t border-border">
                        {canControl && (
                            <Button onClick={() => run('Start', api.proxy.start)} disabled={busy !== null}>
                                {busy === 'Start' ? 'Starting…' : 'Start'}
                            </Button>
                        )}
                        {canReload && (
                            <>
                                <Button variant="secondary" onClick={() => setPush({ kind: 'reload' })} disabled={busy !== null}>Reload</Button>
                                <Button variant="secondary" onClick={() => run('Validate', api.proxy.validate)} disabled={busy !== null}>Validate</Button>
                            </>
                        )}
                        {canControl && <Button variant="danger" onClick={() => run('Stop', api.proxy.stop)} disabled={busy !== null}>Stop</Button>}
                    </div>
                )}
            </div>

            {validation && (
                <div className={`p-4 rounded-xl border text-sm ${validation.valid ? 'border-success/30 bg-success/10 text-success' : 'border-danger/30 bg-danger/10 text-on-surface'}`}>
                    <p className="font-semibold">{validation.valid ? 'Configuration is valid.' : 'Configuration has issues:'}</p>
                    {validation.issues.length > 0 && (
                        <ul className="list-disc ml-5 mt-1">{validation.issues.map((i, idx) => <li key={idx}>{i}</li>)}</ul>
                    )}
                    <p className="text-xs text-on-surface-muted mt-1">
                        {validation.engineValidated ? 'Validated by the Caddy engine.' : 'Structural checks only (engine not available).'}
                    </p>
                </div>
            )}

            {push && (
                <Modal isOpen wide onClose={() => setPush(null)}
                    title={push.kind === 'reload' ? 'Reload preview' : `Roll back to snapshot ${push.snapshot.id}`}>
                    <PushPreview
                        load={push.kind === 'reload' ? api.proxy.preview : () => api.proxy.snapshotPreview(push.snapshot.id)}
                        apply={digest => push.kind === 'reload' ? api.proxy.reload(digest) : api.proxy.rollback(push.snapshot.id, digest)}
                        applyLabel={push.kind === 'reload' ? 'Reload' : 'Roll back'}
                        applyVariant={push.kind === 'reload' ? 'primary' : 'danger'}
                        onCancel={() => setPush(null)}
                        onApplied={() => { setPush(null); void refresh(); }}
                    />
                </Modal>
            )}

            {canControl && snapshots && (
                <div className="card p-6">
                    <h3 className="text-base font-semibold text-on-surface mb-4">Config history</h3>
                    {snapshots.length === 0 ? (
                        <p className="text-on-surface-muted text-sm">Each start and reload keeps the config it pushed here.</p>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="data-table" aria-label="Config history">
                                <thead>
                                    <tr><th>Snapshot</th><th>Taken</th><th>By</th><th>Event</th><th>Rules</th><th><span className="sr-only">Actions</span></th></tr>
                                </thead>
                                <tbody>
                                    {snapshots.map(s => (
                                        <tr key={s.id}>
                                            <td className="tabular-nums text-on-surface">{s.id}</td>
                                            <td className="tabular-nums text-on-surface-muted">{new Date(s.createdAt).toLocaleString()}</td>
                                            <td className="text-on-surface-muted">{s.actor}</td>
                                            <td className="text-on-surface-muted">{s.note ?? ''}</td>
                                            <td className="tabular-nums text-on-surface-muted">{s.ruleCount}</td>
                                            <td className="text-right">
                                                <Button size="sm" variant="secondary" onClick={() => setPush({ kind: 'rollback', snapshot: s })}
                                                    disabled={busy !== null} aria-label={`Roll back to snapshot ${s.id}`}>Roll back</Button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}

            {/* Metrics */}
            <div className="card p-6">
                <h3 className="text-base font-semibold text-on-surface mb-4">Runtime metrics</h3>
                {metrics?.available ? (
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-sm">
                        <Stat label="Total requests" value={metrics.totalRequests} />
                        <Stat label="In flight" value={metrics.requestsInFlight} />
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
        <p className="text-xs text-on-surface-muted">{label}</p>
        <p className="mt-0.5 text-on-surface font-medium tabular-nums">{value}</p>
    </div>
);

export default ProxyControl;
