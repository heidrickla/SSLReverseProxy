import React, { useEffect, useState } from 'react';
import Button from './Button';
import { AlertDelivery, AlertsInfo, api, apiErrorMessage } from '../services/apiClient';

export const describeDelivery = (d: AlertDelivery): string =>
    d.delivered
        ? `Delivered (HTTP ${d.status})`
        : `Not delivered: ${d.error ?? 'unknown error'}${d.attempts > 1 ? ` after ${d.attempts} tries` : ''}`;

const AlertsCard: React.FC = () => {
    const [info, setInfo] = useState<AlertsInfo | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [sending, setSending] = useState<string | null>(null);
    const [results, setResults] = useState<Record<string, AlertDelivery>>({});

    useEffect(() => {
        let cancelled = false;
        api.alerts.list()
            .then(i => { if (!cancelled) setInfo(i); })
            .catch(e => { if (!cancelled) setError(apiErrorMessage(e, 'Could not load the alert targets.')); });
        return () => { cancelled = true; };
    }, []);

    const sendTest = async (name: string) => {
        setSending(name);
        try {
            const [result] = await api.alerts.test(name);
            if (result) setResults(r => ({ ...r, [name]: result }));
        } catch (e) {
            const message = apiErrorMessage(e, 'The test could not be sent.');
            setResults(r => ({ ...r, [name]: { target: name, delivered: false, status: null, error: message, attempts: 0 } }));
        } finally {
            setSending(null);
        }
    };

    return (
        <div className="card p-6">
            <h3 className="text-base font-semibold text-on-surface mb-1">Alerts</h3>
            <p className="text-sm text-on-surface-muted mb-4">Targets are set in the server configuration under Alerts:Targets.</p>
            {error && (
                <div role="alert" className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">{error}</div>
            )}
            {info && info.targets.length === 0 && (
                <p className="text-sm text-on-surface-muted py-2">No alert targets are configured.</p>
            )}
            {info && info.targets.length > 0 && (
                <div className="space-y-2">
                    {info.targets.map((t, i) => {
                        const result = results[t.name];
                        return (
                            <div key={`${i}-${t.name}`} className="rounded-xl border border-border bg-background px-4 py-3">
                                <div className="flex justify-between items-center gap-4">
                                    <div className="min-w-0">
                                        <p className="text-sm font-medium text-on-surface">
                                            {t.name} <span className="text-on-surface-muted font-normal">{t.kind}</span>
                                        </p>
                                        <p className="text-xs text-on-surface-muted">{t.events.length ? t.events.join(', ') : 'All events'}</p>
                                    </div>
                                    <Button size="sm" variant="secondary" aria-label={`Send a test alert to ${t.name}`}
                                        disabled={t.problem !== null || sending !== null} onClick={() => sendTest(t.name)}>
                                        {sending === t.name ? 'Sending' : 'Send test'}
                                    </Button>
                                </div>
                                {t.problem && <p className="mt-2 text-xs text-danger">{t.problem}</p>}
                                {result && (
                                    <p role="status" className={`mt-2 text-xs ${result.delivered ? 'text-success' : 'text-danger'}`}>
                                        {describeDelivery(result)}
                                    </p>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
};

export default AlertsCard;
