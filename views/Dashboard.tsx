import React, { useMemo, useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { useAuth } from '../contexts/AuthContext';
import { ServerStatus, CertificateStatus, View } from '../types';
import TotalRequestsIcon from '../components/icons/TotalRequestsIcon';
import BandwidthIcon from '../components/icons/BandwidthIcon';
import TTFBIcon from '../components/icons/TTFBIcon';
import ResponseTimeIcon from '../components/icons/ResponseTimeIcon';
import ActiveConnectionsIcon from '../components/icons/ActiveConnectionsIcon';
import ChevronUpIcon from '../components/icons/ChevronUpIcon';
import ChevronDownIcon from '../components/icons/ChevronDownIcon';
import ServerIcon from '../components/icons/ServerIcon';
import LockIcon from '../components/icons/LockIcon';

type Tone = 'primary' | 'success' | 'danger' | 'muted';

const toneChip: Record<Tone, string> = {
  primary: 'bg-primary/15 text-primary',
  success: 'bg-success/15 text-success',
  danger: 'bg-danger/15 text-danger',
  muted: 'bg-on-surface-muted/15 text-on-surface-muted',
};

const DashboardCard: React.FC<{
  title: string;
  value?: string | number;
  description: string;
  icon: React.ReactNode;
  tone?: Tone;
  children?: React.ReactNode;
  aside?: React.ReactNode;
  onClick?: () => void;
}> = ({ title, value, description, icon, tone = 'primary', children, aside, onClick }) => {
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag
      className={`card p-5 h-full w-full text-left transition-colors duration-150 ${onClick ? 'hover:border-primary/40 outline-none focus-visible:ring-2 focus-visible:ring-primary/50' : ''}`}
      onClick={onClick}
    >
      <div className="flex items-center gap-3">
        <span className={`inline-flex w-9 h-9 shrink-0 items-center justify-center rounded-xl ${toneChip[tone]}`}>{icon}</span>
        <h3 className="text-sm font-medium text-on-surface-muted">{title}</h3>
      </div>
      <div className="mt-4 flex items-end justify-between gap-3">
        <div>
          {children || <p className="text-3xl font-semibold tracking-tight tabular-nums text-on-surface">{value}</p>}
          <p className="text-xs text-on-surface-muted mt-1">{description}</p>
        </div>
        {aside}
      </div>
    </Tag>
  );
};

const Sparkline: React.FC<{ values: number[] }> = ({ values }) => {
  const max = Math.max(...values);
  const min = Math.min(...values);
  const points = values
    .map((v, i) => `${(i / (values.length - 1)) * 80},${22 - ((v - min) / (max - min || 1)) * 20}`)
    .join(' ');
  return (
    <svg width="80" height="24" viewBox="0 0 80 24" aria-hidden="true" className="shrink-0 text-primary">
      <polyline fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinejoin="round" strokeLinecap="round" points={points} />
    </svg>
  );
};

const SectionHeader: React.FC<{ title: string; collapsed: boolean; onToggle: () => void }> = ({ title, collapsed, onToggle }) => (
  <button
    onClick={onToggle}
    aria-expanded={!collapsed}
    className="flex w-full justify-between items-center mb-4 rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
  >
    <h2 className="text-lg font-semibold tracking-tight text-on-surface">{title}</h2>
    <span className="p-1.5 rounded-lg text-on-surface-muted hover:bg-surface hover:text-on-surface transition-colors">
      {collapsed ? <ChevronDownIcon className="w-5 h-5" /> : <ChevronUpIcon className="w-5 h-5" />}
    </span>
  </button>
);

const areaChartData = [
  { name: '12 AM', requests: 4000 },
  { name: '3 AM', requests: 3000 },
  { name: '6 AM', requests: 2000 },
  { name: '9 AM', requests: 2780 },
  { name: '12 PM', requests: 1890 },
  { name: '3 PM', requests: 2390 },
  { name: '6 PM', requests: 3490 },
  { name: '9 PM', requests: 4100 },
];

const statusCodeData = [
    { name: '2xx Success', value: 1250234 },
    { name: '3xx Redirection', value: 105892 },
    { name: '4xx Client Error', value: 58231 },
    { name: '5xx Server Error', value: 4502 },
];

const COLORS = ['rgb(var(--color-success-rgb))', 'rgb(var(--color-primary-rgb))', 'rgb(var(--color-warning-rgb))', 'rgb(var(--color-danger-rgb))'];

const tooltipStyle = {
  backgroundColor: 'rgb(var(--color-surface-raised-rgb))',
  border: '1px solid rgb(var(--color-border-rgb))',
  borderRadius: 12,
  color: 'rgb(var(--color-on-surface-rgb))',
  fontSize: 12,
};

interface DashboardProps {
  setView: (view: View) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ setView }) => {
    const { servers, certificates } = useAuth();
    const [isMetricsCollapsed, setIsMetricsCollapsed] = useState(() => JSON.parse(localStorage.getItem('dashboardMetricsCollapsed') || 'false'));
    const [isChartsCollapsed, setIsChartsCollapsed] = useState(() => JSON.parse(localStorage.getItem('dashboardChartsCollapsed') || 'false'));

    useEffect(() => {
        localStorage.setItem('dashboardMetricsCollapsed', JSON.stringify(isMetricsCollapsed));
    }, [isMetricsCollapsed]);

    useEffect(() => {
        localStorage.setItem('dashboardChartsCollapsed', JSON.stringify(isChartsCollapsed));
    }, [isChartsCollapsed]);

    const serverStats = useMemo(() => {
        return servers.reduce((acc, server) => {
            acc[server.status] = (acc[server.status] || 0) + 1;
            return acc;
        }, {} as Record<ServerStatus, number>);
    }, [servers]);

    const certStats = useMemo(() => {
        return certificates.reduce((acc, cert) => {
            acc[cert.status] = (acc[cert.status] || 0) + 1;
            return acc;
        }, {} as Record<CertificateStatus, number>);
    }, [certificates]);

  return (
    <div className="h-full overflow-auto overscroll-contain pr-2 pb-8">
      <div className="space-y-10">
        {/* Key Metrics Section */}
        <section>
          <SectionHeader title="Key metrics" collapsed={isMetricsCollapsed} onToggle={() => setIsMetricsCollapsed(!isMetricsCollapsed)} />
          {!isMetricsCollapsed && (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 animate-fade-in">
              <DashboardCard title="Active servers" value={serverStats.active || 0} description="Every upstream answering" onClick={() => setView('servers')} tone="success" icon={<ServerIcon className="w-5 h-5" />} />
              <DashboardCard title="Inactive servers" value={serverStats.inactive || 0} description="No enabled rules" onClick={() => setView('servers')} tone="muted" icon={<ServerIcon className="w-5 h-5" />} />
              <DashboardCard title="Server errors" value={serverStats.error || 0} description="Upstreams not answering" onClick={() => setView('servers')} tone="danger" icon={<ServerIcon className="w-5 h-5" />} />
              <DashboardCard title="Valid certificates" value={certStats.valid || 0} description="Secure and up to date" onClick={() => setView('ssl')} tone="success" icon={<LockIcon className="w-5 h-5" />} />
              <DashboardCard title="Active connections" value="1,283" description="Live connections" icon={<ActiveConnectionsIcon className="w-5 h-5" />} />
              <DashboardCard title="Total requests" value="1.4M" description="Last 24 hours" icon={<TotalRequestsIcon className="w-5 h-5" />} aside={<Sparkline values={areaChartData.map(d => d.requests)} />} />
              <DashboardCard title="Bandwidth" description="Last 24 hours" icon={<BandwidthIcon className="w-5 h-5" />}>
                  <div className="flex gap-6 text-on-surface tabular-nums">
                      <div><p className="text-xs text-on-surface-muted">In</p><p className="text-xl font-semibold">1.2 TB</p></div>
                      <div><p className="text-xs text-on-surface-muted">Out</p><p className="text-xl font-semibold">5.8 TB</p></div>
                  </div>
              </DashboardCard>
              <DashboardCard title="Time to first byte" value="85 ms" description="Average response start" icon={<TTFBIcon className="w-5 h-5" />} />
              <DashboardCard title="Response time" description="Percentiles" icon={<ResponseTimeIcon className="w-5 h-5" />}>
                  <div className="grid grid-cols-4 gap-3 text-on-surface tabular-nums">
                      {[['Avg', '120'], ['Median', '110'], ['P90', '250'], ['P95', '310']].map(([label, ms]) => (
                        <div key={label}><p className="text-xs text-on-surface-muted">{label}</p><p className="text-base font-semibold">{ms}<span className="text-xs font-normal text-on-surface-muted"> ms</span></p></div>
                      ))}
                  </div>
              </DashboardCard>
            </div>
           )}
        </section>

        {/* Performance Charts Section */}
        <section>
          <SectionHeader title="Performance" collapsed={isChartsCollapsed} onToggle={() => setIsChartsCollapsed(!isChartsCollapsed)} />
          {!isChartsCollapsed && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 animate-fade-in">
              <div className="card p-6 h-96 flex flex-col">
                  <h3 className="text-sm font-medium text-on-surface-muted mb-4">Requests, last 24 hours</h3>
                  <div className="grow">
                      <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={areaChartData} margin={{ top: 4, right: 4, left: -12, bottom: 0 }}>
                              <defs>
                                  <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                                  <stop offset="0%" stopColor="rgb(var(--color-primary-rgb))" stopOpacity={0.35}/>
                                  <stop offset="100%" stopColor="rgb(var(--color-primary-rgb))" stopOpacity={0}/>
                                  </linearGradient>
                              </defs>
                              <CartesianGrid vertical={false} stroke="rgb(var(--color-border-rgb))" />
                              <XAxis dataKey="name" stroke="rgb(var(--color-on-surface-muted-rgb))" fontSize={12} tickLine={false} axisLine={false} />
                              <YAxis stroke="rgb(var(--color-on-surface-muted-rgb))" fontSize={12} tickLine={false} axisLine={false} />
                              <Tooltip contentStyle={tooltipStyle} cursor={{ stroke: 'rgb(var(--color-border-rgb))' }} />
                              <Area type="monotone" dataKey="requests" stroke="rgb(var(--color-primary-rgb))" strokeWidth={2} fillOpacity={1} fill="url(#colorRequests)" />
                          </AreaChart>
                      </ResponsiveContainer>
                  </div>
              </div>
              <div className="card p-6 h-96 flex flex-col">
                  <h3 className="text-sm font-medium text-on-surface-muted mb-4">HTTP status codes, last 24 hours</h3>
                  <div className="grow">
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie
                                data={statusCodeData}
                                cx="50%"
                                cy="45%"
                                labelLine={false}
                                innerRadius="58%"
                                outerRadius="80%"
                                paddingAngle={2}
                                stroke="none"
                                dataKey="value"
                            >
                                {statusCodeData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: 'rgb(var(--color-on-surface-rgb))' }} formatter={(value: number) => value.toLocaleString()} />
                            <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: '13px' }} formatter={(value: string) => <span style={{ color: 'rgb(var(--color-on-surface-muted-rgb))' }}>{value}</span>} />
                        </PieChart>
                    </ResponsiveContainer>
                  </div>
              </div>
            </div>
          )}
        </section>
      </div>
      <style>{`
        @keyframes fade-in {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        .animate-fade-in {
          animation: fade-in 0.5s ease-out forwards;
        }
      `}</style>
    </div>
  );
};

export default Dashboard;