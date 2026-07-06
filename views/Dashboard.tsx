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

const DashboardCard: React.FC<{
  title: string;
  value?: string | number;
  description: string;
  icon?: React.ReactNode;
  children?: React.ReactNode;
  onClick?: () => void;
  className?: string;
  bubbleColor?: string;
}> = ({ title, value, description, icon, children, onClick, className, bubbleColor }) => (
  <div
    className={`bg-surface rounded-lg p-6 shadow-lg transition-all duration-300 ease-in-out h-full ${className} ${onClick ? 'cursor-pointer group hover:shadow-xl hover:-translate-y-1' : ''}`}
    onClick={onClick}
  >
    <div className="flex items-center justify-between">
      <h3 className="text-sm font-medium text-on-surface-muted">{title}</h3>
      <div className="flex items-center space-x-2">
        {icon}
        {bubbleColor && <span className={`inline-block w-3 h-3 rounded-full ${bubbleColor}`}></span>}
      </div>
    </div>
    {children || <p className="text-3xl font-bold mt-2 text-on-surface">{value}</p>}
    <p className="text-xs text-on-surface-muted mt-1">{description}</p>
  </div>
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

const COLORS = ['#22c55e', '#3b82f6', '#f59e0b', '#ef4444'];

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
      <div className="space-y-8">
        
        {/* Key Metrics Section */}
        <div>
          <div onClick={() => setIsMetricsCollapsed(!isMetricsCollapsed)} className="flex justify-between items-center cursor-pointer mb-6">
            <h2 className="text-2xl font-bold text-on-surface">Key Metrics</h2>
            {isMetricsCollapsed ? <ChevronDownIcon className="w-6 h-6 text-on-surface-muted" /> : <ChevronUpIcon className="w-6 h-6 text-on-surface-muted" />}
          </div>
          {!isMetricsCollapsed && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 animate-fade-in">
              <DashboardCard title="Active Servers" value={serverStats.active || 0} description="Healthy and running" onClick={() => setView('servers')} bubbleColor="bg-success" />
              <DashboardCard title="Inactive Servers" value={serverStats.inactive || 0} description="Offline or stopped" onClick={() => setView('servers')} bubbleColor="bg-gray-500" />
              <DashboardCard title="Server Errors" value={serverStats.error || 0} description="Require attention" onClick={() => setView('servers')} className="text-danger" bubbleColor="bg-danger" />
              <DashboardCard title="Valid Certificates" value={certStats.valid || 0} description="Secure and up-to-date" onClick={() => setView('ssl')} bubbleColor="bg-success" />
              <DashboardCard title="Active Connections" value="1,283" description="Live connections" icon={<ActiveConnectionsIcon className="w-6 h-6 text-primary" />} />
              <DashboardCard title="Total Requests" value="1.4M" description="Last 24 hours" icon={<TotalRequestsIcon className="w-6 h-6 text-primary" />} />
              <DashboardCard title="Bandwidth Usage" description="Last 24 hours" icon={<BandwidthIcon className="w-6 h-6 text-primary" />}>
                  <div className="mt-2 text-on-surface">
                      <p className="text-lg font-bold">In: 1.2 TB</p>
                      <p className="text-lg font-bold">Out: 5.8 TB</p>
                  </div>
              </DashboardCard>
              <DashboardCard title="Time to First Byte (TTFB)" value="85ms" description="Average response start" icon={<TTFBIcon className="w-6 h-6 text-primary" />} />
              <DashboardCard title="Overall Response Time" description="Percentiles" icon={<ResponseTimeIcon className="w-6 h-6 text-primary" />}>
                  <div className="grid grid-cols-2 gap-x-4 mt-2 text-sm">
                      <div><span className="font-semibold">Avg:</span> 120ms</div>
                      <div><span className="font-semibold">P90:</span> 250ms</div>
                      <div><span className="font-semibold">Median:</span> 110ms</div>
                      <div><span className="font-semibold">P95:</span> 310ms</div>
                  </div>
              </DashboardCard>
            </div>
           )}
        </div>

        {/* Performance Charts Section */}
        <div>
          <div onClick={() => setIsChartsCollapsed(!isChartsCollapsed)} className="flex justify-between items-center cursor-pointer mb-6">
            <h2 className="text-2xl font-bold text-on-surface">Performance Charts</h2>
            {isChartsCollapsed ? <ChevronDownIcon className="w-6 h-6 text-on-surface-muted" /> : <ChevronUpIcon className="w-6 h-6 text-on-surface-muted" />}
          </div>
          {!isChartsCollapsed && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 animate-fade-in">
              <div className="bg-surface p-6 rounded-lg shadow-lg h-96 flex flex-col">
                  <h3 className="text-lg font-semibold text-on-surface mb-4">Requests (24h)</h3>
                  <div className="flex-grow">
                      <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={areaChartData}>
                              <defs>
                                  <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                                  <stop offset="5%" stopColor="rgb(var(--color-primary-rgb))" stopOpacity={0.8}/>
                                  <stop offset="95%" stopColor="rgb(var(--color-primary-rgb))" stopOpacity={0}/>
                                  </linearGradient>
                              </defs>
                              <CartesianGrid strokeDasharray="3 3" stroke="rgb(var(--color-border-rgb))" />
                              <XAxis dataKey="name" stroke="rgb(var(--color-on-surface-muted-rgb))" fontSize={12} />
                              <YAxis stroke="rgb(var(--color-on-surface-muted-rgb))" fontSize={12} />
                              <Tooltip contentStyle={{ backgroundColor: 'rgb(var(--color-surface-raised-rgb))', border: '1px solid rgb(var(--color-border-rgb))' }} />
                              <Area type="monotone" dataKey="requests" stroke="rgb(var(--color-primary-rgb))" fillOpacity={1} fill="url(#colorRequests)" />
                          </AreaChart>
                      </ResponsiveContainer>
                  </div>
              </div>
              <div className="bg-surface p-6 rounded-lg shadow-lg h-96 flex flex-col">
                  <h3 className="text-lg font-semibold text-on-surface mb-4">HTTP Status Codes (24h)</h3>
                  <div className="flex-grow">
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie
                                data={statusCodeData}
                                cx="50%"
                                cy="50%"
                                labelLine={false}
                                outerRadius="80%"
                                fill="#8884d8"
                                dataKey="value"
                            >
                                {statusCodeData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: 'rgb(var(--color-surface-raised-rgb))', border: '1px solid rgb(var(--color-border-rgb))' }} formatter={(value: number) => value.toLocaleString()} />
                            <Legend wrapperStyle={{fontSize: "14px"}}/>
                        </PieChart>
                    </ResponsiveContainer>
                  </div>
              </div>
            </div>
          )}
        </div>
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