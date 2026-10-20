import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Server } from '../types';
import WindowsIcon from '../components/icons/WindowsIcon';
import LinuxIcon from '../components/icons/LinuxIcon';
import ServerDetailPane from '../components/ServerDetailPane';
import Button from '../components/Button';
import Modal from '../components/Modal';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import { isValidHostOrIp } from '../utils/validation';
import EmptyState from '../components/EmptyState';
import ServerIcon from '../components/icons/ServerIcon';
import ServerStatusBadge from '../components/ServerStatusBadge';

const AddServerModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    onAddServer: (server: { name: string; ip: string; os: 'linux' | 'windows' }) => void;
}> = ({ isOpen, onClose, onAddServer }) => {
    const [name, setName] = useState('');
    const [ip, setIp] = useState('');
    const [os, setOs] = useState<'linux' | 'windows'>('linux');

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!name || !ip) {
            alert('Please fill in all fields.');
            return;
        }
        if (!isValidHostOrIp(ip.trim())) {
            alert('Enter a valid IP address or hostname.');
            return;
        }
        onAddServer({ name: name.trim(), ip: ip.trim(), os });
        setName('');
        setIp('');
        setOs('linux');
        onClose();
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Add server">
            <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                    <label htmlFor="server-name" className="field-label">Name</label>
                    <input type="text" id="server-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Main web server" className="field" />
                </div>
                <div>
                    <label htmlFor="server-ip" className="field-label">IP address or hostname</label>
                    <input type="text" id="server-ip" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="192.0.2.10" className="field" />
                </div>
                <div>
                    <label className="field-label">Operating system</label>
                    <select value={os} onChange={(e) => setOs(e.target.value as 'linux' | 'windows')} className="field">
                        <option value="linux">Linux</option>
                        <option value="windows">Windows</option>
                    </select>
                </div>
                <div className="flex justify-end gap-2 pt-2">
                    <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
                    <Button type="submit">Add server</Button>
                </div>
            </form>
        </Modal>
    );
};


const ServerRow: React.FC<{ server: Server; onSelect: (server: Server) => void; isSelected: boolean }> = ({ server, onSelect, isSelected }) => {
    return (
        <tr
            className={`cursor-pointer transition-colors duration-200 ${isSelected ? 'bg-primary/10' : 'hover:bg-surface-raised/50'}`}
            onClick={() => onSelect(server)}
        >
            <td className="text-on-surface font-medium">
                <div className="flex items-center gap-3">
                    <span className="inline-flex w-8 h-8 items-center justify-center rounded-lg bg-surface-raised text-on-surface-muted">
                        {server.os === 'linux' ? <LinuxIcon className="w-4 h-4" /> : <WindowsIcon className="w-4 h-4" />}
                    </span>
                    {server.name}
                </div>
            </td>
            <td><ServerStatusBadge server={server} /></td>
            <td className="text-on-surface-muted tabular-nums">{server.host}</td>
            <td><span className="inline-flex min-w-7 justify-center rounded-md bg-surface-raised px-2 py-0.5 text-xs font-medium text-on-surface tabular-nums">{server.ruleCount}</span></td>
        </tr>
    );
};

const Servers: React.FC = () => {
    const { servers, addServer, updateServer, deleteServer, hasPermission } = useAuth();
    const [isAddModalOpen, setIsAddModalOpen] = useState(false);
    const scrollRef = useHorizontalScroll();
    const canCreate = hasPermission('server:create');
    
    // State to track the ID of the server the user wants to see.
    // Initialized to null so no server is selected by default.
    const [selectedId, setSelectedId] = useState<string | null>(null);

    // Derive the server object to display from the stateful ID. This is declarative and robust.
    const selectedServer = selectedId ? servers.find(s => s.id === selectedId) : null;

    return (
        <>
            <div className="flex flex-col gap-6 h-full">
                <div className="flex justify-between items-center shrink-0">
                    <h2 className="page-title">Servers</h2>
                    {canCreate && <Button onClick={() => setIsAddModalOpen(true)}>Add server</Button>}
                </div>
                {servers.length === 0 ? (
                    <EmptyState
                        icon={<ServerIcon className="w-6 h-6" />}
                        title="Add your first server"
                        description="A server is an upstream host the proxy routes domains to."
                        action={canCreate && <Button onClick={() => setIsAddModalOpen(true)}>Add server</Button>}
                    />
                ) : (
                <div ref={scrollRef} className="card overflow-auto overscroll-contain min-h-0">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Status</th>
                                <th>Host</th>
                                <th>Rules</th>
                            </tr>
                        </thead>
                        <tbody>
                            {servers.map((server) => (
                                <ServerRow 
                                    key={server.id} 
                                    server={server} 
                                    onSelect={(s) => setSelectedId(s.id)}
                                    isSelected={selectedId === server.id}
                                />
                            ))}
                        </tbody>
                    </table>
                </div>
                )}
            </div>
            {selectedServer && (
                <ServerDetailPane
                    server={selectedServer}
                    onClose={() => setSelectedId(null)}
                    onUpdateServer={updateServer}
                    onDeleteServer={(serverId) => {
                        deleteServer(serverId);
                        setSelectedId(null);
                    }}
                />
            )}
            <AddServerModal 
                isOpen={isAddModalOpen}
                onClose={() => setIsAddModalOpen(false)}
                onAddServer={addServer}
            />
        </>
    );
};

export default Servers;