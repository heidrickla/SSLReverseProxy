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
        <Modal isOpen={isOpen} onClose={onClose} title="Add New Server">
            <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                    <label htmlFor="server-name" className="block text-sm font-medium text-on-surface-muted mb-1">Server Name</label>
                    <input type="text" id="server-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g., Main Web Server" className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary" />
                </div>
                <div>
                    <label htmlFor="server-ip" className="block text-sm font-medium text-on-surface-muted mb-1">IP Address</label>
                    <input type="text" id="server-ip" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="e.g., 192.168.1.100" className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary" />
                </div>
                <div>
                    <label className="block text-sm font-medium text-on-surface-muted mb-1">Operating System</label>
                    <select value={os} onChange={(e) => setOs(e.target.value as 'linux' | 'windows')} className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary">
                        <option value="linux">Linux</option>
                        <option value="windows">Windows</option>
                    </select>
                </div>
                <div className="flex justify-end pt-4">
                    <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
                    <Button type="submit" className="ml-2">Add Server</Button>
                </div>
            </form>
        </Modal>
    );
};


const ServerRow: React.FC<{ server: Server; onSelect: (server: Server) => void; isSelected: boolean }> = ({ server, onSelect, isSelected }) => {
    return (
        <tr
            className={`cursor-pointer transition-colors duration-200 ${isSelected ? 'bg-primary/20' : 'hover:bg-surface-raised'}`}
            onClick={() => onSelect(server)}
        >
            <td className="p-4 whitespace-nowrap text-on-surface font-medium">
                <div className="flex items-center">
                    {server.os === 'linux' ? <LinuxIcon className="w-5 h-5 mr-3 text-on-surface-muted" /> : <WindowsIcon className="w-5 h-5 mr-3 text-on-surface-muted" />}
                    {server.name}
                </div>
            </td>
            <td className="p-4 whitespace-nowrap text-on-surface-muted">{server.host}</td>
            <td className="p-4 whitespace-nowrap text-on-surface-muted">{server.ruleCount}</td>
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
            <div className="flex flex-col h-full">
                <div className="flex justify-between items-center mb-6 flex-shrink-0">
                    <h2 className="text-xl font-semibold text-on-surface">Servers</h2>
                    {canCreate && <Button onClick={() => setIsAddModalOpen(true)}>Add Server</Button>}
                </div>
                <div ref={scrollRef} className="bg-surface rounded-lg shadow-lg overflow-auto overscroll-contain flex-grow">
                    <table className="min-w-full">
                        <thead className="bg-surface-raised sticky top-0">
                            <tr>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Name</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Host</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Rules</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
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