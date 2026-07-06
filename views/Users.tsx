import React, { useState } from 'react';
import Button from '../components/Button';
import Modal from '../components/Modal';
import { UserRole } from '../types';
import { useAuth } from '../contexts/AuthContext';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import { sanitizeImageFile } from '../utils/imageFile';

const defaultAvatar = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2EwYTBiYiI+PHBhdGggZD0iTTEyIDJDNi40OCAyIDIgNi40OCAyIDEyczQuNDggMTAgMTAgMTAgMTAtNC44OCAxMC0xMFMxNy41MiAyIDEyIDJ6bTAgM2MxLjY2IDAgMyAxLjM0IDMgM3MtMS4zNCAzLTMgMy0zLTEuMzQtMy0zIDEuMzQtMyAzLTMzem0wIDE0LjJjLTIuNSAwLTQuNzEtMS4yOC02LTYuNzIgMS4yMy0yLjA0IDMuMDYtMy40OCA1LjE3LTRuNDcgMS4xMi4yOCAyLjI5LjQ1IDMuNTIuNDcgMi43Mi4wMiA1LjM0LTEuNDIgNy4xMS0zLjgzQzE5LjA1IDE1LjYxIDE1Ljg5IDE3LjIgMTIgMTcuMnoiLz48L3N2Zz4=';


const AddUserModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    onAddUser: (user: { name: string; email: string; role: UserRole; avatar?: string; }) => void;
}> = ({ isOpen, onClose, onAddUser }) => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [role, setRole] = useState<UserRole>('Viewer');
    const [avatar, setAvatar] = useState<string>(defaultAvatar);

    const handleAvatarChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            const result = await sanitizeImageFile(e.target.files[0]);
            if (result.error) {
                alert(result.error);
                return;
            }
            if (result.dataUrl) {
                setAvatar(result.dataUrl);
            }
        }
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!name || !email) {
            alert('Please fill in all required fields.');
            return;
        }
        onAddUser({ name, email, role, avatar });
        // Reset form and close
        setName('');
        setEmail('');
        setRole('Viewer');
        setAvatar(defaultAvatar);
        onClose();
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Add New User">
            <form onSubmit={handleSubmit} className="space-y-4">
                <div className="flex flex-col items-center space-y-2">
                    <img src={avatar} alt="Avatar Preview" className="w-24 h-24 rounded-full object-cover border-4 border-surface-raised" />
                    <label className="cursor-pointer text-sm text-primary hover:underline">
                        Change Avatar
                        <input type="file" accept="image/*" className="hidden" onChange={handleAvatarChange} />
                    </label>
                </div>
                <div>
                    <label htmlFor="name" className="block text-sm font-medium text-on-surface-muted mb-1">Full Name</label>
                    <input type="text" id="name" value={name} onChange={(e) => setName(e.target.value)} className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary" />
                </div>
                <div>
                    <label htmlFor="email" className="block text-sm font-medium text-on-surface-muted mb-1">Email Address</label>
                    <input type="email" id="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary" />
                </div>
                <div>
                    <label htmlFor="role" className="block text-sm font-medium text-on-surface-muted mb-1">Role</label>
                    <select id="role" value={role} onChange={(e) => setRole(e.target.value as UserRole)} className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary">
                        <option>Viewer</option>
                        <option>Editor</option>
                        <option>Admin</option>
                    </select>
                </div>
                <div className="flex justify-end pt-4">
                    <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
                    <Button type="submit" className="ml-2">Save User</Button>
                </div>
            </form>
        </Modal>
    );
};


const Users: React.FC = () => {
    const { users, addUser, hasPermission } = useAuth();
    const [isModalOpen, setIsModalOpen] = useState(false);
    const scrollRef = useHorizontalScroll();
    const canManageUsers = hasPermission('user:create');

    return (
        <div className="space-y-6 h-full flex flex-col">
            <div className="flex justify-between items-center flex-shrink-0">
                <h2 className="text-xl font-semibold text-on-surface">User Management</h2>
                {canManageUsers && <Button onClick={() => setIsModalOpen(true)}>Add User</Button>}
            </div>
            <div ref={scrollRef} className="bg-surface rounded-lg shadow-lg overflow-auto overscroll-contain flex-grow">
                <table className="min-w-full">
                    <thead className="bg-surface-raised sticky top-0">
                        <tr>
                            <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Name</th>
                            <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Email</th>
                            <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Role</th>
                            <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Last Login</th>
                            <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                        {users.map((user) => (
                            <tr key={user.id}>
                                <td className="p-4 whitespace-nowrap text-on-surface font-medium">
                                    <div className="flex items-center">
                                        <img src={user.avatar || defaultAvatar} alt={user.name} className="w-8 h-8 rounded-full object-cover mr-3" />
                                        {user.name}
                                    </div>
                                </td>
                                <td className="p-4 whitespace-nowrap text-on-surface-muted">{user.email}</td>
                                <td className="p-4 whitespace-nowrap text-on-surface-muted">{user.role}</td>
                                <td className="p-4 whitespace-nowrap text-on-surface-muted">{new Date(user.lastLogin).toLocaleString()}</td>
                                <td className="p-4 whitespace-nowrap">
                                    {canManageUsers && <Button size="sm" variant="secondary">Edit</Button>}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <AddUserModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                onAddUser={addUser}
            />
        </div>
    );
};

export default Users;