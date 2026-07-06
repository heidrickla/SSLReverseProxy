import React from 'react';
import LogoIcon from './icons/LogoIcon';
import { useAuth } from '../contexts/AuthContext';

const defaultAvatar = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2EwYTBiYiI+PHBhdGggZD0iTTEyIDJDNi44OCAyIDIgNi44OCAyIDEyczQuODggMTAgMTAgMTAgMTAtNC44OCAxMC0xMFMxNy4xMiAyIDEyIDJ6bTAgM2MxLjY2IDAgMyAxLjM0IDMgM3MtMS4zNCAzLTMgMy0zLTEuMzQtMy0zIDEuMzQtMyAzLTMzem0wIDE0LjJjLTIuNSAwLTQuNzEtMS4yOC02LTYuNzIgMS4yMy0yLjA0IDMuMDYtMy40OCA1LjE3LTRuNDcgMS4xMi4yOCAyLjI5LjQ1IDMuNTIuNDcgMi43Mi4wMiA1LjM0LTEuNDIgNy4xMS0zLjgzQzE5LjA1IDE1LjYxIDE1Ljg5IDE3LjIgMTIgMTcuMnoiLz48L3N2Zz4=';

const LoginView: React.FC = () => {
    const { users, login } = useAuth();

    return (
        <div className="min-h-screen bg-background flex flex-col justify-center items-center p-4">
            <div className="w-full max-w-md">
                <div className="flex justify-center mb-6">
                    <LogoIcon className="w-12 h-12 text-primary" />
                </div>
                <div className="bg-surface rounded-xl shadow-2xl p-8">
                    <h1 className="text-2xl font-bold text-center text-on-surface mb-2">Select a Profile</h1>
                    <p className="text-center text-on-surface-muted mb-8">Choose a user to log in</p>
                    <div className="space-y-3">
                        {users.map(user => (
                            <button
                                key={user.id}
                                onClick={() => login(user.id)}
                                className="w-full flex items-center p-3 bg-surface-raised rounded-lg text-on-surface hover:bg-primary/20 hover:text-primary transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 focus:ring-offset-surface"
                            >
                                <img
                                    src={user.avatar || defaultAvatar}
                                    alt={user.name}
                                    className="w-10 h-10 rounded-full object-cover mr-4"
                                />
                                <div className="text-left">
                                    <p className="font-semibold">{user.name}</p>
                                    <p className="text-xs text-on-surface-muted">{user.role}</p>
                                </div>
                            </button>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LoginView;