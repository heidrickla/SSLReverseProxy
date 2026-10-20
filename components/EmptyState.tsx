import React from 'react';

interface EmptyStateProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
}

const EmptyState: React.FC<EmptyStateProps> = ({ icon, title, description, action }) => (
  <div className="card flex flex-col items-center justify-center text-center px-6 py-14">
    <span className="icon-chip w-12 h-12 mb-4">{icon}</span>
    <h3 className="text-base font-semibold text-on-surface">{title}</h3>
    <p className="mt-1 max-w-sm text-sm text-on-surface-muted">{description}</p>
    {action && <div className="mt-5">{action}</div>}
  </div>
);

export default EmptyState;
