import React from 'react';

const ResponseTimeIcon: React.FC<{ className?: string }> = ({ className = 'w-6 h-6' }) => (
    <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l-1 1M15 5l1 1" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 3V1.5" />
    </svg>
);

export default ResponseTimeIcon;