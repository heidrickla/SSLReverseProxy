import React from 'react';

const TTFBIcon: React.FC<{ className?: string }> = ({ className = 'w-6 h-6' }) => (
    <svg xmlns="http://www.w3.org/2000/svg" className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 12.036A9 9 0 113.34 7.954" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M18 15v4m0 0l-2-2m2 2l2-2" />
    </svg>
);

export default TTFBIcon;