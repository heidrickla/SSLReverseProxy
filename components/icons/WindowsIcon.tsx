import React from 'react';

const WindowsIcon: React.FC<{ className?: string }> = ({ className = 'w-6 h-6' }) => (
    <svg xmlns="http://www.w3.org/2000/svg" className={className} viewBox="0 0 24 24" fill="currentColor">
        <path d="M3,12V6.75L9,5.43V11.91L3,12M21,12V4.5L11,3V11.91L21,12M3,13L9,13.09V18.57L3,17.25V13M21,13L11,13.09V21L21,19.5V13Z" />
    </svg>
);

export default WindowsIcon;
