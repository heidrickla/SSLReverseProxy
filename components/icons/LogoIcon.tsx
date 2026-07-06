
import React from 'react';

const LogoIcon: React.FC<{ className?: string }> = ({ className = 'w-8 h-8' }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M12 2L2 7V17L12 22L22 17V7L12 2Z" className="stroke-primary" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M2 7L12 12M12 22V12M22 7L12 12M17 4.5L7 9.5" className="stroke-primary" strokeOpacity="0.6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export default LogoIcon;
