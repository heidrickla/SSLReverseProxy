import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger';
  size?: 'sm' | 'md';
  children: React.ReactNode;
  icon?: React.ReactNode;
}

const Button: React.FC<ButtonProps> = ({ children, variant = 'primary', size = 'md', icon, className = '', ...props }) => {
  const baseClasses = 'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-[background-color,filter,border-color] duration-150 disabled:opacity-50 disabled:cursor-not-allowed outline-none focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 focus-visible:ring-offset-background';

  const sizeClasses = {
    sm: 'px-2.5 py-1 text-xs',
    md: 'px-4 py-2 text-sm',
  };

  // Hover uses brightness so it works for any theme's primary and danger colours.
  const variantClasses = {
    primary: 'bg-primary text-white enabled:hover:brightness-110',
    secondary: 'border border-border bg-surface-raised text-on-surface enabled:hover:border-on-surface-muted/40 enabled:hover:bg-border/60',
    danger: 'bg-danger text-white enabled:hover:brightness-110',
  };

  return (
    <button className={`${baseClasses} ${sizeClasses[size]} ${variantClasses[variant]} ${className}`} {...props}>
      {icon && <span className="-ml-0.5">{icon}</span>}
      {children}
    </button>
  );
};

export default Button;
