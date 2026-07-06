import React from 'react';

// Fix: Add a `size` prop to the Button component to allow for different button sizes and resolve the type error.
interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger';
  size?: 'sm' | 'md';
  children: React.ReactNode;
  icon?: React.ReactNode;
}

const Button: React.FC<ButtonProps> = ({ children, variant = 'primary', size = 'md', icon, ...props }) => {
  const baseClasses = 'rounded-md font-semibold transition-all duration-200 flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-background';
  
  const sizeClasses = {
    sm: 'px-2 py-1 text-xs',
    md: 'px-4 py-2 text-sm',
  };

  const variantClasses = {
    primary: 'bg-primary text-white hover:bg-sky-400 focus:ring-primary',
    secondary: 'bg-surface text-on-surface hover:bg-slate-600 focus:ring-secondary',
    danger: 'bg-danger text-white hover:bg-red-400 focus:ring-danger',
  };

  return (
    <button className={`${baseClasses} ${sizeClasses[size]} ${variantClasses[variant]}`} {...props}>
      {icon && <span className="mr-2 -ml-1">{icon}</span>}
      {children}
    </button>
  );
};

export default Button;
