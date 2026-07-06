import React from 'react';

interface ToggleSwitchProps {
  label?: string;
  enabled: boolean;
  onChange: (enabled: boolean) => void;
  disabled?: boolean;
}

const ToggleSwitch: React.FC<ToggleSwitchProps> = ({ label, enabled, onChange, disabled = false }) => {
  return (
    <label className={`flex items-center ${disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}`}>
      <div className="relative">
        <input
          type="checkbox"
          className="sr-only"
          checked={enabled}
          disabled={disabled}
          onChange={() => onChange(!enabled)}
        />
        <div className={`block w-10 h-5 rounded-full transition-all ${enabled ? 'bg-primary' : 'bg-secondary'}`}></div>
        <div className={`dot absolute left-0.5 top-0.5 bg-white w-4 h-4 rounded-full transition-transform ${enabled ? 'translate-x-5' : ''}`}></div>
      </div>
      {label && 
        <div className="ml-3 text-on-surface-muted font-medium">
            {label}
        </div>
      }
    </label>
  );
};

export default ToggleSwitch;