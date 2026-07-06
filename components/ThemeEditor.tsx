import React, { useContext, useState } from 'react';
import { ThemeContext } from '../contexts/ThemeContext';
import { Theme, ThemeColors } from '../types';
import PaintBrushIcon from './icons/PaintBrushIcon';
import Button from './Button';
import Modal from './Modal';
import { defaultLight, defaultDark } from '../data/preconfiguredThemes';

interface ThemeEditorProps {
    onClose: () => void;
}

const ThemeEditor: React.FC<ThemeEditorProps> = ({ onClose }) => {
  const { addTheme, allThemes } = useContext(ThemeContext);
  
  const [newThemeName, setNewThemeName] = useState('');
  const [newThemeType, setNewThemeType] = useState<'light' | 'dark'>('dark');
  const [newThemeColors, setNewThemeColors] = useState<ThemeColors>(defaultDark.colors);

  const handleTypeChange = (type: 'light' | 'dark') => {
    setNewThemeType(type);
    setNewThemeColors(type === 'light' ? defaultLight.colors : defaultDark.colors);
  };

  const handleColorChange = (key: keyof ThemeColors, value: string) => {
    setNewThemeColors(prev => ({ ...prev, [key]: value }));
  };
  
  const handleSaveTheme = () => {
    if (!newThemeName.trim()) {
      alert('Please enter a name for your theme.');
      return;
    }
    if (allThemes.some(t => t.name.toLowerCase() === newThemeName.trim().toLowerCase())) {
        alert('A theme with this name already exists.');
        return;
    }

    const newTheme: Omit<Theme, 'custom'> = {
        name: newThemeName.trim(),
        type: newThemeType,
        colors: newThemeColors,
    };
    addTheme(newTheme);
    onClose();
  };

  const formatColorName = (name: string) => {
    return name.replace('--color-', '').replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  return (
    <Modal isOpen={true} onClose={onClose} title="Create Custom Theme">
        <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label htmlFor="custom-theme-name" className="block text-sm font-medium text-on-surface-muted mb-1">
                        Theme Name
                    </label>
                    <input
                        type="text"
                        id="custom-theme-name"
                        value={newThemeName}
                        onChange={(e) => setNewThemeName(e.target.value)}
                        placeholder="e.g., My Awesome Theme"
                        className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary"
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-on-surface-muted mb-1">Theme Type</label>
                    <div className="flex space-x-2">
                        <Button variant={newThemeType === 'light' ? 'primary' : 'secondary'} onClick={() => handleTypeChange('light')}>Light</Button>
                        <Button variant={newThemeType === 'dark' ? 'primary' : 'secondary'} onClick={() => handleTypeChange('dark')}>Dark</Button>
                    </div>
                </div>
            </div>

            {/* Fix: Use Object.keys with type assertion for safer iteration and to resolve typing error on input value. */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 border-t border-border pt-6 max-h-64 overflow-y-auto pr-2">
                {(Object.keys(newThemeColors) as Array<keyof ThemeColors>).map((key) => (
                <div key={key} className="flex items-center justify-between">
                    <label htmlFor={key} className="text-sm font-medium text-on-surface-muted">
                    {formatColorName(key)}
                    </label>
                    <input
                    id={key}
                    type="color"
                    value={newThemeColors[key]}
                    onChange={(e) => handleColorChange(key, e.target.value)}
                    className="p-1 h-8 w-14 block bg-surface border border-border cursor-pointer rounded-lg"
                    />
                </div>
                ))}
            </div>

            <div className="flex justify-end pt-4 border-t border-border">
                <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
                <Button type="button" onClick={handleSaveTheme} className="ml-2">
                    Save Theme
                </Button>
            </div>
        </div>
    </Modal>
  );
};

export default ThemeEditor;
