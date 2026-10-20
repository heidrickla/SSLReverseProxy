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
    <Modal isOpen={true} onClose={onClose} title="Create theme">
        <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label htmlFor="custom-theme-name" className="field-label">
                        Name
                    </label>
                    <input
                        type="text"
                        id="custom-theme-name"
                        value={newThemeName}
                        onChange={(e) => setNewThemeName(e.target.value)}
                        placeholder="Night shift"
                        className="field"
                    />
                </div>
                <div>
                    <label className="field-label">Type</label>
                    <div className="flex gap-2">
                        <Button variant={newThemeType === 'light' ? 'primary' : 'secondary'} onClick={() => handleTypeChange('light')}>Light</Button>
                        <Button variant={newThemeType === 'dark' ? 'primary' : 'secondary'} onClick={() => handleTypeChange('dark')}>Dark</Button>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 border-t border-border pt-6 max-h-64 overflow-y-auto pr-2">
                {(Object.keys(newThemeColors) as Array<keyof ThemeColors>).map((key) => (
                <div key={key} className="flex items-center justify-between">
                    <label htmlFor={key} className="text-sm text-on-surface-muted">
                    {formatColorName(key)}
                    </label>
                    <input
                    id={key}
                    type="color"
                    value={newThemeColors[key]}
                    onChange={(e) => handleColorChange(key, e.target.value)}
                    className="p-0.5 h-8 w-14 block bg-background border border-border cursor-pointer rounded-lg"
                    />
                </div>
                ))}
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t border-border">
                <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
                <Button type="button" onClick={handleSaveTheme}>
                    Save theme
                </Button>
            </div>
        </div>
    </Modal>
  );
};

export default ThemeEditor;
