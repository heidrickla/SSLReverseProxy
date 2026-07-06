import React, { createContext, useState, useEffect, useContext, ReactNode } from 'react';
import { Theme, ThemeContextType } from '../types';
import { preconfiguredThemes, defaultLight, defaultDark } from '../data/preconfiguredThemes';

export const ThemeContext = createContext<ThemeContextType>({} as ThemeContextType);

// Theme data may come from localStorage, which is attacker-editable. Only allow
// known "--color-*" keys and strict #hex values so a tampered theme cannot
// inject arbitrary CSS property names or values (CSS injection).
const COLOR_KEY_REGEX = /^--color-[a-z0-9-]+$/;
const HEX_COLOR_REGEX = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;

const isValidColorEntry = (key: string, value: unknown): value is string =>
  typeof value === 'string' && COLOR_KEY_REGEX.test(key) && HEX_COLOR_REGEX.test(value);

const applyThemeColors = (theme: Theme) => {
  const root = document.documentElement;
  Object.entries(theme.colors).forEach(([key, value]) => {
    if (!isValidColorEntry(key, value)) return;
    root.style.setProperty(key, value);
    const rgb = value.match(/\w\w/g)?.map(x => parseInt(x, 16)).join(' ');
    if (rgb) {
      root.style.setProperty(`${key}-rgb`, rgb);
    }
  });
};

// Keep only structurally valid themes with clean color maps.
const sanitizeThemes = (input: unknown): Theme[] => {
  if (!Array.isArray(input)) return [];
  return input.filter((t): t is Theme => {
    if (!t || typeof t.name !== 'string') return false;
    if (t.type !== 'light' && t.type !== 'dark') return false;
    if (!t.colors || typeof t.colors !== 'object') return false;
    return Object.entries(t.colors).every(([k, v]) => isValidColorEntry(k, v));
  });
};

const applyScale = (scale: number) => {
    document.documentElement.style.fontSize = `${scale}%`;
};

export const ThemeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [customThemes, setCustomThemes] = useState<Theme[]>([]);
  const [allThemes, setAllThemes] = useState<Theme[]>([...preconfiguredThemes]);
  
  const [mode, setMode] = useState<'light' | 'dark'>('dark');
  const [lightTheme, setLightThemeState] = useState<Theme>(defaultLight);
  const [darkTheme, setDarkThemeState] = useState<Theme>(defaultDark);
  const [scale, setScale] = useState(80);

  useEffect(() => {
    // Load custom themes
    const savedCustomThemes = localStorage.getItem('proxyadmin-custom-themes');
    let loadedCustomThemes: Theme[] = [];
    try {
      loadedCustomThemes = sanitizeThemes(savedCustomThemes ? JSON.parse(savedCustomThemes) : []);
    } catch {
      loadedCustomThemes = [];
    }
    setCustomThemes(loadedCustomThemes);
    const availableThemes = [...preconfiguredThemes, ...loadedCustomThemes];
    setAllThemes(availableThemes);

    // Load theme selections
    const savedLightThemeName = localStorage.getItem('proxyadmin-light-theme');
    const savedDarkThemeName = localStorage.getItem('proxyadmin-dark-theme');
    const savedMode = localStorage.getItem('proxyadmin-mode') as 'light' | 'dark' | null;
    const savedScale = localStorage.getItem('proxyadmin-scale');

    const initialLightTheme = availableThemes.find(t => t.name === savedLightThemeName) || defaultLight;
    const initialDarkTheme = availableThemes.find(t => t.name === savedDarkThemeName) || defaultDark;
    const initialMode = savedMode || 'dark';
    const initialScale = savedScale ? parseInt(savedScale, 10) : 80;

    setLightThemeState(initialLightTheme);
    setDarkThemeState(initialDarkTheme);
    setMode(initialMode);
    setScale(initialScale);
    
    applyThemeColors(initialMode === 'light' ? initialLightTheme : initialDarkTheme);
    applyScale(initialScale);
  }, []);

  useEffect(() => {
    localStorage.setItem('proxyadmin-custom-themes', JSON.stringify(customThemes));
    setAllThemes([...preconfiguredThemes, ...customThemes]);
  }, [customThemes]);
  
  useEffect(() => {
    localStorage.setItem('proxyadmin-scale', scale.toString());
    applyScale(scale);
  }, [scale]);


  const setLightTheme = (theme: Theme) => {
    setLightThemeState(theme);
    setMode('light');
    applyThemeColors(theme);
    localStorage.setItem('proxyadmin-light-theme', theme.name);
    localStorage.setItem('proxyadmin-mode', 'light');
  };

  const setDarkTheme = (theme: Theme) => {
    setDarkThemeState(theme);
    setMode('dark');
    applyThemeColors(theme);
    localStorage.setItem('proxyadmin-dark-theme', theme.name);
    localStorage.setItem('proxyadmin-mode', 'dark');
  };

  const toggleMode = () => {
    const newMode = mode === 'light' ? 'dark' : 'light';
    setMode(newMode);
    applyThemeColors(newMode === 'light' ? lightTheme : darkTheme);
    localStorage.setItem('proxyadmin-mode', newMode);
  };
  
  const addTheme = (newThemeData: Omit<Theme, 'custom'>) => {
    const newTheme: Theme = { ...newThemeData, custom: true };
    const updatedCustomThemes = [...customThemes.filter(t => t.name !== newTheme.name), newTheme];
    setCustomThemes(updatedCustomThemes);
    
    if (newTheme.type === 'light') {
        setLightTheme(newTheme);
    } else {
        setDarkTheme(newTheme);
    }
  };

  const deleteTheme = (themeName: string) => {
    const themeToDelete = customThemes.find(t => t.name === themeName);
    if (!themeToDelete) return;

    const updatedCustomThemes = customThemes.filter(t => t.name !== themeName);
    setCustomThemes(updatedCustomThemes);
    
    if (themeToDelete.type === 'light' && lightTheme.name === themeName) {
        setLightTheme(defaultLight);
    }
    if (themeToDelete.type === 'dark' && darkTheme.name === themeName) {
        setDarkTheme(defaultDark);
    }
  };

  return (
    <ThemeContext.Provider value={{ 
      mode, toggleMode, 
      lightTheme, darkTheme, setLightTheme, setDarkTheme,
      allThemes, addTheme, deleteTheme,
      scale, setScale
    }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => useContext(ThemeContext);