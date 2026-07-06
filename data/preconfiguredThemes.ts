import { Theme } from '../types';

// Fix: Corrected the keys in `baseColors` to be CSS custom properties to match the Theme type.
const baseColors = {
  '--color-danger': '#ef4444', // red-500
  '--color-warning': '#f59e0b', // amber-500
  '--color-success': '#22c55e', // green-500
};

const lightThemes: Theme[] = [
    {
        name: 'Default Light',
        type: 'light',
        colors: {
            '--color-primary': '#3b82f6', // blue-500
            '--color-secondary': '#64748b', // slate-500
            '--color-background': '#f1f5f9', // slate-100
            '--color-surface': '#ffffff', // white
            '--color-surface-raised': '#f8fafc', // slate-50
            '--color-border': '#e2e8f0', // slate-200
            '--color-on-surface': '#0f172a', // slate-900
            '--color-on-surface-muted': '#475569', // slate-600
            ...baseColors,
        },
    },
    {
        name: 'Sunny Meadow',
        type: 'light',
        colors: {
            '--color-primary': '#f97316', // orange-500
            '--color-secondary': '#a16207', // yellow-700
            '--color-background': '#fefce8', // yellow-50
            '--color-surface': '#ffffff',
            '--color-surface-raised': '#fef9c3', // yellow-100
            '--color-border': '#fde68a', // yellow-200
            '--color-on-surface': '#422006', // yellow-950
            '--color-on-surface-muted': '#713f12', // yellow-800
            ...baseColors,
        },
    },
    {
        name: 'Minty Fresh',
        type: 'light',
        colors: {
            '--color-primary': '#10b981', // emerald-500
            '--color-secondary': '#5eead4', // teal-300
            '--color-background': '#f0fdfa', // emerald-50
            '--color-surface': '#ffffff',
            '--color-surface-raised': '#ccfbf1', // emerald-100
            '--color-border': '#99f6e4', // emerald-200
            '--color-on-surface': '#064e3b', // emerald-900
            '--color-on-surface-muted': '#047857', // emerald-700
            ...baseColors,
        },
    },
    {
        name: 'Rosewater',
        type: 'light',
        colors: {
            '--color-primary': '#f43f5e', // rose-500
            '--color-secondary': '#fb7185', // rose-400
            '--color-background': '#fff1f2', // rose-50
            '--color-surface': '#ffffff',
            '--color-surface-raised': '#ffe4e6', // rose-100
            '--color-border': '#fecdd3', // rose-200
            '--color-on-surface': '#881337', // rose-900
            '--color-on-surface-muted': '#be123c', // rose-700
            ...baseColors,
        },
    },
    {
        name: 'Sky Blue',
        type: 'light',
        colors: {
            '--color-primary': '#0ea5e9', // sky-500
            '--color-secondary': '#38bdf8', // sky-400
            '--color-background': '#f0f9ff', // sky-50
            '--color-surface': '#ffffff',
            '--color-surface-raised': '#e0f2fe', // sky-100
            '--color-border': '#bae6fd', // sky-200
            '--color-on-surface': '#082f49', // sky-900
            '--color-on-surface-muted': '#0369a1', // sky-700
            ...baseColors,
        },
    },
    {
        name: 'Lavender Fields',
        type: 'light',
        colors: {
            '--color-primary': '#8b5cf6', // violet-500
            '--color-secondary': '#a78bfa', // violet-400
            '--color-background': '#f5f3ff', // violet-50
            '--color-surface': '#ffffff',
            '--color-surface-raised': '#ede9fe', // violet-100
            '--color-border': '#ddd6fe', // violet-200
            '--color-on-surface': '#4c1d95', // violet-900
            '--color-on-surface-muted': '#6d28d9', // violet-700
            ...baseColors,
        },
    },
    {
        name: 'Stone Grove',
        type: 'light',
        colors: {
            '--color-primary': '#6b7280', // gray-500
            '--color-secondary': '#9ca3af', // gray-400
            '--color-background': '#f9fafb', // gray-50
            '--color-surface': '#ffffff',
            '--color-surface-raised': '#f3f4f6', // gray-100
            '--color-border': '#e5e7eb', // gray-200
            '--color-on-surface': '#1f2937', // gray-800
            '--color-on-surface-muted': '#4b5563', // gray-600
            ...baseColors,
        },
    },
    {
        name: 'Ocean Breeze',
        type: 'light',
        colors: {
            '--color-primary': '#14b8a6', // teal-500
            '--color-secondary': '#2dd4bf', // teal-400
            '--color-background': '#f0fdfa',
            '--color-surface': '#ffffff',
            '--color-surface-raised': '#ccfbf1',
            '--color-border': '#99f6e4',
            '--color-on-surface': '#0f766e',
            '--color-on-surface-muted': '#115e59',
            ...baseColors,
        },
    },
    { name: 'Peach Cobbler', type: 'light', colors: { '--color-primary': '#fb923c', '--color-secondary': '#fed7aa', '--color-background': '#fff7ed', '--color-surface': '#ffffff', '--color-surface-raised': '#ffedd5', '--color-border': '#fed7aa', '--color-on-surface': '#7c2d12', '--color-on-surface-muted': '#9a3412', ...baseColors } },
    { name: 'Cherry Blossom', type: 'light', colors: { '--color-primary': '#ec4899', '--color-secondary': '#f9a8d4', '--color-background': '#fdf2f8', '--color-surface': '#ffffff', '--color-surface-raised': '#fce7f3', '--color-border': '#fbcfe8', '--color-on-surface': '#831843', '--color-on-surface-muted': '#9d174d', ...baseColors } },
    { name: 'Forest Path', type: 'light', colors: { '--color-primary': '#22c55e', '--color-secondary': '#86efac', '--color-background': '#f0fdf4', '--color-surface': '#ffffff', '--color-surface-raised': '#dcfce7', '--color-border': '#bbf7d0', '--color-on-surface': '#14532d', '--color-on-surface-muted': '#166534', ...baseColors } },
    { name: 'Coral Reef', type: 'light', colors: { '--color-primary': '#f87171', '--color-secondary': '#fca5a5', '--color-background': '#fef2f2', '--color-surface': '#ffffff', '--color-surface-raised': '#fee2e2', '--color-border': '#fecaca', '--color-on-surface': '#991b1b', '--color-on-surface-muted': '#b91c1c', ...baseColors } },
    { name: 'Indigo Dream', type: 'light', colors: { '--color-primary': '#6366f1', '--color-secondary': '#a5b4fc', '--color-background': '#eef2ff', '--color-surface': '#ffffff', '--color-surface-raised': '#e0e7ff', '--color-border': '#c7d2fe', '--color-on-surface': '#3730a3', '--color-on-surface-muted': '#4338ca', ...baseColors } },
    { name: 'Sandy Beach', type: 'light', colors: { '--color-primary': '#d97706', '--color-secondary': '#f59e0b', '--color-background': '#fffbeb', '--color-surface': '#ffffff', '--color-surface-raised': '#fef3c7', '--color-border': '#fee587', '--color-on-surface': '#78350f', '--color-on-surface-muted': '#92400e', ...baseColors } },
    { name: 'Slate Clean', type: 'light', colors: { '--color-primary': '#475569', '--color-secondary': '#94a3b8', '--color-background': '#f8fafc', '--color-surface': '#ffffff', '--color-surface-raised': '#f1f5f9', '--color-border': '#e2e8f0', '--color-on-surface': '#1e293b', '--color-on-surface-muted': '#334155', ...baseColors } },
    { name: 'Fuchsia Flash', type: 'light', colors: { '--color-primary': '#d946ef', '--color-secondary': '#e879f9', '--color-background': '#fae8ff', '--color-surface': '#ffffff', '--color-surface-raised': '#f5d0fe', '--color-border': '#f0abfc', '--color-on-surface': '#701a75', '--color-on-surface-muted': '#86198f', ...baseColors } },
    { name: 'Lime Zest', type: 'light', colors: { '--color-primary': '#84cc16', '--color-secondary': '#a3e635', '--color-background': '#f7fee7', '--color-surface': '#ffffff', '--color-surface-raised': '#ecfccb', '--color-border': '#d9f99d', '--color-on-surface': '#3f6212', '--color-on-surface-muted': '#4d7c0f', ...baseColors } },
    { name: 'Cyan Splash', type: 'light', colors: { '--color-primary': '#06b6d4', '--color-secondary': '#67e8f9', '--color-background': '#ecfeff', '--color-surface': '#ffffff', '--color-surface-raised': '#cffafe', '--color-border': '#a5f3fc', '--color-on-surface': '#0e7490', '--color-on-surface-muted': '#155e75', ...baseColors } },
    { name: 'Amber Glow', type: 'light', colors: { '--color-primary': '#f59e0b', '--color-secondary': '#fbbf24', '--color-background': '#fffbeb', '--color-surface': '#ffffff', '--color-surface-raised': '#fef3c7', '--color-border': '#fee587', '--color-on-surface': '#b45309', '--color-on-surface-muted': '#92400e', ...baseColors } },
    { name: 'Concrete', type: 'light', colors: { '--color-primary': '#737373', '--color-secondary': '#a3a3a3', '--color-background': '#fafafa', '--color-surface': '#ffffff', '--color-surface-raised': '#f5f5f5', '--color-border': '#e5e5e5', '--color-on-surface': '#262626', '--color-on-surface-muted': '#525252', ...baseColors } },
];

const darkThemes: Theme[] = [
    {
        name: 'Default Dark',
        type: 'dark',
        colors: {
            '--color-primary': '#0ea5e9', // sky-500
            '--color-secondary': '#64748b', // slate-500
            '--color-background': '#0f172a', // slate-900
            '--color-surface': '#1e293b', // slate-800
            '--color-surface-raised': '#334155', // slate-700
            '--color-border': '#475569', // slate-600
            '--color-on-surface': '#f1f5f9', // slate-100
            '--color-on-surface-muted': '#94a3b8', // slate-400
            ...baseColors,
        },
    },
    {
        name: 'Midnight Dusk',
        type: 'dark',
        colors: {
            '--color-primary': '#8b5cf6', // violet-500
            '--color-secondary': '#71717a', // zinc-500
            '--color-background': '#18181b', // zinc-900
            '--color-surface': '#27272a', // zinc-800
            '--color-surface-raised': '#3f3f46', // zinc-700
            '--color-border': '#52525b', // zinc-600
            '--color-on-surface': '#f4f4f5', // zinc-100
            '--color-on-surface-muted': '#a1a1aa', // zinc-400
            ...baseColors,
        },
    },
    {
        name: 'Crimson Night',
        type: 'dark',
        colors: {
            '--color-primary': '#f43f5e', // rose-500
            '--color-secondary': '#7f1d1d', // red-900
            '--color-background': '#1c1917', // stone-900
            '--color-surface': '#292524', // stone-800
            '--color-surface-raised': '#44403c', // stone-700
            '--color-border': '#57534e', // stone-600
            '--color-on-surface': '#f5f5f4', // stone-100
            '--color-on-surface-muted': '#a8a29e', // stone-400
            ...baseColors,
        },
    },
    {
        name: 'Forest Deep',
        type: 'dark',
        colors: {
            '--color-primary': '#22c55e', // green-500
            '--color-secondary': '#166534', // green-800
            '--color-background': '#141E1B',
            '--color-surface': '#1A2923',
            '--color-surface-raised': '#20342B',
            '--color-border': '#284136',
            '--color-on-surface': '#dcfce7', // green-100
            '--color-on-surface-muted': '#86efac', // green-300
            ...baseColors,
        },
    },
    {
        name: 'Abyssal Ocean',
        type: 'dark',
        colors: {
            '--color-primary': '#3b82f6', // blue-500
            '--color-secondary': '#1e40af', // blue-800
            '--color-background': '#171B26',
            '--color-surface': '#1e293b',
            '--color-surface-raised': '#2a3b50',
            '--color-border': '#354962',
            '--color-on-surface': '#dbeafe', // blue-100
            '--color-on-surface-muted': '#93c5fd', // blue-300
            ...baseColors,
        },
    },
    {
        name: 'Cyberpunk',
        type: 'dark',
        colors: {
            '--color-primary': '#ec4899', // pink-500
            '--color-secondary': '#0891b2', // cyan-600
            '--color-background': '#020617', // slate-950
            '--color-surface': '#1e293b',
            '--color-surface-raised': '#334155',
            '--color-border': '#475569',
            '--color-on-surface': '#f0abfc', // fuchsia-300
            '--color-on-surface-muted': '#67e8f9', // cyan-300
            ...baseColors,
        },
    },
    {
        name: 'Royal Purple',
        type: 'dark',
        colors: {
            '--color-primary': '#a855f7', // purple-500
            '--color-secondary': '#6b21a8', // purple-800
            '--color-background': '#1b1926',
            '--color-surface': '#2e2a42',
            '--color-surface-raised': '#393355',
            '--color-border': '#463f69',
            '--color-on-surface': '#f3e8ff', // purple-100
            '--color-on-surface-muted': '#d8b4fe', // purple-300
            ...baseColors,
        },
    },
    { name: 'Golden Empire', type: 'dark', colors: { '--color-primary': '#f59e0b', '--color-secondary': '#b45309', '--color-background': '#201A10', '--color-surface': '#2F2618', '--color-surface-raised': '#3C311F', '--color-border': '#4A3C26', '--color-on-surface': '#fef3c7', '--color-on-surface-muted': '#fde68a', ...baseColors } },
    { name: 'Emerald City', type: 'dark', colors: { '--color-primary': '#10b981', '--color-secondary': '#059669', '--color-background': '#0f1715', '--color-surface': '#11221d', '--color-surface-raised': '#142d26', '--color-border': '#17382f', '--color-on-surface': '#d1fae5', '--color-on-surface-muted': '#a7f3d0', ...baseColors } },
    { name: 'Ruby Red', type: 'dark', colors: { '--color-primary': '#ef4444', '--color-secondary': '#b91c1c', '--color-background': '#1c1111', '--color-surface': '#291818', '--color-surface-raised': '#3b1f1f', '--color-border': '#4a2626', '--color-on-surface': '#fee2e2', '--color-on-surface-muted': '#fecaca', ...baseColors } },
    { name: 'Sapphire', type: 'dark', colors: { '--color-primary': '#38bdf8', '--color-secondary': '#0e7490', '--color-background': '#0c1d24', '--color-surface': '#0e2a36', '--color-surface-raised': '#113545', '--color-border': '#134053', '--color-on-surface': '#e0f2fe', '--color-on-surface-muted': '#bae6fd', ...baseColors } },
    { name: 'Graphite', type: 'dark', colors: { '--color-primary': '#a3a3a3', '--color-secondary': '#525252', '--color-background': '#171717', '--color-surface': '#262626', '--color-surface-raised': '#404040', '--color-border': '#525252', '--color-on-surface': '#f5f5f5', '--color-on-surface-muted': '#d4d4d4', ...baseColors } },
    { name: 'Sunset Orange', type: 'dark', colors: { '--color-primary': '#f97316', '--color-secondary': '#c2410c', '--color-background': '#1c130d', '--color-surface': '#291d16', '--color-surface-raised': '#432c1e', '--color-border': '#573725', '--color-on-surface': '#ffedd5', '--color-on-surface-muted': '#fed7aa', ...baseColors } },
    { name: 'Teal Nebula', type: 'dark', colors: { '--color-primary': '#2dd4bf', '--color-secondary': '#115e59', '--color-background': '#0f1c1b', '--color-surface': '#132e2b', '--color-surface-raised': '#163a36', '--color-border': '#194641', '--color-on-surface': '#ccfbf1', '--color-on-surface-muted': '#99f6e4', ...baseColors } },
    { name: 'Indigo Night', type: 'dark', colors: { '--color-primary': '#6366f1', '--color-secondary': '#4338ca', '--color-background': '#14142B', '--color-surface': '#222245', '--color-surface-raised': '#2C2C5A', '--color-border': '#35356E', '--color-on-surface': '#e0e7ff', '--color-on-surface-muted': '#c7d2fe', ...baseColors } },
    { name: 'Amethyst', type: 'dark', colors: { '--color-primary': '#d946ef', '--color-secondary': '#86198f', '--color-background': '#1e1121', '--color-surface': '#2f1a33', '--color-surface-raised': '#3d2042', '--color-border': '#4b2752', '--color-on-surface': '#fae8ff', '--color-on-surface-muted': '#f5d0fe', ...baseColors } },
    { name: 'Lime Pulse', type: 'dark', colors: { '--color-primary': '#a3e635', '--color-secondary': '#4d7c0f', '--color-background': '#1a1f0f', '--color-surface': '#252e16', '--color-surface-raised': '#2f3b1b', '--color-border': '#394821', '--color-on-surface': '#ecfccb', '--color-on-surface-muted': '#d9f99d', ...baseColors } },
    { name: 'Coffee House', type: 'dark', colors: { '--color-primary': '#a16207', '--color-secondary': '#78350f', '--color-background': '#1E1B16', '--color-surface': '#29251E', '--color-surface-raised': '#3F3A30', '--color-border': '#514A3B', '--color-on-surface': '#fefce8', '--color-on-surface-muted': '#fef9c3', ...baseColors } },
    { name: 'Rose Thorn', type: 'dark', colors: { '--color-primary': '#e11d48', '--color-secondary': '#9f1239', '--color-background': '#1f1013', '--color-surface': '#30181d', '--color-surface-raised': '#441e28', '--color-border': '#592433', '--color-on-surface': '#fff1f2', '--color-on-surface-muted': '#ffe4e6', ...baseColors } },
    { name: 'Arctic Blue', type: 'dark', colors: { '--color-primary': '#7dd3fc', '--color-secondary': '#075985', '--color-background': '#121a20', '--color-surface': '#1a2730', '--color-surface-raised': '#213440', '--color-border': '#274150', '--color-on-surface': '#f0f9ff', '--color-on-surface-muted': '#e0f2fe', ...baseColors } },
];

export const preconfiguredThemes: Theme[] = [...lightThemes, ...darkThemes];

export const defaultLight = lightThemes.find(t => t.name === 'Default Light')!;
export const defaultDark = darkThemes.find(t => t.name === 'Default Dark')!;
