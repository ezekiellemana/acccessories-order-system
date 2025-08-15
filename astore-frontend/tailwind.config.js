/** @type {import('tailwindcss').Config} */
export const darkMode = 'class';

export const content = [
  './index.html',
  './src/**/*.{js,jsx,ts,tsx}',
];

export const theme = {
  extend: {
    fontFamily: {
      sans: ['Inter', 'ui-sans-serif', 'system-ui'],
    },
    colors: {
      primary: {
        50: '#F2F5FF',
        100: '#D6DBFF',
        200: '#B6C3FF',
        300: '#9AB0FF',
        400: '#7D99FF',
        500: '#5E7EFF',
        600: '#4F68E6',
        700: '#4050B3',
        800: '#303983',
        900: '#202652',
      },
      accent: {
        50: '#EFFCF5',
        100: '#C6F7E2',
        200: '#8EEDD1',
        300: '#5CE5BF',
        400: '#31D6A4',
        500: '#10B981',
        600: '#09976B',
        700: '#027B58',
        800: '#05603A',
        900: '#054F31',
      },
      neutral: {
        50: '#FAFAFA',
        100: '#F5F5F5',
        200: '#E5E5E5',
        300: '#D4D4D4',
        400: '#A3A3A3',
        500: '#737373',
        600: '#525252',
        700: '#404040',
        800: '#262626',
        900: '#171717',
      },
      milk: '#fcfcf9',
    },
    boxShadow: {
      card: '0 4px 12px rgba(0, 0, 0, 0.08)',
      navbar: '0 2px 8px rgba(0, 0, 0, 0.06)',
      dropdown: '0 8px 16px rgba(0, 0, 0, 0.1)',
    },
    borderRadius: {
      lg: '0.75rem',
      xl: '1rem',
    },
  },
};

export const plugins = [];
