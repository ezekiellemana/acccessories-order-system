import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    // ensure only one React copy and dedupe hooks
    alias: {
      '@': path.resolve(__dirname, './src'),
      react: path.resolve(__dirname, 'node_modules/react'),
      'react-dom': path.resolve(__dirname, 'node_modules/react-dom'),
    },
    dedupe: ['react', 'react-dom'],
  },
  optimizeDeps: {
    include: ['@react-oauth/google'],
  },
  ssr: {
    // ensure React isn't externalized in SSR and get single copy
    noExternal: ['react', 'react-dom', '@react-oauth/google'],
    noExternal: ['@react-oauth/google'],
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('html2canvas') || id.includes('jspdf')) {
              return 'pdf-html2canvas';
            }
            if (id.includes('recharts') || id.includes('chart.js')) {
              return 'charts';
            }
            return 'vendor';
          }
        },
      },
    },
    chunkSizeWarningLimit: 1000,
  },
});
