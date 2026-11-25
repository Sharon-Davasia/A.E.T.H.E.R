import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

const root = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  base: './',
  plugins: [react()],
  clearScreen: false,
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  build: {
    rollupOptions: {
      input: {
        main: resolve(root, 'index.html'),
        // Dedicated trusted approval modal page (own window/preload).
        approval: resolve(root, 'approval.html'),
      },
    },
  },
});
