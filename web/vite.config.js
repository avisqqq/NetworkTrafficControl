import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../dist',
    emptyOutDir: true,
  },
  server: {
    host: '0.0.0.0',
    proxy: {
      '/events':    { target: 'http://localhost:8086', changeOrigin: true },
      '/blacklist': { target: 'http://localhost:8086', changeOrigin: true },
      '/whitelist': { target: 'http://localhost:8086', changeOrigin: true },
      '/onlylocal': { target: 'http://localhost:8086', changeOrigin: true },
      '/network':   { target: 'http://localhost:8086', changeOrigin: true },
      '/metrics':   { target: 'http://localhost:8086', changeOrigin: true },
      '/runtime':   { target: 'http://localhost:8086', changeOrigin: true },
    }
  }
})
