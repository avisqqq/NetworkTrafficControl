import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../web',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/events':    { target: 'http://localhost:8080', changeOrigin: true },
      '/blacklist': { target: 'http://localhost:8080', changeOrigin: true },
      '/whitelist': { target: 'http://localhost:8080', changeOrigin: true },
    }
  }
})