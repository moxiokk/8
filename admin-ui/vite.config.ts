import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    target: 'es2020',
    sourcemap: false,
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:3312',
    },
  },
})
