import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [tailwindcss(), react()],
  server: {
    host: true,
    port: Number(process.env.VITE_PORT) || undefined,
    allowedHosts: ['aki.internal', 'localhost'],
    proxy: {
      '/oauth2': 'http://localhost:80',
      '/login': 'http://localhost:80',
      '/auth': 'http://localhost:80',
      '/api': 'http://localhost:80',
      '/registration': 'http://localhost:80',
      '/userinfo': 'http://localhost:80',
      '/introspect': 'http://localhost:80',
      '/.well-known': 'http://localhost:80',
    },
  },
})
